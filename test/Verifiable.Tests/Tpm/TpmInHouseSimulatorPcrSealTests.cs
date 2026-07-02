using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives PCR-gated TPM sealing ("tie a secret to this computer <i>and</i> this state") against the in-house
/// behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same
/// production command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CreateInput"/>, <see cref="LoadInput"/>, and <see cref="UnsealInput"/>, the
/// <see cref="TpmDeviceExtensions"/> policy commands, <see cref="TpmSession"/>, and
/// <see cref="TpmPolicySession"/> over the real command/response codecs).
/// </summary>
/// <remarks>
/// <para>
/// A secret is sealed into a <c>TPM_ALG_KEYEDHASH</c> object whose authPolicy is a <c>TPM2_PolicyPCR()</c> digest,
/// so the unseal is authorized only when a policy session reproduces that digest over the live PCR values (TPM 2.0
/// Library Part 3, clause 12.7; Part 1, clause 19.7). Recovery uses two sessions: a satisfied
/// <see cref="TpmPolicySession"/> (the authorizing session, supplied first, which carries an empty HMAC because the
/// policy itself is the authorization, Part 1, clause 19.6) plus a bound HMAC session with AES-CFB parameter
/// encryption and the <c>encrypt</c> attribute (Part 1, clauses 18.7 and 19), so the recovered secret is decrypted
/// only after the response HMAC verifies.
/// </para>
/// <para>
/// The positive test computes the seal's authPolicy from the very session that later authorizes the unseal, so the
/// sealed digest and the unseal digest are bound to the same captured PCR state. The wrapped blob is
/// persisted-and-reloaded through wire bytes only (the private blob is copied and the public area reserialized),
/// mirroring the disk round-trip a real deployment performs. The negative test seals under a deliberately wrong PCR
/// digest (computed in a trial session, Part 3, clause 23.7) and confirms the unseal is rejected with
/// <c>TPM_RC_POLICY_FAIL</c> — the "wrong state ⇒ no access" half of the guarantee.
/// </para>
/// <para>
/// The simulator advances each session's policyDigest and frames the two-session response through the SAME seams
/// the host <see cref="TpmSession"/> verifies with (Part 1, clauses 17.6, 18.7, and 19), so the on-device
/// derivation and the host's verification cannot diverge by construction: a session key, nonce, keystream, or
/// response-framing byte that the simulator produced off by one would make the executor reject the response and
/// fail the positive test's byte-exact equality assertion.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPcrSealTests
{
    /// <summary>The session/policy/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCR bank the policy selects from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The PCR(s) the seal is bound to. PCR 23 is the application/debug register, reset to the all-zero image
    /// (TPM 2.0 Library Part 1, clause 17.5.3), so binding to it keeps the test off the boot-measured registers.
    /// </summary>
    private static int[] PcrIndices { get; } = [23];

    /// <summary>The fixed secret sealed and recovered by the test.</summary>
    private static byte[] SecretBytes { get; } = "Tie this secret to the in-house TPM and its state."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task PcrGatedSealUnsealsWhenPolicySatisfied()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();
        TpmtSymDef symmetric = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        uint policyHandle = 0;
        uint itemHandle = 0;
        uint encryptHandle = 0;
        try
        {
            //1. Start a policy session, bind it to the current PCRs, and read back its policyDigest. Sealing the
            //object to this digest and authorizing the unseal with this same session binds both to one captured
            //PCR state, so the test cannot drift between sealing and unsealing.
            TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

            using StartAuthSessionResponse policyStart = policyStartResult.Value;
            policyHandle = policyStart.SessionHandle.Value;

            //On a real (non-trial) session the TPM binds the policy to the LIVE PCR composite (Part 3, clause 23.7),
            //so no caller pcrDigest is supplied — the empty digest lets the TPM fold in its own live value.
            TpmResult<PolicyPcrResponse> pcrResult = await tpm.PolicyPcrAsync(
                policyHandle, PcrBank, PcrIndices, default, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(pcrResult.IsSuccess, $"PolicyPCR failed: '{pcrResult.ResponseCode}'.");

            byte[] authPolicy;
            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
            using(PolicyGetDigestResponse digestResponse = digestResult.Value)
            {
                authPolicy = digestResponse.PolicyDigest.AsReadOnlySpan().ToArray();
            }

            Assert.IsNotEmpty(authPolicy, "The PCR policy digest must be non-empty.");

            //2. Seal the secret under the PCR policy.
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under PCR policy) failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;

            //3. Persist-then-reload through wire bytes and load the wrapped object.
            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

            using LoadResponse loaded = loadResult.Value;
            itemHandle = loaded.ObjectHandle.Value;
            ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

            //4. Start a bound AES-CFB encrypt session (bound to the parent) for the confidential outData.
            StartAuthSessionInput encryptStartInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(parentHandle, SessionAlg, symmetric);
            TpmResult<StartAuthSessionResponse> encryptStartResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, encryptStartInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(encryptStartResult.IsSuccess, $"StartAuthSession (encrypt) failed: '{encryptStartResult.ResponseCode}'.");

            //nonceTPM ownership transfers to the session below.
            StartAuthSessionResponse encryptStart = encryptStartResult.Value;
            encryptHandle = encryptStart.SessionHandle.Value;

            using Tpm2bAuth encryptBindAuth = Tpm2bAuth.CreateEmpty(pool);
            using TpmSession encryptSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(encryptHandle),
                encryptBindAuth.AsReadOnlyMemory(),
                encryptStartInput.NonceCaller,
                encryptStart.NonceTPM,
                SessionAlg,
                pool,
                symmetric: symmetric,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            encryptSession.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

            //5. Unseal under [policy session (authorizes the object), encrypt session (protects outData)].
            using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession, encryptSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess,
                $"PCR-gated unseal under a satisfied policy session failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                "The unsealed data, decrypted from the encrypted response parameter, must equal the sealed secret.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, encryptHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, parentHandle).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PcrGatedSealRejectsUnsealWhenPolicyUnsatisfied()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        uint trialHandle = 0;
        uint policyHandle = 0;
        uint itemHandle = 0;
        try
        {
            //1. Compute a WRONG PCR policy digest in a trial session, using a fabricated PCR digest the live PCRs
            //will not reproduce (a trial session uses the caller's pcrDigest verbatim, Part 3, clause 23.7).
            byte[] wrongPcrDigest = new byte[32];
            Array.Fill(wrongPcrDigest, (byte)0xAB);

            TpmResult<StartAuthSessionResponse> trialStartResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(trialStartResult.IsSuccess, $"StartAuthSession (trial) failed: '{trialStartResult.ResponseCode}'.");

            using StartAuthSessionResponse trialStart = trialStartResult.Value;
            trialHandle = trialStart.SessionHandle.Value;

            TpmResult<PolicyPcrResponse> trialPcrResult = await tpm.PolicyPcrAsync(
                trialHandle, PcrBank, PcrIndices, wrongPcrDigest, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(trialPcrResult.IsSuccess, $"Trial PolicyPCR failed: '{trialPcrResult.ResponseCode}'.");

            byte[] wrongAuthPolicy;
            TpmResult<PolicyGetDigestResponse> trialDigestResult = await tpm.PolicyGetDigestAsync(
                trialHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(trialDigestResult.IsSuccess, $"Trial PolicyGetDigest failed: '{trialDigestResult.ResponseCode}'.");
            using(PolicyGetDigestResponse trialDigestResponse = trialDigestResult.Value)
            {
                wrongAuthPolicy = trialDigestResponse.PolicyDigest.AsReadOnlySpan().ToArray();
            }

            await FlushIfPresentAsync(tpm, trialHandle).ConfigureAwait(false);
            trialHandle = 0;

            //2. Seal under the WRONG policy.
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, wrongAuthPolicy, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under wrong PCR policy) failed: '{createResult.ResponseCode}'.");

            using CreateResponse sealedObject = createResult.Value;

            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

            using LoadResponse loaded = loadResult.Value;
            itemHandle = loaded.ObjectHandle.Value;
            ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

            //3. Start a real policy session bound to the LIVE PCRs, whose digest differs from the sealed (wrong)
            //authPolicy.
            TpmResult<StartAuthSessionResponse> policyStartResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policyStartResult.IsSuccess, $"StartAuthSession (policy) failed: '{policyStartResult.ResponseCode}'.");

            using StartAuthSessionResponse policyStart = policyStartResult.Value;
            policyHandle = policyStart.SessionHandle.Value;

            TpmResult<PolicyPcrResponse> pcrResult = await tpm.PolicyPcrAsync(
                policyHandle, PcrBank, PcrIndices, default, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(pcrResult.IsSuccess, $"PolicyPCR failed: '{pcrResult.ResponseCode}'.");

            //4. The unseal must be rejected: the session's live-PCR policyDigest does not match the sealed authPolicy.
            using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess,
                "Unseal must be rejected when the policy session's live-PCR digest does not match the sealed authPolicy.");

            //TPM_RC_POLICY_FAIL is a format-one code; the TPM annotates it with the offending session
            //(TPM_RC_S | the session number in TPM_RC_N_MASK), so strip those modifier bits to compare the base
            //error (TPM 2.0 Library Part 2, Section 6.6.3).
            const uint FormatOneModifierMask = (uint)(TpmRcConstants.TPM_RC_P | TpmRcConstants.TPM_RC_S | TpmRcConstants.TPM_RC_N_MASK);
            var baseError = (TpmRcConstants)((uint)unsealResult.ResponseCode & ~FormatOneModifierMask);
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, baseError,
                $"A policy-digest mismatch must surface as TPM_RC_POLICY_FAIL (got '{unsealResult.ResponseCode}').");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, trialHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates the deterministic ECC storage parent under the owner hierarchy and returns the response (the
    /// caller owns it and flushes <see cref="CreatePrimaryResponse.ObjectHandle"/>).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the storage parent.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Creates a response codec registry covering the executor-driven commands these tests issue. The policy
    /// assertion commands run through their own self-contained extension-method registries.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object or session handle when one is present (non-zero), ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="handle">The handle to flush, or 0 when none was acquired.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await tpm.FlushContextAsync(handle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reserializes a public area into a fresh <see cref="Tpm2bPublic"/>, the round-trip a disk-persisted public
    /// blob makes; keeps the seal and unseal steps firewalled to wire bytes.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the public area.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, MemoryPool<byte> pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c>; the storage parent is used only as a handle to parent the sealed object here.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-pcrseal", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }
}
