using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tpm;
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
/// Acceptance tests for PCR-gated TPM sealing ("tie a secret to this computer <i>and</i> this state") against
/// the TCG ms-tpm-20-ref software TPM simulator.
/// </summary>
/// <remarks>
/// <para>
/// A secret is sealed into a KEYEDHASH object whose authPolicy is a <c>TPM2_PolicyPCR</c> digest, so the
/// unseal is authorized only when a policy session reproduces that digest over the live PCR values. Recovery
/// uses two sessions: a satisfied <see cref="TpmPolicySession"/> (the authorizing session, supplied first,
/// which carries an empty HMAC because the policy itself is the authorization) plus a bound HMAC session with
/// AES-CFB parameter encryption and the <c>encrypt</c> attribute, so the recovered secret is decrypted only
/// after the response HMAC verifies — the maximum-security channel the unsealed secret warrants.
/// </para>
/// <para>
/// The positive test computes the seal's authPolicy from the very session that later authorizes the unseal, so
/// the sealed digest and the unseal digest are bound to the same captured PCR state. The negative test seals
/// under a deliberately wrong PCR digest (computed in a trial session) and confirms the unseal is rejected with
/// <c>TPM_RC_POLICY_FAIL</c> — the "wrong state ⇒ no access" half of the guarantee.
/// </para>
/// <para>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorPcrSealTests
{
    /// <summary>The connection to the simulator, established once for the class.</summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>The TPM device created over the simulator connection.</summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>Whether a simulator was reachable at class initialization.</summary>
    private static bool HasSimulator { get; set; }

    /// <summary>The session/policy/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCR bank the policy selects from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The PCR(s) the seal is bound to. PCR 23 is the debug PCR; binding to it keeps the test from depending on
    /// boot-measured PCRs and minimizes interference with other state.
    /// </summary>
    private static int[] PcrIndices { get; } = [23];

    /// <summary>The fixed secret sealed and recovered by the test.</summary>
    private static byte[] SecretBytes { get; } = "PCR-gated secret to this state."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Connects to the simulator (if one is reachable) and brings up a TPM device for the class.</summary>
    /// <param name="context">The class-level test context.</param>
    [ClassInitialize]
    public static async Task ClassInit(TestContext context)
    {
        if(!MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1)))
        {
            return;
        }

        Connection = await MsTpmSimulatorConnection.ConnectAsync(
            "localhost", MsTpmSimulatorConnection.DefaultCommandPort, context.CancellationToken).ConfigureAwait(false);
        Tpm = TpmDevice.Create(Connection.SubmitAsync);
        HasSimulator = true;
    }

    /// <summary>Releases the TPM device and simulator connection.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>Skips the test when no simulator is reachable.</summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task PcrGatedSealUnsealsWhenPolicySatisfied()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
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
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        uint trialHandle = 0;
        uint policyHandle = 0;
        uint itemHandle = 0;
        try
        {
            //1. Compute a WRONG PCR policy digest in a trial session, using a fabricated PCR digest the live PCRs
            //will not reproduce (a trial session uses the caller's pcrDigest verbatim).
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
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

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
}
