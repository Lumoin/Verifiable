using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyCounterTimer()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses (the
/// <see cref="TpmDeviceExtensions"/> policy commands, <see cref="TpmCommandExecutor"/>, and the real
/// command/response codecs). The command compares a live-marshaled <c>TPMS_TIME_INFO</c> against a caller operand
/// (TPM 2.0 Library Part 3, Section 23.10).
/// </summary>
/// <remarks>
/// <para>
/// Every test that compares a fixed field pins it to <c>resetCount</c>/<c>restartCount</c>/<c>Safe</c> (byte
/// offsets 16-24 of the marshaled structure) rather than <c>Time</c>/<c>Clock</c>: the former three are stable for
/// the whole life of a single power cycle (they change only across a <c>TPM2_Startup()</c>/<c>TPM2_Shutdown()</c>
/// boundary, which these tests never cross), while the latter two advance by a fixed quantum on every dispatched
/// command — including the very <c>TPM2_StartAuthSession()</c> a test issues before the assertion itself — so an
/// operand captured from an earlier <c>TPM2_ReadClock()</c> would already be stale by the time
/// <c>TPM2_PolicyCounterTimer()</c> runs. The one exception is the negative "false time comparison" test, which
/// deliberately supplies an operand for the <c>Time</c> field that can never match (a value many orders of
/// magnitude larger than any test run could accumulate), so it needs no live snapshot at all.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyCounterTimerTests
{
    /// <summary>The policy session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The byte offset of <c>resetCount</c> in the marshaled TPMS_TIME_INFO (Part 2, Section 10.11.1/10.11.6).</summary>
    private const ushort ResetCountOffset = 16;

    /// <summary>The fixed secret sealed and recovered by the flagship flow test.</summary>
    private static byte[] SecretBytes { get; } = "Bind this secret to a TPM2_PolicyCounterTimer() authorization."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Flagship flow: predicts the policyDigest a PolicyCounterTimer assertion gated on "resetCount equals its
    /// value at seal time" will produce, seals a secret under that prediction as the object's authPolicy, drives a
    /// real assertion through the production wire path, and unseals — proving the host prediction and the
    /// on-device fold agree end to end, and that the comparison against live state actually authorizes.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerFlowSealsAndUnsealsGatedOnResetCount()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        //resetCount is stable for the whole power cycle these tests run in (only a Startup/Shutdown boundary moves
        //it, and none crosses here), so it is safe to read once and reuse for both the seal-time prediction and
        //the real assertion later.
        byte[] operandB = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(operandB, 1u);

        int size = TpmPolicyDigest.Size(SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCounterTimer(zero, operandB, ResetCountOffset, (ushort)TpmEoConstants.TPM_EO_EQ, SessionAlg, authPolicy);

        uint policyHandle = 0;
        uint itemHandle = 0;
        try
        {
            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy, noDa: true);
            using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(createResult.IsSuccess, $"Create (seal under the PolicyCounterTimer-predicted policy) failed: '{createResult.ResponseCode}'.");

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

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            policyHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                policyHandle, operandB, ResetCountOffset, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policyResult.IsSuccess, $"PolicyCounterTimer (resetCount == initial) failed: '{policyResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                policyHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(authPolicy),
                "The simulator's policyDigest after PolicyCounterTimer must match the independently predicted ExtendForCounterTimer value.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(policyHandle, SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal gated on the PolicyCounterTimer digest failed: '{unsealResult.ResponseCode}'.");

            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(
                unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                "The unsealed data must equal the secret sealed under the PolicyCounterTimer-predicted authPolicy.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, policyHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, itemHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, parentHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a REAL (non-trial) session rejects with <c>TPM_RC_POLICY</c> when the comparison is false — here,
    /// an operand for the <c>Time</c> field (offset 0) that no test run could ever accumulate, so the rejection is
    /// unconditional rather than depending on the exact elapsed quantum.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerRejectsAFalseTimeComparison()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        //An 8-octet Time value of all-0xFF octets (~584 million years in milliseconds) can never equal the live
        //Time this simulator's fixed per-command quantum could accumulate within a test run.
        byte[] impossibleTime = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                sessionHandle, impossibleTime, offset: 0, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policyResult.IsSuccess, "An impossible Time comparison must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY, policyResult.ResponseCode, "A false PolicyCounterTimer comparison must reject with TPM_RC_POLICY.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a straddling offset — one that spans two (here, three: resetCount, restartCount, and Safe) adjacent
    /// TPMS_TIME_INFO fields in a single window — is accepted with no alignment enforcement (Part 3, Section 23.10:
    /// "The TPM does not check for alignment of the offset with a TPMS_TIME_INFO structure member").
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerAcceptsAStraddlingOffsetWithNoAlignmentRule()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        //offset 19, size 6 spans: resetCount's last octet (19), all four octets of restartCount (20-23), and Safe
        //(24) — straddling two field boundaries in one window. A fresh simulator's single Startup(CLEAR) is its
        //first-ever Reset: resetCount = 1, restartCount = 0, Safe = YES, none of which move again in this test.
        const ushort Offset = 19;
        byte[] operandB = [0x01, 0x00, 0x00, 0x00, 0x00, 0x01];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                sessionHandle, operandB, Offset, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policyResult.IsSuccess, $"PolicyCounterTimer with a straddling offset failed: '{policyResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            int size = TpmPolicyDigest.Size(SessionAlg);
            byte[] predicted = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            _ = TpmPolicyDigest.ExtendForCounterTimer(zero, operandB, Offset, (ushort)TpmEoConstants.TPM_EO_EQ, SessionAlg, predicted);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The simulator's policyDigest after a straddling-offset PolicyCounterTimer must match the host-computed value.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a TRIAL session skips the comparison entirely (Part 3, Section 23.10: a trial session "will not
    /// perform any validation") and folds the digest unconditionally, even fed an operand that could never satisfy
    /// a real comparison — proving the fold, not the check, is what a trial session exercises.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerTrialSessionPredictsTheSameDigestRegardlessOfTheOperand()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        //An operand that can never satisfy a real comparison against the live Time field, fed to a trial session
        //where it must still fold successfully without ever being checked.
        byte[] neverMatchingOperand = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        const ushort Offset = 0;

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                sessionHandle, neverMatchingOperand, Offset, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policyResult.IsSuccess, $"A trial session must fold unconditionally: '{policyResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            int size = TpmPolicyDigest.Size(SessionAlg);
            byte[] predicted = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            _ = TpmPolicyDigest.ExtendForCounterTimer(zero, neverMatchingOperand, Offset, (ushort)TpmEoConstants.TPM_EO_EQ, SessionAlg, predicted);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "A trial session's policyDigest must fold the caller-supplied operand as-is, with no comparison performed.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>offset &gt; 25</c> (the marshaled TPMS_TIME_INFO's total size) is rejected with
    /// <c>TPM_RC_VALUE</c>, and that this range check runs even for a TRIAL session (Part 3, Section 23.10: "the
    /// offset checks are made even for a trial policy").
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerRejectsAnOffsetBeyondTheStructureEvenOnATrialSession()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        byte[] operandB = [0x00];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                sessionHandle, operandB, offset: 26, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policyResult.IsSuccess, "An offset beyond the 25-octet TPMS_TIME_INFO must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, policyResult.ResponseCode, "offset > 25 must reject with TPM_RC_VALUE, even for a trial session.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>offset + operandB.Length</c> overflowing the 25-octet TPMS_TIME_INFO is rejected with
    /// <c>TPM_RC_RANGE</c>, and that this range check also runs even for a TRIAL session.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerRejectsAWindowOverflowingTheStructureEvenOnATrialSession()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        //offset 24 (Safe, the last legal octet) plus a 4-octet operand overflows the 25-octet structure by 3.
        byte[] operandB = [0x00, 0x00, 0x00, 0x00];

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                sessionHandle, operandB, offset: 24, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policyResult.IsSuccess, "A window overflowing the 25-octet TPMS_TIME_INFO must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_RANGE, policyResult.ResponseCode, "offset + operandB.Length > 25 must reject with TPM_RC_RANGE, even for a trial session.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Exploit-becomes-regression test: an undefined <c>TPM_EO</c> value (0x0100, outside the 12 Table 22 defines)
    /// on a REAL policy session must reject with <c>TPM_RC_VALUE</c> through the production wire path, not throw
    /// an unhandled exception out of <c>TpmSimulator.SubmitAsync</c> (TPM 2.0 Library Part 3, clause 5.1: an
    /// undefined selector is rejected at unmarshal).
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerWithAnUndefinedOperationReturnsValueOnARealSession()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        byte[] operandB = [0x00, 0x00, 0x00, 0x00];
        const TpmEoConstants UndefinedOperation = (TpmEoConstants)0x0100;

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (real) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                sessionHandle, operandB, ResetCountOffset, UndefinedOperation, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policyResult.IsSuccess, "An undefined TPM_EO must be rejected, not silently accepted.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, policyResult.ResponseCode, "An undefined TPM_EO must reject with TPM_RC_VALUE at unmarshal.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a TRIAL session rejects the same undefined <c>TPM_EO</c> identically to a REAL session (the FIX
    /// 1 uniformity requirement): the parse-time check runs before the trial/real branch, so the trial session's
    /// "skip the comparison, fold unconditionally" path never gets a chance to silently accept it.
    /// </summary>
    [TestMethod]
    public async Task PolicyCounterTimerWithAnUndefinedOperationReturnsValueOnATrialSessionToo()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        byte[] operandB = [0x00, 0x00, 0x00, 0x00];
        const TpmEoConstants UndefinedOperation = (TpmEoConstants)0x0100;

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyCounterTimerResponse> policyResult = await tpm.PolicyCounterTimerAsync(
                sessionHandle, operandB, ResetCountOffset, UndefinedOperation, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(policyResult.IsSuccess, "A trial session must reject an undefined TPM_EO too, not silently fold it.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, policyResult.ResponseCode, "A trial session's undefined TPM_EO must also reject with TPM_RC_VALUE at unmarshal.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
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
    /// Creates a response codec registry covering the executor-driven commands these tests issue directly (the
    /// policy assertion device verbs run through their own self-contained extension-method registries).
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
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
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired (needed to create the ECC storage
    /// parent), powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-policy-countertimer", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");
    }
}
