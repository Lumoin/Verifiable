using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the NV PIN Fail/PIN Pass Index machinery — <c>TPM_NT</c> validation at
/// <c>TPM2_NV_DefineSpace()</c>, the localized pinCount/pinLimit authorization gate, and the pinCount update
/// on authorization success/failure — against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process with no external assets, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0 Library Part 1, clause
/// 37.2.6.6 and 37.2.8; Part 2, clauses 13.2-13.4.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvPinIndexTests
{
    /// <summary>The size in octets of <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (pinCount + pinLimit).</summary>
    private const ushort PinCounterParametersSize = 8;

    /// <summary>A PIN Fail Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint PinFailIndexHandle = 0x0100_0021;

    /// <summary>A PIN Pass Index handle, distinct from <see cref="PinFailIndexHandle"/>.</summary>
    private const uint PinPassIndexHandle = 0x0100_0022;

    /// <summary>
    /// PIN Fail attributes with the spec-mandated <c>TPMA_NV_NO_DA</c> set (TPM 2.0 Library Part 2, clause 13.4)
    /// and <c>TPMA_NV_AUTHWRITE</c> CLEAR (Part 1, clause 37.2.6.1): a PIN Index's own authValue authorizes reads
    /// only, so provisioning/recovery goes through the owner-authorized <c>TPM2_NV_Write()</c> arm.
    /// </summary>
    private const TpmaNv PinFailAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The same PIN Fail type, deliberately missing the mandated <c>TPMA_NV_NO_DA</c>.</summary>
    private const TpmaNv PinFailAttributesWithoutNoDa =
        TpmaNv.TPMA_NV_AUTHREAD | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The same PIN Fail type, with the mandated <c>TPMA_NV_NO_DA</c> present but <c>TPMA_NV_AUTHWRITE</c>
    /// deliberately (and forbiddenly) SET.</summary>
    private const TpmaNv PinFailAttributesWithAuthWrite =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The same PIN Fail type, deliberately missing <c>TPMA_NV_OWNERWRITE</c>: with a PIN Index's own
    /// authValue forbidden from writing (no <c>TPMA_NV_AUTHWRITE</c>) and owner authorization equally refused,
    /// no authorization can write it at all.</summary>
    private const TpmaNv PinFailAttributesWithoutOwnerWrite =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The same PIN Fail type as <see cref="PinFailAttributes"/>, additionally carrying
    /// <c>TPMA_NV_OWNERREAD</c> so the owner-authorized <c>TPM2_NV_Read()</c> arm (TPM 2.0 Library Part 3,
    /// clause 31.13) may read it. <see cref="PinFailAttributes"/> itself deliberately lacks this bit, so it
    /// doubles as the OWNERREAD-clear negative fixture.</summary>
    private const TpmaNv PinFailAttributesWithOwnerRead =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>
    /// PIN Pass attributes, opted out of the global dictionary-attack mechanism for test isolation, with
    /// <c>TPMA_NV_AUTHWRITE</c> CLEAR (Part 1, clause 37.2.6.1) — see <see cref="PinFailAttributes"/>.
    /// </summary>
    private const TpmaNv PinPassAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_PASS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Attributes whose TPM_NT field (0x3) is a reserved value — none of the six defined constants.</summary>
    private const TpmaNv ReservedIndexTypeAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | (TpmaNv)(0x3u << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The Index authorization value (the PIN) used throughout.</summary>
    private static byte[] CorrectPin { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong PIN, distinct from <see cref="CorrectPin"/>.</summary>
    private static byte[] WrongPin { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>A wrong owner authorization value; the simulator's owner authValue is empty throughout this
    /// slice (TPM 2.0 Library, no command in this slice changes it from empty), so any non-empty value is wrong.</summary>
    private static byte[] WrongOwnerAuth { get; } = [0x77, 0x77, 0x77, 0x77];

    /// <summary>
    /// A single-octet payload for a rejected-arm <c>TPM2_NV_Write()</c> attempt; its content is immaterial since
    /// the write must never reach <c>WriteData</c>.
    /// </summary>
    private static byte[] RejectedWriteAttempt { get; } = [0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the PIN Fail brute-force throttle: wrong-PIN reads increment pinCount without touching the
    /// global dictionary-attack counter (a PIN Fail Index is spec-mandated <c>TPMA_NV_NO_DA</c>), at pinLimit
    /// even the CORRECT PIN is rejected, and the Index only accepts the correct PIN again once it has been
    /// rewritten via an OWNER-authorized <c>TPM2_NV_Write()</c> (TPM 2.0 Library Part 1, clause 37.2.6.6; clause
    /// 37.2.8.1's "no automatic self-heal" note; clause 37.2.6.1 forbids the PIN's own authValue from
    /// authorizing that rewrite at all).
    /// </summary>
    [TestMethod]
    public async Task PinFailBruteForceThrottleRejectsEvenTheCorrectPinAtLimitUntilRewritten()
    {
        const uint PinLimit = 2;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= PinLimit; attempt++)
        {
            TpmResult<NvReadResponse> wrongResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode,
                $"Attempt {attempt} of {PinLimit}: a PIN Fail Index is NO_DA-exempt, so a wrong PIN is never TPM_RC_AUTH_FAIL.");
        }

        TpmResult<NvReadResponse> atLimitResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, atLimitResult.ResponseCode,
            "Once pinCount reaches pinLimit, even the CORRECT PIN must be rejected.");

        TpmResult<NvWriteResponse> rewriteResult = await WritePinCounterParametersAsync(
            device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);
        Assert.IsTrue(rewriteResult.IsSuccess, $"The owner-authorized rewrite must succeed: '{rewriteResult.ResponseCode}'.");

        TpmResult<NvReadResponse> reArmedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.IsTrue(reArmedResult.IsSuccess, $"The correct PIN must be accepted again once the Index has been rewritten: '{reArmedResult.ResponseCode}'.");
    }

    /// <summary>
    /// Verifies a successful PIN Fail authorization below pinLimit resets pinCount to zero (TPM 2.0 Library
    /// Part 1, clause 37.2.6.6), observed directly in the read's own returned octets — the pinCount update is
    /// resolved as part of authorization, ahead of the command body that returns the data.
    /// </summary>
    [TestMethod]
    public async Task PinFailSuccessfulAuthBelowTheLimitResetsPinCount()
    {
        const uint PinLimit = 2;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        //One failure short of pinLimit, then the correct PIN: a response payload is only ever parsed on
        //success (an error response carries no parameters), so the reset is observed through the SUCCESSFUL
        //read's own returned octets, not by inspecting the failed attempt's (nonexistent) data.
        TpmResult<NvReadResponse> seedingFailure = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, seedingFailure.ResponseCode, "The seeding failure must be a NO_DA-exempt bad-authorization, not yet at pinLimit.");

        TpmResult<NvReadResponse> successResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.IsTrue(successResult.IsSuccess, $"The correct PIN below pinLimit must succeed: '{successResult.ResponseCode}'.");

        using(NvReadResponse successResponse = successResult.Value)
        {
            Assert.AreEqual(0u, ReadPinCount(successResponse.Data), "A successful PIN Fail authorization must reset pinCount to zero.");
            Assert.AreEqual(PinLimit, ReadPinLimit(successResponse.Data), "pinLimit must be left unchanged by the reset.");
        }

        //Proof the reset actually zeroed pinCount rather than leaving it at 1: two MORE failures are needed to
        //reach pinLimit again, not one — if the earlier success had not reset pinCount, a single further
        //failure would already have reached pinLimit (1 seeding failure + 1 more == 2).
        TpmResult<NvReadResponse> firstFailureAfterReset = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, firstFailureAfterReset.ResponseCode, "The first failure after the reset must not yet be at pinLimit.");

        TpmResult<NvReadResponse> secondFailureAfterReset = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, secondFailureAfterReset.ResponseCode, "The second failure after the reset must still be counted, not yet AUTH_UNAVAILABLE.");

        TpmResult<NvReadResponse> atLimitAfterReset = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, atLimitAfterReset.ResponseCode, "pinLimit must be reached only after two further failures, confirming pinCount was genuinely reset to zero.");
    }

    /// <summary>
    /// Verifies a PIN Pass Index's pinCount increments on every successful authorization and, once it reaches
    /// pinLimit, rejects even the CORRECT PIN (TPM 2.0 Library Part 1, clause 37.2.6.6) — the same throttle
    /// shape as PIN Fail, driven by successes rather than failures.
    /// </summary>
    [TestMethod]
    public async Task PinPassCountsSuccessfulUsesAndStopsAtTheLimit()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinPassIndexHandle, PinPassAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinPassIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        for(uint expectedPinCount = 1; expectedPinCount <= PinLimit; expectedPinCount++)
        {
            TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, PinPassIndexHandle, CorrectPin).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Use {expectedPinCount} of {PinLimit} must still succeed: '{result.ResponseCode}'.");

            using NvReadResponse response = result.Value;
            Assert.AreEqual(expectedPinCount, ReadPinCount(response.Data), $"pinCount must be {expectedPinCount} after {expectedPinCount} successful uses.");
        }

        TpmResult<NvReadResponse> atLimitResult = await ReadIndexAsync(device, pool, registry, PinPassIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, atLimitResult.ResponseCode,
            "Once pinCount reaches pinLimit, even the CORRECT PIN must be rejected — PIN Pass stops counting further uses.");
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> rejects a PIN Fail Index defined without the spec-mandated
    /// <c>TPMA_NV_NO_DA</c> (TPM 2.0 Library Part 2, clause 13.4): this keeps a PIN Fail Index's own defense
    /// disjoint from the TPM-wide dictionary-attack mechanism by construction, never by caller discipline.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfPinFailIndexWithoutNoDaReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, PinFailIndexHandle, PinFailAttributesWithoutNoDa).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode);
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> rejects a reserved <c>TPM_NT</c> bit pattern (TPM 2.0 Library
    /// Part 2, clause 13.2): only the six defined values (Ordinary, Counter, Bits, Extend, PIN Fail, PIN Pass)
    /// are legal.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithUnsupportedIndexTypeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, PinFailIndexHandle, ReservedIndexTypeAttributes).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode);
    }

    /// <summary>
    /// Verifies an unwritten PIN Index rejects auth use with <c>TPM_RC_AUTH_UNAVAILABLE</c>, even with the
    /// eventual-correct PIN: the authValue of a PIN Index is not accessible until the Index is written (TPM
    /// 2.0 Library Part 1, clause 37.2.6.6), distinct from the generic <c>TPM_RC_NV_UNINITIALIZED</c> an
    /// ordinary unwritten Index answers with.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfUnwrittenPinIndexReturnsAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode);
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_DefineSpace()</c> rejects a PIN Fail Index defined with the forbidden
    /// <c>TPMA_NV_AUTHWRITE</c> SET (TPM 2.0 Library Part 1, clause 37.2.6.1): a PIN Index's own authValue may
    /// authorize reads only, so an attribute combination that would let it authorize writes too is rejected at
    /// definition rather than trusted to caller discipline.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfPinIndexWithAuthWriteSetReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, PinFailIndexHandle, PinFailAttributesWithAuthWrite).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode);
    }

    /// <summary>
    /// Exploit-becomes-regression test for the unthrottled PIN-write oracle: an index-authValue
    /// <c>TPM2_NV_Write()</c> against a PIN Index rejects a WRONG and the RIGHT PIN with the IDENTICAL
    /// <c>TPM_RC_NV_AUTHORIZATION</c> — proving the AUTHWRITE-clear gate refuses before ever comparing the
    /// supplied value, so no correct/incorrect distinction leaks (TPM 2.0 Library Part 1, clause 37.2.6.1) —
    /// and that neither attempt moves pinCount: a PIN Pass Index only increments pinCount on a successful
    /// AUTHORIZED use, so a single PIN-auth read afterward reporting pinCount == 1 (not 2 or more) proves the
    /// two rejected writes above never touched it.
    /// </summary>
    [TestMethod]
    public async Task IndexAuthValueNvWriteAgainstPinIndexRejectsWrongAndRightPinIdenticallyWithoutMovingPinCount()
    {
        const uint PinLimit = 5;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinPassIndexHandle, PinPassAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinPassIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvWriteResponse> wrongPinWriteResult = await WriteIndexAuthValueAsync(
            device, pool, registry, PinPassIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, wrongPinWriteResult.ResponseCode,
            "A PIN Index forbids AUTHWRITE, so even a WRONG PIN's write attempt must be TPM_RC_NV_AUTHORIZATION, never a distinct auth-mismatch code.");

        TpmResult<NvWriteResponse> rightPinWriteResult = await WriteIndexAuthValueAsync(
            device, pool, registry, PinPassIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, rightPinWriteResult.ResponseCode,
            "The CORRECT PIN must be rejected with the SAME code as the wrong one - proving no oracle distinguishes them.");

        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(device, pool, registry, PinPassIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The PIN-auth read must still succeed: '{readResult.ResponseCode}'.");

        using NvReadResponse readResponse = readResult.Value;
        Assert.AreEqual(
            1u, ReadPinCount(readResponse.Data),
            "pinCount must be exactly 1 (from this single read), proving neither rejected write attempt above moved it.");
    }

    /// <summary>
    /// Verifies the owner-authorized <c>TPM2_NV_Write()</c> arm is a genuine provisioning-and-recovery path for
    /// a PIN Index: it provisions the Index for PIN-auth reads to use, and — once pinCount has reached
    /// pinLimit — recovers it for further PIN-auth use, all without the PIN's own authValue ever authorizing a
    /// write (TPM 2.0 Library Part 1, clause 37.2.6.1; clause 37.2.8.1's recovery note).
    /// </summary>
    [TestMethod]
    public async Task OwnerAuthNvWriteProvisionsAndRecoversAPinIndexForPinAuthReadsToUse()
    {
        const uint PinLimit = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> provisionResult = await WritePinCounterParametersAsync(
            device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);
        Assert.IsTrue(provisionResult.IsSuccess, $"The owner-authorized provisioning write must succeed: '{provisionResult.ResponseCode}'.");

        TpmResult<NvReadResponse> firstUseResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.IsTrue(firstUseResult.IsSuccess, $"A PIN-auth read must succeed once the owner-authorized write has provisioned the Index: '{firstUseResult.ResponseCode}'.");

        TpmResult<NvReadResponse> wrongPinAtLimitResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, wrongPinAtLimitResult.ResponseCode,
            "One wrong PIN against pinLimit == 1 is a plain bad-authorization, moving pinCount to pinLimit.");

        TpmResult<NvReadResponse> lockedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, lockedResult.ResponseCode,
            "pinCount has reached pinLimit; even the CORRECT PIN must be rejected until the Index is rewritten.");

        TpmResult<NvWriteResponse> recoverResult = await WritePinCounterParametersAsync(
            device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);
        Assert.IsTrue(recoverResult.IsSuccess, $"The owner-authorized recovery write must succeed: '{recoverResult.ResponseCode}'.");

        TpmResult<NvReadResponse> recoveredUseResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.IsTrue(recoveredUseResult.IsSuccess, $"A PIN-auth read must succeed again once the owner-authorized write has recovered the Index: '{recoveredUseResult.ResponseCode}'.");
    }

    /// <summary>
    /// Verifies the owner-authorized <c>TPM2_NV_Write()</c> arm honors <c>TPMA_NV_OWNERWRITE</c> (TPM 2.0
    /// Library Part 2, clause 13.4): an Index whose <c>TPMA_NV_OWNERWRITE</c> is clear rejects an owner write
    /// with <c>TPM_RC_NV_AUTHORIZATION</c>. The access-permission gate runs before the owner authValue is
    /// compared, so a correct (here, empty) owner authorization is refused just the same — owner authority is
    /// not a blanket write bypass over the Index's own access bits.
    /// </summary>
    [TestMethod]
    public async Task OwnerAuthNvWriteAgainstIndexWithoutOwnerWriteReturnsAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributesWithoutOwnerWrite).ConfigureAwait(false);

        TpmResult<NvWriteResponse> result = await WritePinCounterParametersAsync(
            device, pool, registry, PinFailIndexHandle, pinCount: 0, pinLimit: 5).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode,
            "An owner write against an Index without TPMA_NV_OWNERWRITE must be refused even under a correct owner authorization.");
    }

    /// <summary>
    /// Verifies the owner-authorized <c>TPM2_NV_Read()</c> arm (TPM 2.0 Library Part 3, clause 31.13) reports
    /// the current counter parameters WITHOUT ever moving <c>pinCount</c> itself - proven below the limit and
    /// again once it has actually been reached, with several repeated reads at each stage never advancing it
    /// further (Part 1, clause 37.2.6.6 ties the pinCount update to the INDEX's own authValue resolving
    /// authorization, never the owner arm's).
    /// </summary>
    [TestMethod]
    public async Task OwnerReadNvReadReportsCountersWithoutMovingPinCountBelowAndAtTheLimit()
    {
        const uint PinLimit = 2;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributesWithOwnerRead).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadResponse> seedingFailure = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, seedingFailure.ResponseCode);

        for(int repeat = 0; repeat < 3; repeat++)
        {
            TpmResult<NvReadResponse> belowLimitOwnerRead = await ReadIndexAsOwnerAsync(device, pool, registry, PinFailIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(belowLimitOwnerRead.IsSuccess, $"Owner-read {repeat + 1} failed: '{belowLimitOwnerRead.ResponseCode}'.");

            using NvReadResponse response = belowLimitOwnerRead.Value;
            Assert.AreEqual(1u, ReadPinCount(response.Data), $"Owner-read {repeat + 1} must never move pinCount away from the single seeded failure.");
        }

        TpmResult<NvReadResponse> exhaustingFailure = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, exhaustingFailure.ResponseCode);

        for(int repeat = 0; repeat < 3; repeat++)
        {
            TpmResult<NvReadResponse> atLimitOwnerRead = await ReadIndexAsOwnerAsync(device, pool, registry, PinFailIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
            Assert.IsTrue(atLimitOwnerRead.IsSuccess, $"Owner-read {repeat + 1} at the limit failed: '{atLimitOwnerRead.ResponseCode}'.");

            using NvReadResponse response = atLimitOwnerRead.Value;
            Assert.AreEqual(PinLimit, ReadPinCount(response.Data), $"Owner-read {repeat + 1} must never move pinCount even once it has reached pinLimit.");
        }

        TpmResult<NvReadResponse> stillBlockedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, stillBlockedResult.ResponseCode,
            "The repeated owner-reads above must not have consumed the throttle: the correct PIN is still refused.");
    }

    /// <summary>
    /// Verifies the owner-authorized <c>TPM2_NV_Read()</c> arm honors a wrong owner authorization value with a
    /// plain <c>TPM_RC_BAD_AUTH</c> (TPM 2.0 Library Part 1, clause 17.8.1: owner authorization is never
    /// dictionary-attack protected), mirroring the owner-write arm's own wrong-owner-auth behavior.
    /// </summary>
    [TestMethod]
    public async Task OwnerReadNvReadWithWrongOwnerAuthReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributesWithOwnerRead).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, pinLimit: 5).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadIndexAsOwnerAsync(device, pool, registry, PinFailIndexHandle, WrongOwnerAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode);
    }

    /// <summary>
    /// Verifies the owner-authorized <c>TPM2_NV_Read()</c> arm's <c>TPMA_NV_OWNERREAD</c> gate runs BEFORE the
    /// owner-auth compare (TPM 2.0 Library Part 3, clause 31.13; the same non-leaking order the owner-write
    /// arm's <c>TPMA_NV_OWNERWRITE</c> gate uses): against an Index with <c>TPMA_NV_OWNERREAD</c> clear (
    /// <see cref="PinFailAttributes"/>), even a WRONG owner authorization is refused with
    /// <c>TPM_RC_NV_AUTHORIZATION</c>, never <c>TPM_RC_BAD_AUTH</c> - proving the gate fires without ever
    /// reaching the compare.
    /// </summary>
    [TestMethod]
    public async Task OwnerReadNvReadAgainstIndexWithoutOwnerReadReturnsAuthorizationBeforeComparingOwnerAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, pinLimit: 5).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadIndexAsOwnerAsync(device, pool, registry, PinFailIndexHandle, WrongOwnerAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode,
            "TPMA_NV_OWNERREAD clear must refuse before the owner authValue is ever compared, even a wrong one.");
    }

    /// <summary>
    /// Companion to <see cref="OwnerReadNvReadAgainstIndexWithoutOwnerReadReturnsAuthorizationBeforeComparingOwnerAuth"/>:
    /// proves the same gate-order guarantee with a genuinely CORRECT owner authorization (empty, matching the
    /// simulator's default owner authValue) rather than a wrong one. An implementation that checks
    /// <c>TPMA_NV_OWNERREAD</c> only along the failure path - skipping the gate once the supplied authorization
    /// happens to match, and proceeding straight to the read - would pass every wrong-owner-auth test yet
    /// incorrectly succeed here; this is the case that catches it.
    /// </summary>
    [TestMethod]
    public async Task OwnerReadNvReadAgainstIndexWithoutOwnerReadReturnsAuthorizationEvenWithCorrectOwnerAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, pinLimit: 5).ConfigureAwait(false);

        //The simulator's owner authValue is empty by default, so an EMPTY supplied authorization is the
        //genuinely CORRECT owner authorization here.
        TpmResult<NvReadResponse> result = await ReadIndexAsOwnerAsync(device, pool, registry, PinFailIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode,
            "TPMA_NV_OWNERREAD clear must refuse the read even when the supplied owner authorization is correct.");
    }

    /// <summary>
    /// Verifies the owner-authorized <c>TPM2_NV_Read()</c> arm answers <c>TPM_RC_NV_UNINITIALIZED</c> for an
    /// unwritten PIN Index (TPM 2.0 Library Part 3, clause 31.13) - the contrast the Index-authorized arm does
    /// NOT exhibit for the same unwritten Index, since its own <c>TPM_RC_AUTH_UNAVAILABLE</c> pre-gate (
    /// <see cref="NvReadOfUnwrittenPinIndexReturnsAuthUnavailable"/>) is Index-arm-only.
    /// </summary>
    [TestMethod]
    public async Task OwnerReadNvReadOfUnwrittenPinIndexReturnsUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributesWithOwnerRead).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadIndexAsOwnerAsync(device, pool, registry, PinFailIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, result.ResponseCode);
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_UndefineSpace()</c> now compares the supplied authorization against the owner
    /// authValue (closing the previously discarded-auth residual, TPM 2.0 Library Part 3, clause 31.4): a
    /// wrong owner authorization is refused with <c>TPM_RC_BAD_AUTH</c> and the Index remains defined,
    /// confirmed by a subsequent successful PIN-auth read.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceWithWrongOwnerAuthReturnsBadAuthAndLeavesTheIndexDefined()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, pinLimit: 5).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PinFailIndexHandle, WrongOwnerAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, undefineResult.ResponseCode);

        TpmResult<NvReadResponse> stillDefinedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.IsTrue(stillDefinedResult.IsSuccess, "The Index must still be defined and usable: an unauthenticated undefine attempt must not have removed it.");
    }

    /// <summary>
    /// Verifies <c>TPM2_NV_UndefineSpace()</c> rejects an <c>@authHandle</c> outside the modelled provisioning
    /// authority (TPM 2.0 Library Part 3, clause 31.4's <c>TPMI_RH_PROVISION</c> handle typed <c>TPM_RH_OWNER</c>
    /// or <c>TPM_RH_PLATFORM</c>): with the platform hierarchy unmodelled this slice, a platform authHandle is
    /// refused with <c>TPM_RC_HANDLE</c>, mirroring <c>TPM2_NV_DefineSpace()</c>'s identical handle-type-check
    /// gate.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceWithNonOwnerAuthHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> result = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_PLATFORM, PinFailIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
    }

    /// <summary>
    /// Exploit-becomes-regression test for the wavepin R-9 residual: before this wave's fix, an unauthenticated
    /// <c>TPM2_NV_UndefineSpace()</c> composed with a redefinition was a direct PIN-throttle-reset primitive,
    /// since the phantom high-water mark is COUNTER-only (no PIN-count carryover is modelled). Drives a PIN
    /// Fail Index to <c>TPM_RC_AUTH_UNAVAILABLE</c> (fully exhausted), then proves an undefine WITHOUT the
    /// correct owner authorization is refused - so the Index remains exhausted and a subsequent redefinition
    /// attempt at the same handle answers <c>TPM_RC_NV_DEFINED</c> rather than ever starting fresh.
    /// </summary>
    [TestMethod]
    public async Task UndefineThenRedefineWithoutCorrectOwnerAuthCannotResetAnExhaustedPinFailThrottle()
    {
        const uint PinLimit = 1;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadResponse> exhaustingFailure = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, WrongPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, exhaustingFailure.ResponseCode, "One wrong PIN against pinLimit == 1 must exhaust the throttle.");

        TpmResult<NvReadResponse> blockedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, blockedResult.ResponseCode, "The correct PIN must be refused once exhausted.");

        TpmResult<NvUndefineSpaceResponse> exploitUndefineResult = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PinFailIndexHandle, WrongOwnerAuth).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, exploitUndefineResult.ResponseCode,
            "The exploit's unauthenticated undefine attempt must be refused, not silently succeed.");

        TpmResult<NvDefineSpaceResponse> exploitRedefineResult = await DefineIndexAsync(
            device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_DEFINED, exploitRedefineResult.ResponseCode,
            "The Index must still be defined (the undefine never ran), so a redefinition attempt collides rather than starting a fresh throttle.");

        TpmResult<NvReadResponse> stillBlockedResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, stillBlockedResult.ResponseCode,
            "The original exhausted Index must remain in place and still blocked - the exploit path achieved nothing.");

        TpmResult<NvUndefineSpaceResponse> correctAuthUndefineResult = await UndefineIndexAsync(
            device, pool, registry, TpmRh.TPM_RH_OWNER, PinFailIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(correctAuthUndefineResult.IsSuccess, $"An undefine WITH the correct owner authorization must still succeed: '{correctAuthUndefineResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> genuineRedefineResult = await DefineIndexAsync(
            device, pool, registry, PinFailIndexHandle, PinFailAttributes).ConfigureAwait(false);
        Assert.IsTrue(genuineRedefineResult.IsSuccess, $"A redefinition after the AUTHENTICATED undefine must succeed: '{genuineRedefineResult.ResponseCode}'.");

        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadResponse> freshThrottleResult = await ReadIndexAsync(device, pool, registry, PinFailIndexHandle, CorrectPin).ConfigureAwait(false);
        Assert.IsTrue(freshThrottleResult.IsSuccess, $"The genuinely redefined Index must accept the correct PIN on a fresh throttle: '{freshThrottleResult.ResponseCode}'.");
    }

    /// <summary>
    /// Issues an OWNER-authorized <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/>'s full
    /// <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window (TPM 2.0 Library Part 3, clause 31.13's owner-authorized
    /// arm), authorized by <paramref name="ownerAuthSupplied"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="ownerAuthSupplied">The owner authorization value to supply.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsOwnerAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> ownerAuthSupplied)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(ownerAuthSupplied.Span, pool);
        var readInput = new NvReadInput(AuthHandle: (uint)TpmRh.TPM_RH_OWNER, NvIndex: nvIndex, Size: PinCounterParametersSize, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_UndefineSpace()</c> against <paramref name="nvIndex"/> with the given
    /// <paramref name="authHandle"/> and supplied authorization (TPM 2.0 Library Part 3, clause 31.4).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The provisioning-hierarchy handle to authorize with.</param>
    /// <param name="nvIndex">The Index to undefine.</param>
    /// <param name="authSupplied">The authorization value to supply.</param>
    /// <returns>The undefine-space result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, TpmRh authHandle, uint nvIndex, ReadOnlyMemory<byte> authSupplied)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(authSupplied.Span, pool);
        var input = new NvUndefineSpaceInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the pinCount field (the first four octets) from a PIN Index read's returned data.</summary>
    /// <param name="data">The octets <see cref="NvReadResponse.Data"/> returned.</param>
    /// <returns>The pinCount value.</returns>
    private static uint ReadPinCount(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadUInt32BigEndian(data);

    /// <summary>Reads the pinLimit field (the second four octets) from a PIN Index read's returned data.</summary>
    /// <param name="data">The octets <see cref="NvReadResponse.Data"/> returned.</param>
    /// <returns>The pinLimit value.</returns>
    private static uint ReadPinLimit(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadUInt32BigEndian(data[sizeof(uint)..]);

    /// <summary>Creates a response codec registry for the NV commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectPin"/> as the
    /// Index authValue, authorized by the (empty) owner authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectPin, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, PinCounterParametersSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/> for the full
    /// <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window, authorized by Index authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue (PIN) the caller supplies for the Index.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: PinCounterParametersSize, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an OWNER-authorized <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/>, storing
    /// <paramref name="pinCount"/> and <paramref name="pinLimit"/> as the 8-octet
    /// <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> blob (TPM 2.0 Library Part 2, clause 13.3). A PIN Index forbids
    /// <c>TPMA_NV_AUTHWRITE</c> (Part 1, clause 37.2.6.1), so the owner-authorized arm is the sole provisioning
    /// and recovery path — the (empty) owner authValue authorizes it, never the PIN.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="pinCount">The pinCount value to store.</param>
    /// <param name="pinLimit">The pinLimit value to store.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WritePinCounterParametersAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, uint pinCount, uint pinLimit)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using IMemoryOwner<byte> owner = pool.Rent(PinCounterParametersSize);
        Memory<byte> blob = owner.Memory[..PinCounterParametersSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        var writeInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, new Tpm2bMaxBuffer(blob), Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an index-authValue <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/> — the AUTHWRITE-gated
    /// arm a PIN Index's own authValue can never satisfy (it forbids <c>TPMA_NV_AUTHWRITE</c>) — writing a
    /// single octet at offset 0. Used only to exercise the rejection path itself; the data content is
    /// irrelevant, since the write must never reach <c>WriteData</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authValue (PIN) supplied for the Index.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAuthValueAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, new Tpm2bMaxBuffer(RejectedWriteAttempt), Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-pin-index");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        BaseMemoryPool pool = BaseMemoryPool.Shared;
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

        return simulator;
    }
}
