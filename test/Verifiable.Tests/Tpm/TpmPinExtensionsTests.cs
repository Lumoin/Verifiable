using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Flow coverage for the <c>Extensions/Pin</c> business-capability verbs
/// (<see cref="TpmDeviceExtensions.DefinePinFailIndexAsync"/>, <see cref="TpmDeviceExtensions.VerifyPinAsync"/>,
/// <see cref="TpmDeviceExtensions.ReadPinCountersAsync"/>, <see cref="TpmDeviceExtensions.ResetPinCountAsync"/>,
/// <see cref="TpmDeviceExtensions.UndefinePinIndexAsync"/>) against the in-house behavioural
/// <see cref="TpmSimulator"/> - entirely in-process, with no external assets - through the same production wire
/// path <see cref="TpmInHouseSimulatorNvPinIndexTests"/> exercises directly, except every define/verify/read/
/// reset/undefine step here goes exclusively through the verbs under test. TPM 2.0 Library Part 1, Section
/// 37.2.6.6; Part 2, Section 13.3; Part 3, Sections 31.3, 31.13, 31.7, 31.4.
/// </summary>
[TestClass]
internal sealed class TpmPinExtensionsTests
{
    /// <summary>The primary PIN Fail Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint PinIndexHandle = 0x0100_0071;

    /// <summary>The stored-PIN-form authorization value used by the positive-path tests.</summary>
    private static byte[] CorrectPinHash { get; } = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF];

    /// <summary>A wrong stored-PIN-form value, distinct from <see cref="CorrectPinHash"/>.</summary>
    private static byte[] WrongPinHash { get; } = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

    /// <summary>A rotated stored-PIN-form value used by the redefinition test, distinct from both the above.</summary>
    private static byte[] RotatedPinHash { get; } = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78];

    /// <summary>
    /// A wrong owner authorization value; the simulator's owner authValue is empty throughout this suite (no
    /// command in this slice changes it from empty, TPM 2.0 Library Part 1, Section 37.2.6.6's owner-arm
    /// verbs are the only owner-authorized path exercised here), so any non-empty value is wrong.
    /// </summary>
    private static byte[] WrongOwnerAuth { get; } = [0x55, 0x55, 0x55, 0x55];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the define-then-verify happy path through the verbs alone: a fresh PIN Fail Index accepts the
    /// correct PIN and the successful authorization resets <c>pinCount</c> to zero (TPM 2.0 Library Part 1,
    /// Section 37.2.6.6), leaving <c>pinLimit</c> unchanged.
    /// </summary>
    [TestMethod]
    public async Task DefinePinFailIndexThenVerifyWithCorrectPinAsyncSucceedsAndReportsPinCountZero()
    {
        const uint PinLimit = 3;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> defineResult = await device.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> verifyResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"VerifyPinAsync with the correct PIN failed: '{verifyResult.ResponseCode}'.");
        Assert.AreEqual(0u, verifyResult.Value.PinCount, "A successful authorization below pinLimit must reset pinCount to zero.");
        Assert.AreEqual(PinLimit, verifyResult.Value.PinLimit, "pinLimit must be left unchanged by a successful verify.");
    }

    /// <summary>
    /// Pins the CTAP-relevant negative rung: a wrong candidate answers <c>TPM_RC_BAD_AUTH</c> (a PIN Fail
    /// Index is spec-mandated <c>TPMA_NV_NO_DA</c>, so this is never <c>TPM_RC_AUTH_FAIL</c>) and the
    /// compare-and-move is one atomic command, so <c>pinCount</c> has already advanced by the time the caller
    /// observes the failure - confirmed here via the owner-read arm, which never moves it further itself.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncWithWrongPinHashReturnsBadAuthAndAdvancesPinCount()
    {
        const uint PinLimit = 3;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> wrongResult = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongResult.IsSuccess, "A wrong PIN must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode);

        TpmResult<TpmPinCounterParameters> countersResult = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersAsync failed: '{countersResult.ResponseCode}'.");
        Assert.AreEqual(1u, countersResult.Value.PinCount, "A single wrong PIN must advance pinCount by exactly one.");
    }

    /// <summary>
    /// Proves a successful <see cref="TpmDeviceExtensions.VerifyPinAsync"/> genuinely resets <c>pinCount</c> to
    /// zero rather than merely leaving it unchanged: after one prior mismatch, the correct PIN succeeds and
    /// reports <c>pinCount == 0</c>, and two FURTHER mismatches (not one) are then needed to reach
    /// <paramref name="PinLimit"/> again.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulVerifyPinAsyncBelowLimitResetsPinCountRequiringTwoMoreMismatchesToReachLimitAgain()
    {
        const uint PinLimit = 2;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> seedingFailure = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, seedingFailure.ResponseCode, "The seeding failure must not yet be at pinLimit.");

        TpmResult<TpmPinCounterParameters> successResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(successResult.IsSuccess, $"The correct PIN below pinLimit must succeed: '{successResult.ResponseCode}'.");
        Assert.AreEqual(0u, successResult.Value.PinCount, "The successful verify must reset pinCount to zero.");

        TpmResult<TpmPinCounterParameters> firstFailureAfterReset = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, firstFailureAfterReset.ResponseCode, "The first failure after the reset must not yet be at pinLimit.");

        TpmResult<TpmPinCounterParameters> secondFailureAfterReset = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, secondFailureAfterReset.ResponseCode, "The second failure after the reset must still be counted, not yet AUTH_UNAVAILABLE.");

        TpmResult<TpmPinCounterParameters> atLimitAfterReset = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, atLimitAfterReset.ResponseCode,
            "pinLimit must be reached only after two further mismatches, confirming pinCount was genuinely reset to zero.");
    }

    /// <summary>
    /// Pins the CTAP-relevant blocked rung: once <c>pinCount</c> reaches <c>pinLimit</c>,
    /// <see cref="TpmDeviceExtensions.VerifyPinAsync"/> refuses even the CORRECT PIN with
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> (TPM 2.0 Library Part 1, Section 37.2.6.6) - the TPM-side equivalent of
    /// CTAP's <c>PIN_BLOCKED</c>.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncAtPinLimitRefusesEvenTheCorrectPinWithAuthUnavailable()
    {
        const uint PinLimit = 2;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= PinLimit; attempt++)
        {
            TpmResult<TpmPinCounterParameters> wrongResult = await device.VerifyPinAsync(
                PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode,
                $"Attempt {attempt} of {PinLimit} must be a plain bad-authorization, not yet at the limit.");
        }

        TpmResult<TpmPinCounterParameters> atLimitResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(atLimitResult.IsSuccess, "Once pinCount reaches pinLimit, even the CORRECT PIN must be rejected.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, atLimitResult.ResponseCode);
    }

    /// <summary>
    /// Pins the CTAP-relevant recovery rung: <see cref="TpmDeviceExtensions.ResetPinCountAsync"/> restores an
    /// at-limit PIN Fail Index for further PIN-auth use, mirroring CTAP's owner-equivalent "set new PIN" reset
    /// path (TPM 2.0 Library Part 1, Section 37.2.8.1's recovery note: no automatic self-heal exists until the
    /// owner rewrites the counter parameters).
    /// </summary>
    [TestMethod]
    public async Task ResetPinCountAsyncRestoresPinAuthAfterTheLimitIsReached()
    {
        const uint PinLimit = 1;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> exhaustingFailure = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, exhaustingFailure.ResponseCode, "One wrong PIN against pinLimit == 1 must reach the limit.");

        TpmResult<TpmPinCounterParameters> blockedResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, blockedResult.ResponseCode, "The correct PIN must be refused once at the limit.");

        TpmResult<NvWriteResponse> resetResult = await device.ResetPinCountAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetResult.IsSuccess, $"ResetPinCountAsync failed: '{resetResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> recoveredResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(recoveredResult.IsSuccess, $"The correct PIN must succeed again once reset: '{recoveredResult.ResponseCode}'.");
        Assert.AreEqual(0u, recoveredResult.Value.PinCount, "The recovered verify must report pinCount reset to zero.");
    }

    /// <summary>
    /// Pins the no-oracle "how many tries remain" query: <see cref="TpmDeviceExtensions.ReadPinCountersAsync"/>
    /// reports the current counter parameters WITHOUT ever moving <c>pinCount</c> itself, whether below the
    /// limit or already at it - repeated reads observe the identical value each time (TPM 2.0 Library Part 3,
    /// Section 31.13's owner-authorized arm; Part 1, Section 37.2.6.6's pinCount update is scoped to the
    /// Index's OWN authValue resolving authorization, never the owner arm).
    /// </summary>
    [TestMethod]
    public async Task ReadPinCountersAsyncReportsCountersWithoutMovingPinCountBelowOrAtTheLimit()
    {
        const uint PinLimit = 2;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> seedingFailure = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, seedingFailure.ResponseCode);

        for(int repeat = 0; repeat < 3; repeat++)
        {
            TpmResult<TpmPinCounterParameters> belowLimitRead = await device.ReadPinCountersAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(belowLimitRead.IsSuccess, $"ReadPinCountersAsync failed: '{belowLimitRead.ResponseCode}'.");
            Assert.AreEqual(1u, belowLimitRead.Value.PinCount, $"Repeated owner-read {repeat + 1} must never move pinCount away from the single seeded failure.");
        }

        TpmResult<TpmPinCounterParameters> exhaustingFailure = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, exhaustingFailure.ResponseCode);

        for(int repeat = 0; repeat < 3; repeat++)
        {
            TpmResult<TpmPinCounterParameters> atLimitRead = await device.ReadPinCountersAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(atLimitRead.IsSuccess, $"ReadPinCountersAsync at the limit failed: '{atLimitRead.ResponseCode}'.");
            Assert.AreEqual(PinLimit, atLimitRead.Value.PinCount, $"Repeated owner-read {repeat + 1} must never move pinCount even once it has reached pinLimit.");
        }

        TpmResult<TpmPinCounterParameters> stillBlockedResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, stillBlockedResult.ResponseCode,
            "The repeated owner-reads above must not have consumed the throttle: the correct PIN is still refused.");
    }

    /// <summary>
    /// Verifies <see cref="TpmDeviceExtensions.UndefinePinIndexAsync"/> composed with a fresh
    /// <see cref="TpmDeviceExtensions.DefinePinFailIndexAsync"/> genuinely rotates the Index authValue: the OLD
    /// PIN no longer authorizes the redefined Index (its authValue is now <see cref="RotatedPinHash"/>), while
    /// the NEW PIN succeeds - the PIN-rotation precedent a stale snapshot's old stored form can never resurrect
    /// once authorized undefine-then-redefine has actually run.
    /// </summary>
    [TestMethod]
    public async Task UndefinePinIndexAsyncThenRedefineWithANewPinHashRotatesTheAuthValue()
    {
        const uint PinLimit = 3;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> undefineResult = await device.UndefinePinIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefinePinIndexAsync with the correct owner auth failed: '{undefineResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> redefineResult = await device.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, RotatedPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"Redefining the same handle with a rotated PIN failed: '{redefineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> oldPinResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(oldPinResult.IsSuccess, "The OLD PIN must no longer authorize the redefined Index.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, oldPinResult.ResponseCode);

        TpmResult<TpmPinCounterParameters> newPinResult = await device.VerifyPinAsync(
            PinIndexHandle, RotatedPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(newPinResult.IsSuccess, $"The NEW (rotated) PIN must authorize the redefined Index: '{newPinResult.ResponseCode}'.");
    }

    /// <summary>
    /// Proves <see cref="TpmDeviceExtensions.DefinePinFailIndexAsync"/> actually threads its <c>ownerAuth</c>
    /// parameter to the wire rather than ignoring it: a WRONG owner authorization is refused with
    /// <c>TPM_RC_BAD_AUTH</c> and defines nothing, while the CORRECT (empty, matching the simulator's default)
    /// owner authorization then succeeds at the very same handle. A mutation that hard-coded away
    /// <c>ownerAuth</c> (e.g. always building the internal session from an empty value) would make the first
    /// call incorrectly succeed - this is the case that catches it.
    /// </summary>
    [TestMethod]
    public async Task DefinePinFailIndexAsyncWithWrongOwnerAuthReturnsBadAuthAndDefinesNothing()
    {
        const uint PinLimit = 3;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> wrongAuthResult = await device.DefinePinFailIndexAsync(
            WrongOwnerAuth, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong owner authorization must not be able to define the Index.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongAuthResult.ResponseCode);

        TpmResult<NvWriteResponse> correctAuthResult = await device.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctAuthResult.IsSuccess, $"The correct (empty) owner authorization must still define the Index: '{correctAuthResult.ResponseCode}'.");
    }

    /// <summary>
    /// Proves <see cref="TpmDeviceExtensions.ReadPinCountersAsync"/> actually threads its <c>ownerAuth</c>
    /// parameter to the wire: a WRONG owner authorization is refused with <c>TPM_RC_BAD_AUTH</c>, while the
    /// CORRECT (empty) owner authorization then reports the counters. A mutation that hard-coded away
    /// <c>ownerAuth</c> would make the first call incorrectly succeed - this is the case that catches it.
    /// </summary>
    [TestMethod]
    public async Task ReadPinCountersAsyncWithWrongOwnerAuthReturnsBadAuth()
    {
        const uint PinLimit = 3;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> wrongAuthResult = await device.ReadPinCountersAsync(
            WrongOwnerAuth, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong owner authorization must not be able to read the counters.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongAuthResult.ResponseCode);

        TpmResult<TpmPinCounterParameters> correctAuthResult = await device.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctAuthResult.IsSuccess, $"The correct (empty) owner authorization must still read the counters: '{correctAuthResult.ResponseCode}'.");
    }

    /// <summary>
    /// Proves <see cref="TpmDeviceExtensions.ResetPinCountAsync"/> actually threads its <c>ownerAuth</c>
    /// parameter to the wire: a WRONG owner authorization is refused with <c>TPM_RC_BAD_AUTH</c> and leaves
    /// the exhausted counter untouched, while the CORRECT (empty) owner authorization then resets it. A
    /// mutation that hard-coded away <c>ownerAuth</c> would make the first call incorrectly succeed - this is
    /// the case that catches it.
    /// </summary>
    [TestMethod]
    public async Task ResetPinCountAsyncWithWrongOwnerAuthReturnsBadAuthAndLeavesTheCounterUntouched()
    {
        const uint PinLimit = 1;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<TpmPinCounterParameters> exhaustingFailure = await device.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, exhaustingFailure.ResponseCode, "One wrong PIN against pinLimit == 1 must reach the limit.");

        TpmResult<NvWriteResponse> wrongAuthResult = await device.ResetPinCountAsync(
            WrongOwnerAuth, PinIndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong owner authorization must not be able to reset the counter.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongAuthResult.ResponseCode);

        TpmResult<TpmPinCounterParameters> stillBlockedResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, stillBlockedResult.ResponseCode,
            "The failed reset attempt above must not have touched the counter: the correct PIN is still refused.");

        TpmResult<NvWriteResponse> correctAuthResult = await device.ResetPinCountAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctAuthResult.IsSuccess, $"The correct (empty) owner authorization must still reset the counter: '{correctAuthResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> recoveredResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(recoveredResult.IsSuccess, $"The correct PIN must succeed again once genuinely reset: '{recoveredResult.ResponseCode}'.");
    }

    /// <summary>
    /// Proves <see cref="TpmDeviceExtensions.UndefinePinIndexAsync"/> actually threads its <c>ownerAuth</c>
    /// parameter to the wire: a WRONG owner authorization is refused with <c>TPM_RC_BAD_AUTH</c> and leaves the
    /// Index defined and usable, while the CORRECT (empty) owner authorization then undefines it. A mutation
    /// that hard-coded away <c>ownerAuth</c> would make the first call incorrectly succeed - this is the case
    /// that catches it.
    /// </summary>
    [TestMethod]
    public async Task UndefinePinIndexAsyncWithWrongOwnerAuthReturnsBadAuthAndLeavesTheIndexDefined()
    {
        const uint PinLimit = 3;

        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        await DefineAsync(device, PinLimit).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> wrongAuthResult = await device.UndefinePinIndexAsync(
            WrongOwnerAuth, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong owner authorization must not be able to undefine the Index.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongAuthResult.ResponseCode);

        TpmResult<TpmPinCounterParameters> stillDefinedResult = await device.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(stillDefinedResult.IsSuccess, "The Index must still be defined: an unauthenticated undefine attempt must not have removed it.");

        TpmResult<NvUndefineSpaceResponse> correctAuthResult = await device.UndefinePinIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(correctAuthResult.IsSuccess, $"The correct (empty) owner authorization must still undefine the Index: '{correctAuthResult.ResponseCode}'.");
    }

    /// <summary>Defines <see cref="PinIndexHandle"/> as a PIN Fail Index with <see cref="CorrectPinHash"/> via <see cref="TpmDeviceExtensions.DefinePinFailIndexAsync"/>, asserting success.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pinLimit">The attempt threshold to provision.</param>
    /// <returns>A task that completes once the Index is provisioned.</returns>
    private async Task DefineAsync(TpmDevice device, uint pinLimit)
    {
        TpmResult<NvWriteResponse> defineResult = await device.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, pinLimit,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");
    }

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-pin-verbs");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
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
