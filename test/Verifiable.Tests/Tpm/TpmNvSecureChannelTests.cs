using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the PIN-over-HMAC-session authorization channel (<see cref="TpmDeviceExtensions"/>'s
/// <c>VerifyPinAsync</c>, its salted overload, the four owner-authorized verbs, and every
/// <c>…WithPasswordAsync</c> opt-out) against the in-house behavioural <see cref="TpmSimulator"/> - entirely
/// in-process, with no external assets - through the same production command path production code uses
/// (<see cref="TpmCommandExecutor"/> and the real verb surface).
/// </summary>
/// <remarks>
/// <para>
/// <b>The channel itself.</b> <c>VerifyPinAsync</c>'s default composes an UNBOUND, unsalted HMAC session (TPM
/// 2.0 Library Part 1, Section 16.6.9's Empty Buffer session key) whose authValue term is the candidate PIN
/// hash - never a session bound to the PIN Index itself, which Part 1, Section 34.2.8.3 forbids outright
/// (<c>TPM_RC_HANDLE</c>: "the sequence in which the TPM processes authorizations would enable a hammering
/// attack on the Index"). A wrong candidate is therefore an HMAC mismatch, never a plaintext compare, and the
/// candidate never crosses the bus as bytes a passive observer can read.
/// </para>
/// <para>
/// <b>The throttle.</b> Part 1, Section 34.2.6.6's pinCount rule is written purely in terms of "the authValue
/// of a PIN Index is used for authorization... succeeds/fails" - an outcome, not a mechanism - so it applies
/// identically whether that authValue is presented as a password or folded into an HMAC session's key. A
/// mismatch increments pinCount and answers a session-encoded <c>TPM_RC_BAD_AUTH</c> (a PIN Fail Index is
/// spec-mandated <c>TPMA_NV_NO_DA</c>, so never <c>TPM_RC_AUTH_FAIL</c>); a match resets it to zero; the
/// at-limit refusal (<c>TPM_RC_AUTH_UNAVAILABLE</c>) fires from a gate that precedes the HMAC-session
/// verification queue entirely, so it carries no session-index modifier at all.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmNvSecureChannelTests
{
    /// <summary>The session/policy hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Every RSA storage-parent-shaped template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (TPM 2.0 Library Part 2, Table 228).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The primary PIN Fail Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint PinIndexHandle = 0x0100_00A1;

    /// <summary>The stored-PIN-form authorization value used by the positive-path tests.</summary>
    private static byte[] CorrectPinHash { get; } = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF];

    /// <summary>A wrong stored-PIN-form value, distinct from <see cref="CorrectPinHash"/>.</summary>
    private static byte[] WrongPinHash { get; } = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The correct candidate succeeds over the default HMAC session and resets pinCount to zero; the captured
    /// wire command's authorizing session is never <c>TPM_RS_PW</c>, proving the default genuinely rides a
    /// session rather than a password.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncSucceedsOverAnHmacSessionThatIsNeverTpmRsPwAndResetsPinCount()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> defineResult = await plainDevice.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        byte[]? nvReadCommand = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_NV_Read)
            {
                nvReadCommand = bytes;
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);

        TpmResult<TpmPinCounterParameters> verifyResult = await capturingDevice.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verifyResult.IsSuccess, $"VerifyPinAsync (default) failed: '{verifyResult.ResponseCode}'.");
        Assert.AreEqual(0u, verifyResult.Value.PinCount, "A successful authorization below pinLimit must reset pinCount to zero.");
        Assert.AreEqual(PinLimit, verifyResult.Value.PinLimit, "pinLimit must be left unchanged by a successful verify.");

        Assert.IsNotNull(nvReadCommand, "The capturing wrapper must have observed the NV_Read command.");
        uint sessionHandle = ReadFirstSessionHandleAfterHandleCount(nvReadCommand!, handleCount: 2);
        Assert.AreNotEqual((uint)TpmRh.TPM_RH_PW, sessionHandle, "VerifyPinAsync's default must never send a TPM_RS_PW password session.");
    }

    /// <summary>
    /// A wrong candidate is a genuine HMAC mismatch: the returned response code's base error is
    /// <c>TPM_RC_BAD_AUTH</c>, but the raw wire response code is NOT the bare constant - it carries the
    /// session-index modifier (TPM 2.0 Library Part 2, Section 6.6.2) that only a session-authorized rejection
    /// applies, distinguishing it from the password channel's own bare-coded rejection. pinCount advances by
    /// exactly one.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncWithWrongPinReturnsASessionEncodedBadAuthAndAdvancesPinCount()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> wrongResult = await tpm.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(wrongResult.IsSuccess, "A wrong PIN must not be accepted.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.BaseError,
            "A PIN Fail Index is spec-mandated TPMA_NV_NO_DA, so a mismatch is TPM_RC_BAD_AUTH, never TPM_RC_AUTH_FAIL.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode,
            "The default HMAC session's mismatch carries a session-index modifier - the bare constant must NOT equal the raw wire response code.");

        TpmResult<TpmPinCounterParameters> countersResult = await tpm.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersAsync failed: '{countersResult.ResponseCode}'.");
        Assert.AreEqual(1u, countersResult.Value.PinCount, "A single wrong PIN over the HMAC session must advance pinCount by exactly one, exactly as a password mismatch does.");
    }

    /// <summary>
    /// Once pinCount reaches pinLimit, even the CORRECT candidate is refused with <c>TPM_RC_AUTH_UNAVAILABLE</c>
    /// (TPM 2.0 Library Part 3, clause 5.6, Authorization Checks) BEFORE any HMAC work runs (TPM 2.0 Library
    /// Part 1, clause 34.2.6.6: "If the authValue of an PIN Index is used for authorization, then the
    /// authorization will fail if the pinCount field of the Index is not less than the pinLimit field..." - a
    /// condition distinct from, and checked ahead of, the compare itself). This gate precedes the HMAC-session
    /// verification queue entirely, so the returned code carries no session-index modifier: the bare constant
    /// equals the raw wire response code directly, unlike a genuine mismatch.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncAtPinLimitRefusesTheCorrectPinWithAuthUnavailableBeforeAnyHmacWork()
    {
        const uint PinLimit = 2;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        for(uint attempt = 1; attempt <= PinLimit; attempt++)
        {
            TpmResult<TpmPinCounterParameters> wrongResult = await tpm.VerifyPinAsync(
                PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.BaseError,
                $"Attempt {attempt} of {PinLimit} must be a plain bad-authorization, not yet at the limit.");
        }

        TpmResult<TpmPinCounterParameters> atLimitResult = await tpm.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(atLimitResult.IsSuccess, "Once pinCount reaches pinLimit, even the CORRECT PIN must be rejected.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, atLimitResult.ResponseCode,
            "The at-limit gate runs before the HMAC-session verification queue is ever entered, so no session-index modifier is applied.");
    }

    /// <summary>
    /// Captures every command byte VerifyPinAsync's default composition sends (StartAuthSession, NV_ReadPublic,
    /// NV_Read, FlushContext) and proves the candidate PIN hash never appears as a contiguous byte sequence in
    /// any of them: the candidate enters only as the HMAC session's authValue key term (Part 1, Section 16.6.9),
    /// never as wire content the command itself carries.
    /// </summary>
    /// <remarks>
    /// The scope is deliberately the VERIFICATION exchange. Enrollment is a separate concern: <c>DefinePinFailIndexAsync</c>
    /// installs the stored PIN form by riding <c>TPM2_NV_DefineSpace</c>'s <c>auth</c> command parameter, which it
    /// encrypts on the bus (structurally by default, confidentially under the salted define) - its own
    /// honest-accounting remarks cover that, and dedicated tests here pin both the encryption and its confidentiality
    /// boundary. The provisioning call runs on a non-capturing device here because what this test pins is a different
    /// property: that the candidate never crosses the bus when a PIN is VERIFIED - the property the HMAC channel
    /// exists to give.
    /// </remarks>
    [TestMethod]
    public async Task VerifyPinAsyncNeverSendsTheCandidatePinHashBytesOnTheWire()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> defineResult = await plainDevice.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        var capturedCommands = new List<byte[]>();
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);

        TpmResult<TpmPinCounterParameters> verifyResult = await capturingDevice.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"VerifyPinAsync failed: '{verifyResult.ResponseCode}'.");

        Assert.HasCount(4, capturedCommands, "VerifyPinAsync's default composition sends exactly StartAuthSession, NV_ReadPublic, NV_Read, and FlushContext.");
        foreach(byte[] command in capturedCommands)
        {
            Assert.IsFalse(
                ContainsSubsequence(command, CorrectPinHash),
                "The candidate PIN hash must never appear as a contiguous byte sequence on the wire.");
        }
    }

    /// <summary>
    /// A session bound directly to a PIN Fail Index is refused with <c>TPM_RC_HANDLE</c> (TPM 2.0 Library Part
    /// 1, Section 34.2.8.3): "If a PIN Pass or PIN Fail Index is referenced as a bind entity, the TPM must
    /// return TPM_RC_HANDLE." This is why <c>VerifyPinAsync</c>'s default session is unbound rather than
    /// bound-to-self - the bind attempt itself never gets far enough to matter.
    /// </summary>
    [TestMethod]
    public async Task BindingAnHmacSessionDirectlyToAPinIndexIsRefusedWithHandle()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(PinIndexHandle, SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(startResult.IsSuccess, "Binding a session directly to a PIN Fail Index must never succeed.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, startResult.ResponseCode);
    }

    /// <summary>
    /// The salted overload succeeds against an RSA tpmKey and resets pinCount exactly as the unsalted default
    /// does - the salt (Part 1, Section 16.6.12, equation 25) changes only where the session key's entropy comes
    /// from, never the atomic compare-and-move semantics.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncSaltedOverloadSucceedsAgainstAnRsaTpmKeyAndResetsPinCount()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRsaKeyRegistry();

        TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            TpmResult<TpmPinCounterParameters> verifyResult = await tpm.VerifyPinAsync(
                PinIndexHandle, CorrectPinHash, tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg,
                rsaBackend.EncryptOaep, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(verifyResult.IsSuccess, $"VerifyPinAsync (salted overload) failed: '{verifyResult.ResponseCode}'.");
            Assert.AreEqual(0u, verifyResult.Value.PinCount, "A successful salted verify must reset pinCount to zero exactly as the unsalted default does.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The four owner-authorized verbs (define, read counters, reset, undefine) complete a full PIN Index
    /// lifecycle over their bound-to-owner HMAC session defaults, and not one of the commands they send ever
    /// carries <c>TPM_RS_PW</c> as its authorizing session.
    /// </summary>
    [TestMethod]
    public async Task OwnerVerbsOverBoundHmacSessionsCompleteTheFullPinIndexLifecycleWithoutEverSendingAPasswordSession()
    {
        const uint PinLimit = 2;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        var capturedCommands = new List<byte[]>();
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice tpm = TpmDevice.Create(CaptureAsync);

        TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> countersResult = await tpm.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersAsync failed: '{countersResult.ResponseCode}'.");
        Assert.AreEqual(0u, countersResult.Value.PinCount, "A freshly provisioned Index must report pinCount zero.");

        TpmResult<TpmPinCounterParameters> wrongResult = await tpm.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.BaseError, "Seed exactly one mismatch to give ResetPinCountAsync something genuine to undo.");

        TpmResult<NvWriteResponse> resetResult = await tpm.ResetPinCountAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetResult.IsSuccess, $"ResetPinCountAsync failed: '{resetResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> resetCountersResult = await tpm.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetCountersResult.IsSuccess, $"ReadPinCountersAsync after reset failed: '{resetCountersResult.ResponseCode}'.");
        Assert.AreEqual(0u, resetCountersResult.Value.PinCount, "ResetPinCountAsync must genuinely reset pinCount to zero.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await tpm.UndefinePinIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefinePinIndexAsync failed: '{undefineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> afterUndefineResult = await tpm.ReadPinCountersAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, afterUndefineResult.ResponseCode, "The Index must genuinely no longer exist once UndefinePinIndexAsync has run.");

        Assert.IsNotEmpty(capturedCommands, "The capturing wrapper must have observed at least one command.");
        foreach(byte[] command in capturedCommands)
        {
            TpmCcConstants code = ReadCommandCode(command);
            int handleCount = OwnerAuthorizedHandleCount(code);
            if(handleCount < 0)
            {
                continue;
            }

            uint sessionHandle = ReadFirstSessionHandleAfterHandleCount(command, handleCount);
            Assert.AreNotEqual(
                (uint)TpmRh.TPM_RH_PW, sessionHandle,
                $"The owner-authorized default must never send a TPM_RS_PW password session ('{code}' command).");
        }
    }

    /// <summary>
    /// Every <c>…WithPasswordAsync</c> opt-out still authorizes correctly and genuinely sends a <c>TPM_RS_PW</c>
    /// password session for each of its commands - proving the opt-outs are not accidentally identical to the
    /// secure defaults on the wire.
    /// </summary>
    [TestMethod]
    public async Task WithPasswordOptOutsStillAuthorizeAndGenuinelySendATpmRsPwSession()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        var capturedCommands = new List<byte[]>();
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice tpm = TpmDevice.Create(CaptureAsync);

        TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexWithPasswordAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> verifyResult = await tpm.VerifyPinWithPasswordAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"VerifyPinWithPasswordAsync failed: '{verifyResult.ResponseCode}'.");
        Assert.AreEqual(0u, verifyResult.Value.PinCount, "A successful password-channel verify must still reset pinCount to zero.");

        TpmResult<TpmPinCounterParameters> countersResult = await tpm.ReadPinCountersWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(countersResult.IsSuccess, $"ReadPinCountersWithPasswordAsync failed: '{countersResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> resetResult = await tpm.ResetPinCountWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resetResult.IsSuccess, $"ResetPinCountWithPasswordAsync failed: '{resetResult.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await tpm.UndefinePinIndexWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefinePinIndexWithPasswordAsync failed: '{undefineResult.ResponseCode}'.");

        Assert.HasCount(
            6, capturedCommands,
            "Six authorized commands are expected: NV_DefineSpace + NV_Write (provisioning), NV_Read (verify), NV_Read (read counters), NV_Write (reset), NV_UndefineSpace.");
        foreach(byte[] command in capturedCommands)
        {
            TpmCcConstants code = ReadCommandCode(command);
            int handleCount = OwnerAuthorizedHandleCount(code);
            Assert.IsGreaterThanOrEqualTo(0, handleCount, $"Unexpected command code '{code}' captured.");

            uint sessionHandle = ReadFirstSessionHandleAfterHandleCount(command, handleCount);
            Assert.AreEqual(
                (uint)TpmRh.TPM_RH_PW, sessionHandle,
                $"Every WithPasswordAsync opt-out must genuinely send TPM_RS_PW ('{code}' command).");
        }
    }

    /// <summary>
    /// An active transport that answers the session-authorized <c>TPM2_NV_Read</c> with a forged, perfectly
    /// well-formed <c>TPM_ST_NO_SESSIONS</c> success carrying attacker-chosen counter parameters must be
    /// REFUSED, even though every byte of it parses: a response to a command an HMAC session authorized has to
    /// carry that session's own response authorization (TPM 2.0 Library Part 1, clauses 15.6.1 and 16.6.5 - a
    /// successful response carries one entry per request session, each keyed as the command's was).
    /// Accepting the untagged form would let anything on the bus turn a WRONG PIN into
    /// <c>TpmResult.Success</c> with a fabricated retry budget - the channel would prove the PIN to the TPM
    /// while proving nothing at all to the host.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncRefusesAForgedNoSessionsSuccessInPlaceOfTheSessionAuthorizedNvReadResponse()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> defineResult = await plainDevice.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        bool forged = false;
        async ValueTask<TpmResult<TpmResponse>> ForgeNvReadAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            if(ReadCommandCode(command.ToArray()) == TpmCcConstants.TPM_CC_NV_Read)
            {
                forged = true;

                return ForgeNoSessionsPinCounterSuccess(commandPool, pinCount: 0, PinLimit);
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice forgingDevice = TpmDevice.Create(ForgeNvReadAsync);

        TpmResult<TpmPinCounterParameters> verifyResult = await forgingDevice.VerifyPinAsync(
            PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(forged, "The forging transport must have observed and replaced the NV_Read response.");
        Assert.IsFalse(
            verifyResult.IsSuccess,
            "A response that dropped the authorization area the command's HMAC session requires must never be reported as a successful PIN verification.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, verifyResult.ResponseCode,
            "The missing response authorization is an integrity failure, not a parse failure.");
    }

    /// <summary>
    /// Trailing zero octets are not part of an authorization value (TPM 2.0 Library Part 1, Section 16.6.4.3:
    /// "Trailing octets of zero are to be removed from any string before it is used as an authValue", and
    /// Section 16.6.5's identical note on the authValue term of the HMAC key), so the stored PIN form and the
    /// candidate authorize against each other's stripped form on BOTH sides of the channel: an Index provisioned
    /// with a value ending in zero octets accepts the candidate without them, and an Index provisioned without
    /// them accepts a candidate that carries them.
    /// </summary>
    [TestMethod]
    public async Task VerifyPinAsyncAuthorizesAgainstTheTrailingZeroStrippedFormOnBothSidesOfTheChannel()
    {
        const uint PinLimit = 3;
        const uint SecondPinIndexHandle = 0x0100_00A2;

        byte[] paddedPinHash = [.. CorrectPinHash, 0x00, 0x00];

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> paddedDefineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, paddedPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(paddedDefineResult.IsSuccess, $"DefinePinFailIndexAsync (padded stored form) failed: '{paddedDefineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> strippedCandidateResult = await tpm.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            strippedCandidateResult.IsSuccess,
            $"An Index provisioned with a trailing-zero-padded PIN must accept the same PIN without the padding: '{strippedCandidateResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> strippedDefineResult = await tpm.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, SecondPinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(strippedDefineResult.IsSuccess, $"DefinePinFailIndexAsync (stripped stored form) failed: '{strippedDefineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> paddedCandidateResult = await tpm.VerifyPinAsync(
            SecondPinIndexHandle, paddedPinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            paddedCandidateResult.IsSuccess,
            $"An Index provisioned without padding must accept the same PIN carrying trailing zero octets: '{paddedCandidateResult.ResponseCode}'.");
    }

    /// <summary>
    /// A session claiming the <c>encrypt</c> attribute on the session-authorized <c>TPM2_NV_Read</c> is refused
    /// with a session-encoded <c>TPM_RC_ATTRIBUTES</c> before any HMAC work: this simulator implements no
    /// parameter encryption for the NV family's HMAC arms, so it fails closed rather than returning the counter
    /// window in the clear to a caller that believes the response parameter was encrypted. The attribute is set
    /// on the built command by an intervening transport, because the host executor refuses to compose such a
    /// command in the first place (its codec declares no encryptable first response parameter).
    /// </summary>
    [TestMethod]
    public async Task NvReadOverAnEncryptAttributedSessionIsRefusedWithAttributes()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvWriteResponse> defineResult = await plainDevice.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        async ValueTask<TpmResult<TpmResponse>> ClaimEncryptOnNvReadAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_NV_Read)
            {
                SetFirstSessionAttributeBit(bytes, handleCount: 2, (byte)TpmaSession.ENCRYPT);

                return await simulator.SubmitAsync(bytes, commandPool, ct).ConfigureAwait(false);
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice tamperingDevice = TpmDevice.Create(ClaimEncryptOnNvReadAsync);

        TpmResult<TpmPinCounterParameters> verifyResult = await tamperingDevice.VerifyPinAsync(
            PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(verifyResult.IsSuccess, "An encrypt-attributed session must not be accepted on the NV_Read HMAC arm.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, verifyResult.BaseError,
            "Parameter encryption is refused for the NV family's HMAC arms, so the attribute itself is the error.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, verifyResult.ResponseCode,
            "The refusal names the offending session, so the raw wire code carries the session-index modifier.");
    }

    /// <summary>
    /// The default enrollment encrypts the stored PIN form on the bus: it rides <c>TPM2_NV_DefineSpace</c>'s
    /// <c>auth</c> command parameter over an owner-authorized session that carries the decrypt attribute (Part 3,
    /// Section 31.3; Part 1, clause 18.1, Session-based encryption, Introduction), so the pinHash never appears
    /// as a contiguous byte sequence in the definition command. This closes the enrollment exclusion the
    /// verification-wire-capture test documented.
    /// </summary>
    [TestMethod]
    public async Task DefinePinFailIndexAsyncEncryptsTheAuthParameterSoThePinHashNeverAppearsInTheDefineCommand()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        byte[]? defineCommand = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_NV_DefineSpace)
            {
                defineCommand = bytes;
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);

        TpmResult<NvWriteResponse> defineResult = await capturingDevice.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        Assert.IsNotNull(defineCommand, "The capturing wrapper must have observed the NV_DefineSpace command.");
        Assert.IsFalse(
            ContainsSubsequence(defineCommand!, CorrectPinHash),
            "The default define encrypts the auth parameter, so the stored PIN form must never appear as a contiguous byte sequence in the NV_DefineSpace command.");
    }

    /// <summary>
    /// The <c>…WithPasswordAsync</c> enrollment opt-out sends the stored PIN form as a plaintext <c>auth</c>
    /// parameter with no encryption path at all, so the pinHash IS present verbatim in the definition command -
    /// documenting the cost of choosing the low-protection opt-out over the encrypting default.
    /// </summary>
    [TestMethod]
    public async Task DefinePinFailIndexWithPasswordAsyncSendsThePinHashAsAPlaintextAuthParameter()
    {
        const uint PinLimit = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        byte[]? defineCommand = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_NV_DefineSpace)
            {
                defineCommand = bytes;
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);

        TpmResult<NvWriteResponse> defineResult = await capturingDevice.DefinePinFailIndexWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexWithPasswordAsync failed: '{defineResult.ResponseCode}'.");

        Assert.IsNotNull(defineCommand, "The capturing wrapper must have observed the NV_DefineSpace command.");
        Assert.IsTrue(
            ContainsSubsequence(defineCommand!, CorrectPinHash),
            "The password opt-out sends the stored PIN form as a plaintext auth parameter with no encryption path - documenting the opt-out's cost.");
    }

    /// <summary>
    /// A salted define genuinely decrypts to the supplied pinHash on the far side: the Index authValue after a
    /// decrypted enrollment equals the stored PIN form, so a later <c>VerifyPinAsync</c> with the correct PIN
    /// succeeds and resets pinCount, while a wrong PIN is a session-encoded <c>TPM_RC_BAD_AUTH</c>. A correct
    /// verify against garbage (which is what a mis-decrypted authValue would be) is impossible, so this proves the
    /// decrypt recovered the right bytes end to end.
    /// </summary>
    [TestMethod]
    public async Task SaltedDefineInstallsThePinHashSoAVerifyPinRoundTripsAndAWrongPinIsSessionEncodedBadAuth()
    {
        const uint PinLimit = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRsaKeyRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        try
        {
            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            TpmResult<NvWriteResponse> defineResult = await tpm.DefinePinFailIndexAsync(
                ReadOnlyMemory<byte>.Empty, PinIndexHandle, CorrectPinHash, PinLimit,
                tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, rsaBackend.EncryptOaep, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"Salted DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

            TpmResult<TpmPinCounterParameters> correctResult = await tpm.VerifyPinAsync(
                PinIndexHandle, CorrectPinHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                correctResult.IsSuccess,
                $"A salted define must decrypt the auth parameter to the supplied pinHash, so the correct PIN verifies: '{correctResult.ResponseCode}'.");
            Assert.AreEqual(0u, correctResult.Value.PinCount, "A correct verify below pinLimit resets pinCount to zero.");

            TpmResult<TpmPinCounterParameters> wrongResult = await tpm.VerifyPinAsync(
                PinIndexHandle, WrongPinHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrongResult.IsSuccess, "A wrong PIN against the salted-provisioned Index must not be accepted.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.BaseError,
                "A wrong PIN is TPM_RC_BAD_AUTH, confirming the authValue was decrypted to the correct stored form rather than to garbage.");
            Assert.AreNotEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode,
                "The mismatch carries the session-index modifier the HMAC channel applies.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The confidentiality boundary, proven both ways by ONE independent keystream derivation: the parameter
    /// encryption is keyed on <c>sessionValue = KDFa("ATH", key, nonceTPM, nonceCaller)</c> then the XOR mask
    /// <c>KDFa("XOR", sessionValue, nonceCaller, nonceTPM)</c> (TPM 2.0 Library Part 1, Sections 16.6.10 and
    /// 19.2), assembled here through the project's own <c>Kdfa</c>/<c>TpmParameterEncryption</c> seam - the same
    /// primitives <c>KdfaTests</c> pins to known-answer vectors. For the UNSALTED default (empty owner authValue)
    /// the key seed is empty, so this fully public derivation recovers the pinHash from the captured auth
    /// ciphertext - structural encryption, not confidential. For the SALTED define the key seed additionally
    /// folds a salt only the TPM can recover, so the SAME public derivation no longer recovers the pinHash: the
    /// salt is where genuine enrollment confidentiality lives.
    /// </summary>
    [TestMethod]
    public async Task TheUnsaltedDefaultAuthYieldsToThePublicNonceKeystreamButTheSaltedDefineDoesNot()
    {
        const uint PinLimit = 3;
        const uint UnsaltedIndexHandle = 0x0100_00B1;
        const uint SaltedIndexHandle = 0x0100_00B2;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRsaKeyRegistry();

        var unsaltedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice unsaltedDevice = CreateCapturingDevice(simulator, unsaltedPairs))
        {
            TpmResult<NvWriteResponse> defineResult = await unsaltedDevice.DefinePinFailIndexAsync(
                ReadOnlyMemory<byte>.Empty, UnsaltedIndexHandle, CorrectPinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"Unsalted DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");
        }

        (byte[] unsaltedStartCommand, byte[] unsaltedStartResponse) = FirstPair(unsaltedPairs, TpmCcConstants.TPM_CC_StartAuthSession);
        byte[] unsaltedDefineCommand = FirstCommand(unsaltedPairs, TpmCcConstants.TPM_CC_NV_DefineSpace);

        byte[] unsaltedRecovered = await RecoverAuthWithPublicBoundKeyAsync(
            unsaltedStartCommand, unsaltedStartResponse, unsaltedDefineCommand, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            unsaltedRecovered.AsSpan().SequenceEqual(CorrectPinHash),
            "The unsalted default keys its parameter encryption from the public StartAuthSession nonces alone (empty owner authValue), so the public derivation recovers the pinHash - structural, not confidential.");

        var saltedPairs = new List<(TpmCcConstants Code, byte[] Command, byte[] Response)>();
        using(TpmDevice saltedDevice = CreateCapturingDevice(simulator, saltedPairs))
        {
            using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(saltedDevice, registry, pool).ConfigureAwait(false);
            uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

            try
            {
                ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
                TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

                TpmResult<NvWriteResponse> defineResult = await saltedDevice.DefinePinFailIndexAsync(
                    ReadOnlyMemory<byte>.Empty, SaltedIndexHandle, CorrectPinHash, PinLimit,
                    tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, rsaBackend.EncryptOaep, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(defineResult.IsSuccess, $"Salted DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");
            }
            finally
            {
                await FlushIfPresentAsync(saltedDevice, registry, tpmKeyHandle).ConfigureAwait(false);
            }
        }

        (byte[] saltedStartCommand, byte[] saltedStartResponse) = FirstPair(saltedPairs, TpmCcConstants.TPM_CC_StartAuthSession);
        byte[] saltedDefineCommand = FirstCommand(saltedPairs, TpmCcConstants.TPM_CC_NV_DefineSpace);

        byte[] saltedRecovered = await RecoverAuthWithPublicBoundKeyAsync(
            saltedStartCommand, saltedStartResponse, saltedDefineCommand, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(
            saltedRecovered.AsSpan().SequenceEqual(CorrectPinHash),
            "The salted define folds a salt only the TPM can recover into the session key, so the public-nonce derivation that unlocked the unsalted default cannot recover the pinHash - genuine confidentiality.");
    }

    /// <summary>
    /// <c>TPM2_NV_Read</c>'s Index-authValue arm, authorized over a REAL HMAC session whose <c>authHandle</c>
    /// equals the Index itself, runs the <c>TPMA_NV_AUTHREAD</c> availability gate BEFORE the session entry's
    /// HMAC work (TPM 2.0 Library Part 3, Section 5.6): an Index defined with <c>TPMA_NV_AUTHREAD</c> CLEAR
    /// (<c>TPMA_NV_AUTHWRITE</c> and <c>TPMA_NV_OWNERREAD</c> SET, so it is definable and owner-readable but
    /// never USER-readable) answers the bare <c>TPM_RC_AUTH_UNAVAILABLE</c> for a WRONG session-keyed
    /// credential exactly as it would for a correct one - the gate fires ahead of the Name hop and the
    /// command-HMAC verification entirely, so the wrong credential is never evaluated. The wrong credential is
    /// what makes this test distinguish the entry gate from the (unreachable) post-HMAC backstop: a correct
    /// credential would verify and reach that backstop, masking a neutered entry gate. Because the gate
    /// precedes the HMAC-session verification queue, the raw wire response code carries no session-index
    /// modifier and the shared dictionary-attack <c>failedTries</c> counter is left untouched.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverHmacWithWrongAuthOnAuthReadClearIndexHitsEarlyAvailabilityGateWithoutChargingFailedTries()
    {
        const uint AuthReadClearIndexHandle = 0x0100_00C1;
        const ushort IndexDataSize = 1;
        const TpmaNv AuthReadClearAttributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERREAD;

        byte[] correctIndexAuth = [0x11, 0x22, 0x33, 0x44];
        byte[] wrongIndexAuth = [0x55, 0x66, 0x77, 0x88];
        byte[] indexData = [0x2A];

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvReadOverHmacRegistry();

        using(TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool))
        using(Tpm2bAuth auth = Tpm2bAuth.Create(correctIndexAuth, pool))
        using(Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool))
        using(var publicInfo = new TpmsNvPublic(AuthReadClearIndexHandle, SessionAlg, AuthReadClearAttributes, policyDigest, IndexDataSize))
        using(var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo))
        {
            TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace (AUTHREAD-clear Index) failed: '{defineResult.ResponseCode}'.");
        }

        using(TpmPasswordSession writeAuth = TpmPasswordSession.Create(correctIndexAuth, pool))
        {
            using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(indexData, pool);
            var writeInput = new NvWriteInput(AuthReadClearIndexHandle, AuthReadClearIndexHandle, writeInputBuffer, Offset: 0);
            TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(writeResult.IsSuccess, $"NV_Write (provisioning) failed: '{writeResult.ResponseCode}'.");
        }

        TpmResult<NvReadPublicResponse> readPublicResult = await tpm.NvReadPublicAsync(
            AuthReadClearIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readPublicResult.IsSuccess, $"NvReadPublicAsync failed: '{readPublicResult.ResponseCode}'.");

        byte[] indexName;
        using(NvReadPublicResponse readPublicResponse = readPublicResult.Value)
        {
            indexName = readPublicResponse.NvName.Span.ToArray();
        }

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess, $"GetDictionaryAttackParametersAsync (before) failed: '{before.ResponseCode}'.");

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession indexAuthSession = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, pool);
            indexAuthSession.SetAuthValue(wrongIndexAuth, pool);

            var readInput = new NvReadInput(AuthReadClearIndexHandle, AuthReadClearIndexHandle, Size: IndexDataSize, Offset: 0);
            ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

            TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, readInput, [indexAuthSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(readResult.IsSuccess, "A wrong credential over an AUTHREAD-clear Index's HMAC session entry must never be accepted.");
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, readResult.ResponseCode,
                "The availability gate answers BARE, ahead of the session entry's HMAC work, so the raw wire code carries no session-index modifier.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(after.IsSuccess, $"GetDictionaryAttackParametersAsync (after) failed: '{after.ResponseCode}'.");
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "The gate precedes the HMAC-session verification queue entirely, so the shared failedTries counter must be left untouched.");
    }

    /// <summary>
    /// Builds a complete, well-formed <c>TPM_ST_NO_SESSIONS</c> success response for <c>TPM2_NV_Read</c>
    /// carrying a chosen <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> window - the shape an active transport would
    /// forge to answer a session-authorized read without any authorization at all.
    /// </summary>
    /// <param name="pool">The memory pool the response buffer is rented from.</param>
    /// <param name="pinCount">The attacker-chosen attempt count to report.</param>
    /// <param name="pinLimit">The attacker-chosen attempt threshold to report.</param>
    /// <returns>The forged response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The rented buffer's ownership transfers to the TpmResponse, which is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> ForgeNoSessionsPinCounterSuccess(BaseMemoryPool pool, uint pinCount, uint pinLimit)
    {
        const int CounterWindowSize = 2 * sizeof(uint);
        int total = TpmHeader.HeaderSize + sizeof(ushort) + CounterWindowSize;

        IMemoryOwner<byte> owner = pool.Rent(total);
        var writer = new TpmWriter(owner.Memory.Span[..total]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)total, (uint)TpmRcConstants.TPM_RC_SUCCESS);
        header.WriteTo(ref writer);

        Span<byte> counterWindow = stackalloc byte[CounterWindowSize];
        BinaryPrimitives.WriteUInt32BigEndian(counterWindow, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(counterWindow[sizeof(uint)..], pinLimit);
        writer.WriteTpm2b(counterWindow);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
    }

    /// <summary>
    /// Sets a bit in the first authorizing session's <c>sessionAttributes</c> octet of a built command,
    /// navigating the handle and authorization areas with a <see cref="TpmReader"/> so it holds regardless of
    /// nonce and HMAC sizes. Mutates <paramref name="command"/> in place.
    /// </summary>
    /// <param name="command">The built command bytes to modify.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <param name="bit">The <c>TPMA_SESSION</c> bit to set.</param>
    private static void SetFirstSessionAttributeBit(byte[] command, int handleCount, byte bit)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        _ = reader.ReadUInt32(); //authorizationSize.
        _ = reader.ReadUInt32(); //sessionHandle.
        ushort nonceSize = reader.ReadUInt16();
        reader.Skip(nonceSize);

        int attributesIndex = reader.Consumed;
        command[attributesIndex] |= bit;
    }

    /// <summary>Reads a captured TPM command's header <c>code</c> field, leaving every other field unexamined.</summary>
    /// <param name="command">The captured command bytes.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(byte[] command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>
    /// Reads a captured command's first (and, throughout this file, only) authorizing session's
    /// <c>sessionHandle</c> field: handle area (<paramref name="handleCount"/> handles), then
    /// <c>authorizationSize</c>, then <c>sessionHandle</c> - firewalled to the wire, no back-channel into
    /// simulator or session internals.
    /// </summary>
    /// <param name="command">The captured command bytes.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <returns>The authorizing session's handle.</returns>
    private static uint ReadFirstSessionHandleAfterHandleCount(byte[] command, int handleCount)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        _ = reader.ReadUInt32(); //authorizationSize.
        return reader.ReadUInt32(); //sessionHandle.
    }

    /// <summary>
    /// The handle-area size of each single-session-authorized NV command this file's owner verbs compose
    /// (TPM 2.0 Library Part 3, Sections 31.3/31.4/31.7/31.13); a code not in this set answers -1.
    /// </summary>
    /// <param name="code">The command code to map.</param>
    /// <returns>The handle count, or -1 when the code carries no authorizing session this file inspects.</returns>
    private static int OwnerAuthorizedHandleCount(TpmCcConstants code) => code switch
    {
        TpmCcConstants.TPM_CC_NV_DefineSpace => 1,
        TpmCcConstants.TPM_CC_NV_Write => 2,
        TpmCcConstants.TPM_CC_NV_Read => 2,
        TpmCcConstants.TPM_CC_NV_UndefineSpace => 2,
        _ => -1
    };

    /// <summary>Reports whether <paramref name="needle"/> occurs as a contiguous byte sequence within <paramref name="haystack"/>.</summary>
    /// <param name="haystack">The bytes to search.</param>
    /// <param name="needle">The bytes to search for; an empty needle never matches.</param>
    /// <returns><see langword="true"/> when found.</returns>
    private static bool ContainsSubsequence(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if(needle.IsEmpty || needle.Length > haystack.Length)
        {
            return false;
        }

        for(int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if(haystack.Slice(i, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Wraps a device whose transport records every <c>(commandCode, command bytes, response bytes)</c> triple
    /// into <paramref name="pairs"/> - the wire archaeology the confidentiality KAT needs, firewalled to the wire
    /// with no back-channel into the session or simulator internals.
    /// </summary>
    /// <param name="simulator">The simulator the recording transport forwards to.</param>
    /// <param name="pairs">The list each observed command/response is appended to, in submission order.</param>
    /// <returns>A device the caller disposes; its transport records as a side effect of forwarding.</returns>
    private static TpmDevice CreateCapturingDevice(TpmSimulator simulator, List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs)
    {
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            byte[] commandBytes = command.ToArray();
            TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            byte[] responseBytes = result.IsSuccess ? result.Value.AsReadOnlySpan().ToArray() : [];
            pairs.Add((ReadCommandCode(commandBytes), commandBytes, responseBytes));

            return result;
        }

        return TpmDevice.Create(CaptureAsync);
    }

    /// <summary>Returns the command and response bytes of the first recorded triple whose command code equals <paramref name="code"/>.</summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="code">The command code to locate.</param>
    /// <returns>The matching command and response bytes.</returns>
    private static (byte[] Command, byte[] Response) FirstPair(List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, TpmCcConstants code)
    {
        foreach((TpmCcConstants Code, byte[] Command, byte[] Response) pair in pairs)
        {
            if(pair.Code == code)
            {
                return (pair.Command, pair.Response);
            }
        }

        throw new InvalidOperationException($"No captured command with code '{code}' was recorded.");
    }

    /// <summary>Returns the command bytes of the first recorded triple whose command code equals <paramref name="code"/>.</summary>
    /// <param name="pairs">The recorded command/response triples.</param>
    /// <param name="code">The command code to locate.</param>
    /// <returns>The matching command bytes.</returns>
    private static byte[] FirstCommand(List<(TpmCcConstants Code, byte[] Command, byte[] Response)> pairs, TpmCcConstants code) =>
        FirstPair(pairs, code).Command;

    /// <summary>
    /// Extracts the two initial session nonces from a captured <c>TPM2_StartAuthSession</c> exchange: the caller
    /// nonce from the command (after <c>tpmKey</c> and <c>bind</c>) and the TPM nonce from the response (after
    /// <c>sessionHandle</c>) - the KDFa <c>contextU</c>/<c>contextV</c> a bound session key derives from (TPM 2.0
    /// Library Part 1, Section 16.6.10, equation 20). Navigated with a <see cref="TpmReader"/> so it holds
    /// regardless of nonce widths.
    /// </summary>
    /// <param name="startCommand">The captured StartAuthSession command bytes.</param>
    /// <param name="startResponse">The captured StartAuthSession response bytes.</param>
    /// <returns>The initial caller nonce and TPM nonce.</returns>
    private static (byte[] NonceCaller, byte[] NonceTpm) ExtractStartAuthSessionNonces(byte[] startCommand, byte[] startResponse)
    {
        var commandReader = new TpmReader(startCommand);
        _ = TpmHeader.Parse(ref commandReader);
        _ = commandReader.ReadUInt32(); //tpmKey.
        _ = commandReader.ReadUInt32(); //bind.
        ushort callerNonceSize = commandReader.ReadUInt16();
        byte[] nonceCaller = commandReader.PeekBytes(callerNonceSize).ToArray();

        var responseReader = new TpmReader(startResponse);
        _ = TpmHeader.Parse(ref responseReader);
        _ = responseReader.ReadUInt32(); //sessionHandle.
        ushort tpmNonceSize = responseReader.ReadUInt16();
        byte[] nonceTpm = responseReader.PeekBytes(tpmNonceSize).ToArray();

        return (nonceCaller, nonceTpm);
    }

    /// <summary>
    /// Extracts the command caller nonce and the encrypted <c>auth</c> ciphertext from a captured
    /// <c>TPM2_NV_DefineSpace</c> command: single handle area (<c>@authHandle</c>), then the one authorizing
    /// session, then the first parameter <c>auth</c> (a <c>TPM2B_AUTH</c>, its size never encrypted, Part 1,
    /// Section 20.1). Navigated with a <see cref="TpmReader"/> so it holds regardless of nonce/HMAC widths.
    /// </summary>
    /// <param name="defineCommand">The captured NV_DefineSpace command bytes.</param>
    /// <returns>The command caller nonce and the encrypted auth data portion.</returns>
    private static (byte[] NonceCaller, byte[] AuthCiphertext) ExtractDefineAuthParameter(byte[] defineCommand)
    {
        var reader = new TpmReader(defineCommand);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //@authHandle (owner).
        _ = reader.ReadUInt32(); //authorizationSize.
        _ = reader.ReadUInt32(); //sessionHandle.
        ushort nonceSize = reader.ReadUInt16();
        byte[] nonceCaller = reader.PeekBytes(nonceSize).ToArray();
        reader.Skip(nonceSize);
        _ = reader.ReadByte(); //sessionAttributes.
        ushort hmacSize = reader.ReadUInt16();
        reader.Skip(hmacSize);

        ushort authSize = reader.ReadUInt16();
        byte[] ciphertext = reader.PeekBytes(authSize).ToArray();

        return (nonceCaller, ciphertext);
    }

    /// <summary>
    /// Reconstructs the stored PIN form a passive bus observer could recover from a captured define, assuming NO
    /// salt and an empty owner authValue: derives the session key it would compute, <c>KDFa(SHA-256, Empty,
    /// "ATH", nonceTPM, nonceCaller)</c> (TPM 2.0 Library Part 1, Section 16.6.10), then XOR-decrypts the auth
    /// ciphertext with the command-direction mask keyed on that value (Section 18.2). Uses the project's own
    /// <c>Kdfa</c> and <c>TpmParameterEncryption</c> primitives, so a match means the encryption was genuinely
    /// keyed on public material and a mismatch means it was not.
    /// </summary>
    /// <param name="startCommand">The captured StartAuthSession command bytes.</param>
    /// <param name="startResponse">The captured StartAuthSession response bytes.</param>
    /// <param name="defineCommand">The captured NV_DefineSpace command bytes.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A token observed across the derivations.</param>
    /// <returns>The bytes the public-key derivation recovers from the encrypted auth parameter.</returns>
    private static async Task<byte[]> RecoverAuthWithPublicBoundKeyAsync(
        byte[] startCommand, byte[] startResponse, byte[] defineCommand, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        const int SessionKeyBits = 256;
        const int SessionKeyBytes = SessionKeyBits / 8;

        (byte[] startNonceCaller, byte[] startNonceTpm) = ExtractStartAuthSessionNonces(startCommand, startResponse);
        (byte[] commandNonceCaller, byte[] ciphertext) = ExtractDefineAuthParameter(defineCommand);

        //The observer's public reconstruction: a session whose key seed is empty (no salt, empty owner authValue)
        //has sessionKey = KDFa("ATH", Empty, nonceTPM_start, nonceCaller_start), and since it authorizes the owner
        //by binding, sessionValue for encryption reduces to that session key alone.
        using IMemoryOwner<byte> sessionKey = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, ReadOnlyMemory<byte>.Empty, "ATH", startNonceTpm, startNonceCaller, SessionKeyBits, pool, cancellationToken).ConfigureAwait(false);

        byte[] recovered = (byte[])ciphertext.Clone();

        //Command direction (Part 1, Section 18.2): nonceNewer = nonceCaller, nonceOlder = nonceTPM; nonceTPM for
        //the first command over the session is still the StartAuthSession response nonce (not yet rolled).
        await TpmParameterEncryption.XorAsync(
            HashAlgorithmName.SHA256, sessionKey.Memory[..SessionKeyBytes], commandNonceCaller, startNonceTpm, recovered, pool, cancellationToken).ConfigureAwait(false);

        return recovered;
    }

    /// <summary>Creates the standard RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as the salted overload's tpmKey.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry, already carrying the CreatePrimary codec.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The created primary key's response; the caller owns and disposes it.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Flushes a transient object or session handle when one is present (non-zero), ignoring the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry (the FlushContext codec is registered on demand).</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        if(!registry.TryGet(TpmCcConstants.TPM_CC_FlushContext, out _))
        {
            _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        }

        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a response codec registry for the RSA-tpmKey creation this file's salted-overload test drives directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRsaKeyRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>Creates a response codec registry for the low-level NV Index define/write/read and HMAC-session commands the AUTHREAD-gate test drives directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvReadOverHmacRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with BOTH the ECC (BouncyCastle) and RSA (framework key generation, BouncyCastle
    /// OAEP) signing backends wired, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-nv-secure-channel", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
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
