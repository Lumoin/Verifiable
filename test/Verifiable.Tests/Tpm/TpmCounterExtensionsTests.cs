using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Counter;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Flow coverage for the <c>Extensions/Counter</c> business-capability verbs (<see cref="TpmDeviceExtensions.DefineCounterAsync"/>,
/// <see cref="TpmDeviceExtensions.IncrementCounterAsync"/>, <see cref="TpmDeviceExtensions.ReadCounterAsync"/>,
/// <see cref="TpmDeviceExtensions.UndefineCounterAsync"/>) against the in-house behavioural <see cref="TpmSimulator"/> -
/// entirely in-process, with no external assets - through the same production wire path
/// <see cref="TpmInHouseSimulatorNvCounterTests"/> exercises directly with <see cref="NvIncrementInput"/>/
/// <see cref="NvReadInput"/>/<see cref="NvDefineSpaceInput"/>/<see cref="NvUndefineSpaceInput"/>, except every
/// define/increment/read/undefine step here goes exclusively through the verbs under test. TPM 2.0 Library Part 1,
/// Section 34.2.6.3; Part 3, Sections 31.3.1, 31.7.1, 31.8.
/// </summary>
[TestClass]
internal sealed class TpmCounterExtensionsTests
{
    /// <summary>The primary Counter Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint CounterIndexHandle = 0x0100_0061;

    /// <summary>The Index authorization value used by the positive-path tests.</summary>
    private static byte[] CounterAuthBytes { get; } = [0x11, 0x22, 0x33, 0x44];

    /// <summary>A wrong Index authorization value, distinct from <see cref="CounterAuthBytes"/>.</summary>
    private static byte[] WrongCounterAuthBytes { get; } = [0x99, 0x88, 0x77, 0x66];

    /// <summary>
    /// A single-octet payload for the rejected raw <c>TPM2_NV_Write()</c> attempt; its content is immaterial since
    /// the write must never reach the Index's stored data.
    /// </summary>
    private static byte[] RejectedWriteAttempt { get; } = [0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a define-then-increment run through the verbs alone reads back strictly monotonically: each
    /// <see cref="TpmDeviceExtensions.IncrementCounterAsync"/> call returns exactly the run index, and a follow-up
    /// <see cref="TpmDeviceExtensions.ReadCounterAsync"/> agrees with the last increment's returned count - proving
    /// the verb's internal NV_Increment+NV_Read composition and a standalone read observe the same stored value.
    /// </summary>
    [TestMethod]
    public async Task DefineThenIncrementRunThroughTheVerbsIsMonotonic()
    {
        const int IncrementCount = 5;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        for(ulong expected = 1; expected <= IncrementCount; expected++)
        {
            TpmResult<ulong> incrementResult = await device.IncrementCounterAsync(
                CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(incrementResult.IsSuccess, $"Increment {expected} of {IncrementCount} failed: '{incrementResult.ResponseCode}'.");
            Assert.AreEqual(expected, incrementResult.Value, $"Increment {expected} must return exactly {expected}.");
        }

        TpmResult<ulong> readResult = await device.ReadCounterAsync(
            CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"ReadCounterAsync failed: '{readResult.ResponseCode}'.");
        Assert.AreEqual((ulong)IncrementCount, readResult.Value, "A standalone read after the run must agree with the last increment's returned count.");
    }

    /// <summary>
    /// The flagship rollback-protection positive, driven entirely through the verbs: increments a Counter
    /// Index to a known value, undefines it with <see cref="TpmDeviceExtensions.UndefineCounterAsync"/>, redefines
    /// the same handle with <see cref="TpmDeviceExtensions.DefineCounterAsync"/>, and verifies the first
    /// <see cref="TpmDeviceExtensions.IncrementCounterAsync"/> of the redefined Index seeds strictly above (exactly
    /// one past) the deleted counter's last value - the phantom high-water mark (TPM 2.0 Library Part 1, Section
    /// 37.2.6.3 NOTE 2/NOTE 6) proving delete-then-redefine can never roll a counter with this Name back.
    /// </summary>
    [TestMethod]
    public async Task RedefiningAfterUndefineThroughTheVerbsSeedsStrictlyAboveTheDeletedCountersLastValue()
    {
        const int IncrementsBeforeDelete = 3;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"Initial DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        for(int i = 0; i < IncrementsBeforeDelete; i++)
        {
            TpmResult<ulong> seedingResult = await device.IncrementCounterAsync(
                CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(seedingResult.IsSuccess, $"Seeding increment {i + 1} failed: '{seedingResult.ResponseCode}'.");
        }

        TpmResult<NvUndefineSpaceResponse> undefineResult = await device.UndefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefineCounterAsync failed: '{undefineResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> redefineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"Redefine of the same handle failed: '{redefineResult.ResponseCode}'.");

        TpmResult<ulong> firstIncrementAfterRedefine = await device.IncrementCounterAsync(
            CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(firstIncrementAfterRedefine.IsSuccess, $"First increment after redefine failed: '{firstIncrementAfterRedefine.ResponseCode}'.");

        Assert.IsGreaterThan(
            (ulong)IncrementsBeforeDelete, firstIncrementAfterRedefine.Value,
            $"The redefined counter's first increment ({firstIncrementAfterRedefine.Value}) must exceed the deleted counter's last value ({IncrementsBeforeDelete}).");
        Assert.AreEqual(
            (ulong)IncrementsBeforeDelete + 1, firstIncrementAfterRedefine.Value,
            "The phantom high-water mark must seed the redefined counter's first increment at exactly one past the deleted counter's last value.");
    }

    /// <summary>
    /// Verifies <see cref="TpmDeviceExtensions.IncrementCounterAsync"/> with a wrong Index authValue rejects with
    /// <c>TPM_RC_BAD_AUTH</c>. The Index is defined with <c>noDa: true</c> (dictionary-attack opted out) so this
    /// negative is a clean bad-authorization answer, uncomplicated by the dictionary-attack lockout ladder a
    /// DA-protected Index would instead feed (TPM 2.0 Library Part 1, Section 16.8.1). The verb's default channel
    /// is an HMAC session, so the mismatch is a genuine command-HMAC failure and the raw wire code
    /// carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2) - the base error is what
    /// decodes to the bare constant.
    /// </summary>
    [TestMethod]
    public async Task IncrementCounterAsyncWithWrongAuthOnANoDaIndexReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes, noDa: true,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync (noDa) failed: '{defineResult.ResponseCode}'.");

        TpmResult<ulong> wrongAuthResult = await device.IncrementCounterAsync(
            CounterIndexHandle, WrongCounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong Index authValue must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongAuthResult.BaseError);
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, wrongAuthResult.ResponseCode,
            "The default channel is an HMAC session, so the raw wire code carries the session-index modifier.");
    }

    /// <summary>
    /// Pins <see cref="TpmDeviceExtensions.DefineCounterAsync"/>'s SECURE DEFAULT: with <c>noDa</c> left at its
    /// default the Index is dictionary-attack PROTECTED, so a wrong Index authValue is an auth-failure that feeds
    /// the shared lockout counter (<c>TPM_RC_AUTH_FAIL</c>, TPM 2.0 Library Part 1, Section 16.8.3) rather than the
    /// plain bad-authorization a <c>TPMA_NV_NO_DA</c> Index answers (<c>TPM_RC_BAD_AUTH</c>, Section 16.8.1 — the
    /// contrast <see cref="IncrementCounterAsyncWithWrongAuthOnANoDaIndexReturnsBadAuth"/> exercises). Flipping the
    /// default to opt every counter out of lockout protection therefore fails here rather than passing silently.
    /// The verb's default channel is an HMAC session, so the raw wire code carries the session-index
    /// modifier (TPM 2.0 Library Part 2, clause 6.6.2) - the base error is what decodes to the bare constant.
    /// </summary>
    [TestMethod]
    public async Task DefineCounterAsyncDefaultsToDictionaryAttackProtected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<ulong> wrongAuthResult = await device.IncrementCounterAsync(
            CounterIndexHandle, WrongCounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong Index authValue must not be accepted.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, wrongAuthResult.BaseError,
            "A counter defined with the default must be dictionary-attack protected, so a wrong authValue answers TPM_RC_AUTH_FAIL, not TPM_RC_BAD_AUTH.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, wrongAuthResult.ResponseCode,
            "The default channel is an HMAC session, so the raw wire code carries the session-index modifier.");
    }

    /// <summary>
    /// Verifies the required behavioral contrast between the two read-side verbs on a freshly defined Counter
    /// Index: <see cref="TpmDeviceExtensions.ReadCounterAsync"/> rejects with <c>TPM_RC_NV_UNINITIALIZED</c>
    /// (TPM 2.0 Library Part 3, Section 31.13.1) before any increment has ever run, while
    /// <see cref="TpmDeviceExtensions.IncrementCounterAsync"/> against that very same, still-unwritten Index
    /// succeeds outright (Section 31.8.1's explicit non-error) and returns exactly <c>1</c>.
    /// </summary>
    [TestMethod]
    public async Task ReadCounterAsyncBeforeFirstIncrementFailsWhileIncrementCounterAsyncOnTheSameFreshIndexSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<ulong> readBeforeIncrementResult = await device.ReadCounterAsync(
            CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(readBeforeIncrementResult.IsSuccess, "A read of an unwritten Counter Index must not succeed.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, readBeforeIncrementResult.ResponseCode);

        TpmResult<ulong> incrementResult = await device.IncrementCounterAsync(
            CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            incrementResult.IsSuccess,
            $"The first increment of an unwritten counter must succeed even though the read above rejected: '{incrementResult.ResponseCode}'.");
        Assert.AreEqual(1ul, incrementResult.Value, "The first increment of a fresh counter must produce exactly 1.");
    }

    /// <summary>
    /// Regression proof that a Counter Index defined through <see cref="TpmDeviceExtensions.DefineCounterAsync"/>
    /// still refuses a raw <c>TPM2_NV_Write()</c> with <c>TPM_RC_ATTRIBUTES</c> (TPM 2.0 Library Part 3, Section
    /// 31.7.1: the four update commands partition NV Index types; only <c>TPM2_NV_Increment()</c> may modify a
    /// Counter Index). This verb group has no write verb, so the negative is driven with the raw
    /// <see cref="NvWriteInput"/> through <see cref="TpmCommandExecutor"/> directly, mirroring
    /// <see cref="TpmInHouseSimulatorNvCounterTests.NvWriteOfCounterIndexReturnsAttributes"/>.
    /// </summary>
    [TestMethod]
    public async Task RawNvWriteAgainstAVerbDefinedCounterIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        using TpmPasswordSession writeSession = TpmPasswordSession.Create(CounterAuthBytes, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(RejectedWriteAttempt, pool);
        var writeInput = new NvWriteInput(CounterIndexHandle, CounterIndexHandle, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [writeSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(writeResult.IsSuccess, "A raw TPM2_NV_Write() against a Counter Index must not succeed.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, writeResult.ResponseCode,
            "TPM2_NV_Write() must refuse a Counter Index once authorization has already succeeded - only TPM2_NV_Increment() may modify it.");
    }

    /// <summary>
    /// A full define→increment→read→undefine lifecycle driven ENTIRELY
    /// over the four verbs' DEFAULT channel is monotonic exactly as the all-password lifecycle (see
    /// <see cref="DefineThenIncrementRunThroughTheVerbsIsMonotonic"/>) is, and not one command the verbs
    /// compose ever carries <c>TPM_RS_PW</c> as its authorizing session - proving the default channel
    /// genuinely rides a session rather than a password (TPM 2.0 Library Part 1, Sections 16.6.9/16.6.10).
    /// </summary>
    [TestMethod]
    public async Task DefineIncrementReadUndefineOverTheDefaultChannelRoundTripsMonotonicWithoutEverSendingAPasswordSession()
    {
        const int IncrementCount = 3;

        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        var capturedCommands = new List<byte[]>();
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice device = TpmDevice.Create(CaptureAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        for(ulong expected = 1; expected <= IncrementCount; expected++)
        {
            TpmResult<ulong> incrementResult = await device.IncrementCounterAsync(
                CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(incrementResult.IsSuccess, $"Increment {expected} of {IncrementCount} failed: '{incrementResult.ResponseCode}'.");
            Assert.AreEqual(expected, incrementResult.Value, $"Increment {expected} must return exactly {expected}.");
        }

        TpmResult<ulong> readResult = await device.ReadCounterAsync(
            CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"ReadCounterAsync failed: '{readResult.ResponseCode}'.");
        Assert.AreEqual((ulong)IncrementCount, readResult.Value, "A standalone read after the run must agree with the last increment's returned count.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await device.UndefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefineCounterAsync failed: '{undefineResult.ResponseCode}'.");

        Assert.IsNotEmpty(capturedCommands, "The capturing wrapper must have observed at least one command.");
        foreach(byte[] command in capturedCommands)
        {
            TpmCcConstants code = ReadCommandCode(command);
            int handleCount = CounterCommandHandleCount(code);
            if(handleCount < 0)
            {
                continue;
            }

            uint sessionHandle = ReadFirstSessionHandleAfterHandleCount(command, handleCount);
            Assert.AreNotEqual(
                (uint)TpmRh.TPM_RH_PW, sessionHandle,
                $"The default channel must never send a TPM_RS_PW password session ('{code}' command).");
        }
    }

    /// <summary>
    /// Every <c>…WithPasswordAsync</c> opt-out still authorizes
    /// correctly through the same lifecycle and genuinely sends <c>TPM_RS_PW</c> for each composed command -
    /// proving the opt-outs are not accidentally identical to the secure defaults on the wire.
    /// </summary>
    [TestMethod]
    public async Task DefineIncrementReadUndefineWithPasswordOptOutsRoundTripAndGenuinelySendATpmRsPwSession()
    {
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        var capturedCommands = new List<byte[]>();
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken ct)
        {
            capturedCommands.Add(command.ToArray());
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice device = TpmDevice.Create(CaptureAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterWithPasswordAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<ulong> incrementResult = await device.IncrementCounterWithPasswordAsync(
            CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(incrementResult.IsSuccess, $"IncrementCounterWithPasswordAsync failed: '{incrementResult.ResponseCode}'.");
        Assert.AreEqual(1ul, incrementResult.Value, "The first increment must return exactly 1.");

        TpmResult<ulong> readResult = await device.ReadCounterWithPasswordAsync(
            CounterIndexHandle, CounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"ReadCounterWithPasswordAsync failed: '{readResult.ResponseCode}'.");
        Assert.AreEqual(1ul, readResult.Value, "A standalone read after the single increment must agree with it.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await device.UndefineCounterWithPasswordAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefineCounterWithPasswordAsync failed: '{undefineResult.ResponseCode}'.");

        Assert.IsNotEmpty(capturedCommands, "The capturing wrapper must have observed at least one command.");
        foreach(byte[] command in capturedCommands)
        {
            TpmCcConstants code = ReadCommandCode(command);
            int handleCount = CounterCommandHandleCount(code);
            if(handleCount < 0)
            {
                continue;
            }

            uint sessionHandle = ReadFirstSessionHandleAfterHandleCount(command, handleCount);
            Assert.AreEqual(
                (uint)TpmRh.TPM_RH_PW, sessionHandle,
                $"Every WithPasswordAsync opt-out must genuinely send TPM_RS_PW ('{code}' command).");
        }
    }

    /// <summary>
    /// The salted overload round-trips against an RSA tpmKey exactly as
    /// the unsalted default does - the salt (TPM 2.0 Library Part 1, Section 16.6.11, equation 23) changes only
    /// where the session key's entropy comes from, never the increment's return value (mirrors the Pin group's
    /// own salted-overload proof, <c>VerifyPinAsyncSaltedOverloadSucceedsAgainstAnRsaTpmKeyAndResetsPinCount</c>).
    /// </summary>
    [TestMethod]
    public async Task IncrementCounterAsyncSaltedOverloadSucceedsAgainstAnRsaTpmKeyAndReturnsTheFreshCount()
    {
        const uint DefaultRsaExponent = 65537;
        const TpmAlgIdConstants RsaKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withRsaBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> keyResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(keyResult.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{keyResult.ResponseCode}'.");

        using CreatePrimaryResponse tpmKey = keyResult.Value;
        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        TpmResult<ulong> incrementResult = await device.IncrementCounterAsync(
            CounterIndexHandle, CounterAuthBytes, tpmKey.ObjectHandle.Value, modulus, DefaultRsaExponent, RsaKeyNameAlg,
            rsaBackend.EncryptOaep, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(incrementResult.IsSuccess, $"IncrementCounterAsync (salted overload) failed: '{incrementResult.ResponseCode}'.");
        Assert.AreEqual(1ul, incrementResult.Value, "The salted overload's first increment must return exactly 1, exactly as the unsalted default does.");
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
    /// Reads a captured command's first (and, throughout these additions, only) authorizing session's
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

    /// <summary>The handle-area size of each Counter-group command the four verbs compose (TPM 2.0 Library Part 3, Sections 31.3/31.4/31.8/31.13).</summary>
    /// <param name="code">The command code to map.</param>
    /// <returns>The handle count, or -1 when the code is not one of this file's Counter commands.</returns>
    private static int CounterCommandHandleCount(TpmCcConstants code) => code switch
    {
        TpmCcConstants.TPM_CC_NV_DefineSpace => 1,
        TpmCcConstants.TPM_CC_NV_Increment => 2,
        TpmCcConstants.TPM_CC_NV_Read => 2,
        TpmCcConstants.TPM_CC_NV_UndefineSpace => 2,
        _ => -1
    };

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase. When <paramref name="withRsaBackend"/> is set, the simulator is also wired with the ECC
    /// (BouncyCastle) and RSA (framework) signing backends a salted HMAC session's RSA <c>tpmKey</c> needs from
    /// <c>TPM2_CreatePrimary()</c> (TPM 2.0 Library Part 1, clause 10.4.10.3).
    /// </summary>
    /// <param name="withRsaBackend">When <see langword="true"/>, wires the ECC and RSA signing backends; otherwise the simulator carries neither.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(bool withRsaBackend = false)
    {
        var simulator = withRsaBackend
            ? new TpmSimulator(
                "tpm-in-house-counter-verbs", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create())
            : new TpmSimulator("tpm-in-house-counter-verbs");
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
