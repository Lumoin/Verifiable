using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Counter;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Flow coverage for the <c>Extensions/Counter</c> business-capability verbs (<see cref="TpmDeviceExtensions.DefineCounterAsync"/>,
/// <see cref="TpmDeviceExtensions.IncrementCounterAsync"/>, <see cref="TpmDeviceExtensions.ReadCounterAsync"/>,
/// <see cref="TpmDeviceExtensions.UndefineCounterAsync"/>) against the in-house behavioural <see cref="TpmSimulator"/> -
/// entirely in-process, with no external assets - through the same production wire path
/// <see cref="TpmInHouseSimulatorNvCounterTests"/> exercises directly with <see cref="NvIncrementInput"/>/
/// <see cref="NvReadInput"/>/<see cref="NvDefineSpaceInput"/>/<see cref="NvUndefineSpaceInput"/>, except every
/// define/increment/read/undefine step here goes exclusively through the verbs under test. TPM 2.0 Library Part 1,
/// Section 37.2.6.3; Part 3, Sections 31.3.1, 31.7.1, 31.8.
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

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
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
    /// The wave's flagship rollback-protection positive, driven entirely through the verbs: increments a Counter
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

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
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
    /// DA-protected Index would instead feed (TPM 2.0 Library Part 1, Section 17.8.1).
    /// </summary>
    [TestMethod]
    public async Task IncrementCounterAsyncWithWrongAuthOnANoDaIndexReturnsBadAuth()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes, noDa: true,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync (noDa) failed: '{defineResult.ResponseCode}'.");

        TpmResult<ulong> wrongAuthResult = await device.IncrementCounterAsync(
            CounterIndexHandle, WrongCounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong Index authValue must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongAuthResult.ResponseCode);
    }

    /// <summary>
    /// Pins <see cref="TpmDeviceExtensions.DefineCounterAsync"/>'s SECURE DEFAULT: with <c>noDa</c> left at its
    /// default the Index is dictionary-attack PROTECTED, so a wrong Index authValue is an auth-failure that feeds
    /// the shared lockout counter (<c>TPM_RC_AUTH_FAIL</c>, TPM 2.0 Library Part 1, Section 17.8.3) rather than the
    /// plain bad-authorization a <c>TPMA_NV_NO_DA</c> Index answers (<c>TPM_RC_BAD_AUTH</c>, Section 17.8.1 — the
    /// contrast <see cref="IncrementCounterAsyncWithWrongAuthOnANoDaIndexReturnsBadAuth"/> exercises). Flipping the
    /// default to opt every counter out of lockout protection therefore fails here rather than passing silently.
    /// </summary>
    [TestMethod]
    public async Task DefineCounterAsyncDefaultsToDictionaryAttackProtected()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<ulong> wrongAuthResult = await device.IncrementCounterAsync(
            CounterIndexHandle, WrongCounterAuthBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(wrongAuthResult.IsSuccess, "A wrong Index authValue must not be accepted.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, wrongAuthResult.ResponseCode,
            "A counter defined with the default must be dictionary-attack protected, so a wrong authValue answers TPM_RC_AUTH_FAIL, not TPM_RC_BAD_AUTH.");
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
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
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
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, CounterAuthBytes,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);

        using TpmPasswordSession writeSession = TpmPasswordSession.Create(CounterAuthBytes, pool);
        var writeInput = new NvWriteInput(CounterIndexHandle, CounterIndexHandle, new Tpm2bMaxBuffer(RejectedWriteAttempt), Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [writeSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(writeResult.IsSuccess, "A raw TPM2_NV_Write() against a Counter Index must not succeed.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, writeResult.ResponseCode,
            "TPM2_NV_Write() must refuse a Counter Index once authorization has already succeeded - only TPM2_NV_Increment() may modify it.");
    }

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase.
    /// </summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-counter-verbs");
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
