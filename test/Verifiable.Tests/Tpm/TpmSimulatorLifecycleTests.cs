using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Coverage for <see cref="TpmSimulator"/>: the lifecycle state machine (power-on, startup, shutdown,
/// self-test, failure mode), per-phase command admissibility, the response framing, and the trace
/// stream. Commands are built from the real typed <see cref="ITpmCommandInput"/> types and serialized
/// into pooled buffers, mirroring how the executor frames a command on the wire. All scenarios run
/// against the in-process simulator; no real TPM hardware is touched.
/// </summary>
[TestClass]
internal sealed class TpmSimulatorLifecycleTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void NewSimulatorIsPoweredOff()
    {
        var simulator = new TpmSimulator("tpm-new");

        Assert.AreEqual(TpmLifecyclePhase.PoweredOff, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task CommandBeforePowerOnReturnsInitialize()
    {
        var simulator = new TpmSimulator("tpm-poweredoff");

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new GetTestResultInput()).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, responseCode);
        Assert.AreEqual(TpmLifecyclePhase.PoweredOff, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task PowerOnMovesToInitializing()
    {
        var simulator = new TpmSimulator("tpm-init");

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task NonStartupCommandInInitializingReturnsInitialize()
    {
        var simulator = new TpmSimulator("tpm-await-startup");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new GetTestResultInput()).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, responseCode);
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task StartupClearReachesOperational()
    {
        var simulator = new TpmSimulator("tpm-startup-clear");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, responseCode);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task StartupStateWithoutSavedStateReturnsValueAndStaysInitializing()
    {
        var simulator = new TpmSimulator("tpm-resume-nostate");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, responseCode);
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task ResumePathReachesOperational()
    {
        var simulator = new TpmSimulator("tpm-resume");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitForCodeAsync(simulator, new ShutdownInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false));

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);

        TpmRcConstants resumeCode = await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_STATE)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, resumeCode);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task SecondStartupReturnsInitialize()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, responseCode);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task SelfTestPassesStaysOperationalAndReportsSuccess()
    {
        TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Passes).ConfigureAwait(false);

        TpmRcConstants selfTestCode = await SubmitForCodeAsync(simulator, new SelfTestInput(IsFullTest: true)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, selfTestCode);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        TpmRcConstants testResult = await SubmitForTestResultBodyAsync(simulator).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, testResult);
    }

    [TestMethod]
    public async Task SelfTestFailureEntersFailureMode()
    {
        TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);

        TpmRcConstants selfTestCode = await SubmitForCodeAsync(simulator, new SelfTestInput(IsFullTest: false)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode);
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task GetTestResultInFailureModeReportsFailureInBody()
    {
        TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        _ = await SubmitForCodeAsync(simulator, new SelfTestInput(IsFullTest: false)).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase);

        TpmRcConstants testResult = await SubmitForTestResultBodyAsync(simulator).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, testResult);
    }

    [TestMethod]
    public async Task CommandsInFailureModeReturnFailure()
    {
        TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        _ = await SubmitForCodeAsync(simulator, new SelfTestInput(IsFullTest: false)).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase);

        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, await SubmitForCodeAsync(simulator, new ShutdownInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, await SubmitForCodeAsync(simulator, new SelfTestInput(IsFullTest: false)).ConfigureAwait(false));
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, await SubmitForCodeAsync(simulator, new GetRandomInput(16)).ConfigureAwait(false));
    }

    [TestMethod]
    public async Task FailureModeExitsViaPowerOn()
    {
        TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        _ = await SubmitForCodeAsync(simulator, new SelfTestInput(IsFullTest: false)).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase);

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);

        TpmRcConstants startupCode = await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, startupCode);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task UnsupportedCommandWhileOperationalReturnsCommandCode()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new GetRandomInput(16)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, responseCode);
    }

    [TestMethod]
    public async Task TruncatedCommandReturnsCommandSize()
    {
        var simulator = new TpmSimulator("tpm-truncated");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = pool.Rent(4);
        Memory<byte> command = owner.Memory[..4];
        BinaryPrimitives.WriteUInt16BigEndian(command.Span, (ushort)TpmStConstants.TPM_ST_NO_SESSIONS);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, command).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_SIZE, responseCode);
    }

    [TestMethod]
    public async Task CommandWithMismatchedSizeFieldReturnsCommandSize()
    {
        var simulator = new TpmSimulator("tpm-size-mismatch");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = RentCommand(new GetTestResultInput(), pool, out int length);
        Memory<byte> command = owner.Memory[..length];
        BinaryPrimitives.WriteUInt32BigEndian(command.Span.Slice(sizeof(ushort)), (uint)(length + 1));

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, command).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_SIZE, responseCode);
    }

    [TestMethod]
    public async Task CommandWithUnknownTagReturnsBadTag()
    {
        var simulator = new TpmSimulator("tpm-bad-tag");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = RentCommand(new GetTestResultInput(), pool, out int length);
        Memory<byte> command = owner.Memory[..length];
        BinaryPrimitives.WriteUInt16BigEndian(command.Span, 0x1234);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, command).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_TAG, responseCode);
    }

    [TestMethod]
    public async Task GetTestResultSuccessResponseIsWellFormed()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        TpmResult<TpmResponse> result = await SubmitAsync(simulator, new GetTestResultInput()).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using TpmResponse response = result.Value;

        const int ExpectedLength = 16;
        Assert.AreEqual(ExpectedLength, response.Length);

        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);
        Assert.AreEqual((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, header.Tag);
        Assert.AreEqual((uint)ExpectedLength, header.Size);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)header.Code);

        ReadOnlySpan<byte> outData = reader.ReadTpm2b();
        Assert.AreEqual(0, outData.Length);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)reader.ReadUInt32());
    }

    [TestMethod]
    public async Task TraceEmitsOneEntryPerStep()
    {
        var simulator = new TpmSimulator("tpm-trace");
        var observer = new TestObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>();
        using IDisposable subscription = simulator.Subscribe(observer);

        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        TpmRcConstants startupCode = await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, startupCode);

        var entries = observer.Received;
        Assert.HasCount(2, entries);
        foreach(TraceEntry<TpmSimulatorState, TpmSimulatorInput> entry in entries)
        {
            Assert.AreEqual("tpm-trace", entry.RunId);
            Assert.AreEqual(TraceOutcome.Transitioned, entry.Outcome);
            Assert.IsNotNull(entry.Label);
        }

        Assert.AreEqual("TpmInit", entries[0].Label);
        Assert.AreEqual("Startup:Clear", entries[1].Label);
    }

    [TestMethod]
    public async Task PlugsIntoTpmDeviceTransport()
    {
        var simulator = new TpmSimulator("tpm-device");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = RentCommand(new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool, out int length);
        TpmResult<TpmResponse> result = await device.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)header.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    private async Task<TpmSimulator> CreateOperationalAsync(TpmSelfTestBehavior selfTest = TpmSelfTestBehavior.Passes)
    {
        var simulator = new TpmSimulator("tpm-operational", selfTest);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants startupCode = await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, startupCode);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return simulator;
    }

    private async Task<TpmRcConstants> SubmitForCodeAsync(TpmSimulator simulator, ITpmCommandInput input)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = RentCommand(input, pool, out int length);

        return await SubmitForCodeAsync(simulator, owner.Memory[..length]).ConfigureAwait(false);
    }

    private async Task<TpmRcConstants> SubmitForCodeAsync(TpmSimulator simulator, ReadOnlyMemory<byte> command)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)header.Code;
    }

    private async Task<TpmResult<TpmResponse>> SubmitAsync(TpmSimulator simulator, ITpmCommandInput input)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = RentCommand(input, pool, out int length);

        return await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
    }

    private async Task<TpmRcConstants> SubmitForTestResultBodyAsync(TpmSimulator simulator)
    {
        TpmResult<TpmResponse> result = await SubmitAsync(simulator, new GetTestResultInput()).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)header.Code);
        _ = reader.ReadTpm2b();

        return (TpmRcConstants)reader.ReadUInt32();
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented command buffer transfers to the caller, which disposes it.")]
    private static IMemoryOwner<byte> RentCommand(ITpmCommandInput input, MemoryPool<byte> pool, out int length)
    {
        length = TpmHeader.HeaderSize + input.GetSerializedSize();
        IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        return owner;
    }
}
