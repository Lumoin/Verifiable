using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
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

        //TPM2_MakeCredential is not modelled by this slice, so while operational it is rejected as an unknown
        //command code. (TPM2_GetRandom is modelled and would instead succeed here.)
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = pool.Rent(TpmHeader.HeaderSize);
        Memory<byte> command = owner.Memory[..TpmHeader.HeaderSize];
        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)TpmHeader.HeaderSize, (uint)TpmCcConstants.TPM_CC_MakeCredential);
        header.WriteTo(ref writer);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, command).ConfigureAwait(false);

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
        Assert.AreEqual("Startup:Reset", entries[1].Label, "A fresh simulator's first Startup(CLEAR), with no prior orderly shutdown, is a TPM Reset (Part 3, clause 9.3).");
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

    [TestMethod]
    public async Task GetRandomReturnsRequestedBytesThroughExecutor()
    {
        const int RequestedBytes = 16;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRandomRegistry();

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(RequestedBytes), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result.ResponseCode}'.");
        using GetRandomResponse response = result.Value;
        Assert.AreEqual(RequestedBytes, response.RandomBytes.Size);
    }

    [TestMethod]
    public async Task GetRandomClampsRequestToLargestDigest()
    {
        //Part 3, 16.1: a request larger than fits in a TPM2B_DIGEST is not an error; the TPM returns
        //only as much as fits (the largest digest it can produce).
        const ushort OversizedRequest = 200;
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRandomRegistry();

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(OversizedRequest), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result.ResponseCode}'.");
        using GetRandomResponse response = result.Value;
        Assert.AreEqual(TpmLifecycleTransitions.MaxRandomBytes, response.RandomBytes.Size);
    }

    [TestMethod]
    public async Task GetRandomBeforeStartupReturnsInitialize()
    {
        var simulator = new TpmSimulator("tpm-getrandom-init");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new GetRandomInput(16)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, responseCode);
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task GetRandomEmitsActionLoopTrace()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        var observer = new TestObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>();
        using IDisposable subscription = simulator.Subscribe(observer);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, new GetRandomInput(16)).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, responseCode);

        //Two transitions: the command declares the RNG action, then the action result is folded back.
        var entries = observer.Received;
        Assert.HasCount(2, entries);
        Assert.AreEqual("GetRandom:Requested", entries[0].Label);
        Assert.AreEqual("GetRandom:Completed", entries[1].Label);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task SuccessiveGetRandomDrawsDiffer()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRandomRegistry();

        TpmResult<GetRandomResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(32), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        TpmResult<GetRandomResponse> secondResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, new GetRandomInput(32), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(firstResult.IsSuccess);
        Assert.IsTrue(secondResult.IsSuccess);
        using GetRandomResponse first = firstResult.Value;
        using GetRandomResponse second = secondResult.Value;

        //The default deterministic RNG advances across draws, so two successive results differ — a
        //value backend that returned the same octets twice would break nonce uniqueness.
        Assert.IsFalse(
            first.RandomBytes.AsReadOnlySpan().SequenceEqual(second.RandomBytes.AsReadOnlySpan()),
            "Successive deterministic draws must differ.");
    }

    [TestMethod]
    public async Task GetRandomWithoutParameterReturnsInsufficient()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //A GetRandom command framed without its UINT16 bytesRequested parameter cannot be unmarshalled,
        //which the TPM reports as TPM_RC_INSUFFICIENT (Part 2, Table 4), not TPM_RC_SIZE.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = pool.Rent(TpmHeader.HeaderSize);
        Memory<byte> command = owner.Memory[..TpmHeader.HeaderSize];
        var writer = new TpmWriter(command.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)TpmHeader.HeaderSize, (uint)TpmCcConstants.TPM_CC_GetRandom);
        header.WriteTo(ref writer);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, command).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INSUFFICIENT, responseCode);
    }

    [TestMethod]
    public async Task FailedRandomDrawDoesNotCorruptNextCommand()
    {
        //An injected RNG backend that always throws models a hardware entropy failure.
        void ThrowingRng(Span<byte> destination) => throw new InvalidOperationException("entropy backend failed");

        var simulator = new TpmSimulator("tpm-rng-throws", TpmSelfTestBehavior.Passes, ThrowingRng);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitForCodeAsync(simulator, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false));

        //The faulted draw surfaces as an exception rather than silently corrupting state.
        bool threw = false;
        try
        {
            _ = await SubmitForCodeAsync(simulator, new GetRandomInput(16)).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "A throwing RNG backend must surface, not be swallowed.");

        //The next command must return ITS OWN response, not a stale random response left by the aborted
        //draw's pending action.
        TpmRcConstants testResult = await SubmitForTestResultBodyAsync(simulator).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, testResult);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    [TestMethod]
    public async Task GetDictionaryAttackParametersReadsSimulatorDefaults()
    {
        //The headline V.5a path: the client-side DA-parameters carrier reads the simulator's lockout
        //state end-to-end via TPM2_GetCapability(TPM_PROPERTIES), with no real hardware.
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        TpmResult<TpmDictionaryAttackParameters> result = await device.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result}'.");
        TpmDictionaryAttackParameters parameters = result.Value;
        Assert.AreEqual(0u, parameters.LockoutCounter);
        Assert.AreEqual(TpmSimulatorState.DefaultMaxTries, parameters.MaxAuthFail);
        Assert.AreEqual(TimeSpan.FromSeconds(TpmSimulatorState.DefaultRecoveryTimeSeconds), parameters.LockoutInterval);
        Assert.AreEqual(TimeSpan.FromSeconds(TpmSimulatorState.DefaultLockoutRecoverySeconds), parameters.LockoutRecovery);
        Assert.IsFalse(parameters.IsLockedOut);
    }

    [TestMethod]
    public async Task GetCapabilityAllowedInFailureMode()
    {
        TpmSimulator simulator = await CreateOperationalAsync(TpmSelfTestBehavior.Fails).ConfigureAwait(false);
        _ = await SubmitForCodeAsync(simulator, new SelfTestInput(IsFullTest: false)).ConfigureAwait(false);
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase);

        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateCapabilityRegistry();

        //Clause 10.4: Failure Mode admits TPM2_GetTestResult() and TPM2_GetCapability().
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"GetCapability must be permitted in Failure Mode; got '{result}'.");
        result.Value.Dispose();
    }

    [TestMethod]
    public async Task GetCapabilityBeforeStartupReturnsInitialize()
    {
        var simulator = new TpmSimulator("tpm-getcap-init");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER)).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, responseCode);
    }

    [TestMethod]
    public async Task GetCapabilityForUnsupportedCapabilityReturnsValue()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);

        //Only TPM_CAP_TPM_PROPERTIES is modelled this slice; another capability category is rejected.
        TpmRcConstants responseCode = await SubmitForCodeAsync(simulator, GetCapabilityInput.ForAlgorithms()).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, responseCode);
    }

    [TestMethod]
    public async Task GetCapabilityPagesWhenWindowTruncated()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateCapabilityRegistry();

        //Requesting fewer than the available lockout properties truncates the window and sets moreData.
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, count: 2), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result}'.");
        using GetCapabilityResponse response = result.Value;
        Assert.IsTrue(response.MoreData.IsYes, "A truncated property window must set moreData.");
        var properties = response.CapabilityData.TpmProperties;
        Assert.IsNotNull(properties);
        Assert.HasCount(2, properties);
    }

    [TestMethod]
    public async Task GetCapabilityPagingGathersEveryPropertyExactlyOnce()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateCapabilityRegistry();

        //Page the full property set in windows of two, following moreData exactly as the DA carrier
        //does, and assert the rounds cover every reported property once, strictly ascending — the
        //paging-convergence contract the windowing relies on.
        var collected = new List<uint>();
        uint property = TpmPtConstants.TPM_PT_FAMILY_INDICATOR;
        bool more = true;
        while(more)
        {
            TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
                device, GetCapabilityInput.ForTpmProperties(property, count: 2), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result}'.");
            using GetCapabilityResponse response = result.Value;
            var properties = response.CapabilityData.TpmProperties;
            Assert.IsNotNull(properties);
            if(properties.Count == 0)
            {
                break;
            }

            foreach(var tagged in properties)
            {
                collected.Add(tagged.Property);
                property = tagged.Property + 1;
            }

            more = response.MoreData.IsYes;
        }

        Assert.HasCount(9, collected);
        for(int i = 1; i < collected.Count; i++)
        {
            Assert.IsGreaterThan(collected[i - 1], collected[i], "Paged properties must be strictly ascending across rounds.");
        }
    }

    [TestMethod]
    public async Task GetCapabilityReportsNotInLockoutByDefault()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateCapabilityRegistry();

        //TPM_PT_PERMANENT carries the IN_LOCKOUT bit; a freshly-started TPM is not in lockout, so the
        //bit is clear. Driving it SET requires authorization failures, which arrive with V.5b.
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_PERMANENT, count: 1), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result}'.");
        using GetCapabilityResponse response = result.Value;
        var properties = response.CapabilityData.TpmProperties;
        Assert.IsNotNull(properties);
        Assert.HasCount(1, properties);
        Assert.AreEqual(TpmPtConstants.TPM_PT_PERMANENT, properties[0].Property);
        var permanent = (TpmaPermanent)properties[0].Value;
        Assert.IsFalse(permanent.HasFlag(TpmaPermanent.IN_LOCKOUT), "A freshly-started TPM must not report IN_LOCKOUT.");
    }

    private static TpmResponseRegistry CreateRandomRegistry() =>
        new TpmResponseRegistry().Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

    private static TpmResponseRegistry CreateCapabilityRegistry() =>
        new TpmResponseRegistry().Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);

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
