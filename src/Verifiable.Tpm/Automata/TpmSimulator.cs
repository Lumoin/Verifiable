using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// A behavioural TPM simulator built on a <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>.
/// Unlike <see cref="TpmVirtualDevice"/>, which replays recorded bytes, this models TPM behaviour and
/// computes responses from state, so command sequences that depend on lifecycle and per-command
/// preconditions behave correctly.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="SubmitAsync"/> has the <see cref="TpmSubmitHandler"/> shape, so the simulator plugs
/// straight into <see cref="TpmDevice.Create(TpmSubmitHandler, Action?)"/>:
/// </para>
/// <code>
/// var simulator = new TpmSimulator("tpm-under-test");
/// await simulator.PowerOnAsync();
/// using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
/// </code>
/// <para>
/// The device owns a single live automaton with one run identifier and one trace stream
/// (design decision D2), reachable via <see cref="Subscribe"/>. Commands are processed serially, as a
/// physical TPM does; the simulator is not safe for concurrent calls to <see cref="SubmitAsync"/>.
/// </para>
/// <para>
/// <strong>Scope.</strong> This lifecycle skeleton models <c>_TPM_Init</c>, <c>TPM2_Startup()</c>,
/// <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>, and <c>TPM2_GetTestResult()</c> — no cryptography.
/// Its primary value is letting destructive and lockout state-machine scenarios be exercised in
/// software, never against real hardware.
/// </para>
/// <para>
/// <strong>Skeleton limitations.</strong> Failure Mode is reachable only via an explicit
/// <c>TPM2_SelfTest()</c> on a TPM configured to fail, not via init-time power-on self-test.
/// <c>TPM2_Shutdown()</c> records the orderly shutdown type and leaves the TPM operational until the
/// next <c>_TPM_Init</c>; the rule that a state-modifying command issued after Shutdown(STATE)
/// invalidates the saved state (Part 1, clause 10.2.4) is modelled when such commands are added.
/// A disorderly power loss is not modelled — power-on is always the orderly <c>_TPM_Init</c>.
/// </para>
/// </remarks>
/// <seealso cref="TpmVirtualDevice"/>
/// <seealso cref="TpmDevice"/>
public sealed class TpmSimulator: IObservable<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>
{
    private readonly PushdownAutomaton<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> automaton;
    private readonly TimeProvider timeProvider;

    /// <summary>
    /// Creates a simulator for a TPM that is powered off and awaiting <c>_TPM_Init</c>.
    /// </summary>
    /// <param name="tpmId">A stable identifier for this simulated TPM; also the automaton's run identifier.</param>
    /// <param name="selfTest">The modelled self-test behaviour, used to drive Failure Mode deterministically.</param>
    /// <param name="timeProvider">The time source for trace timestamps. Defaults to <see cref="TimeProvider.System"/>.</param>
    public TpmSimulator(string tpmId, TpmSelfTestBehavior selfTest = TpmSelfTestBehavior.Passes, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tpmId);

        this.timeProvider = timeProvider ?? TimeProvider.System;
        automaton = new PushdownAutomaton<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol>(
            runId: tpmId,
            initialState: TpmSimulatorState.PoweredOff(tpmId, selfTest),
            initialStackSymbol: TpmSimulatorStackSymbol.Lifecycle,
            transition: TpmLifecycleTransitions.Create(),
            acceptPredicate: static state => state.Phase == TpmLifecyclePhase.Operational,
            timeProvider: this.timeProvider);
    }

    /// <summary>
    /// Gets the current lifecycle phase of the simulated TPM.
    /// </summary>
    public TpmLifecyclePhase CurrentPhase => automaton.CurrentState.Phase;

    /// <inheritdoc />
    public IDisposable Subscribe(IObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>> observer) =>
        automaton.Subscribe(observer);

    /// <summary>
    /// Applies a platform <c>_TPM_Init</c> indication, moving the TPM into
    /// <see cref="TpmLifecyclePhase.Initializing"/> (and out of <see cref="TpmLifecyclePhase.FailureMode"/>
    /// if it was there). This is not a TPM command and produces no response.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that completes when the indication has been applied.</returns>
    public ValueTask PowerOnAsync(CancellationToken cancellationToken = default) =>
        StepAsync(new TpmInitSignal(), cancellationToken);

    /// <summary>
    /// Processes a command and produces its response. Has the <see cref="TpmSubmitHandler"/> shape.
    /// </summary>
    /// <param name="command">The command bytes.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The response. The caller owns the returned response and must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    public async ValueTask<TpmResult<TpmResponse>> SubmitAsync(ReadOnlyMemory<byte> command, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryParseCommand(command.Span, out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode))
        {
            return SerializeResponse(new TpmHeaderOnlyResponse(malformedResponseCode), pool);
        }

        await StepAsync(input, cancellationToken).ConfigureAwait(false);

        TpmResponseIntent intent = automaton.CurrentState.ResponseIntent
            ?? new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_FAILURE);

        return SerializeResponse(intent, pool);
    }

    private async ValueTask StepAsync(TpmSimulatorInput input, CancellationToken cancellationToken)
    {
        _ = await PdaRunner.StepWithEffectsAsync<TpmSimulatorState, TpmSimulatorInput, int>(
            automaton.CurrentState,
            automaton.StepCount,
            input,
            step: StepCoreAsync,
            actionExtractor: static state => state.NextAction,
            actionExecutor: static (action, _, _) =>
                throw new NotSupportedException($"The lifecycle simulator declares no effectful actions; got '{action.GetType().Name}'."),
            actionContext: 0,
            timeProvider,
            cancellationToken).ConfigureAwait(false);
    }

    //Bridges the runner's value-threaded step to the live automaton (design decision D2: one live
    //automaton per simulated TPM holds the state of record). The runner threads back exactly the
    //(state, step count) the previous call returned, so the live automaton and the threaded values
    //stay in lockstep; reading the automaton here is therefore equivalent to using the arguments.
    private async ValueTask<(TpmSimulatorState State, int StepCount)> StepCoreAsync(
        TpmSimulatorState currentState,
        int currentStepCount,
        TpmSimulatorInput input,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        _ = await automaton.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (automaton.CurrentState, automaton.StepCount);
    }

    private static bool TryParseCommand(ReadOnlySpan<byte> command, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(command.Length < TpmHeader.HeaderSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_SIZE;

            return false;
        }

        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        //The declared command size must match the octet count actually received (Part 3, 5.2).
        if(header.Size != (uint)command.Length)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_SIZE;

            return false;
        }

        //Only the two structurally valid command tags are accepted; an authorization area carried by a
        //sessions-tagged command is not parsed until sessions are modelled.
        if(header.Tag != (ushort)TpmStConstants.TPM_ST_NO_SESSIONS && header.Tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_BAD_TAG;

            return false;
        }

        var commandCode = (TpmCcConstants)header.Code;

        switch(commandCode)
        {
            case TpmCcConstants.TPM_CC_Startup:
            {
                input = new TpmStartupRequested(ReadStartupType(ref reader));

                break;
            }
            case TpmCcConstants.TPM_CC_Shutdown:
            {
                input = new TpmShutdownRequested(ReadStartupType(ref reader));

                break;
            }
            case TpmCcConstants.TPM_CC_SelfTest:
            {
                bool isFullTest = reader.Remaining >= sizeof(byte) && reader.ReadByte() != 0;
                input = new TpmSelfTestRequested(isFullTest);

                break;
            }
            case TpmCcConstants.TPM_CC_GetTestResult:
            {
                input = new TpmTestResultRequested();

                break;
            }
            default:
            {
                input = new TpmUnsupportedCommandReceived(commandCode);

                break;
            }
        }

        return true;
    }

    private static TpmSuConstants ReadStartupType(ref TpmReader reader)
    {
        //An absent or short startup type is surfaced as an out-of-range value, which the transition
        //rejects with TPM_RC_VALUE — the same outcome the TPM gives for an invalid startupType.
        if(reader.Remaining < sizeof(ushort))
        {
            return (TpmSuConstants)0xFFFF;
        }

        return (TpmSuConstants)reader.ReadUInt16();
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeResponse(TpmResponseIntent intent, MemoryPool<byte> pool)
    {
        int parameterSize = intent is TpmTestResultResponse { ResponseCode: TpmRcConstants.TPM_RC_SUCCESS }
            ? sizeof(ushort) + sizeof(uint)
            : 0;
        int total = TpmHeader.HeaderSize + parameterSize;

        IMemoryOwner<byte> owner = pool.Rent(total);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)total, (uint)intent.ResponseCode);
        header.WriteTo(ref writer);

        if(intent is TpmTestResultResponse { ResponseCode: TpmRcConstants.TPM_RC_SUCCESS } testResultResponse)
        {
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteUInt32((uint)testResultResponse.TestResult);
        }

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
    }
}
