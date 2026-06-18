using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
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
/// <strong>Scope.</strong> The simulator models the lifecycle commands <c>_TPM_Init</c>,
/// <c>TPM2_Startup()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>, and
/// <c>TPM2_GetTestResult()</c>, plus <c>TPM2_GetRandom()</c>, which is the first command driven through
/// the fine-grained action layer: its transition declares a <see cref="TpmRngAction"/>, the effectful
/// loop draws octets from the injected RNG backend, and the transition frames the
/// <c>TPM2B_DIGEST</c> response. Its primary value is letting destructive and lockout state-machine
/// scenarios be exercised in software, never against real hardware.
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
    private readonly FillEntropyDelegate rng;
    private ulong rngCounter;

    /// <summary>
    /// Creates a simulator for a TPM that is powered off and awaiting <c>_TPM_Init</c>.
    /// </summary>
    /// <param name="tpmId">A stable identifier for this simulated TPM; also the automaton's run identifier.</param>
    /// <param name="selfTest">The modelled self-test behaviour, used to drive Failure Mode deterministically.</param>
    /// <param name="rng">
    /// The random-number backend used by <c>TPM2_GetRandom()</c>. The simulator models the device's RNG,
    /// not a real entropy source, so the default is a deterministic counter stream seeded per instance —
    /// reproducible for replay yet distinct across successive draws (so nonces and salts do not collide).
    /// Tests inject a fixed pattern or a platform CSPRNG via this delegate. The delegate must fill the
    /// entire destination span.
    /// </param>
    /// <param name="timeProvider">The time source for trace timestamps. Defaults to <see cref="TimeProvider.System"/>.</param>
    public TpmSimulator(string tpmId, TpmSelfTestBehavior selfTest = TpmSelfTestBehavior.Passes, FillEntropyDelegate? rng = null, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tpmId);

        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.rng = rng ?? FillDeterministic;
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
    public async ValueTask PowerOnAsync(CancellationToken cancellationToken = default)
    {
        //_TPM_Init is a pure lifecycle transition that declares no effect, so it is stepped directly
        //through the automaton rather than the effectful runner (which would need a memory pool it
        //has no use for here). The automaton still emits the single trace entry for the step.
        _ = await automaton.StepAsync(new TpmInitSignal(), cancellationToken).ConfigureAwait(false);
    }

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

        await RunWithEffectsAsync(input, pool, cancellationToken).ConfigureAwait(false);

        TpmResponseIntent intent = automaton.CurrentState.ResponseIntent
            ?? new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_FAILURE);

        return SerializeResponse(intent, pool);
    }

    private async ValueTask RunWithEffectsAsync(TpmSimulatorInput input, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        _ = await PdaRunner.StepWithEffectsAsync<TpmSimulatorState, TpmSimulatorInput, RngActionContext>(
            automaton.CurrentState,
            automaton.StepCount,
            input,
            step: StepCoreAsync,
            actionExtractor: static state => state.NextAction,
            actionExecutor: static (action, context, _) => ExecuteAction(action, context),
            actionContext: new RngActionContext(rng, pool),
            timeProvider,
            cancellationToken).ConfigureAwait(false);
    }

    //Executes the effectful work a transition declared. The only effect in this slice is drawing
    //random octets for TPM2_GetRandom(); the result is fed back as a TpmRandomGenerated input so the
    //pure transition can frame the response without ever touching the RNG or a buffer itself.
    private static ValueTask<TpmSimulatorInput> ExecuteAction(PdaAction action, RngActionContext context) =>
        action switch
        {
            TpmRngAction rngAction => ValueTask.FromResult<TpmSimulatorInput>(GenerateRandom(rngAction, context)),
            _ => throw new NotSupportedException($"No executor is registered for action '{action.GetType().Name}'.")
        };

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned TpmRandomGenerated, then to the TpmRandomResponse intent, and is released by SerializeResponse after framing.")]
    private static TpmRandomGenerated GenerateRandom(TpmRngAction action, RngActionContext context)
    {
        //Rent at least one octet so a zero-length request still yields a valid (empty) buffer.
        IMemoryOwner<byte> owner = context.Pool.Rent(Math.Max(action.ByteCount, 1));
        try
        {
            context.Rng(owner.Memory.Span[..action.ByteCount]);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        return new TpmRandomGenerated(owner, action.ByteCount);
    }

    //The default deterministic RNG backend: a per-instance counter stream. Reproducible across runs
    //yet advancing across draws, so successive TPM2_GetRandom() calls return distinct octets. Not a
    //real entropy source — provenance is the concern of TpmEntropyProvider, not the device model.
    private void FillDeterministic(Span<byte> destination)
    {
        Span<byte> block = stackalloc byte[sizeof(ulong)];
        for(int i = 0; i < destination.Length; i += sizeof(ulong))
        {
            BinaryPrimitives.WriteUInt64LittleEndian(block, rngCounter);
            rngCounter++;

            int take = Math.Min(sizeof(ulong), destination.Length - i);
            block[..take].CopyTo(destination[i..(i + take)]);
        }
    }

    //Caller-supplied context threaded to the action executor without closure capture: the injected
    //RNG backend and the per-call memory pool.
    private readonly struct RngActionContext(FillEntropyDelegate rng, MemoryPool<byte> pool)
    {
        public FillEntropyDelegate Rng { get; } = rng;

        public MemoryPool<byte> Pool { get; } = pool;
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
            case TpmCcConstants.TPM_CC_GetRandom:
            {
                //TPM2_GetRandom() carries a single UINT16 bytesRequested parameter (Part 3, 16.1); a
                //command whose parameter area is too short to unmarshal it is a shortfall, which the
                //TPM reports as TPM_RC_INSUFFICIENT ("not enough octets in the input buffer"), not the
                //size-value-out-of-range TPM_RC_SIZE (Part 2, Table 4).
                if(reader.Remaining < sizeof(ushort))
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                    return false;
                }

                input = new TpmGetRandomRequested(reader.ReadUInt16());

                break;
            }
            case TpmCcConstants.TPM_CC_GetCapability:
            {
                //capability (UINT32) + property (UINT32) + propertyCount (UINT32) (Part 3, 30.2). A
                //parameter area too short to unmarshal these is a shortfall (TPM_RC_INSUFFICIENT).
                if(reader.Remaining < 3 * sizeof(uint))
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                    return false;
                }

                var capability = (TpmCapConstants)reader.ReadUInt32();
                uint property = reader.ReadUInt32();
                uint propertyCount = reader.ReadUInt32();
                input = new TpmGetCapabilityRequested(capability, property, propertyCount);

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
        //The TpmRandomResponse intent is the terminal owner of the RNG buffer rented by the action
        //executor; release it in the finally regardless of how framing completes (its octets are
        //copied into the framed TPM2B_DIGEST on the success path).
        IMemoryOwner<byte>? randomBuffer = (intent as TpmRandomResponse)?.RandomBytes;
        TpmsCapabilityData? capabilityData = (intent as TpmCapabilityResponse)?.CapabilityData;
        try
        {
            int parameterSize = intent switch
            {
                TpmTestResultResponse { ResponseCode: TpmRcConstants.TPM_RC_SUCCESS } => sizeof(ushort) + sizeof(uint),
                TpmRandomResponse random => sizeof(ushort) + random.Length,
                TpmCapabilityResponse capabilityResponse => sizeof(byte) + capabilityResponse.CapabilityData.GetSerializedSize(),
                _ => 0
            };
            int total = TpmHeader.HeaderSize + parameterSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span);
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                switch(intent)
                {
                    case TpmTestResultResponse { ResponseCode: TpmRcConstants.TPM_RC_SUCCESS } testResultResponse:
                    {
                        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                        writer.WriteUInt32((uint)testResultResponse.TestResult);

                        break;
                    }
                    case TpmRandomResponse randomResponse:
                    {
                        writer.WriteTpm2b(randomResponse.RandomBytes.Memory.Span[..randomResponse.Length]);

                        break;
                    }
                    case TpmCapabilityResponse capabilityResponse:
                    {
                        capabilityResponse.MoreData.WriteTo(ref writer);
                        capabilityResponse.CapabilityData.WriteTo(ref writer);

                        break;
                    }
                    default:
                    {
                        break;
                    }
                }

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            randomBuffer?.Dispose();
            capabilityData?.Dispose();
        }
    }
}
