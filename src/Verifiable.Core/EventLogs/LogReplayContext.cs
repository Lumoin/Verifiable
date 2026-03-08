namespace Verifiable.Core.EventLogs;

/// <summary>
/// Groups all delegates and configuration required to replay an
/// authenticated append-only log.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LogReplayContext{TState,TOperation,TProof,TContext}"/> is the
/// single injection point for all caller-supplied behavior. The replayer
/// holds no state and no policy — it drives the delegates in order for each
/// entry and emits results.
/// </para>
/// <para>
/// <strong>Why a context record rather than separate parameters.</strong>
/// The delegates form a coherent behavioral unit. Classifying an entry,
/// verifying its chain position, validating its proofs, and applying its
/// operation to the current state are four aspects of the same decision about
/// whether and how an entry advances the log. Grouping them in a single
/// immutable record makes the caller's intent explicit, allows a single
/// instance to serve multiple concurrent replay calls, and makes it
/// straightforward to vary behavior across log methods by constructing
/// different contexts for the same replayer instance.
/// </para>
/// <para>
/// <strong>Proof validation context.</strong>
/// <typeparamref name="TContext"/> is the caller-defined proof validation
/// context. It carries trust anchors, a <see cref="System.TimeProvider"/>,
/// revocation information, and any other inputs required by
/// <see cref="ValidateProof"/>. The replayer passes it through to the
/// delegate unchanged. For logs that require no proof validation context —
/// such as tests or logs where proofs are always accepted — the caller
/// may use a zero-size struct to eliminate all allocation overhead.
/// </para>
/// <para>
/// <strong>Chain of trust and hardware roots.</strong>
/// The same structural pattern recurs across all trust domains this infrastructure
/// serves: an identifier is bound to a key, the binding has temporal validity,
/// the binding can be revoked, and trust traces back through a chain to an anchor
/// the relying party has decided to trust. This holds for X.509 certificate chains,
/// DID documents with verification methods, TPM endorsement key certificate chains,
/// and Trusted Lists pointing to QTSPs. The lifecycle operations are isomorphic:
/// creation, rotation, revocation, expiration. The mechanisms differ; the semantics
/// are identical. When the log's proofs are hardware-bound — a TPM-resident key
/// producing a signed attestation, or a YubiKey-backed signature — the
/// <typeparamref name="TContext"/> carries the endorsement key certificate chain
/// required to verify that the signature was produced by a specific piece of
/// silicon, completing the chain from hardware entropy source to verified log entry.
/// </para>
/// <para>
/// <strong>Time provider.</strong>
/// <see cref="TimeProvider"/> is a first-class member of the context rather
/// than an ambient dependency because temporal constraints during replay —
/// such as rejecting entries whose claimed version time exceeds the current
/// wall clock, or enforcing that heartbeat intervals do not exceed a configured
/// maximum — must be testable without manipulating system time. Callers inject
/// <see cref="System.TimeProvider.System"/> in production and a fake provider
/// in tests.
/// </para>
/// <para>
/// <strong>Apply delegate composition.</strong>
/// The <see cref="Apply"/> delegate is the single dispatch point for all state
/// transitions. The library provides composable base implementations via
/// <see cref="LogReplayDefaults.CreateApplyDelegate{TState,TOperation,TProof}"/>.
/// Callers wrap the base delegate to handle custom classifications, exactly as
/// a key format reader delegate chains to its base for unrecognized properties.
/// </para>
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <typeparam name="TOperation">The domain operation type.</typeparam>
/// <typeparam name="TProof">The proof type.</typeparam>
/// <typeparam name="TContext">The caller-defined proof validation context type.</typeparam>
public sealed class LogReplayContext<TState, TOperation, TProof, TContext>
{
    /// <summary>
    /// Gets the delegate that classifies each entry before dispatch.
    /// </summary>
    public required ClassifyOperationDelegate<TOperation, TProof> Classify { get; init; }

    /// <summary>
    /// Gets the delegate that verifies hash-chain or Merkle-inclusion integrity
    /// for each entry.
    /// </summary>
    /// <remarks>
    /// The delegate receives the authoritative previous digest threaded forward
    /// by the replayer — not the value the current entry claims. For logs backed
    /// by a sequential hash chain the delegate compares the entry's
    /// <see cref="LogEntry{TOperation,TProof}.PreviousDigest"/> against this
    /// authoritative value. For logs backed by a Merkle tree (for example,
    /// a Certificate Transparency-style log or a SCITT transparency service)
    /// the delegate verifies a Merkle inclusion proof instead. Both integrity
    /// mechanisms are valid implementations of this single delegate slot.
    /// </remarks>
    public required VerifyChainIntegrityDelegate<TOperation, TProof> VerifyChainIntegrity { get; init; }

    /// <summary>
    /// Gets the delegate that validates the proofs carried by each entry.
    /// </summary>
    /// <remarks>
    /// For DID event logs the delegate checks that the controller proof verifies
    /// against the currently authorized update key and that the witness proofs
    /// meet the configured quorum threshold. For CRDT delta logs the delegate
    /// checks that the author's zero-knowledge role credential proves membership
    /// in the required role set at the time of the operation. For TPM-backed logs
    /// the delegate verifies the hardware signature against the endorsement key
    /// certificate chain. The delegate has full access to the current log state,
    /// which is required when the authorized key set is itself part of the
    /// evolving state (as in DID key rotation).
    /// </remarks>
    public required ValidateProofDelegate<TState, TOperation, TProof, TContext> ValidateProof { get; init; }

    /// <summary>
    /// Gets the caller-defined context passed to <see cref="ValidateProof"/>.
    /// </summary>
    public required TContext ValidationContext { get; init; }

    /// <summary>
    /// Gets the delegate that applies a classified entry to the current log state.
    /// </summary>
    /// <remarks>
    /// This single delegate replaces separate genesis, update, and deactivate
    /// delegates. The caller pattern-matches on the classification and log state
    /// variant to implement all required transitions. Use
    /// <see cref="LogReplayDefaults.CreateApplyDelegate{TState,TOperation,TProof}"/>
    /// to obtain a composable base implementation.
    /// </remarks>
    public required ApplyDelegate<TState, TOperation, TProof> Apply { get; init; }

    /// <summary>
    /// Gets the optional delegate called after each entry is successfully processed,
    /// or <see langword="null"/> when no listener is attached.
    /// </summary>
    /// <remarks>
    /// Use this hook to drive audit sinks, UI notifications, webhook dispatchers,
    /// or any other downstream consumer that needs to react to each state transition
    /// without taking ownership of the replay stream. Multiple consumers can be
    /// composed by the caller using <see cref="System.Threading.Channels.Channel{T}"/>
    /// fan-out above this layer; the infrastructure provides the single notification
    /// point and leaves fan-out to the caller.
    /// </remarks>
    public OnEntryProcessedDelegate<TState, TOperation, TProof>? OnEntryProcessed { get; init; }

    /// <summary>
    /// Gets the <see cref="System.TimeProvider"/> used to validate temporal
    /// constraints during replay, such as ensuring version times do not exceed
    /// the current time.
    /// </summary>
    /// <remarks>
    /// Inject <see cref="System.TimeProvider.System"/> in production.
    /// Inject a deterministic fake provider in tests to make time-dependent
    /// validation behavior reproducible without manipulating system clocks.
    /// </remarks>
    public required System.TimeProvider TimeProvider { get; init; }
}