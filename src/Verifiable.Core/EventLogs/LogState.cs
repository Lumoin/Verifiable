namespace Verifiable.Core.EventLogs;

/// <summary>
/// Represents the state of a log at a given point in replay.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LogState{TState}"/> eliminates null from the replay pipeline by
/// giving each phase of a log's lifecycle a distinct, named type. The replayer
/// starts with <see cref="EmptyLogState{TState}"/> and transitions through
/// <see cref="ActiveLogState{TState}"/> on genesis. A deactivation entry
/// produces <see cref="DeactivatedLogState{TState}"/>, which is terminal.
/// </para>
/// <para>
/// Apply delegates receive the current <see cref="LogState{TState}"/> and
/// pattern-match on the variant to enforce correct lifecycle transitions without
/// null checks or suppression operators. An update delegate that receives an
/// <see cref="EmptyLogState{TState}"/> knows immediately that the log is
/// malformed — no null propagation, no silent wrong-state behavior.
/// </para>
/// <para>
/// <strong>Lifecycle as entropy reduction.</strong>
/// The three variants correspond to three phases of information state.
/// <see cref="EmptyLogState{TState}"/> represents maximum uncertainty — nothing
/// is yet known about the subject. <see cref="ActiveLogState{TState}"/> carries
/// the accumulated knowledge after each verified entry has reduced that uncertainty
/// one step further. <see cref="DeactivatedLogState{TState}"/> records the final
/// known state at the point the subject was permanently deactivated — a terminal
/// snapshot preserving the last verified reduction of uncertainty for audit and
/// historical resolution. The pattern is the same one that recurs across all
/// trust domains in this library: an identifier bound to a key, the binding
/// carrying temporal validity, the binding traceable back through a chain to an
/// anchor. The mechanisms differ — X.509, DID, TPM EK, QTSP Trusted List — but
/// the entropy structure is identical. Each verified state transition is one
/// preserved link in that chain.
/// </para>
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
public abstract record LogState<TState>;

/// <summary>
/// The log state before the genesis entry has been applied.
/// </summary>
/// <remarks>
/// This is the initial state supplied to the replayer. A genesis apply delegate
/// receives this variant and must produce an <see cref="ActiveLogState{TState}"/>.
/// Any other apply delegate receiving this variant indicates a malformed log —
/// the base implementation in
/// <see cref="LogReplayDefaults.CreateApplyDelegate{TState,TOperation,TProof}"/>
/// returns an error in that case.
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
public sealed record EmptyLogState<TState>: LogState<TState>;

/// <summary>
/// The log state after the genesis entry has been applied and before deactivation.
/// </summary>
/// <remarks>
/// Update and heartbeat delegates receive this variant. The <see cref="Value"/>
/// property carries the current domain state — a DID document, a CRDT document
/// snapshot, a supply chain object state, or any other accumulation of the
/// operations applied so far.
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <param name="Value">The current domain state.</param>
public sealed record ActiveLogState<TState>(TState Value): LogState<TState>;

/// <summary>
/// The terminal log state after a deactivation entry has been applied.
/// </summary>
/// <remarks>
/// No further state-mutating entries are valid after this variant is reached.
/// The <see cref="Value"/> property carries the domain state at deactivation time,
/// preserved for audit and historical resolution queries. The replayer does not
/// enforce the terminal nature of this state — the apply delegate is responsible
/// for returning an error if further mutating entries arrive after deactivation.
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <param name="Value">The domain state at the time of deactivation.</param>
public sealed record DeactivatedLogState<TState>(TState Value): LogState<TState>;