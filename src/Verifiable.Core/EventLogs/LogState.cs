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
/// null checks or suppression operators.
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
/// Any other apply delegate receiving this variant indicates a malformed log.
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
public sealed record EmptyLogState<TState>: LogState<TState>;

/// <summary>
/// The log state after the genesis entry has been applied and before deactivation.
/// </summary>
/// <remarks>
/// Update and heartbeat delegates receive this variant. The <see cref="Value"/>
/// property carries the current domain state.
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <param name="Value">The current domain state.</param>
public sealed record ActiveLogState<TState>(TState Value): LogState<TState>;

/// <summary>
/// The terminal log state after a deactivation entry has been applied.
/// </summary>
/// <remarks>
/// No further state-mutating entries are valid after this variant is reached.
/// The <see cref="Value"/> property carries the domain state at deactivation time.
/// </remarks>
/// <typeparam name="TState">The domain state type.</typeparam>
/// <param name="Value">The domain state at the time of deactivation.</param>
public sealed record DeactivatedLogState<TState>(TState Value): LogState<TState>;