namespace Verifiable.Core.Automata;

/// <summary>
/// Base type for actions produced alongside PDA state transitions.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="PdaAction"/> describes the effectful work that must be performed
/// after a pure PDA transition before the next input can be constructed. The pure
/// PDA produces the action as part of the new state — it never executes it.
/// </para>
/// <para>
/// The effectful layer reads the action from the new state, dispatches it to the
/// appropriate registered handler, and feeds the handler's result back as the next
/// input to the pure PDA.
/// </para>
/// <para>
/// Use <see cref="NullAction"/> when no effectful work is needed and the next input
/// arrives from an external source such as an HTTP request.
/// </para>
/// </remarks>
public abstract record PdaAction;
