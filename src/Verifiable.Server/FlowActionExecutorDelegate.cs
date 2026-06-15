using Verifiable.Core;
using Verifiable.Foundation.Automata;

namespace Verifiable.Server;

/// <summary>
/// Drives the effectful work a flow PDA declares between pure transitions: takes the
/// <see cref="PdaAction"/> the state surfaced through <see cref="FlowState.NextAction"/>,
/// performs the effect, and returns the <see cref="FlowInput"/> that feeds the next
/// transition.
/// </summary>
/// <remarks>
/// The dispatch host owns the loop that calls this delegate after each pure transition
/// until a state declares <see cref="NullAction"/>. Each protocol family supplies its own
/// implementation — a type-keyed handler registry over its concrete action subtypes — and
/// wires it onto the host. The host itself stays free of any single family's action
/// vocabulary: it sees only <see cref="PdaAction"/> and <see cref="FlowInput"/>.
/// </remarks>
/// <param name="action">The action the current state surfaced as its next effectful step.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The input that drives the next pure PDA transition.</returns>
public delegate ValueTask<FlowInput> FlowActionExecutorDelegate(
    PdaAction action,
    ExchangeContext context,
    CancellationToken cancellationToken);
