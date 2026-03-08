using System.Diagnostics;

namespace Verifiable.Core.Automata;

/// <summary>
/// The result of a pushdown automaton transition: the next state,
/// what to do with the stack, and an optional label for tracing.
/// </summary>
/// <typeparam name="TState">The state type.</typeparam>
/// <typeparam name="TStackSymbol">The stack symbol type.</typeparam>
/// <param name="NextState">The state to transition to.</param>
/// <param name="StackAction">The stack operation to perform.</param>
/// <param name="Label">
/// An optional human-readable label for this transition (e.g., <c>"ParseDid"</c>,
/// <c>"FetchLog"</c>, <c>"AwaitUserConsent"</c>). Recorded in the trace for
/// debugging, logging, and formal verification.
/// </param>
[DebuggerDisplay("→ {NextState} [{StackAction}] '{Label}'")]
public sealed record TransitionResult<TState, TStackSymbol>(
    TState NextState,
    StackAction<TStackSymbol> StackAction,
    string? Label = null);
