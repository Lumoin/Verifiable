using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Automata;

/// <summary>
/// The transition function of a pushdown automaton. Given the current state,
/// an input, and the top of the stack, produces the next state and a stack action.
/// </summary>
/// <remarks>
/// <para>
/// This is the core extensibility point. Callers provide transition logic as a delegate.
/// The PDA calls this on each step and applies the result.
/// </para>
/// <para>
/// <strong>Pure mode (recommended):</strong> The delegate performs no I/O, reads no time,
/// uses no randomness. All I/O results enter as inputs. This yields deterministic replay:
/// replaying the same input log from the same initial configuration produces the same
/// trace and final state.
/// </para>
/// <para>
/// <strong>Effectful mode:</strong> The delegate may await I/O (remote HSM, ledger query,
/// HTTP fetch). It must respect <paramref name="cancellationToken"/> and must not retry
/// indefinitely. If the delegate throws, the PDA shields the exception, does not apply
/// the transition, and transitions to a faulted state.
/// </para>
/// <para>
/// Returning <see langword="null"/> signals that no transition is defined for this
/// combination of state, input, and stack top — the PDA halts.
/// </para>
/// </remarks>
/// <typeparam name="TState">The state type.</typeparam>
/// <typeparam name="TInput">The input type.</typeparam>
/// <typeparam name="TStackSymbol">The stack symbol type.</typeparam>
/// <param name="currentState">The current state of the automaton.</param>
/// <param name="input">The input being processed.</param>
/// <param name="stackTop">
/// The symbol currently on top of the stack. Never <see langword="default"/> because the
/// sentinel symbol is always present.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// A <see cref="TransitionResult{TState, TStackSymbol}"/> describing the next state and stack action,
/// or <see langword="null"/> if no transition is defined (the automaton halts).
/// </returns>
public delegate ValueTask<TransitionResult<TState, TStackSymbol>?> TransitionDelegate<TState, TInput, TStackSymbol>(
    TState currentState,
    TInput input,
    TStackSymbol stackTop,
    CancellationToken cancellationToken);
