namespace Verifiable.Core.Automata;

/// <summary>
/// The outcome of a single pushdown automaton step.
/// </summary>
public enum TraceOutcome
{
    /// <summary>
    /// A transition was found and applied successfully.
    /// </summary>
    Transitioned,

    /// <summary>
    /// No transition was defined for the current configuration. The automaton halted.
    /// </summary>
    Halted,

    /// <summary>
    /// The transition delegate threw an exception. The automaton's state was not modified.
    /// The exception is available via <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}.FaultException"/>.
    /// </summary>
    Faulted
}