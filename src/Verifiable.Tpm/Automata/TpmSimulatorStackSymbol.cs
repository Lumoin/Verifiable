namespace Verifiable.Tpm.Automata;

/// <summary>
/// The stack alphabet of the TPM simulator's pushdown automaton.
/// </summary>
/// <remarks>
/// The lifecycle skeleton uses only the bottom sentinel, and no other symbol has joined it: sequence
/// contexts, sessions, and loaded objects are all bounded, handle-keyed tables rather than a LIFO
/// discipline, so they live as dictionary fields on <see cref="TpmSimulatorState"/> — for example
/// <see cref="TpmSimulatorState.SequenceObjects"/> — rather than as stack symbols. A TPM application may
/// open several sequences concurrently (multiple <c>TPM2_SignSequenceStart()</c> calls, each returning
/// its own handle) and complete or flush them in any order; nothing in TPM 2.0 Library Part 3's sequence
/// clauses imposes a "last one started must be the first one completed" nesting rule that a stack symbol
/// would model. A future bounded, genuinely nested scope would be the one candidate for a second symbol.
/// </remarks>
public enum TpmSimulatorStackSymbol
{
    /// <summary>The bottom-of-stack sentinel representing the TPM lifecycle scope. Never popped.</summary>
    Lifecycle
}
