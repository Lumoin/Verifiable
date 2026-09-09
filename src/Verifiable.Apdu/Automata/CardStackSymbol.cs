namespace Verifiable.Apdu.Automata;

/// <summary>
/// The stack alphabet of the eMRTD card simulator's pushdown automaton.
/// </summary>
/// <remarks>
/// Only the bottom sentinel is used. A bounded nested scope — for example the chained
/// GENERAL AUTHENTICATE rounds of PACE, or a command-chaining sequence — is added to this alphabet when
/// those flows are modelled. The selected file and (later) the Secure Messaging session are single-valued
/// state rather than a LIFO discipline, so they live as fields on <see cref="CardSimulatorState"/> rather
/// than as stack symbols.
/// </remarks>
public enum CardStackSymbol
{
    /// <summary>The bottom-of-stack sentinel representing the card application scope. Never popped.</summary>
    Application
}
