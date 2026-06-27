namespace Verifiable.Tpm.Automata;

/// <summary>
/// The stack alphabet of the TPM simulator's pushdown automaton.
/// </summary>
/// <remarks>
/// The lifecycle skeleton uses only the bottom sentinel. Bounded nested scopes — for example a hash
/// sequence pushed by <c>TPM2_HashSequenceStart()</c> and popped by <c>TPM2_SequenceComplete()</c> —
/// are added to this alphabet when those commands are modelled. Sessions and loaded objects are
/// bounded handle tables rather than a LIFO discipline, so they live as fields on the operational
/// state rather than as stack symbols.
/// </remarks>
public enum TpmSimulatorStackSymbol
{
    /// <summary>The bottom-of-stack sentinel representing the TPM lifecycle scope. Never popped.</summary>
    Lifecycle
}
