namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Stack alphabet for the server-side OID4VP Verifier flow PDA.
/// </summary>
/// <remarks>
/// The Verifier server flow is linear — no sub-flows are pushed onto the stack —
/// so only the sentinel bottom-of-stack symbol is needed.
/// </remarks>
public enum Oid4VpVerifierStackSymbol
{
    /// <summary>Bottom-of-stack sentinel pushed at PDA construction.</summary>
    Base
}
