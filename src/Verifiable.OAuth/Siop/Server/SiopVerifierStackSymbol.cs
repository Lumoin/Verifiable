namespace Verifiable.OAuth.Siop.Server;

/// <summary>
/// Stack alphabet for the server-side SIOPv2 Relying Party flow PDA.
/// </summary>
/// <remarks>
/// The SIOP RP flow is linear — request preparation then response verification, with no
/// sub-flows pushed onto the stack — so only the sentinel bottom-of-stack symbol is needed.
/// </remarks>
public enum SiopVerifierStackSymbol
{
    /// <summary>Bottom-of-stack sentinel pushed at PDA construction.</summary>
    Base
}
