namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Stack alphabet for the Wallet-side OID4VP presentation flow PDA.
/// </summary>
/// <remarks>
/// The Wallet flow is linear — no sub-flows are pushed onto the stack — so only
/// the sentinel bottom-of-stack symbol is needed. The symbol is kept as a dedicated
/// type rather than reusing the Verifier's <c>Oid4VpStackSymbol</c> so that the two
/// PDAs remain independently composable.
/// </remarks>
public enum WalletFlowStackSymbol
{
    /// <summary>Bottom-of-stack sentinel pushed at PDA construction.</summary>
    Base
}
