namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Stack alphabet for the W3C VCALM 1.0 §3.6 exchange-instance flow PDA.
/// </summary>
/// <remarks>
/// The exchange lifecycle this PDA models is linear — <c>pending → active → (complete | invalid)</c>
/// with no sub-flows pushed onto the stack — so only the sentinel bottom-of-stack symbol is needed.
/// A later surface that layers the §3.6.1 multi-step workflow step graph onto the exchange can extend
/// this alphabet to push and pop per-step frames.
/// </remarks>
public enum VcalmExchangeStackSymbol
{
    /// <summary>Bottom-of-stack sentinel pushed at PDA construction.</summary>
    Base
}
