using System.Diagnostics.CodeAnalysis;
using Verifiable.Server;

namespace Verifiable.Vcalm.Exchange;

/// <summary>
/// Discoverable accessor for the W3C VCALM 1.0 library-provided <see cref="FlowKind"/> singleton, so
/// consumers write <c>FlowKind.VcalmExchange</c> rather than <c>VcalmExchangeFlowKind.Instance</c> —
/// the VCALM parallel of the OAuth family's flow-kind extension block.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class VcalmFlowKindExtensions
{
    extension(FlowKind)
    {
        /// <summary>
        /// The W3C VCALM 1.0 §3.6 exchange-instance flow. Models the exchange lifecycle the §3.6.5
        /// vcapi participation drives (§3.6.6 <c>pending → active → (complete | invalid)</c>).
        /// </summary>
        public static VcalmExchangeFlowKind VcalmExchange =>
            VcalmExchangeFlowKind.Instance;
    }
}
