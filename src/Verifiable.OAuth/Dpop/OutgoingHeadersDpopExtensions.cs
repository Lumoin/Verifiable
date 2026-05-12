using System.Diagnostics.CodeAnalysis;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// Composes DPoP-bearing values onto <see cref="OutgoingHeaders"/>.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class OutgoingHeadersDpopExtensions
{
    extension(OutgoingHeaders headers)
    {
        /// <summary>
        /// Returns a new <see cref="OutgoingHeaders"/> with the
        /// <c>DPoP</c> header set to <paramref name="proof"/>. Used on
        /// outbound token-endpoint requests when the client is establishing
        /// a DPoP-bound access token.
        /// </summary>
        public OutgoingHeaders WithDpop(string proof) =>
            headers.With(WellKnownHttpHeaderNames.DPoP, proof);
    }
}
