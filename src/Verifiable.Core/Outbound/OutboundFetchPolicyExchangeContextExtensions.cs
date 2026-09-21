using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Outbound;

/// <summary>
/// Per-call accessor for the <see cref="OutboundFetchPolicy"/> on an
/// <see cref="ExchangeContext"/>. Lives in the outbound-fetch layer (over the
/// neutral context) so every consumer that dereferences a URL — OAuth,
/// federation, DID resolution and service endpoints, JSON-LD <c>@context</c> —
/// reads the same policy without dragging a transport into the core.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class OutboundFetchPolicyExchangeContextExtensions
{
    private const string OutboundFetchPolicyKey = "exchange.outboundFetchPolicy";


    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the outbound-fetch policy for this operation, or
        /// <see cref="OutboundFetchPolicy.SecureDefault"/> when none has been
        /// set — so an unconfigured operation is governed by the secure default
        /// rather than no policy at all.
        /// </summary>
        public OutboundFetchPolicy OutboundFetchPolicy =>
            context.ResolveOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        /// <summary>
        /// Gets the outbound-fetch policy this operation carries, or
        /// <paramref name="configurationDefault"/> when none has been set on the
        /// context. Lets a deployment's own configuration — a client infrastructure or wallet
        /// configuration's own <c>OutboundFetchPolicy</c> member — stand in for the library-wide
        /// <see cref="OutboundFetchPolicy.SecureDefault"/> as the fallback, while a policy set
        /// explicitly on this context — via <see cref="SetOutboundFetchPolicy"/> — still takes
        /// precedence.
        /// </summary>
        /// <param name="configurationDefault">The policy to use when this context carries none.</param>
        public OutboundFetchPolicy ResolveOutboundFetchPolicy(OutboundFetchPolicy configurationDefault) =>
            context.TryGetValue(OutboundFetchPolicyKey, out object? value)
                && value is OutboundFetchPolicy policy
                ? policy
                : configurationDefault;

        /// <summary>
        /// Sets the outbound-fetch policy for this operation. A deployment calls
        /// this to relax or tighten the default for the current call (for
        /// example to permit an internal federation endpoint, or to forbid the
        /// network entirely for <c>@context</c> resolution).
        /// </summary>
        /// <param name="policy">The policy to apply.</param>
        public void SetOutboundFetchPolicy(OutboundFetchPolicy policy)
        {
            System.ArgumentNullException.ThrowIfNull(policy);
            context[OutboundFetchPolicyKey] = policy;
        }
    }
}
