using Verifiable.Core;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The one reading of the capabilities a request is served under, for the builders and handlers of this library
/// that act on a capability: the set the chain build resolved for the registration the request is judged by and
/// held to the bound, which the context carries as <c>ResolvedCapabilities</c> of
/// <see cref="Verifiable.Server.ExchangeContextServerExtensions"/>.
/// </summary>
/// <remarks>
/// <para>
/// A reader that acts on a capability reads this set rather than the registration's own
/// <see cref="ClientRecord.AllowedCapabilities"/>: the capability resolution may withhold a capability the
/// registration allows, and a materialized registration may allow a capability the bound withholds, and in both
/// cases the request is answered as for a registration that never held it. The non-expansion of a materialized
/// registration is this library's rule:
/// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
/// </para>
/// <para>
/// The chain build writes the set before it calls any endpoint builder, so a builder and a handler read the same
/// set the chain's capability filter applies. A context that carries no set, such as one handed to a builder outside
/// a chain build, allows no capability: the reading fails closed.
/// </para>
/// </remarks>
internal static class ExchangeContextBoundedCapabilityExtensions
{
    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets whether the capabilities the request is served under hold <paramref name="capability"/>.
        /// </summary>
        /// <param name="capability">The capability the reader acts on.</param>
        /// <returns>
        /// <see langword="true"/> when the context carries the resolved set and the set holds
        /// <paramref name="capability"/>; <see langword="false"/> when it does not hold it or no set is carried.
        /// </returns>
        internal bool IsBoundedCapabilityAllowed(CapabilityIdentifier capability) =>
            context.ResolvedCapabilities is { } resolved && resolved.Contains(capability);
    }
}
