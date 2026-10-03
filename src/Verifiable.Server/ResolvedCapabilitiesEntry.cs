using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// The value the library stores under the context entry named <c>server.resolvedCapabilities</c>: the set of
/// capabilities a request is served under, held inside a type only this library creates, together with the
/// <see cref="ExchangeContext"/> it was written for.
/// </summary>
/// <remarks>
/// The request context is a bag of entries keyed by name, and <c>server.resolvedCapabilities</c> is a string any
/// code that holds the context can write under. <c>ResolvedCapabilities</c> of
/// <see cref="ExchangeContextServerExtensions"/> answers a set only when the value under that name is an entry of
/// this type whose <see cref="Context"/> is the very context read, compared by reference, since
/// <see cref="ExchangeContext"/> compares by value: any other value, and an entry carried from another request's
/// context, reads as no set, and a reader of no set allows no capability. The entry overrides neither
/// <see cref="object.Equals(object?)"/> nor <see cref="object.GetHashCode"/>.
/// </remarks>
internal sealed class ResolvedCapabilitiesEntry
{
    /// <summary>Creates the entry that carries <paramref name="capabilities"/> for <paramref name="context"/>.</summary>
    /// <param name="context">The request context the entry is written to.</param>
    /// <param name="capabilities">The set the request is served under.</param>
    internal ResolvedCapabilitiesEntry(ExchangeContext context, IReadOnlySet<CapabilityIdentifier> capabilities)
    {
        Context = context;
        Capabilities = capabilities;
    }

    /// <summary>The request context the entry was written to, the one context it answers a set for.</summary>
    internal ExchangeContext Context { get; }

    /// <summary>The set the request is served under.</summary>
    internal IReadOnlySet<CapabilityIdentifier> Capabilities { get; }
}
