using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Did.Methods.Cheqd;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Cryptography;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Composes a multi-method <see cref="DidResolver"/> from the in-process method drivers — the local
/// binding of the W3C DID Resolution "Multiple Methods" resolver architecture. The dispatch core
/// (<see cref="DidResolver"/> / <see cref="DidMethodSelectors"/>) is method-agnostic; this is the one
/// place that wires the standard methods together with their cross-cutting seams (memory pool, hash
/// function, the SSRF-guarded transport, and the document deserializers supplied by the JSON layer).
/// </summary>
/// <remarks>
/// <para>
/// The composition is the analogue of an application host wiring its dependency graph: a deployment (or
/// a test harness) supplies the concrete delegates and gets back a resolver that dispatches across
/// <c>did:key</c>, <c>did:web</c>, <c>did:cheqd</c> and <c>did:peer</c>. Additional methods are appended
/// through <paramref name="additionalMethods"/> rather than by editing this type, so new methods
/// (for example <c>did:webvh</c> or <c>did:ebsi</c>) register without touching the standard set.
/// </para>
/// </remarks>
public static class DidResolverComposition
{
    /// <summary>
    /// Builds a <see cref="DidResolver"/> wired for the standard methods plus any
    /// <paramref name="additionalMethods"/>.
    /// </summary>
    /// <param name="pool">The memory pool the key-decoding methods (<c>did:key</c>, <c>did:peer</c>) allocate from.</param>
    /// <param name="webTransport">The single-hop transport the guarded fetch drives for <c>did:web</c>.</param>
    /// <param name="webDocumentDeserializer">Parses a fetched <c>did:web</c> <c>did.json</c> into a DID document.</param>
    /// <param name="peerDocumentDeserializer">Parses an embedded <c>did:peer</c> numalgo-4 DID document.</param>
    /// <param name="dereferencerSelector">
    /// An optional selector of method-specific DID URL dereferencers (built with
    /// <see cref="DidMethodSelectors.FromDereferencers"/>) — the extension point for methods such as
    /// <c>did:webvh</c> that dereference a DID URL path themselves. When <see langword="null"/>, all
    /// dereferencing falls back to resolution then DID-Core service/fragment matching.
    /// </param>
    /// <param name="additionalMethods">
    /// Extra <c>(prefix, resolver)</c> registrations appended to the standard set — the extension point
    /// for methods not wired here. A later registration for an already-registered prefix overrides it.
    /// </param>
    /// <returns>A <see cref="DidResolver"/> dispatching across the registered methods.</returns>
    /// <remarks>
    /// The <c>did:peer</c> numalgo-4 SHA-256 integrity hash is taken from the registered
    /// <see cref="ComputeDigestDelegate"/>. To control that digest per resolver, compose
    /// <see cref="PeerDidResolver.Build(MemoryPool{byte}, PeerDidDocumentDeserializer, ComputeDigestDelegate)"/>
    /// explicitly and pass it through <paramref name="additionalMethods"/> (a later registration overrides the
    /// default <c>did:peer</c> one).
    /// </remarks>
    public static DidResolver Build(
        MemoryPool<byte> pool,
        OutboundTransportDelegate webTransport,
        WebDidDocumentDeserializer webDocumentDeserializer,
        PeerDidDocumentDeserializer peerDocumentDeserializer,
        SelectMethodDereferencerDelegate? dereferencerSelector = null,
        params (string Prefix, DidMethodResolverDelegate Resolver)[] additionalMethods)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(webTransport);
        ArgumentNullException.ThrowIfNull(webDocumentDeserializer);
        ArgumentNullException.ThrowIfNull(peerDocumentDeserializer);
        ArgumentNullException.ThrowIfNull(additionalMethods);

        var registrations = new List<(string Prefix, DidMethodResolverDelegate Resolver)>(4 + additionalMethods.Length)
        {
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(pool)),
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, WebDidResolver.BuildResolving(webTransport, webDocumentDeserializer)),
            (WellKnownDidMethodPrefixes.CheqdDidMethodPrefix, CheqdDidResolver.ResolveAsync),
            (WellKnownDidMethodPrefixes.PeerDidMethodPrefix, PeerDidResolver.Build(pool, peerDocumentDeserializer))
        };
        registrations.AddRange(additionalMethods);

        return new DidResolver(DidMethodSelectors.FromResolvers([.. registrations]), dereferencerSelector);
    }
}
