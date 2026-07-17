using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// A shared harness that builds the <see cref="WebPlusDidResolver"/> under test wired with the JSON-layer seams
/// and an independent BLAKE3 oracle, and serves a <c>did-documents.jsonl</c> body over a faked transport. Used by
/// both the resolving tests and the minter round-trip/negative tests so the resolver wiring lives in one place.
/// </summary>
internal static class WebPlusTestResolver
{
    /// <summary>
    /// Deserializes a resolved microledger line into a full <see cref="DidDocument"/> through the lenient
    /// method-polymorphic converter; <c>Verifiable.Core</c> never parses the line itself.
    /// </summary>
    /// <param name="jcsDocument">The JCS bytes of the resolved DID document.</param>
    /// <returns>The deserialized document, or <see langword="null"/> when the bytes are malformed.</returns>
    public static DidDocument? DeserializeDocument(ReadOnlySpan<byte> jcsDocument)
    {
        try
        {
            return JsonSerializerExtensions.Deserialize<DidDocument>(Encoding.UTF8.GetString(jcsDocument), TestSetup.DefaultSerializationOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    /// <summary>Builds the did:webplus resolver delegate wired with the JSON-layer seams and the BLAKE3 oracle.</summary>
    /// <param name="transport">The transport the guarded fetch drives.</param>
    /// <returns>The resolver delegate under test.</returns>
    public static DidMethodResolverDelegate Build(OutboundTransportDelegate transport)
    {
        //The registry-backed BLAKE3-default overload: the registered digest (the TestSetup dispatcher routes a
        //BLAKE3 tag to the BouncyCastle backend) verifies each self-hash under did:webplus's default algorithm.
        return WebPlusDidResolver.Build(
            transport,
            WebPlusDidDocumentJson.Parser,
            WebPlusUpdateRulesJson.Parser,
            WebPlusDidDocumentJson.ProofExtractor,
            WebPlusDidDocumentJson.Canonicalizer,
            DeserializeDocument,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base58Decoder,
            BaseMemoryPool.Shared,
            new FakeTimeProvider(TestClock.CanonicalEpoch));
    }


    /// <summary>Resolves a DID over a transport serving the given microledger body at the DID's resolution URL.</summary>
    /// <param name="did">The DID to resolve.</param>
    /// <param name="microledger">The <c>did-documents.jsonl</c> body to serve.</param>
    /// <param name="options">The resolution options, or <see langword="null"/> for the latest version.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The resolution result.</returns>
    public static Task<DidResolutionResult> ResolveAsync(string did, string microledger, DidResolutionOptions? options, CancellationToken cancellationToken)
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebPlusDidResolver.Resolve(did)] = (200, microledger)
        });

        return ResolveAsync(did, transport, options, cancellationToken);
    }


    /// <summary>Resolves a DID over the given transport.</summary>
    /// <param name="did">The DID to resolve.</param>
    /// <param name="transport">The transport serving the microledger.</param>
    /// <param name="options">The resolution options, or <see langword="null"/> for the latest version.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The resolution result.</returns>
    public static async Task<DidResolutionResult> ResolveAsync(string did, RoutingTransport transport, DidResolutionOptions? options, CancellationToken cancellationToken)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidMethodResolverDelegate resolver = Build(transport.Delegate);

        return await resolver(did, options ?? DidResolutionOptions.Empty, context, cancellationToken).ConfigureAwait(false);
    }
}


/// <summary>A single-hop transport returning a canned (status, body) per absolute URL; an unknown URL is a 404.</summary>
internal sealed class RoutingTransport
{
    /// <summary>The per-URL canned responses.</summary>
    private readonly Dictionary<string, (int Status, string? Body)> routes;


    /// <summary>Creates a routing transport over the given per-URL responses.</summary>
    /// <param name="routes">The per-URL canned (status, body) responses.</param>
    public RoutingTransport(Dictionary<string, (int Status, string? Body)> routes)
    {
        this.routes = routes;
    }


    /// <summary>The transport delegate dispatching each request by its absolute URL.</summary>
    public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
    {
        if(!routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, string? Body) route))
        {
            route = (404, null);
        }

        TaggedMemory<byte> body = route.Body is null
            ? TaggedMemory<byte>.Empty
            : new TaggedMemory<byte>(Encoding.UTF8.GetBytes(route.Body), BufferTags.Json);

        return ValueTask.FromResult(new OutboundResponse { StatusCode = route.Status, Body = body });
    };
}
