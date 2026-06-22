using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebDidResolver.BuildResolving"/> — the <c>did:web</c> resolver that fetches the
/// <c>did.json</c> through the guarded <see cref="OutboundFetch"/> chokepoint and parses it into a
/// <see cref="DidDocument"/>. The single-hop transport is faked (the established pattern for outbound-fetch
/// consumers), so resolution, the document-id binding, the SSRF policy gate, and the error mapping are
/// exercised deterministically without a live network.
/// </summary>
[TestClass]
internal sealed class WebDidResolverResolvingTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string AliceDid = "did:web:example.com:alice";
    private const string AliceDocumentUrl = "https://example.com/alice/did.json";


    /// <summary>A did:web whose did.json is served and declares the requested DID resolves to that document.</summary>
    [TestMethod]
    public async Task ResolvesServedDocumentToDocumentResult()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJson(AliceDid))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:web MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.IsNotNull(result.Document);
        Assert.AreEqual(AliceDid, result.Document!.Id?.ToString());
    }


    /// <summary>A document served at the did:web location but declaring a different subject is rejected.</summary>
    [TestMethod]
    public async Task RejectsDocumentWhoseIdDoesNotMatchTheDid()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJson("did:web:example.com:eve"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
    }


    /// <summary>Malformed JSON at the did:web location is an invalid DID document.</summary>
    [TestMethod]
    public async Task RejectsMalformedDocument()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, "{ this is not a valid DID document")
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
    }


    /// <summary>A non-200 response at the did:web location is a not-found.</summary>
    [TestMethod]
    public async Task ReportsNotFoundForNon200()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (404, null)
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A did:web whose host is an IP literal is rejected at the method layer as an invalid DID — the
    /// did:web spec forbids an IP-address host — before any policy evaluation or network call, so the
    /// transport is never contacted. This is a stronger refusal than the downstream SSRF policy, which
    /// only classifies loopback/private ranges.
    /// </summary>
    [TestMethod]
    public async Task LoopbackTargetIsRejectedAsInvalidDidAndNotContacted()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:web:127.0.0.1", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "An IP-literal did:web MUST never reach the transport.");
    }


    /// <summary>A public IP-address host is rejected as an invalid DID just as a loopback literal is.</summary>
    [TestMethod]
    public async Task PublicIpAddressHostIsRejectedAsInvalidDid()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:web:8.8.8.8", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "A public IP-literal did:web MUST never reach the transport.");
    }


    /// <summary>An IPv6-literal host (bracketed, port colon percent-encoded) is rejected as an invalid DID.</summary>
    [TestMethod]
    public async Task Ipv6LiteralHostIsRejectedAsInvalidDid()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal));

        //A bracketed IPv6 literal with its port colon percent-encoded: %5B[::1]%5D%3A3000.
        DidResolutionResult result = await Resolve("did:web:%5B%3A%3A1%5D%3A3000", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "An IPv6-literal did:web MUST never reach the transport.");
    }


    /// <summary>
    /// A path segment that percent-encodes a path separator (<c>%2F</c>) is rejected: the segment-to-path
    /// mapping happens on the undecoded segments, so an encoded slash cannot forge an extra path component.
    /// </summary>
    [TestMethod]
    public async Task EncodedSlashInSegmentIsRejected()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:web:example.com:path%2Fto", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "An encoded path separator MUST be rejected before any fetch.");
    }


    /// <summary>
    /// A resolved did:web document whose verification method id names a DIFFERENT DID is rejected as an
    /// invalid DID document — the key-confusion mitigation requiring embedded ids to resolve under the DID.
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWhoseVerificationMethodIdNamesAnotherDid()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithForeignVerificationMethod(AliceDid, "did:web:eve.example.com"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A resolved did:web document whose verification method id names a FOREIGN DID but whose controller
    /// resolves UNDER the requested DID is still rejected. Here the controller equals the requested DID, so the
    /// controller branch is satisfied and ONLY the id-absoluteness branch can reject the document — isolating it
    /// from the combined-foreign fixture (where a foreign controller alone would already fail).
    /// </summary>
    [TestMethod]
    public async Task RejectsDocumentWhoseVerificationMethodIdIsForeignButControllerIsLocal()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithForeignIdLocalController(AliceDid, "did:web:eve.example.com"))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDidDocument, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A resolved did:web document with NO <c>@context</c> resolves successfully: the did:web spec makes
    /// <c>@context</c> OPTIONAL — an absent context is processed via the plain-JSON rules of DID Core §6.2.2,
    /// not rejected — and the result carries the <c>application/did+json</c> (non-JSON-LD) media type.
    /// </summary>
    [TestMethod]
    public async Task DocumentWithoutContextResolves()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJsonWithoutContext(AliceDid))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A context-less did:web document MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(AliceDid, result.Document!.Id?.ToString());
        Assert.AreEqual("application/did+json", result.ResolutionMetadata.ContentType,
            "A document without @context is the plain-JSON representation and MUST report application/did+json.");
    }


    /// <summary>
    /// A resolved did:web document that DOES carry an <c>@context</c> is the JSON-LD representation and reports
    /// the <c>application/did+ld+json</c> media type (the conditional counterpart to
    /// <see cref="DocumentWithoutContextResolves"/>).
    /// </summary>
    [TestMethod]
    public async Task ResolvedDocumentCarriesJsonLdContentType()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [AliceDocumentUrl] = (200, DidDocumentJson(AliceDid))
        });

        DidResolutionResult result = await Resolve(AliceDid, transport).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful);
        Assert.AreEqual("application/did+ld+json", result.ResolutionMetadata.ContentType);
    }


    /// <summary>An identifier that is not a did:web is rejected as an invalid DID without any fetch.</summary>
    [TestMethod]
    public async Task RejectsNonWebDid()
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal));

        DidResolutionResult result = await Resolve("did:key:z6MkExample", transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsEmpty(transport.Calls, "A non-did:web identifier MUST never reach the transport.");
    }


    //Runs the resolving delegate against the faked transport under the secure-default policy.
    private async Task<DidResolutionResult> Resolve(string did, RoutingTransport transport)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidMethodResolverDelegate resolver = WebDidResolver.BuildResolving(transport.Delegate, DeserializeDocument);

        return await resolver(did, DidResolutionOptions.Empty, context, TestContext.CancellationToken).ConfigureAwait(false);
    }


    //The JSON layer supplies document deserialization; Verifiable.Core never parses the did.json itself.
    private static DidDocument? DeserializeDocument(ReadOnlySpan<byte> jsonUtf8)
    {
        try
        {
            return JsonSerializerExtensions.Deserialize<DidDocument>(Encoding.UTF8.GetString(jsonUtf8), TestSetup.DefaultSerializationOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    //Serializes a minimal did:web document with the given subject id, guaranteeing it round-trips through
    //the same serializer the resolver's deserializer uses. The DID v1 @context is included because a resolved
    //did:web document is a JSON-LD representation the resolver requires to carry it.
    private static string DidDocumentJson(string did)
    {
        var document = new DidDocument
        {
            Context = new Verifiable.Core.Model.Common.Context
            {
                Contexts = [Verifiable.Core.Model.Common.Context.DidCore10]
            },
            Id = new GenericDidMethod(did)
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    //Serializes a did:web document whose subject is the requested DID but whose verification method id points
    //at a DIFFERENT DID — the key-confusion shape the absoluteness check rejects.
    private static string DidDocumentJsonWithForeignVerificationMethod(string did, string foreignDid)
    {
        var document = new DidDocument
        {
            Context = new Verifiable.Core.Model.Common.Context
            {
                Contexts = [Verifiable.Core.Model.Common.Context.DidCore10, Verifiable.Core.Model.Common.Context.Multikey10]
            },
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{foreignDid}#key-1",
                    Type = "Multikey",
                    Controller = foreignDid,
                    KeyFormat = new PublicKeyMultibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                }
            ]
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    //Serializes a did:web document whose subject AND verification-method controller are the requested DID, but
    //whose verification method id names a DIFFERENT (foreign) DID. The controller check passes (controller ==
    //did), so only the id-absoluteness branch can reject this — isolating that branch from the controller one.
    private static string DidDocumentJsonWithForeignIdLocalController(string did, string foreignDid)
    {
        var document = new DidDocument
        {
            Context = new Verifiable.Core.Model.Common.Context
            {
                Contexts = [Verifiable.Core.Model.Common.Context.DidCore10, Verifiable.Core.Model.Common.Context.Multikey10]
            },
            Id = new GenericDidMethod(did),
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = $"{foreignDid}#key-1",
                    Type = "Multikey",
                    Controller = did,
                    KeyFormat = new PublicKeyMultibase("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                }
            ]
        };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    //Serializes a did:web document that omits @context entirely — the did:web plain-JSON representation, which
    //resolves successfully (the spec makes @context optional) and reports the application/did+json media type.
    private static string DidDocumentJsonWithoutContext(string did)
    {
        var document = new DidDocument { Id = new GenericDidMethod(did) };

        return JsonSerializerExtensions.Serialize(document, TestSetup.DefaultSerializationOptions);
    }


    //A single-hop transport returning a canned (status, body) per absolute URL; an unknown URL is a 404.
    //Bodies are carried as TaggedMemory<byte>, mirroring the production OutboundResponse shape.
    private sealed class RoutingTransport
    {
        private readonly Dictionary<string, (int Status, string? Body)> routes;


        public RoutingTransport(Dictionary<string, (int Status, string? Body)> routes)
        {
            this.routes = routes;
        }


        public List<OutboundRequest> Calls { get; } = [];


        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            Calls.Add(request);

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
}
