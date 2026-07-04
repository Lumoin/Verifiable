using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// End-to-end tests for the W3C DID Resolution HTTP(S) binding driven over a real loopback socket. A
/// <see cref="DidResolutionHttpApplication"/> serves <c>GET /1.0/identifiers/{did-or-did-url}</c> backed
/// by a composed <see cref="DidResolver"/>; did:webvh is backed by a faked in-memory transport that
/// serves the minted <c>did.jsonl</c> / <c>whois.vp</c> (so only the OUTER identifiers request crosses
/// the socket, no SSRF relaxation needed), and did:key resolves with no network at all. Each test asserts
/// the HTTP status, the <c>Content-Type</c>, and the parsed response body against the spec's
/// content-negotiation and error-to-status rules.
/// </summary>
/// <remarks>
/// TLS is the deployment transport's responsibility (the spec's "All HTTPS bindings MUST use TLS" is a
/// transport requirement satisfied by terminating TLS in front of the handler); the handler is
/// transport-agnostic, so this test drives it over the plain http loopback socket — the repo convention
/// for real-socket binding tests.
/// </remarks>
[TestClass]
internal sealed class DidResolutionHttpBindingTests
{
    private const string Domain = "example.com";
    private const string GenesisTime = "2025-01-01T00:00:00Z";
    private const string KeyDid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    private static readonly EncodeDelegate Base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));
    private static readonly DecodeDelegate Base58Decoder = DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase));

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);


    public TestContext TestContext { get; set; } = null!;


    /// <summary>A: <c>application/did-resolution</c> returns the full resolution-result envelope.</summary>
    [TestMethod]
    public async Task WebVhResolutionResultEnvelopeIsReturned()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(LogRoutes(log))).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, log.Did, WellKnownDidResolutionMediaTypes.DidResolution).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(WellKnownDidResolutionMediaTypes.DidResolution, response.Content.Headers.ContentType?.MediaType);

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement root = body.RootElement;

        Assert.AreEqual(log.Did, root.GetProperty("didDocument").GetProperty("id").GetString(),
            "The envelope's didDocument.id MUST equal the resolved DID.");
        Assert.IsTrue(root.GetProperty("didDocumentMetadata").TryGetProperty("versionId", out _),
            "The didDocumentMetadata MUST carry the versionId.");
        Assert.AreEqual(JsonValueKind.Object, root.GetProperty("didResolutionMetadata").ValueKind,
            "The envelope MUST carry didResolutionMetadata.");
    }


    /// <summary>B: a bare <c>application/did</c> accept returns ONLY the DID document.</summary>
    [TestMethod]
    public async Task WebVhBareAcceptReturnsOnlyDocument()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(LogRoutes(log))).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(host, log.Did, "application/did").ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(WellKnownDidResolutionMediaTypes.DidJson, response.Content.Headers.ContentType?.MediaType);

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement root = body.RootElement;

        Assert.AreEqual(log.Did, root.GetProperty("id").GetString(),
            "The bare-accept body MUST be the DID document itself (with an id).");
        Assert.IsFalse(root.TryGetProperty("didResolutionMetadata", out _),
            "The bare-accept body MUST NOT be wrapped in a resolution-result envelope.");
        Assert.IsFalse(root.TryGetProperty("didDocument", out _),
            "The bare-accept body IS the document, so it MUST NOT carry a nested didDocument wrapper key.");
        Assert.IsFalse(root.TryGetProperty("didDocumentMetadata", out _),
            "The bare-accept body MUST NOT carry the didDocumentMetadata wrapper key.");
        Assert.IsTrue(root.TryGetProperty("service", out _),
            "The bare-accept body MUST be a real DID document carrying the resolver's implicit #files/#whois services.");
    }


    /// <summary>
    /// The Accept header q-value is honored: excluding the envelope with q=0 while accepting the document selects
    /// the DID document, even though the envelope is the default preference (RFC 9110 content negotiation).
    /// </summary>
    [TestMethod]
    public async Task WebVhAcceptQZeroExcludesEnvelope()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(LogRoutes(log))).ConfigureAwait(false);

        //The envelope is explicitly excluded (q=0); the document type is accepted, so the document is served.
        using HttpResponseMessage response = await GetWithRawAcceptAsync(
            host, log.Did, "application/did-resolution;q=0, application/did+json").ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(WellKnownDidResolutionMediaTypes.DidJson, response.Content.Headers.ContentType?.MediaType);

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        Assert.AreEqual(log.Did, body.RootElement.GetProperty("id").GetString(),
            "A q=0 exclusion of the envelope MUST select the DID document.");
        Assert.IsFalse(body.RootElement.TryGetProperty("didResolutionMetadata", out _),
            "The q=0-excluded envelope MUST NOT be returned.");
    }


    /// <summary>
    /// An Accept header that no offered representation satisfies returns 406 Not Acceptable (RFC 9110 content
    /// negotiation).
    /// </summary>
    [TestMethod]
    public async Task WebVhUnsatisfiableAcceptIs406()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(LogRoutes(log))).ConfigureAwait(false);

        //Neither the resolution-result envelope nor the DID document is an image/png, so no offered
        //representation is acceptable.
        using HttpResponseMessage response = await GetWithRawAcceptAsync(host, log.Did, "image/png").ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.NotAcceptable, response.StatusCode,
            "An Accept no representation satisfies MUST be 406 Not Acceptable.");
    }


    /// <summary>C: a nonexistent did:webvh returns 404 with a NOT_FOUND error and no document.</summary>
    [TestMethod]
    public async Task WebVhNonexistentIsNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //The composed resolver knows the method but the log is served as a 404, so resolution fails NOT_FOUND.
        var routes = new Dictionary<string, (int, byte[]?, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (404, null, null)
        };

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(routes)).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, log.Did, WellKnownDidResolutionMediaTypes.DidResolution).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement root = body.RootElement;

        JsonElement notFoundMetadata = root.GetProperty("didResolutionMetadata");
        Assert.AreEqual("notFound", notFoundMetadata.GetProperty("error").GetString(),
            "A NOT_FOUND failure MUST carry the 'notFound' string error code.");
        Assert.AreEqual(DidErrorTypes.NotFound.AbsoluteUri,
            notFoundMetadata.GetProperty("problemDetails").GetProperty("type").GetString(),
            "A NOT_FOUND failure's problemDetails MUST carry the W3C NOT_FOUND error type.");

        JsonValueKind documentKind = root.TryGetProperty("didDocument", out JsonElement documentElement)
            ? documentElement.ValueKind
            : JsonValueKind.Null;
        Assert.AreEqual(JsonValueKind.Null, documentKind, "A failed resolution MUST NOT carry a document.");
    }


    /// <summary>D: <c>did:webvh/whois</c> with <c>application/did-url-dereferencing</c> returns the verified presentation.</summary>
    [TestMethod]
    public async Task WebVhWhoisDereferencingEnvelopeIsReturned()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(routes)).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, $"{log.Did}/whois", WellKnownDidResolutionMediaTypes.DidUrlDereferencing).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(WellKnownDidResolutionMediaTypes.DidUrlDereferencing, response.Content.Headers.ContentType?.MediaType);

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement root = body.RootElement;

        JsonElement contentStream = root.GetProperty("contentStream");
        Assert.IsTrue(contentStream.TryGetProperty("proof", out _),
            "The dereferenced whois content stream MUST be the verified presentation (carrying a proof).");
        Assert.IsTrue(contentStream.TryGetProperty("verifiableCredential", out _),
            "The dereferenced whois content stream MUST carry the verifiable credential about the DID.");
        Assert.AreEqual(JsonValueKind.Object, root.GetProperty("dereferencingMetadata").ValueKind,
            "The envelope MUST carry dereferencingMetadata.");
    }


    /// <summary>E: a deactivated did:webvh resolves to HTTP 410 Gone.</summary>
    [TestMethod]
    public async Task WebVhDeactivatedIsGone()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await MintDeactivatedAsync(controller).ConfigureAwait(false);

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(LogRoutes(log))).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, log.Did, WellKnownDidResolutionMediaTypes.DidResolution).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Gone, response.StatusCode,
            "A deactivated DID MUST resolve to HTTP 410 Gone.");
        Assert.AreEqual(WellKnownDidResolutionMediaTypes.DidResolution, response.Content.Headers.ContentType?.MediaType,
            "A 410 Gone MUST keep the resolution-result envelope media type.");

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement root = body.RootElement;

        Assert.IsTrue(root.GetProperty("didDocumentMetadata").GetProperty("deactivated").GetBoolean(),
            "A 410 Gone MUST carry didDocumentMetadata.deactivated == true.");

        //A resolver MUST NOT return the DIDDoc for a deactivated DID, so the 410 envelope's didDocument is the
        //spec-required JSON null (did:webvh v1.0, Deactivate: L1019).
        Assert.AreEqual(JsonValueKind.Null, root.GetProperty("didDocument").ValueKind,
            "A 410 Gone for a deactivated DID MUST write didDocument as JSON null (the DIDDoc MUST NOT be returned).");
    }


    /// <summary>F: an unsupported DID method returns HTTP 501 (METHOD_NOT_SUPPORTED).</summary>
    [TestMethod]
    public async Task UnsupportedMethodIsNotImplemented()
    {
        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(EmptyRoutes())).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, "did:example:123", WellKnownDidResolutionMediaTypes.DidResolution).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.NotImplemented, response.StatusCode,
            "An unsupported DID method MUST map to HTTP 501.");

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement methodMetadata = body.RootElement.GetProperty("didResolutionMetadata");
        Assert.AreEqual("methodNotSupported", methodMetadata.GetProperty("error").GetString(),
            "An unsupported method MUST carry the 'methodNotSupported' string error code.");
        Assert.AreEqual(DidErrorTypes.MethodNotSupported.AbsoluteUri,
            methodMetadata.GetProperty("problemDetails").GetProperty("type").GetString());
    }


    /// <summary>G: a did:key resolves with no network to a 200 resolution-result envelope.</summary>
    [TestMethod]
    public async Task DidKeyResolvesWithoutNetwork()
    {
        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(EmptyRoutes())).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, KeyDid, WellKnownDidResolutionMediaTypes.DidResolution).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(WellKnownDidResolutionMediaTypes.DidResolution, response.Content.Headers.ContentType?.MediaType);

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        Assert.AreEqual(KeyDid, body.RootElement.GetProperty("didDocument").GetProperty("id").GetString(),
            "The did:key envelope's didDocument.id MUST equal the did:key.");
    }


    /// <summary>H: a <c>/whois</c> with a tampered proof dereferences to 400 INVALID_DID through the binding.</summary>
    [TestMethod]
    public async Task WebVhWhoisWithTamperedProofIsBadRequest()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions).ConfigureAwait(false);

        //Flip the last character of the proofValue so the presentation's signature no longer verifies; the
        //dereferencer's whois verify is load-bearing through the binding, so the failure must surface as the
        //spec's INVALID_DID -> 400 mapping rather than a 200.
        string tampered = TamperProofValue(whois);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(tampered), WellKnownWebVhValues.WhoisMediaType);

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(routes)).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, $"{log.Did}/whois", WellKnownDidResolutionMediaTypes.DidUrlDereferencing).ConfigureAwait(false);

        Assert.AreNotEqual(HttpStatusCode.OK, response.StatusCode,
            "A whois.vp with a tampered proof MUST NOT dereference to 200.");
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode,
            "A tampered whois proof MUST surface as the spec's INVALID_DID -> 400 mapping.");

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement derefMetadata = body.RootElement.GetProperty("dereferencingMetadata");
        Assert.AreEqual("invalidDid", derefMetadata.GetProperty("error").GetString(),
            "A tampered whois proof MUST carry the 'invalidDid' string error code.");
        Assert.AreEqual(DidErrorTypes.InvalidDid.AbsoluteUri,
            derefMetadata.GetProperty("problemDetails").GetProperty("type").GetString(),
            "A tampered whois proof's problemDetails MUST carry the W3C INVALID_DID error type.");
    }


    /// <summary>I: a bare-accept path dereference returns the file itself, not the dereferencing-result envelope.</summary>
    [TestMethod]
    public async Task WebVhBareAcceptPathReturnsFileItself()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[]}");
        var routes = LogRoutes(log);
        routes[FilesUrl] = (200, served, "application/json");

        await using DidResolutionHttpHost host = await StartHostAsync(BuildWebVhResolver(routes)).ConfigureAwait(false);

        using HttpResponseMessage response = await GetAsync(
            host, $"{log.Did}/governance/issuers.json", "application/json").ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("application/json", response.Content.Headers.ContentType?.MediaType,
            "A bare-accept dereference MUST be labelled with the dereferenced resource's media type.");

        using JsonDocument body = await ReadJsonAsync(response).ConfigureAwait(false);
        JsonElement root = body.RootElement;

        Assert.IsTrue(root.TryGetProperty("issuers", out _),
            "The bare-accept body MUST be the dereferenced file itself.");
        Assert.IsFalse(root.TryGetProperty("contentStream", out _),
            "The bare-accept body MUST NOT be wrapped in a dereferencing-result envelope.");
        Assert.IsFalse(root.TryGetProperty("dereferencingMetadata", out _),
            "The bare-accept body MUST NOT carry the dereferencingMetadata wrapper key.");
    }


    //The absolute URL the resolver fetches the bare-domain DID's log from, and the implicit whois.vp endpoint.
    private const string WhoisUrl = "https://example.com/whois.vp";

    //The implicit #files endpoint a path DID URL dereferences against for the bare-domain DID.
    private const string FilesUrl = "https://example.com/governance/issuers.json";


    //Flips the last character of the presentation's proofValue so the signature no longer verifies, mirroring
    //WebVhDidUrlDereferencerTests.TamperProofValue.
    private static string TamperProofValue(string presentationJson)
    {
        JsonObject presentation = JsonNode.Parse(presentationJson)!.AsObject();
        JsonObject proof = (JsonObject)((JsonArray)presentation["proof"]!)[0]!;
        string proofValue = (string)proof["proofValue"]!;
        proof["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');

        return presentation.ToJsonString();
    }


    private static Dictionary<string, (int Status, byte[]? Body, string? ContentType)> LogRoutes(WebVhMintedLog log)
    {
        return new Dictionary<string, (int, byte[]?, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (200, Encoding.UTF8.GetBytes(string.Join('\n', log.Lines)), null)
        };
    }


    private static Dictionary<string, (int Status, byte[]? Body, string? ContentType)> EmptyRoutes() =>
        new(StringComparer.Ordinal);


    //Mints a two-entry log whose second entry declares deactivated:true, signed by the same controller.
    private static Task<WebVhMintedLog> MintDeactivatedAsync(WebVhController controller)
    {
        return WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], null, Deactivated: true, "2025-02-01T00:00:00Z")
        ]);
    }


    private async Task<HttpResponseMessage> GetAsync(DidResolutionHttpHost host, string didOrUrl, string accept)
    {
        Uri target = new(host.BaseAddress, WellKnownDidResolutionMediaTypes.IdentifiersBasePath + Uri.EscapeDataString(didOrUrl));
        using HttpRequestMessage request = new(HttpMethod.Get, target);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(accept));

        return await host.Client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Sends a GET with a RAW Accept header value (a full RFC 9110 media-range list with q-values), bypassing the
    //typed MediaTypeWithQualityHeaderValue so the binding's own Accept parsing is exercised.
    private async Task<HttpResponseMessage> GetWithRawAcceptAsync(DidResolutionHttpHost host, string didOrUrl, string rawAccept)
    {
        Uri target = new(host.BaseAddress, WellKnownDidResolutionMediaTypes.IdentifiersBasePath + Uri.EscapeDataString(didOrUrl));
        using HttpRequestMessage request = new(HttpMethod.Get, target);
        request.Headers.TryAddWithoutValidation("Accept", rawAccept);

        return await host.Client.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response)
    {
        string text = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonDocument.Parse(text);
    }


    //Composes a resolver wired for the standard methods (did:key with no network) plus did:webvh backed
    //by a faked in-memory transport serving the supplied routes — so only the outer identifiers GET goes
    //over the socket and the inner log/whois fetches need no SSRF-policy relaxation.
    private static DidResolver BuildWebVhResolver(Dictionary<string, (int Status, byte[]? Body, string? ContentType)> routes)
    {
        var transport = new RoutingTransport(routes);

        DidMethodResolverDelegate webVhResolver = WebVhDidResolver.Build(
            transport.Delegate,
            WebVhLogEntryJson.Parser,
            WebVhLogEntryJson.WitnessFileParser,
            WebVhLogEntryJson.DocumentIdentityReader,
            DeserializeState,
            WebVhLogEntryJson.Canonicalizer,
            Base58Encoder,
            Base58Decoder,
            BaseMemoryPool.Shared,
            TimeProvider.System);

        DidMethodDereferencerDelegate webVhDereferencer = WebVhDidUrlDereferencer.Build(
            webVhResolver,
            transport.Delegate,
            DeserializePresentation,
            JcsCanonicalizer,
            ProofValueCodecs.DecodeBase58Btc,
            SerializePresentation,
            SerializeProofOptions,
            Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared);

        return DidResolverComposition.Build(
            BaseMemoryPool.Shared,
            transport.Delegate,
            static jsonUtf8 => null,
            static jsonUtf8 => null,
            dereferencerSelector: DidMethodSelectors.FromDereferencers(
                (WellKnownDidMethodPrefixes.WebVhDidMethodPrefix, webVhDereferencer)),
            additionalMethods: (WellKnownDidMethodPrefixes.WebVhDidMethodPrefix, webVhResolver));
    }


    //The JSON layer supplies state deserialization; Verifiable.Core never parses the did.jsonl itself.
    private static DidDocument? DeserializeState(ReadOnlySpan<byte> rawEntryLine)
    {
        try
        {
            if(JsonNode.Parse(rawEntryLine) is not JsonObject entry || entry["state"] is not JsonObject state)
            {
                return null;
            }

            return JsonSerializerExtensions.Deserialize<DidDocument>(state.ToJsonString(), JsonOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    private async Task<DidResolutionHttpHost> StartHostAsync(DidResolver resolver)
    {
        var application = new DidResolutionHttpApplication(
            resolver,
            DidResolutionResultJson.CreateResultSerializer(JsonOptions),
            DidResolutionResultJson.CreateDereferencingSerializer(JsonOptions),
            DidResolutionResultJson.CreateDocumentSerializer(JsonOptions),
            DidResolutionResultJson.CreateContentStreamSerializer(JsonOptions),
            OutboundFetchPolicy.SecureDefault);

        return await DidResolutionHttpHost.StartAsync(application, TestContext.CancellationToken).ConfigureAwait(false);
    }


    //A single-hop transport returning a canned (status, body, content-type) per absolute URL; an unknown
    //URL is a 404. The body is served as the transport-owned JSON-tagged buffer the guarded fetch returns.
    private sealed class RoutingTransport
    {
        private readonly Dictionary<string, (int Status, byte[]? Body, string? ContentType)> routes;

        public RoutingTransport(Dictionary<string, (int Status, byte[]? Body, string? ContentType)> routes)
        {
            this.routes = routes;
        }

        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            if(!routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, byte[]? Body, string? ContentType) route))
            {
                route = (404, null, null);
            }

            TaggedMemory<byte> body = route.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(route.Body, BufferTags.Json);

            IReadOnlyDictionary<string, string> headers = route.ContentType is null
                ? OutboundRequest.EmptyHeaders
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Content-Type"] = route.ContentType };

            return ValueTask.FromResult(new OutboundResponse { StatusCode = route.Status, Body = body, Headers = headers });
        };
    }


    //An in-process Kestrel listener bound to the http loopback socket on an OS-assigned ephemeral port,
    //mounting the DID-resolution skin. The same bootstrap as TestHostShell.StartHttpHostAsync, kept
    //standalone here so the resolution binding test owns its lifecycle.
    private sealed class DidResolutionHttpHost: IAsyncDisposable
    {
        private readonly KestrelServer server;

        private DidResolutionHttpHost(KestrelServer server, Uri baseAddress, HttpClient client)
        {
            this.server = server;
            BaseAddress = baseAddress;
            Client = client;
        }

        public Uri BaseAddress { get; }

        public HttpClient Client { get; }

        public static async Task<DidResolutionHttpHost> StartAsync(
            DidResolutionHttpApplication application, System.Threading.CancellationToken cancellationToken)
        {
            KestrelServerOptions kestrelOptions = new();
            kestrelOptions.Listen(IPAddress.Loopback, port: 0);

            SocketTransportOptions socketOptions = new();
            SocketTransportFactory socketFactory = new(Options.Create(socketOptions), NullLoggerFactory.Instance);

            KestrelServer kestrel = new(Options.Create(kestrelOptions), socketFactory, NullLoggerFactory.Instance);
            await kestrel.StartAsync(application, cancellationToken).ConfigureAwait(false);

            var addresses = kestrel.Features.Get<global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>();
            if(addresses is null || addresses.Addresses.Count == 0)
            {
                throw new InvalidOperationException("Kestrel started but exposed no server address.");
            }

            Uri baseAddress = new(addresses.Addresses.First());
            HttpClient client = new() { BaseAddress = baseAddress };

            return new DidResolutionHttpHost(kestrel, baseAddress, client);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await server.StopAsync(System.Threading.CancellationToken.None).ConfigureAwait(false);
            server.Dispose();
        }
    }
}
