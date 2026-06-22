using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
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
/// A REAL two-node cross-wire did:webvh flow: node A is an in-process Kestrel host that PUBLISHES a minted
/// did:webvh log (the <c>did.jsonl</c>, the <c>did-witness.json</c>, the <c>whois.vp</c> and a path file) over
/// a plain-http loopback socket, and node B is a composed <see cref="DidResolver"/> that RESOLVES the DID and
/// DEREFERENCES its <c>/whois</c> and <c>/governance/issuers.json</c> URLs over that same socket through a real
/// <see cref="HttpClient"/>. The cross-node hops are genuine socket traffic — node A's request log is asserted
/// to prove every fetch (the log, the witness file, the whois.vp, the path file) crossed the wire, so no hop is
/// secretly served by an in-memory transport.
/// </summary>
/// <remarks>
/// <para>
/// The DID's domain is the bare host <c>127.0.0.1%3A{port}</c> (a <c>%3A</c>-encoded port, no path), so the
/// did:webvh DID-to-HTTPS transform lands on <c>https://127.0.0.1:{port}/.well-known/did.jsonl</c>, the witness
/// file on <c>https://127.0.0.1:{port}/.well-known/did-witness.json</c>, the implicit whois on
/// <c>https://127.0.0.1:{port}/whois.vp</c>, and the implicit #files base on <c>https://127.0.0.1:{port}/</c>
/// (so a <c>/governance/issuers.json</c> path URL dereferences to
/// <c>https://127.0.0.1:{port}/governance/issuers.json</c>).
/// </para>
/// <para>
/// Node A listens on plain http (the repo convention for real-socket binding tests; TLS is the deployment
/// transport's responsibility). Node B's resolver computes the genuine <c>https://127.0.0.1:{port}/...</c> URL,
/// the policy on the threaded <see cref="ExchangeContext"/> gates it (loopback explicitly allowed, exactly like
/// <c>TestHostShell.LoopbackOutboundFetchPolicy</c>), and the single-hop transport rewrites only the scheme
/// (<c>https</c> → <c>http</c>) before dialing node A's socket — the same scheme-rebind the did:web cross-wire
/// resolver uses.
/// </para>
/// </remarks>
[TestClass]
internal sealed class WebVhCrossWireFlowTests
{
    private const string GenesisTime = "2025-01-01T00:00:00Z";
    private const string SecondTime = "2025-02-01T00:00:00Z";
    private const string WitnessTime = "2025-02-02T00:00:00Z";

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


    /// <summary>
    /// The full cross-wire flow: node A publishes a multi-entry, witnessed did:webvh log with a genesis
    /// authentication key; node B resolves it, dereferences <c>/whois</c> and a path file — each hop over the
    /// real socket, each proven by node A's request log.
    /// </summary>
    [TestMethod]
    public async Task ResolvesAndDereferencesDidWebVhAcrossTheWire()
    {
        await using StaticContentHttpHost nodeA = await StaticContentHttpHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        int port = nodeA.BaseAddress.Port;

        //The bare-host domain whose %3A-encoded port resolves to node A's loopback socket.
        string domain = $"127.0.0.1%3A{port}";

        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        using WebVhController witness = WebVhController.Create();

        //A multi-entry (genesis + one update) log under a k-of-1 witness rule with a genesis authentication key,
        //so the resolve forces the did-witness.json fetch and the whois.vp verifies against the resolved document.
        WebVhMintedLog log = await WebVhTestLog.MintAsync(domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Witness: WebVhWitnessSpec.Rule(1, witness), Authentication: authentication),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, Witness: WebVhWitnessSpec.Rule(1, witness), Authentication: authentication)
        ]).ConfigureAwait(false);

        //The witness rule activated by the genesis takes effect for the NEXT entry, so entry 2 (versionId 2-...)
        //is the witnessed one; approving it confirms the active rule and forces the did-witness.json socket fetch.
        string witnessFile = await WebVhTestLog.MintWitnessFileAsync(
        [
            new WebVhWitnessApproval(log.VersionIds[1], [witness], WitnessTime)
        ]).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions).ConfigureAwait(false);

        byte[] issuersFile = Encoding.UTF8.GetBytes("{\"issuers\":[\"did:webvh:issuer\"]}");

        //Publish the log artifacts at the exact transform paths a bare-domain DID resolves to.
        nodeA.Publish("/.well-known/did.jsonl", Encoding.UTF8.GetBytes(string.Join('\n', log.Lines)), "application/jsonl");
        nodeA.Publish("/.well-known/did-witness.json", Encoding.UTF8.GetBytes(witnessFile), WellKnownWebVhValues.WitnessFileMediaType);
        nodeA.Publish("/whois.vp", Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);
        nodeA.Publish("/governance/issuers.json", issuersFile, "application/json");

        using HttpClient httpClient = new();
        DidResolver composed = BuildCrossWireResolver(httpClient, nodeA.BaseAddress);

        //(a) Resolve the DID over the real socket: it MUST verify despite the active witness rule, which forces
        //the did-witness.json fetch — both fetches are asserted against node A's request log below.
        ExchangeContext resolveContext = NewLoopbackContext();
        DidResolutionResult resolution = await composed.ResolveAsync(
            log.Did, resolveContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsSuccessful, $"The did:webvh DID MUST resolve across the wire. Error: {resolution.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.Did, resolution.Document!.Id?.ToString(), "The resolved document id MUST equal the published DID.");
        Assert.AreEqual(log.VersionIds[^1], resolution.DocumentMetadata.VersionId, "The resolved versionId MUST be the latest entry.");
        Assert.IsFalse(resolution.DocumentMetadata.Deactivated, "The resolved DID MUST NOT be deactivated.");

        Assert.IsTrue(nodeA.WasRequested("/.well-known/did.jsonl"), "The DID Log MUST have been fetched over the socket.");
        Assert.IsTrue(nodeA.WasRequested("/.well-known/did-witness.json"),
            "The active witness rule MUST have forced the did-witness.json fetch over the socket.");

        //(b) Dereference <did>/whois over the real socket: the content stream MUST be the verified presentation,
        //carrying a proof and a credential whose subject is the DID.
        ExchangeContext whoisContext = NewLoopbackContext();
        DidDereferencingResult whoisResult = await composed.DereferenceAsync(
            $"{log.Did}/whois", whoisContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(whoisResult.IsSuccessful, $"The /whois DID URL MUST dereference across the wire. Error: {whoisResult.DereferencingMetadata.Error?.Type}.");
        Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(whoisResult.ContentStream,
            "A dereferenced whois MUST return the verified secured presentation.");

        DataIntegritySecuredPresentation securedPresentation = (DataIntegritySecuredPresentation)whoisResult.ContentStream!;
        Assert.IsNotNull(securedPresentation.Proof, "The verified whois presentation MUST carry a proof.");
        Assert.IsNotEmpty(securedPresentation.Proof!, "The verified whois presentation MUST carry at least one proof.");
        Assert.IsNotNull(securedPresentation.VerifiableCredential, "The whois presentation MUST carry a credential about the DID.");
        Assert.AreEqual(log.Did, securedPresentation.VerifiableCredential![0].CredentialSubject![0].Id?.ToString(),
            "The whois credential subject MUST be the resolved DID.");

        Assert.IsTrue(nodeA.WasRequested("/whois.vp"), "The whois.vp MUST have been fetched over the socket.");

        //(c) Dereference a path file over the real socket: the content bytes MUST equal the served file.
        ExchangeContext filesContext = NewLoopbackContext();
        DidDereferencingResult filesResult = await composed.DereferenceAsync(
            $"{log.Did}/governance/issuers.json", filesContext, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(filesResult.IsSuccessful, $"The path DID URL MUST dereference across the wire. Error: {filesResult.DereferencingMetadata.Error?.Type}.");

        TaggedMemory<byte> filesBody = (TaggedMemory<byte>)filesResult.ContentStream!;
        CollectionAssert.AreEqual(issuersFile, filesBody.Span.ToArray(), "The dereferenced content bytes MUST equal the served file.");

        Assert.IsTrue(nodeA.WasRequested("/governance/issuers.json"), "The path file MUST have been fetched over the socket.");

        //Every cross-node hop went over the real socket: the host saw at least the four distinct paths above.
        Assert.IsGreaterThanOrEqualTo(4, nodeA.TotalRequests, $"Node A MUST have served the cross-wire hops over the socket (saw {nodeA.TotalRequests}).");
    }


    /// <summary>
    /// A negative cross-wire case: a DID whose log node A does NOT serve (404) MUST resolve to notFound — proving
    /// the 404 over the socket maps correctly rather than being masked by an in-memory transport.
    /// </summary>
    [TestMethod]
    public async Task UnservedDidIsNotFoundAcrossTheWire()
    {
        await using StaticContentHttpHost nodeA = await StaticContentHttpHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        int port = nodeA.BaseAddress.Port;

        //Mint a valid DID at node A's host but DO NOT publish its log: every path 404s over the socket.
        string domain = $"127.0.0.1%3A{port}";
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(domain, controller, GenesisTime).ConfigureAwait(false);

        using HttpClient httpClient = new();
        DidResolver composed = BuildCrossWireResolver(httpClient, nodeA.BaseAddress);

        ExchangeContext context = NewLoopbackContext();
        DidResolutionResult resolution = await composed.ResolveAsync(
            log.Did, context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(resolution.IsSuccessful, "An unserved did:webvh DID MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.NotFound, resolution.ResolutionMetadata.Error,
            "A 404 DID Log over the socket MUST map to notFound.");

        //The 404 came from the real socket: node A saw the genuine did.jsonl fetch and answered 404.
        Assert.IsTrue(nodeA.WasRequested("/.well-known/did.jsonl"),
            "The notFound MUST have come from a real 404 over the socket, not an in-memory transport.");
    }


    /// <summary>
    /// A portability move across the wire: a Portable genesis at node A's bare host, then a move to a path
    /// location <c>127.0.0.1%3A{port}:moved</c>. A path-bearing domain has no <c>.well-known</c> segment, so the
    /// whole log is published at <c>/moved/did.jsonl</c>; node B resolves the moved DID and gets the moved id.
    /// </summary>
    [TestMethod]
    public async Task ResolvesMovedPortableDidAcrossTheWire()
    {
        await using StaticContentHttpHost nodeA = await StaticContentHttpHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        int port = nodeA.BaseAddress.Port;

        string originDomain = $"127.0.0.1%3A{port}";
        string movedDomain = $"127.0.0.1%3A{port}:moved";

        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(originDomain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Portable: true),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, MoveToDomain: movedDomain)
        ]).ConfigureAwait(false);

        //The moved DID's path-bearing domain (".../moved") transforms to https://127.0.0.1:{port}/moved/did.jsonl
        //(no .well-known for a path location), so the whole log is published there.
        string movedLogUrl = WebVhDidResolver.Resolve(log.Did);
        Assert.AreEqual($"https://127.0.0.1:{port}/moved/did.jsonl", movedLogUrl,
            "The moved DID's log URL MUST transform to the path location, not a .well-known segment.");

        nodeA.Publish("/moved/did.jsonl", Encoding.UTF8.GetBytes(string.Join('\n', log.Lines)), "application/jsonl");

        using HttpClient httpClient = new();
        DidResolver composed = BuildCrossWireResolver(httpClient, nodeA.BaseAddress);

        ExchangeContext context = NewLoopbackContext();
        DidResolutionResult resolution = await composed.ResolveAsync(
            log.Did, context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resolution.IsSuccessful, $"A portable moved did:webvh DID MUST resolve across the wire. Error: {resolution.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.Did, resolution.Document!.Id?.ToString(), "The resolved id MUST be the moved DID.");
        Assert.IsTrue(log.Did.Contains(":moved", StringComparison.Ordinal), "The resolved DID MUST reflect the moved location.");
        Assert.IsTrue(nodeA.WasRequested("/moved/did.jsonl"), "The moved DID Log MUST have been fetched over the socket.");
    }


    //A fresh ExchangeContext whose policy allows https loopback so the genuine https://127.0.0.1:{port}/... URL
    //the resolver computes is permitted, mirroring TestHostShell.LoopbackOutboundFetchPolicy: production keeps
    //SecureDefault (which would deny a loopback target before any network contact).
    private static ExchangeContext NewLoopbackContext()
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with
        {
            AllowedSchemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "http", "https" },
            BlockPrivateAndLoopback = false
        });

        return context;
    }


    //Composes node B's resolver: the did:webvh resolver + dereferencer backed by a REAL HttpClient single-hop
    //transport, wrapped to rewrite only the scheme (https -> http) so the genuine https URL the resolver computes
    //dials node A's plain-http loopback socket. The chokepoint has already evaluated the genuine https URL.
    private static DidResolver BuildCrossWireResolver(HttpClient httpClient, Uri loopbackBase)
    {
        OutboundTransportDelegate singleHop = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);

        OutboundTransportDelegate transport = async (request, context, cancellationToken) =>
        {
            UriBuilder rebased = new(request.Target) { Scheme = loopbackBase.Scheme };
            OutboundRequest rebasedRequest = request with { Target = rebased.Uri };

            return await singleHop(rebasedRequest, context, cancellationToken).ConfigureAwait(false);
        };

        DidMethodResolverDelegate webVhResolver = WebVhDidResolver.Build(
            transport,
            WebVhLogEntryJson.Parser,
            WebVhLogEntryJson.WitnessFileParser,
            WebVhLogEntryJson.DocumentIdentityReader,
            DeserializeState,
            WebVhLogEntryJson.Canonicalizer,
            SHA256.HashData,
            Base58Encoder,
            Base58Decoder,
            BaseMemoryPool.Shared,
            TimeProvider.System);

        DidMethodDereferencerDelegate webVhDereferencer = WebVhDidUrlDereferencer.Build(
            webVhResolver,
            transport,
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
            SHA256.HashData,
            transport,
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


    //An in-process Kestrel listener bound to the http loopback socket on an OS-assigned ephemeral port, serving
    //published static content by path and recording every requested path so the test can prove a hop crossed the
    //wire. This is node A — the publisher half of the cross-wire flow.
    private sealed class StaticContentHttpHost: IAsyncDisposable
    {
        private readonly KestrelServer server;

        private StaticContentHttpHost(KestrelServer server, Uri baseAddress, StaticContentApplication application)
        {
            this.server = server;
            BaseAddress = baseAddress;
            Application = application;
        }

        public Uri BaseAddress { get; }

        private StaticContentApplication Application { get; }

        public int TotalRequests => Application.TotalRequests;

        public void Publish(string path, byte[] body, string contentType) => Application.Publish(path, body, contentType);

        public bool WasRequested(string path) => Application.WasRequested(path);

        public static async Task<StaticContentHttpHost> StartAsync(CancellationToken cancellationToken)
        {
            KestrelServerOptions kestrelOptions = new();
            kestrelOptions.Listen(IPAddress.Loopback, port: 0);

            SocketTransportOptions socketOptions = new();
            SocketTransportFactory socketFactory = new(Options.Create(socketOptions), NullLoggerFactory.Instance);

            KestrelServer kestrel = new(Options.Create(kestrelOptions), socketFactory, NullLoggerFactory.Instance);
            StaticContentApplication application = new();
            await kestrel.StartAsync(application, cancellationToken).ConfigureAwait(false);

            IServerAddressesFeature? addresses = kestrel.Features.Get<IServerAddressesFeature>();
            if(addresses is null || addresses.Addresses.Count == 0)
            {
                throw new InvalidOperationException("Kestrel started but exposed no server address.");
            }

            Uri baseAddress = new(addresses.Addresses.First());

            return new StaticContentHttpHost(kestrel, baseAddress, application);
        }

        public async ValueTask DisposeAsync()
        {
            await server.StopAsync(CancellationToken.None).ConfigureAwait(false);
            server.Dispose();
        }
    }


    //The IHttpApplication skin serving GET {path} from a published-content map: 404 for an unknown path, 405 for
    //a non-GET method. Every requested path is recorded so the cross-wire assertions can prove the socket was hit.
    private sealed class StaticContentApplication: IHttpApplication<HttpContext>
    {
        private readonly ConcurrentDictionary<string, (byte[] Body, string ContentType)> content = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, int> requestCounts = new(StringComparer.Ordinal);
        private int totalRequests;

        public int TotalRequests => Volatile.Read(ref totalRequests);

        public void Publish(string path, byte[] body, string contentType)
        {
            content[path] = (body, contentType);
        }

        public bool WasRequested(string path) => requestCounts.ContainsKey(path);

        public HttpContext CreateContext(IFeatureCollection contextFeatures) => new DefaultHttpContext(contextFeatures);

        public async Task ProcessRequestAsync(HttpContext context)
        {
            HttpResponse httpResponse = context.Response;
            string path = context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty;

            Interlocked.Increment(ref totalRequests);
            requestCounts.AddOrUpdate(path, 1, static (_, count) => count + 1);

            if(!HttpMethods.IsGet(context.Request.Method))
            {
                httpResponse.StatusCode = StatusCodes.Status405MethodNotAllowed;

                return;
            }

            if(!content.TryGetValue(path, out (byte[] Body, string ContentType) served))
            {
                httpResponse.StatusCode = StatusCodes.Status404NotFound;

                return;
            }

            httpResponse.StatusCode = StatusCodes.Status200OK;
            httpResponse.ContentType = served.ContentType;
            await httpResponse.Body.WriteAsync(served.Body, context.RequestAborted).ConfigureAwait(false);
        }

        public void DisposeContext(HttpContext context, Exception? exception) { }
    }
}
