using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Outbound;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// End-to-end tests for <see cref="WebVhDidUrlDereferencer.Build"/> driven through the full
/// <see cref="DidResolver.DereferenceAsync"/> composition. The dereferencer resolves and verifies the base DID
/// (the same fetch/replay/verify pipeline a plain resolution runs), reads the implicit <c>#files</c> and
/// <c>#whois</c> services off the resolved document, and retrieves the targeted resource. The <c>did.jsonl</c>
/// log, the served file and the <c>whois.vp</c> are minted by <see cref="WebVhTestLog"/> and served by a faked
/// transport, so path dereferencing, the whois static-presentation verify, and the spec's two-error mapping
/// (<c>invalidDid</c> for a malformed/non-HTTP target, <c>notFound</c> for an unretrievable one) are exercised
/// deterministically without a live network (did:webvh v1.0, DID URL Resolution).
/// </summary>
[TestClass]
internal sealed class WebVhDidUrlDereferencerTests
{
    /// <summary>The domain the minted test DIDs live under, so their DID Log is served at <c>https://example.com/...</c>.</summary>
    private const string Domain = "example.com";

    /// <summary>The <c>versionTime</c> of every minted genesis entry.</summary>
    private const string GenesisTime = "2025-01-01T00:00:00Z";

    /// <summary>The implicit <c>#whois</c> service endpoint of the bare-domain DIDs these tests mint.</summary>
    private const string WhoisUrl = "https://example.com/whois.vp";

    /// <summary>The base58btc encoder the resolver encodes multihashes and keys with.</summary>
    private static EncodeDelegate Base58Encoder { get; } = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));

    /// <summary>The base58btc decoder the resolver decodes multihashes, keys and whois proof values with.</summary>
    private static DecodeDelegate Base58Decoder { get; } = DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase));

    /// <summary>The serializer options every JSON delegate of these tests uses.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>The JCS canonicalizer the eddsa-jcs-2022 whois presentations are signed and verified over.</summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    /// <summary>Serializes a presentation for signing, verification and serving.</summary>
    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    /// <summary>Parses a served <c>whois.vp</c> into a presentation, the dereferencer's default parser in these tests.</summary>
    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    /// <summary>Serializes the proof options a whois proof hashes.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);


    /// <summary>The MSTest context, whose cancellation token bounds every dereference these tests run.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A path DID URL dereferences to the bytes served at the <c>#files</c> service endpoint with the path appended
    /// (did:webvh v1.0, DID URL Path Resolution).
    /// </summary>
    [TestMethod]
    public async Task PathDereferencesFileBytes()
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[\"did:webvh:issuer\"]}");
        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (200, served, "application/json");

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A did:webvh path DID URL MUST dereference. Error: {result.DereferencingMetadata.Error?.Type}.");

        TaggedMemory<byte> body = (TaggedMemory<byte>)result.ContentStream!;
        Assert.AreSequenceEqual(served, body.Span.ToArray(), "The dereferenced content bytes MUST equal the served bytes.");
    }


    /// <summary>
    /// A path-dereferenced file response carrying <c>Cache-Control: max-age</c> reports that many seconds of
    /// storable freshness on the dereferencing metadata, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task PathDereferenceMaxAgeResponseReportsThatManySecondsOfStorableFreshness()
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[\"did:webvh:issuer\"]}");
        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (200, served, "application/json");

        DidDereferencingResult result = await DereferenceAsync(
            $"{log.Did}/governance/issuers.json",
            routes,
            new Dictionary<string, string> { ["https://example.com/governance/issuers.json"] = "max-age=90" }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A did:webvh path DID URL MUST dereference. Error: {result.DereferencingMetadata.Error?.Type}.");
        Assert.IsTrue(result.DereferencingMetadata.Freshness.IsStorable, "A max-age response is storable.");
        Assert.AreEqual(TimeSpan.FromSeconds(90), result.DereferencingMetadata.Freshness.FreshnessLifetime,
            "The reported lifetime is exactly the max-age directive's delta-seconds.");
    }


    /// <summary>
    /// A path dereference against a not-found file reports non-storable freshness — there is no document a
    /// cache could keep, per <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task PathDereferenceNon200ResponseReportsNonStorableFreshness()
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (404, null, null);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A 404 file MUST NOT dereference.");
        Assert.IsFalse(result.DereferencingMetadata.Freshness.IsStorable,
            "A dereference that never reached a document reports no storable freshness.");
    }


    /// <summary>
    /// A path DID URL whose file the <c>#files</c> endpoint answers with a 404 reports <c>notFound</c> (did:webvh v1.0,
    /// DID URL Path Resolution).
    /// </summary>
    [TestMethod]
    public async Task PathNotFoundWhenFileMissing()
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);

        //The #files endpoint resolves but the targeted file is served as a 404.
        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (404, null, null);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A 404 file MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// A path DID URL whose explicit <c>#files</c> endpoint uses a scheme other than HTTP(S) reports <c>invalidDid</c>
    /// (did:webvh v1.0, DID URL Path Resolution).
    /// </summary>
    [TestMethod]
    public async Task PathWithNonHttpServiceEndpointIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();

        //An explicit #files service whose endpoint scheme is not HTTP(S) is an invalidDid (the resolved DID is
        //valid, but the DID URL cannot be dereferenced over a supported transport).
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, explicitFilesServiceEndpoint: "ftp://example.com/", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", LogRoutes(log)).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A non-HTTP(S) #files endpoint MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didwebvh/v1.0/#did-url-path-resolution">did:webvh v1.0 DID URL Path
    /// Resolution</see>: "If the resolution of the constructed URL fails with a “not found” condition (e.g., HTTP 404), the
    /// resolver MUST return the notFound error." A retrieval of the resource that was cancelled has met no “not found”
    /// condition. When the transport reports that cancellation inside an exception of its own, as the inner exception of its
    /// own fault or among an aggregate's inner exceptions, the DID URL dereference lets it propagate as the cancellation it
    /// is instead of answering notFound, both when the caller abandoned the dereference while the resource was fetched and
    /// when the fetch ended on its own budget while the caller still waits, so the caller tells the two apart by its own
    /// token.
    /// </summary>
    /// <param name="cancellationShape">How the transport carries the cancellation: <c>wrapped</c> or <c>aggregated</c>.</param>
    /// <param name="isCallerCancelled">Whether the caller abandons the dereference while the resource is fetched.</param>
    [TestMethod]
    [DataRow("wrapped", false)]
    [DataRow("wrapped", true)]
    [DataRow("aggregated", false)]
    [DataRow("aggregated", true)]
    public async Task PathFetchCancellationCarriedInsideTheTransportFaultPropagates(string cancellationShape, bool isCallerCancelled)
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);

        //The DID Log is served, so the base DID resolves; only the resource fetch meets the cancellation.
        DidResolver composed = BuildDereferencer(
            new RoutingTransport(LogRoutes(log)).Delegate,
            CarriedCancellationFixtures.CreateTransport(cancellationShape, isCallerCancelled ? caller : null),
            DeserializePresentation);

        await CarriedCancellationFixtures.AssertPropagatesAsTheCancellationAsync(
            async () => await composed.DereferenceAsync(
                $"{log.Did}/governance/issuers.json", CreateContext(), cancellationToken: caller.Token).ConfigureAwait(false),
            isCallerCancelled,
            caller.Token).ConfigureAwait(false);
    }


    /// <summary>
    /// A faithfully minted <c>whois.vp</c>, signed by the DID's authentication key and carrying a credential about the
    /// DID, dereferences to the verified secured presentation (did:webvh v1.0, WHOIS Resolution).
    /// </summary>
    [TestMethod]
    public async Task WhoisDereferencesSignedPresentation()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions, TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A faithfully minted whois.vp MUST dereference. Error: {result.DereferencingMetadata.Error?.Type}.");
        _ = Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(result.ContentStream,
            "A dereferenced whois MUST return the verified secured presentation.");
    }


    /// <summary>
    /// A <c>whois.vp</c> whose proof value was altered after signing does not verify and reports <c>invalidDid</c>
    /// (did:webvh v1.0, WHOIS Resolution: the presentation MUST be signed by the DID).
    /// </summary>
    [TestMethod]
    public async Task WhoisWithTamperedProofIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions, TestContext.CancellationToken).ConfigureAwait(false);

        //Flip the last character of the proofValue so the signature no longer verifies.
        string tampered = TamperProofValue(whois);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(tampered), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp with a tampered proof MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// A <c>whois.vp</c> signed by a key outside the DID document's authentication methods reports <c>invalidDid</c>
    /// (did:webvh v1.0, WHOIS Resolution: the presentation MUST be signed by the DID).
    /// </summary>
    [TestMethod]
    public async Task WhoisSignedByForeignKeyIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        using WebVhController foreign = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The presentation is signed by a key that is NOT the document's authentication key. The verify resolves
        //the verification method through authentication and fails to find the foreign key.
        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, foreign, GenesisTime, SerializePresentation, SerializeProofOptions, TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp signed by a key outside the document's authentication MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// A <c>whois.vp</c> that verifies but carries no credential whose subject is the DID reports <c>invalidDid</c>
    /// (did:webvh v1.0, WHOIS Resolution: the presentation MUST include a credential about the DID).
    /// </summary>
    [TestMethod]
    public async Task WhoisWithoutCredentialAboutDidIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A presentation re-signed WITHOUT the DID's credential: it verifies cryptographically (the proof covers
        //the credential-less presentation), so the rejection is specifically the missing-credential-about-DID
        //conformance gate, not a signature failure.
        var withoutCredential = await ReSignWithoutCredentialAsync(log.Did, authentication, TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(withoutCredential), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp with no credential about the DID MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// A <c>whois.vp</c> minted with a challenge and domain binding is refused by the static linked-presentation verify
    /// and reports <c>invalidDid</c>, even though its signature is valid.
    /// </summary>
    [TestMethod]
    public async Task WhoisMintedBoundIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //A whois minted WITH a challenge/domain replay binding: the static linked-presentation verify is
        //fail-closed against a bound proof, so even a cryptographically valid presentation is rejected.
        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions,
            boundChallenge: "challenge-abc", boundDomain: "verifier.example", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp carrying a challenge/domain binding MUST NOT dereference through the static verify.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// A <c>/whois</c> DID URL whose <c>whois.vp</c> endpoint answers with a 404 reports <c>notFound</c> (did:webvh v1.0,
    /// WHOIS Resolution).
    /// </summary>
    [TestMethod]
    public async Task WhoisNotFoundWhenFileMissing()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The base DID resolves, but no whois.vp is served (a 404 at its endpoint).
        var routes = LogRoutes(log);
        routes[WhoisUrl] = (404, null, null);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A missing whois.vp MUST be NotFound.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// <see href="https://identity.foundation/didwebvh/v1.0/#whois-resolution">did:webvh v1.0 WHOIS Resolution</see>: "The
    /// returned whois.vp MUST contain a W3C VCDM verifiable signed by the DID and containing verifiable credentials that MUST
    /// have the DID as the credentialSubject." A parse of the retrieved <c>whois.vp</c> that was cancelled has shown
    /// nothing about the presentation. When the presentation parser reports that cancellation inside an exception of its
    /// own, as the inner exception of its own fault or among an aggregate's inner exceptions, the DID URL dereference lets
    /// it propagate as the cancellation it is instead of answering invalidDid, both when the caller abandoned the
    /// dereference while the presentation was parsed and when the parse ended on its own budget while the caller still
    /// waits, so the caller tells the two apart by its own token.
    /// </summary>
    /// <param name="cancellationShape">How the parser carries the cancellation: <c>wrapped</c> or <c>aggregated</c>.</param>
    /// <param name="isCallerCancelled">Whether the caller abandons the dereference while the presentation is parsed.</param>
    [TestMethod]
    [DataRow("wrapped", false)]
    [DataRow("wrapped", true)]
    [DataRow("aggregated", false)]
    [DataRow("aggregated", true)]
    public async Task WhoisParseCancellationCarriedInsideTheParserFaultPropagates(string cancellationShape, bool isCallerCancelled)
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        VerifiablePresentation CancelledPresentationParser(string serialized)
        {
            if(isCallerCancelled)
            {
                caller.Cancel();
            }

            throw CarriedCancellationFixtures.Create(cancellationShape);
        }

        //The DID Log and a whois.vp are served, so the fetch succeeds and only the parse meets the cancellation.
        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes("{}"), WellKnownWebVhValues.WhoisMediaType);
        RoutingTransport transport = new(routes);
        DidResolver composed = BuildDereferencer(transport.Delegate, transport.Delegate, CancelledPresentationParser);

        await CarriedCancellationFixtures.AssertPropagatesAsTheCancellationAsync(
            async () => await composed.DereferenceAsync($"{log.Did}/whois", CreateContext(), cancellationToken: caller.Token).ConfigureAwait(false),
            isCallerCancelled,
            caller.Token).ConfigureAwait(false);
    }


    /// <summary>
    /// An explicit <c>#files</c> service overrides the implicit one, so a path is dereferenced against the explicit
    /// endpoint, not the DID's default web location (did:webvh v1.0, DID URL Path Resolution).
    /// </summary>
    [TestMethod]
    public async Task ExplicitFilesServiceOverrideIsHonored()
    {
        using WebVhController controller = WebVhController.Create();

        //An explicit #files service overrides the implicit one (did:webvh v1.0, DID URL Path Resolution); the
        //path is dereferenced against the explicit endpoint, not the DID's default web location.
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, explicitFilesServiceEndpoint: "https://files.example/", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[]}");
        var routes = LogRoutes(log);

        //Served ONLY at the explicit endpoint; the implicit https://example.com/... location is never populated,
        //so a successful dereference proves the explicit override was used.
        routes["https://files.example/governance/issuers.json"] = (200, served, "application/json");

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"An explicit #files override MUST be dereferenced. Error: {result.DereferencingMetadata.Error?.Type}.");

        TaggedMemory<byte> body = (TaggedMemory<byte>)result.ContentStream!;
        Assert.AreSequenceEqual(served, body.Span.ToArray(), "The content MUST come from the explicit #files endpoint.");
    }


    /// <summary>
    /// An explicit #files override MAY express its endpoint as a serviceEndpoint MAP (the URL is a member value)
    /// rather than a bare string; the resolver MUST resolve the HTTP(S) URL from the map form (did:webvh v1.0,
    /// DID URL Resolution).
    /// </summary>
    [TestMethod]
    public async Task ExplicitFilesServiceEndpointMapIsResolved()
    {
        using WebVhController controller = WebVhController.Create();

        //The explicit #files service's serviceEndpoint is a map {"uri": "https://files.example/"} rather than a
        //bare string. The file is served ONLY at that endpoint, so a successful dereference proves the map form
        //was resolved.
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, explicitFilesServiceEndpointMap: "https://files.example/", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[]}");
        var routes = LogRoutes(log);
        routes["https://files.example/governance/issuers.json"] = (200, served, "application/json");

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A serviceEndpoint map #files override MUST be dereferenced. Error: {result.DereferencingMetadata.Error?.Type}.");

        TaggedMemory<byte> body = (TaggedMemory<byte>)result.ContentStream!;
        Assert.AreSequenceEqual(served, body.Span.ToArray(), "The content MUST come from the map-form #files endpoint.");
    }


    /// <summary>
    /// An explicit #whois service overrides the implicit one and is used (in preference to the implicit endpoint)
    /// for /whois dereferencing, even when it points to a different HTTP(S) location (did:webvh v1.0, WHOIS
    /// Resolution: "Such an entry MUST override the implicit service above").
    /// </summary>
    [TestMethod]
    public async Task ExplicitWhoisServiceOverrideIsHonored()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();

        const string explicitWhoisUrl = "https://whois.example/custom-whois.vp";

        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, authentication: authentication, explicitWhoisServiceEndpoint: explicitWhoisUrl, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions, TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);

        //Served ONLY at the explicit endpoint; the implicit https://example.com/whois.vp location is never
        //populated, so a successful dereference proves the explicit #whois override was used.
        routes[explicitWhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"An explicit #whois override MUST be dereferenced. Error: {result.DereferencingMetadata.Error?.Type}.");
        _ = Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(result.ContentStream,
            "The explicit #whois override MUST return the verified secured presentation.");
    }


    /// <summary>
    /// A whois.vp whose proof references the parallel did:web DID (listed in the resolved document's
    /// alsoKnownAs) rather than the did:webvh DID is verified against the already-resolved did:webvh document,
    /// because the two DIDs share the same verification methods (did:webvh v1.0, WHOIS Resolution).
    /// </summary>
    [TestMethod]
    public async Task WhoisProofReferencingAlsoKnownAsDidWebIsVerified()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();

        //The parallel did:web DID for the bare-domain DID, listed in the resolved document's alsoKnownAs.
        const string parallelDidWeb = "did:web:example.com";

        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, authentication: authentication, genesisAlsoKnownAs: [parallelDidWeb], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The whois proof references the did:web DID's verification method (#key-1), signed by the SAME
        //authentication key. The resolved did:webvh document's authentication method shares the fragment, so the
        //resolver cross-verifies the proof against the resolved document.
        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions,
            verificationMethodId: $"{parallelDidWeb}#key-1", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A whois proof referencing the alsoKnownAs did:web DID MUST cross-verify. Error: {result.DereferencingMetadata.Error?.Type}.");
        _ = Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(result.ContentStream,
            "The cross-verified whois MUST return the verified secured presentation.");
    }


    /// <summary>
    /// A whois proof referencing a foreign DID that is NOT in the resolved document's alsoKnownAs MUST NOT
    /// cross-verify: the alsoKnownAs gate ensures only the established parallel pair is cross-verified.
    /// </summary>
    [TestMethod]
    public async Task WhoisProofReferencingUnrelatedDidWebIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();

        //No alsoKnownAs is declared, so a proof referencing a did:web DID has no established parallel pairing.
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions,
            verificationMethodId: "did:web:unrelated.example#key-1", cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois proof referencing an unrelated did:web DID MUST NOT cross-verify.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// A path DID URL pinned by <c>versionId</c> to a version the log does not carry reports <c>notFound</c>, although
    /// the file itself is served, so the version query is threaded into the base resolution (did:webvh v1.0, Reading
    /// did:webvh DID URLs).
    /// </summary>
    [TestMethod]
    public async Task PathWithUnknownVersionQueryIsNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);

        //The file IS served, so the only reason to fail is the version query: a versionId that does not exist
        //makes base resolution NotFound, proving the DID-URL version query is threaded into resolution rather
        //than silently dereferencing the latest version.
        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (200, Encoding.UTF8.GetBytes("{}"), "application/json");

        DidDereferencingResult result = await DereferenceAsync(
            $"{log.Did}/governance/issuers.json?versionId=9-QmUnknownVersionXXXXXXXXXXXXXXXXXXXXXXXXXXXX", routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A path DID URL pinned to a nonexistent version MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }


    /// <summary>
    /// A query-only DID URL (no path) carries its version selection into base resolution: a versionId pinning
    /// the genesis dereferences the genesis DIDDoc, not the latest (did:webvh v1.0, Reading did:webvh DID URLs).
    /// </summary>
    [TestMethod]
    public async Task QueryOnlyVersionIdDereferencesRequestedVersion()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, "2025-02-01T00:00:00Z")
        ], TestContext.CancellationToken).ConfigureAwait(false);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}?versionId={log.VersionIds[0]}", LogRoutes(log)).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A query-only versionId DID URL MUST dereference. Error: {result.DereferencingMetadata.Error?.Type}.");
        _ = Assert.IsInstanceOfType<DidDocument>(result.ContentStream, "A query-only DID URL with no path/fragment MUST return the DID document.");
        Assert.AreEqual(log.VersionIds[0], result.ContentMetadata?.VersionId,
            "The dereferenced version MUST be the requested genesis version, not the latest.");
    }


    /// <summary>A query-only DID URL pinned to a nonexistent versionId MUST be NotFound (did:webvh v1.0, Reading did:webvh DID URLs).</summary>
    [TestMethod]
    public async Task QueryOnlyUnknownVersionIdIsNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        var log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, TestContext.CancellationToken).ConfigureAwait(false);

        DidDereferencingResult result = await DereferenceAsync(
            $"{log.Did}?versionId=9-QmUnknownVersionXXXXXXXXXXXXXXXXXXXXXXXXXXXX", LogRoutes(log)).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A query-only DID URL pinned to a nonexistent version MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }


    /// <summary>The routes serving <paramref name="log"/>'s <c>did.jsonl</c> at the URL its DID resolves to.</summary>
    /// <param name="log">The minted DID Log.</param>
    /// <returns>A route table a test adds its own resources to.</returns>
    private static Dictionary<string, (int Status, byte[]? Body, string? ContentType)> LogRoutes(WebVhMintedLog log)
    {
        return new Dictionary<string, (int, byte[]?, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (200, Encoding.UTF8.GetBytes(string.Join('\n', log.Lines)), null)
        };
    }


    /// <summary>Flips the last character of the first proof's <c>proofValue</c>, so the signature no longer verifies.</summary>
    /// <param name="presentationJson">The signed presentation's JSON text.</param>
    /// <returns>The altered presentation's JSON text.</returns>
    private static string TamperProofValue(string presentationJson)
    {
        JsonObject presentation = JsonNode.Parse(presentationJson)!.AsObject();
        JsonObject proof = (JsonObject)((JsonArray)presentation["proof"]!)[0]!;
        string proofValue = (string)proof["proofValue"]!;
        proof["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');

        return presentation.ToJsonString();
    }


    /// <summary>
    /// Mints a signed whois presentation with NO credential: the production verify canonicalizes the proofless
    /// presentation, so a credential-less presentation verifies cryptographically but carries no credential about the
    /// DID, isolating the missing-credential conformance gate from a signature failure.
    /// </summary>
    /// <param name="did">The DID the presentation's holder names.</param>
    /// <param name="authentication">The controller of the DID's authentication key, which signs.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The signed presentation's JSON text.</returns>
    private static async Task<string> ReSignWithoutCredentialAsync(string did, WebVhController authentication, CancellationToken cancellationToken)
    {
        VerifiablePresentation unsigned = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            Holder = did
        };

        DataIntegrityProof newProof = new()
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Created = GenesisTime,
            VerificationMethod = new AuthenticationMethod($"{did}#key-1"),
            ProofPurpose = AuthenticationMethod.Purpose
        };

        ProofOptionsDocument proofOptions = ProofOptionsDocument.FromProof(newProof, null);
        string proofOptionsSerialized = SerializeProofOptions(proofOptions);
        string presentationSerialized = SerializePresentation(unsigned);

        using IMemoryOwner<byte> hashOwner = BaseMemoryPool.Shared.Rent(64);
        Memory<byte> hashData = hashOwner.Memory[..64];
        HashCanonical(proofOptionsSerialized, hashData.Span[..32]);
        HashCanonical(presentationSerialized, hashData.Span[32..]);

        newProof.ProofValue = await authentication.SignProofValueAsync(hashData, cancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation secured = new()
        {
            Context = unsigned.Context,
            Type = unsigned.Type,
            Holder = unsigned.Holder,
            Proof = [newProof]
        };

        return SerializePresentation(secured);
    }


    /// <summary>
    /// Writes the SHA-256 digest of the JCS form of <paramref name="json"/> into <paramref name="destination"/>, through
    /// the project's registered digest function.
    /// </summary>
    /// <param name="json">The JSON text to canonicalize and hash.</param>
    /// <param name="destination">The 32-byte span receiving the digest.</param>
    private static void HashCanonical(string json, Span<byte> destination)
    {
        var canonical = new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(canonical.Span, destination.Length, CryptoTags.Sha256Digest, BaseMemoryPool.Shared);
        digest.AsReadOnlySpan().CopyTo(destination);
    }


    /// <summary>The per-operation context a dereference runs under: the secure-default outbound-fetch policy.</summary>
    /// <returns>A fresh context.</returns>
    private static ExchangeContext CreateContext()
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        return context;
    }


    /// <summary>
    /// Builds the resolver composition with the real did:webvh resolver fetching the DID Log over
    /// <paramref name="logTransport"/> and the real did:webvh dereferencer fetching a DID URL's resource over
    /// <paramref name="resourceTransport"/> and parsing a <c>whois.vp</c> with <paramref name="presentationDeserializer"/>,
    /// so a test can let the base DID resolve while the resource retrieval or its parse meets a condition of its own.
    /// </summary>
    /// <param name="logTransport">The transport the resolver fetches the <c>did.jsonl</c> over.</param>
    /// <param name="resourceTransport">The transport the dereferencer fetches the file or <c>whois.vp</c> over.</param>
    /// <param name="presentationDeserializer">Parses a fetched <c>whois.vp</c>.</param>
    /// <returns>The composed resolver.</returns>
    private static DidResolver BuildDereferencer(
        OutboundTransportDelegate logTransport,
        OutboundTransportDelegate resourceTransport,
        PresentationDeserializeDelegate presentationDeserializer)
    {
        DidMethodResolverDelegate webVhResolver = WebVhDidResolver.Build(
            logTransport,
            WebVhLogEntryJson.Parser,
            WebVhLogEntryJson.WitnessFileParser,
            WebVhLogEntryJson.DocumentIdentityReader,
            DeserializeState,
            WebVhLogEntryJson.Canonicalizer,
            Base58Encoder,
            Base58Decoder,
            BaseMemoryPool.Shared,
            new FakeTimeProvider(TestClock.CanonicalEpoch));

        DidMethodDereferencerDelegate webVhDereferencer = WebVhDidUrlDereferencer.Build(
            webVhResolver,
            resourceTransport,
            presentationDeserializer,
            JcsCanonicalizer,
            ProofValueCodecs.DecodeBase58Btc,
            SerializePresentation,
            SerializeProofOptions,
            Base58Decoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            BaseMemoryPool.Shared,
            Context.FromIris(Context.Credentials20));

        return DidResolverComposition.Build(
            BaseMemoryPool.Shared,
            static (request, context, cancellationToken) => ValueTask.FromResult(new OutboundResponse { StatusCode = 404, Body = TaggedMemory<byte>.Empty }),
            static jsonUtf8 => null,
            static jsonUtf8 => null,
            dereferencerSelector: DidMethodSelectors.FromDereferencers(
                (WellKnownDidMethodPrefixes.WebVhDidMethodPrefix, webVhDereferencer)),
            additionalMethods: (WellKnownDidMethodPrefixes.WebVhDidMethodPrefix, webVhResolver));
    }


    /// <summary>
    /// Dereferences <paramref name="didUrl"/> through <see cref="BuildDereferencer"/> over one transport serving
    /// <paramref name="routes"/> to both the resolver and the dereferencer, with the default <c>whois.vp</c> parser.
    /// </summary>
    /// <param name="didUrl">The DID URL to dereference.</param>
    /// <param name="routes">The served resources by absolute URL.</param>
    /// <param name="cacheControlOverrides">A <c>Cache-Control</c> value per URL, or <see langword="null"/> for none.</param>
    /// <returns>The dereferencing result.</returns>
    private async Task<DidDereferencingResult> DereferenceAsync(
        string didUrl,
        Dictionary<string, (int Status, byte[]? Body, string? ContentType)> routes,
        Dictionary<string, string>? cacheControlOverrides = null)
    {
        var transport = new RoutingTransport(routes);
        if(cacheControlOverrides is not null)
        {
            foreach((string url, string cacheControl) in cacheControlOverrides)
            {
                transport.CacheControlOverrides[url] = cacheControl;
            }
        }

        DidResolver composed = BuildDereferencer(transport.Delegate, transport.Delegate, DeserializePresentation);

        return await composed.DereferenceAsync(didUrl, CreateContext(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>The JSON layer's state deserialization of one <c>did.jsonl</c> entry; Verifiable.Core never parses the log itself.</summary>
    /// <param name="rawEntryLine">The UTF-8 entry line.</param>
    /// <returns>The entry's DID document state, or <see langword="null"/> when the line carries none.</returns>
    private static DidDocument? DeserializeState(ReadOnlySpan<byte> rawEntryLine)
    {
        try
        {
            if(JsonNode.Parse(rawEntryLine) is not JsonObject entry || entry["state"] is not JsonObject state)
            {
                return null;
            }

            return JsonSerializerExtensions.Deserialize<DidDocument>(state.ToJsonString(), TestSetup.DefaultSerializationOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    /// <summary>
    /// A single-hop transport returning a canned (status, body, content-type) per absolute URL; an unknown URL is a 404.
    /// The body is served as the transport-owned JSON-tagged buffer the guarded fetch returns.
    /// </summary>
    private sealed class RoutingTransport
    {
        /// <summary>The canned answers by absolute URL.</summary>
        private Dictionary<string, (int Status, byte[]? Body, string? ContentType)> Routes { get; }


        /// <summary>Creates the transport over <paramref name="routes"/>.</summary>
        /// <param name="routes">The canned answers by absolute URL.</param>
        public RoutingTransport(Dictionary<string, (int Status, byte[]? Body, string? ContentType)> routes)
        {
            this.Routes = routes;
        }


        /// <summary>
        /// A <c>Cache-Control</c> value per URL, layered onto the route's content type header; a URL without an entry is
        /// served without one.
        /// </summary>
        public Dictionary<string, string> CacheControlOverrides { get; } = new(StringComparer.Ordinal);


        /// <summary>The transport delegate answering from <see cref="Routes"/>.</summary>
        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            if(!Routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, byte[]? Body, string? ContentType) route))
            {
                route = (404, null, null);
            }

            TaggedMemory<byte> body = route.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(route.Body, BufferTags.Json);

            bool hasCacheControl = CacheControlOverrides.TryGetValue(request.Target.AbsoluteUri, out string? cacheControl);

            HttpHeaderSet headers = (route.ContentType, hasCacheControl) switch
            {
                (null, false) => HttpHeaderSet.Empty,
                ({ } contentType, false) => HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, contentType)),
                (null, true) => HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.CacheControl, cacheControl!)),
                ({ } contentType, true) => HttpHeaderSet.FromPairs(
                    (WellKnownHttpHeaderNames.ContentType, contentType), (WellKnownHttpHeaderNames.CacheControl, cacheControl!))
            };

            return ValueTask.FromResult(new OutboundResponse { StatusCode = route.Status, Body = body, Headers = headers });
        };
    }
}
