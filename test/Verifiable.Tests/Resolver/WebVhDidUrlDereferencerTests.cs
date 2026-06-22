using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
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
    private const string Domain = "example.com";
    private const string GenesisTime = "2025-01-01T00:00:00Z";

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


    [TestMethod]
    public async Task PathDereferencesFileBytes()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[\"did:webvh:issuer\"]}");
        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (200, served, "application/json");

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", log, routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A did:webvh path DID URL MUST dereference. Error: {result.DereferencingMetadata.Error?.Type}.");

        TaggedMemory<byte> body = (TaggedMemory<byte>)result.ContentStream!;
        CollectionAssert.AreEqual(served, body.Span.ToArray(), "The dereferenced content bytes MUST equal the served bytes.");
    }


    [TestMethod]
    public async Task PathNotFoundWhenFileMissing()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //The #files endpoint resolves but the targeted file is served as a 404.
        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (404, null, null);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", log, routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A 404 file MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task PathWithNonHttpServiceEndpointIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();

        //An explicit #files service whose endpoint scheme is not HTTP(S) is an invalidDid (the resolved DID is
        //valid, but the DID URL cannot be dereferenced over a supported transport).
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, explicitFilesServiceEndpoint: "ftp://example.com/").ConfigureAwait(false);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", log, LogRoutes(log)).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A non-HTTP(S) #files endpoint MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task WhoisDereferencesSignedPresentation()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A faithfully minted whois.vp MUST dereference. Error: {result.DereferencingMetadata.Error?.Type}.");
        Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(result.ContentStream,
            "A dereferenced whois MUST return the verified secured presentation.");
    }


    [TestMethod]
    public async Task WhoisWithTamperedProofIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions).ConfigureAwait(false);

        //Flip the last character of the proofValue so the signature no longer verifies.
        string tampered = TamperProofValue(whois);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(tampered), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp with a tampered proof MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task WhoisSignedByForeignKeyIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        using WebVhController foreign = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        //The presentation is signed by a key that is NOT the document's authentication key. The verify resolves
        //the verification method through authentication and fails to find the foreign key.
        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, foreign, GenesisTime, SerializePresentation, SerializeProofOptions).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp signed by a key outside the document's authentication MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task WhoisWithoutCredentialAboutDidIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        //A presentation re-signed WITHOUT the DID's credential: it verifies cryptographically (the proof covers
        //the credential-less presentation), so the rejection is specifically the missing-credential-about-DID
        //conformance gate, not a signature failure.
        string withoutCredential = await ReSignWithoutCredentialAsync(log.Did, authentication).ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(withoutCredential), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp with no credential about the DID MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task WhoisMintedBoundIsInvalidDid()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        //A whois minted WITH a challenge/domain replay binding: the static linked-presentation verify is
        //fail-closed against a bound proof, so even a cryptographically valid presentation is rejected.
        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions,
            boundChallenge: "challenge-abc", boundDomain: "verifier.example").ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois.vp carrying a challenge/domain binding MUST NOT dereference through the static verify.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task WhoisNotFoundWhenFileMissing()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController authentication = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        //The base DID resolves, but no whois.vp is served (a 404 at its endpoint).
        var routes = LogRoutes(log);
        routes[WhoisUrl] = (404, null, null);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A missing whois.vp MUST be NotFound.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task ExplicitFilesServiceOverrideIsHonored()
    {
        using WebVhController controller = WebVhController.Create();

        //An explicit #files service overrides the implicit one (did:webvh v1.0, DID URL Path Resolution); the
        //path is dereferenced against the explicit endpoint, not the DID's default web location.
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(
            Domain, controller, GenesisTime, explicitFilesServiceEndpoint: "https://files.example/").ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[]}");
        var routes = LogRoutes(log);

        //Served ONLY at the explicit endpoint; the implicit https://example.com/... location is never populated,
        //so a successful dereference proves the explicit override was used.
        routes["https://files.example/governance/issuers.json"] = (200, served, "application/json");

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", log, routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"An explicit #files override MUST be dereferenced. Error: {result.DereferencingMetadata.Error?.Type}.");

        TaggedMemory<byte> body = (TaggedMemory<byte>)result.ContentStream!;
        CollectionAssert.AreEqual(served, body.Span.ToArray(), "The content MUST come from the explicit #files endpoint.");
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
            Domain, controller, GenesisTime, explicitFilesServiceEndpointMap: "https://files.example/").ConfigureAwait(false);

        byte[] served = Encoding.UTF8.GetBytes("{\"issuers\":[]}");
        var routes = LogRoutes(log);
        routes["https://files.example/governance/issuers.json"] = (200, served, "application/json");

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/governance/issuers.json", log, routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A serviceEndpoint map #files override MUST be dereferenced. Error: {result.DereferencingMetadata.Error?.Type}.");

        TaggedMemory<byte> body = (TaggedMemory<byte>)result.ContentStream!;
        CollectionAssert.AreEqual(served, body.Span.ToArray(), "The content MUST come from the map-form #files endpoint.");
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
            Domain, controller, GenesisTime, authentication: authentication, explicitWhoisServiceEndpoint: explicitWhoisUrl).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions).ConfigureAwait(false);

        var routes = LogRoutes(log);

        //Served ONLY at the explicit endpoint; the implicit https://example.com/whois.vp location is never
        //populated, so a successful dereference proves the explicit #whois override was used.
        routes[explicitWhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"An explicit #whois override MUST be dereferenced. Error: {result.DereferencingMetadata.Error?.Type}.");
        Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(result.ContentStream,
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
            Domain, controller, GenesisTime, authentication: authentication, genesisAlsoKnownAs: [parallelDidWeb]).ConfigureAwait(false);

        //The whois proof references the did:web DID's verification method (#key-1), signed by the SAME
        //authentication key. The resolved did:webvh document's authentication method shares the fragment, so the
        //resolver cross-verifies the proof against the resolved document.
        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions,
            verificationMethodId: $"{parallelDidWeb}#key-1").ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A whois proof referencing the alsoKnownAs did:web DID MUST cross-verify. Error: {result.DereferencingMetadata.Error?.Type}.");
        Assert.IsInstanceOfType<DataIntegritySecuredPresentation>(result.ContentStream,
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
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime, authentication: authentication).ConfigureAwait(false);

        string whois = await WebVhTestLog.MintWhoisPresentationAsync(
            log.Did, authentication, GenesisTime, SerializePresentation, SerializeProofOptions,
            verificationMethodId: "did:web:unrelated.example#key-1").ConfigureAwait(false);

        var routes = LogRoutes(log);
        routes[WhoisUrl] = (200, Encoding.UTF8.GetBytes(whois), WellKnownWebVhValues.WhoisMediaType);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}/whois", log, routes).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A whois proof referencing an unrelated did:web DID MUST NOT cross-verify.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.DereferencingMetadata.Error);
    }


    [TestMethod]
    public async Task PathWithUnknownVersionQueryIsNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //The file IS served, so the only reason to fail is the version query: a versionId that does not exist
        //makes base resolution NotFound, proving the DID-URL version query is threaded into resolution rather
        //than silently dereferencing the latest version.
        var routes = LogRoutes(log);
        routes["https://example.com/governance/issuers.json"] = (200, Encoding.UTF8.GetBytes("{}"), "application/json");

        DidDereferencingResult result = await DereferenceAsync(
            $"{log.Did}/governance/issuers.json?versionId=9-QmUnknownVersionXXXXXXXXXXXXXXXXXXXXXXXXXXXX", log, routes).ConfigureAwait(false);

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
        ]).ConfigureAwait(false);

        DidDereferencingResult result = await DereferenceAsync($"{log.Did}?versionId={log.VersionIds[0]}", log, LogRoutes(log)).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A query-only versionId DID URL MUST dereference. Error: {result.DereferencingMetadata.Error?.Type}.");
        Assert.IsInstanceOfType<DidDocument>(result.ContentStream, "A query-only DID URL with no path/fragment MUST return the DID document.");
        Assert.AreEqual(log.VersionIds[0], result.ContentMetadata?.VersionId,
            "The dereferenced version MUST be the requested genesis version, not the latest.");
    }


    /// <summary>A query-only DID URL pinned to a nonexistent versionId MUST be NotFound (did:webvh v1.0, Reading did:webvh DID URLs).</summary>
    [TestMethod]
    public async Task QueryOnlyUnknownVersionIdIsNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        DidDereferencingResult result = await DereferenceAsync(
            $"{log.Did}?versionId=9-QmUnknownVersionXXXXXXXXXXXXXXXXXXXXXXXXXXXX", log, LogRoutes(log)).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A query-only DID URL pinned to a nonexistent version MUST NOT dereference.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.DereferencingMetadata.Error);
    }


    //The absolute URL the resolver fetches the bare-domain DID's log from, and the implicit whois.vp endpoint.
    private const string WhoisUrl = "https://example.com/whois.vp";


    private static Dictionary<string, (int Status, byte[]? Body, string? ContentType)> LogRoutes(WebVhMintedLog log)
    {
        return new Dictionary<string, (int, byte[]?, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (200, Encoding.UTF8.GetBytes(string.Join('\n', log.Lines)), null)
        };
    }


    private static string TamperProofValue(string presentationJson)
    {
        JsonObject presentation = JsonNode.Parse(presentationJson)!.AsObject();
        JsonObject proof = (JsonObject)((JsonArray)presentation["proof"]!)[0]!;
        string proofValue = (string)proof["proofValue"]!;
        proof["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');

        return presentation.ToJsonString();
    }


    //Mints a signed whois presentation with NO credential: the production verify canonicalizes the proofless
    //presentation, so a credential-less presentation verifies cryptographically but carries no credential about
    //the DID — isolating the missing-credential conformance gate from a signature failure.
    private static async Task<string> ReSignWithoutCredentialAsync(string did, WebVhController authentication)
    {
        VerifiablePresentation unsigned = new()
        {
            Context = new Context { Contexts = [Context.Credentials20] },
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

        newProof.ProofValue = await authentication.SignProofValueAsync(hashData).ConfigureAwait(false);

        DataIntegritySecuredPresentation secured = new()
        {
            Context = unsigned.Context,
            Type = unsigned.Type,
            Holder = unsigned.Holder,
            Proof = [newProof]
        };

        return SerializePresentation(secured);
    }


    private static void HashCanonical(string json, Span<byte> destination)
    {
        var canonical = new TaggedMemory<byte>(Jcs.CanonicalizeToUtf8Bytes(json), BufferTags.Json);
        SHA256.HashData(canonical.Span, destination);
    }


    private async Task<DidDereferencingResult> DereferenceAsync(
        string didUrl,
        WebVhMintedLog log,
        Dictionary<string, (int Status, byte[]? Body, string? ContentType)> routes)
    {
        var transport = new RoutingTransport(routes);

        DidMethodResolverDelegate webVhResolver = WebVhDidResolver.Build(
            transport.Delegate,
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
            transport.Delegate,
            DeserializePresentation,
            JcsCanonicalizer,
            ProofValueCodecs.DecodeBase58Btc,
            SerializePresentation,
            SerializeProofOptions,
            Base58Decoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            BaseMemoryPool.Shared);

        DidResolver composed = DidResolverComposition.Build(
            BaseMemoryPool.Shared,
            SHA256.HashData,
            static (request, context, cancellationToken) => ValueTask.FromResult(new OutboundResponse { StatusCode = 404, Body = TaggedMemory<byte>.Empty }),
            static jsonUtf8 => null,
            static jsonUtf8 => null,
            dereferencerSelector: DidMethodSelectors.FromDereferencers(
                (WellKnownDidMethodPrefixes.WebVhDidMethodPrefix, webVhDereferencer)),
            additionalMethods: (WellKnownDidMethodPrefixes.WebVhDidMethodPrefix, webVhResolver));

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        return await composed.DereferenceAsync(didUrl, context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
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

            return JsonSerializerExtensions.Deserialize<DidDocument>(state.ToJsonString(), TestSetup.DefaultSerializationOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    //A single-hop transport returning a canned (status, body, content-type) per absolute URL; an unknown URL is
    //a 404. The body is served as the transport-owned JSON-tagged buffer the guarded fetch returns.
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
}
