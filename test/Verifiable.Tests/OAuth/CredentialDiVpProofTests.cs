using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using System.Net;
using System.Net.Http;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The OPT-IN library-side verification of OID4VCI 1.0 Appendix F.2 <c>di_vp</c> key proofs at the
/// §8 Credential Endpoint, driven through the real dispatch pipeline. A <c>di_vp</c> proof is a W3C
/// Verifiable Presentation secured with a Data Integrity proof; the library verifies it by COMPOSING
/// the same tested <see cref="PresentationDataIntegrityExtensions.VerifyAsync"/> surface the W3C
/// presentation-verification flow uses, mapping the presentation proof's <c>challenge</c> to the
/// expected <c>c_nonce</c> and its <c>domain</c> to the Credential Issuer Identifier (Appendix F.2).
/// </summary>
/// <remarks>
/// The holder-signed presentation, the cryptosuite, and the verify-delegate sourcing mirror
/// <see cref="FlowTests.DataIntegrityPresentationFlowTests"/> verbatim: <see cref="KeyDidBuilder"/>
/// for the holder, <c>SignAsync</c> with <c>Challenge</c>/<c>Domain</c> and the <c>authentication</c>
/// proof purpose, JCS canonicalization, base58btc proof values, and
/// <see cref="MicrosoftEntropyFunctions.ComputeDigestAsync"/>.
/// </remarks>
[TestClass]
internal sealed class CredentialDiVpProofTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://wallet.client.test";
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string CredentialNonce = "c-nonce-di-vp-42";
    private const string IssuedCredential = "issued-credential-opaque-42";
    private const string DidWebHolderDomain = "holder.web.test";
    private const string DidWebHolderDocumentUrl = "https://holder.web.test/.well-known/did.json";

    private static readonly ImmutableHashSet<CapabilityIdentifier> CredentialCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new();
    private static WebDidBuilder WebDidBuilder { get; } = new();

    //The library's DID-resolution seam wired for the did:key holder — the same construction
    //Oid4VpSchemeFixtures uses for the decentralized_identifier: path. The holder did:key
    //self-describes, so the resolver derives the holder DID document locally with no network.
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    //The same delegate sourcing DataIntegrityPresentationFlowTests uses — composed, not re-rolled.
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static readonly ExchangeContext EmptyContext = new();

    private static ProofValueEncoderDelegate ProofValueEncoder { get; } = ProofValueCodecs.EncodeBase58Btc;
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = ProofValueCodecs.DecodeBase58Btc;

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);


    /// <summary>
    /// Happy path. Appendix F.2: "The Credential Issuer MUST validate that the W3C Verifiable
    /// Presentation used as a proof is actually signed with a key in the possession of the Holder."
    /// A holder-signed presentation whose proof's <c>challenge</c> is the expected <c>c_nonce</c>,
    /// <c>domain</c> is the Credential Issuer Identifier, and <c>proofPurpose</c> is
    /// <c>authentication</c> verifies, and issuance proceeds bound to the authenticated holder key.
    /// </summary>
    [TestMethod]
    public async Task HolderSignedDiVpProofVerifiesAndIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        WireDiVpExpectationSeam(host, KeyDidResolverSeam);
        bool seamIssued = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamIssued = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
        Assert.IsTrue(seamIssued, "A verified di_vp proof must let issuance proceed.");

        //The library authenticated the holder verification method id — the binding the issued
        //Credential uses (Appendix F.2: signed with a key in the Holder's possession).
        DiVpProofValidationResult directResult = await CredentialProofValidator.ValidateDiVpAsync(
            SerializePresentation(signedPresentation),
            CredentialNonce,
            issuerIdentifier,
            BuildDiVpVerification(KeyDidResolverSeam),
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(directResult.IsValid, $"Expected valid; got {directResult.FailureReason}.");
        Assert.AreEqual(holderDidDocument.VerificationMethod![0].Id, directResult.AuthenticatedVerificationMethodId,
            "The authenticated holder verification method id is the binding the Credential uses.");
    }


    /// <summary>
    /// Adversarial — challenge binding. Appendix F.2: the presentation proof's "challenge ... where
    /// the value is a server-provided c_nonce". A presentation whose <c>challenge</c> is not the
    /// expected <c>c_nonce</c> is rejected as <c>invalid_nonce</c> — the Wallet must fetch a fresh
    /// c_nonce — and the issuance seam is never consulted.
    /// </summary>
    [TestMethod]
    public async Task DiVpWithWrongChallengeYieldsInvalidNonce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        //The presentation is signed with a stale c_nonce; the server expects CredentialNonce.
        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, "c-nonce-STALE", issuerIdentifier).ConfigureAwait(false);

        WireDiVpExpectationSeam(host, KeyDidResolverSeam);
        bool seamConsulted = WireSeamTripwire(host);

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidNonce, response.Body);
        Assert.IsFalse(seamConsulted, "A stale di_vp challenge must be rejected before the issuance seam.");
    }


    /// <summary>
    /// Adversarial — domain binding. Appendix F.2: "domain: REQUIRED. MUST be set to the Credential
    /// Issuer Identifier." A presentation whose <c>domain</c> is not the Credential Issuer Identifier
    /// is rejected as <c>invalid_proof</c> before issuance.
    /// </summary>
    [TestMethod]
    public async Task DiVpWithWrongDomainYieldsInvalidProof()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        //The presentation's domain is some other audience, not the resolved Credential Issuer.
        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, "https://attacker.example").ConfigureAwait(false);

        WireDiVpExpectationSeam(host, KeyDidResolverSeam);
        bool seamConsulted = WireSeamTripwire(host);

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
        Assert.IsFalse(seamConsulted, "A wrong di_vp domain must be rejected before the issuance seam.");
    }


    /// <summary>
    /// Adversarial — signature integrity. The §F.2 presentation's Data Integrity proof authenticates
    /// the holder key; tampering with the <c>proofValue</c> breaks the signature, so the proof is
    /// rejected as <c>invalid_proof</c> before issuance.
    /// </summary>
    [TestMethod]
    public async Task DiVpWithTamperedProofValueYieldsInvalidProof()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        //Replace the proof value with an invalid one after signing.
        signedPresentation.Proof![0].ProofValue = "zTAMPEREDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        WireDiVpExpectationSeam(host, KeyDidResolverSeam);
        bool seamConsulted = WireSeamTripwire(host);

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
        Assert.IsFalse(seamConsulted, "A tampered di_vp proofValue must be rejected before the issuance seam.");
    }


    /// <summary>
    /// Adversarial — proof purpose. Appendix F.2: "proofPurpose: REQUIRED. MUST be set to
    /// authentication." A presentation proof minted for any other purpose (e.g. assertionMethod) is
    /// rejected as <c>invalid_proof</c> before issuance, even though the same key authenticates.
    /// </summary>
    [TestMethod]
    public async Task DiVpWithWrongProofPurposeYieldsInvalidProof()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        //Forge the purpose to assertionMethod — the same key, but not an authentication proof.
        signedPresentation.Proof![0].ProofPurpose = AssertionMethod.Purpose;

        WireDiVpExpectationSeam(host, KeyDidResolverSeam);
        bool seamConsulted = WireSeamTripwire(host);

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
        Assert.IsFalse(seamConsulted, "A non-authentication di_vp proofPurpose must be rejected before the issuance seam.");
    }


    /// <summary>
    /// The parse-and-surface default holds: with NO <c>di_vp</c> verification seam wired, a di_vp
    /// proof is left in <see cref="CredentialRequest.DiVpProofs"/> for the issuance seam — the
    /// library verifies nothing and issuance proceeds, unchanged from before this wiring.
    /// </summary>
    [TestMethod]
    public async Task DiVpParseAndSurfaceDefaultIsUnchangedWhenSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        //No expectation seam at all — the §F.4 / §F.2 check is entirely the issuance seam's job.
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        CredentialRequest? seenRequest = null;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seenRequest = request;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.IsNotNull(seenRequest);
        Assert.HasCount(1, seenRequest!.DiVpProofs);
        Assert.IsEmpty(seenRequest.Proofs, "A di_vp proof surfaces in DiVpProofs, not the string Proofs map.");
    }


    /// <summary>
    /// The design-validating remote path. A holder whose DID is <c>did:web</c> is resolved end-to-end
    /// through the library's <see cref="DidResolver"/> seam: the validator threads the credential
    /// endpoint's <see cref="ExchangeContext"/> into <see cref="DidResolver.ResolveAsync"/>, the
    /// did:web method handler fetches the holder's <c>did.json</c> through the SSRF-policed
    /// <see cref="OutboundFetch"/> chokepoint (a mocked single-hop transport, no real network), and
    /// the resolved document anchors the Appendix F.2 holder-binding proof. The proof verifies and
    /// issuance proceeds — proving the holder binding works over the async, SSRF-policed remote
    /// resolution path, not just the local did:key derivation.
    /// </summary>
    [TestMethod]
    public async Task RemoteDidWebHolderResolvesThroughSsrfPolicyAndVerifies()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;

        //The holder is a did:web. WebDidBuilder mints the document served at the did:web URL; the
        //presentation is signed under that document's authentication verification method.
        DidDocument holderDidDocument = await WebDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            DidWebHolderDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        //The did:web document the canned transport serves at https://holder.web.test/.well-known/did.json.
        string didJson = SerializeDidDocument(holderDidDocument);
        using CannedDidJsonHandler handler = new(DidWebHolderDocumentUrl, didJson);
        using HttpClient httpClient = new(handler, disposeHandler: false);
        DidResolver webResolver = BuildFetchingWebDidResolver(httpClient);

        WireDiVpExpectationSeam(host, webResolver);
        bool seamIssued = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamIssued = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
        Assert.IsTrue(seamIssued, "A di_vp proof whose did:web holder resolves over the remote path must let issuance proceed.");

        //Direct check: the same remote resolution authenticates the did:web holder verification method.
        DiVpProofValidationResult directResult = await CredentialProofValidator.ValidateDiVpAsync(
            SerializePresentation(signedPresentation),
            CredentialNonce,
            issuerIdentifier,
            BuildDiVpVerification(webResolver),
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(directResult.IsValid, $"Expected valid; got {directResult.FailureReason}.");
        Assert.AreEqual(holderDidDocument.VerificationMethod![0].Id, directResult.AuthenticatedVerificationMethodId,
            "The remote did:web resolution must authenticate the holder verification method the Credential binds to.");
    }


    /// <summary>
    /// The design-validating remote path over a REAL loopback socket, proving the SSRF chokepoint in
    /// BOTH directions. The holder is a <c>did:web</c> whose authority is an in-process loopback
    /// Kestrel host serving the holder's <c>did.json</c> at the computed path; the di_vp validator
    /// threads the credential endpoint's <see cref="ExchangeContext"/> into
    /// <see cref="DidResolver.ResolveAsync"/>, and the did:web method handler dereferences the holder
    /// document through the genuine <see cref="OutboundFetch.FetchAsync"/> chokepoint over an actual
    /// HTTP socket — no mocked <see cref="HttpMessageHandler"/>.
    /// <para>
    /// Assertion A — SSRF blocks. Under <see cref="OutboundFetchPolicy.SecureDefault"/>
    /// (<c>BlockPrivateAndLoopback = true</c>) the chokepoint REFUSES the loopback holder URL before
    /// any socket contact, so the holder is unresolved and §F.2 di_vp verification fails with
    /// <c>invalid_proof</c> ("the Credential Issuer MUST validate that the W3C Verifiable Presentation
    /// used as a proof is actually signed with a key in the possession of the Holder" — unresolvable).
    /// This proves the issuer cannot be coerced into fetching internal/loopback URLs.
    /// </para>
    /// <para>
    /// Assertion B — explicit permit succeeds. Under
    /// <c>new OutboundFetchPolicy { BlockPrivateAndLoopback = false }</c> the chokepoint permits the
    /// loopback dereference, the real fetch to the Kestrel host returns the holder's <c>did.json</c>,
    /// and the §F.2 proof VERIFIES over the real remote path bound to the authenticated holder key.
    /// </para>
    /// </summary>
    [TestMethod]
    public async Task RemoteDidWebHolderResolvesOverRealLoopbackSocketUnderBothPolicies()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;

        //Stand up a real loopback Kestrel (MinimalHttpHost — the lightest existing reuse that serves
        //ONE route over a real socket) that will serve the holder's did.json. The holder's did:web
        //authority is this Kestrel's host:port, with the colon percent-encoded as %3A per the did:web
        //method spec, so WebDidResolver.Resolve computes the loopback document URL the handler fetches.
        string didJsonHolder = string.Empty;
        await using MinimalHttpHost didWebHost = await MinimalHttpHost.StartAsync(
            (request, ct) => Task.FromResult(ServeDidJson(request, didJsonHolder)),
            TestContext.CancellationToken).ConfigureAwait(false);

        //did:web forbids an IP-address host, so the holder's did:web authority is the loopback host's
        //DNS name 'localhost' (which resolves to the loopback address) rather than the 127.0.0.1 literal.
        //The SSRF block under SecureDefault then fires at connection-time address pinning (localhost resolves
        //to loopback) rather than the URL gate, which is the production mechanism for a DNS-named host.
        string loopbackHostName = $"localhost:{didWebHost.BaseAddress.Port}";
        string holderWebDomain = loopbackHostName.Replace(":", "%3A", StringComparison.Ordinal);

        DidDocument holderDidDocument = await WebDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            holderWebDomain,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The handler closes over this captured string; fill it now that the document exists.
        didJsonHolder = SerializeDidDocument(holderDidDocument);

        //The handler serves the did.json at the path WebDidResolver computes (a did:web with no path
        //component resolves to /.well-known/did.json). Compute it to assert the route lines up.
        string computedDocumentUrl = WebDidResolver.Resolve(holderDidDocument.Id!.ToString());
        Assert.AreEqual("/.well-known/did.json", new Uri(computedDocumentUrl).AbsolutePath,
            "The holder did:web with no path component must resolve to /.well-known/did.json.");

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        //The did:web method handler dereferences the holder document through the genuine OutboundFetch
        //chokepoint, driving a real-HttpClient single-hop transport bound to the loopback Kestrel.
        using HttpClient httpClient = new();
        DidResolver webResolver = BuildLoopbackFetchingWebDidResolver(httpClient, didWebHost.BaseAddress);

        WireDiVpExpectationSeam(host, webResolver);
        bool seamIssued = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamIssued = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        //Assertion A — SSRF blocks. SecureDefault refuses the loopback holder fetch at the chokepoint
        //before any socket contact, so §F.2 verification fails invalid_proof (holder unresolved) and
        //the issuance seam is never consulted. The issuer cannot be made to fetch a loopback URL.
        ExchangeContext blockedContext = new();
        blockedContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        ServerHttpResponse blockedResponse = await DispatchDiVpAsync(
            host, material, signedPresentation, blockedContext).ConfigureAwait(false);

        Assert.AreEqual(400, blockedResponse.StatusCode, blockedResponse.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, blockedResponse.Body);
        Assert.IsFalse(seamIssued,
            "Under SecureDefault the loopback holder fetch is refused by the SSRF guard, so the di_vp " +
            "proof is rejected before issuance — the issuer cannot be coerced to fetch a loopback URL.");

        //Direct check of the SAME blocked path: the refusal surfaces specifically as HolderUnresolved
        //(the §F.2 binding cannot be anchored), not some other failure reason.
        ExchangeContext blockedDirectContext = new();
        blockedDirectContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);
        DiVpProofValidationResult blockedResult = await CredentialProofValidator.ValidateDiVpAsync(
            SerializePresentation(signedPresentation),
            CredentialNonce,
            issuerIdentifier,
            BuildDiVpVerification(webResolver),
            blockedDirectContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(blockedResult.IsValid, "The SSRF-refused loopback holder must not verify.");
        Assert.AreEqual(DiVpProofValidationFailureReason.HolderUnresolved, blockedResult.FailureReason,
            "The SecureDefault refusal of the loopback fetch must surface as HolderUnresolved, " +
            "not a signature/challenge/domain failure.");

        //Assertion B — explicit permit succeeds. Relaxing BlockPrivateAndLoopback lets the chokepoint
        //permit the loopback dereference; the real socket fetch returns the holder did.json and the
        //§F.2 proof verifies over the real remote path, so issuance proceeds bound to the holder key.
        ExchangeContext permittedContext = new();
        permittedContext.SetOutboundFetchPolicy(new OutboundFetchPolicy { BlockPrivateAndLoopback = false });

        ServerHttpResponse permittedResponse = await DispatchDiVpAsync(
            host, material, signedPresentation, permittedContext).ConfigureAwait(false);

        Assert.AreEqual(200, permittedResponse.StatusCode, permittedResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(permittedResponse.Body);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
        Assert.IsTrue(seamIssued,
            "Under the explicit loopback permit the real socket fetch resolves the did:web holder, so " +
            "the §F.2 di_vp proof verifies and issuance proceeds.");

        //Direct check of the SAME permitted path: the real loopback resolution authenticates the
        //did:web holder verification method the issued Credential binds to (Appendix F.2).
        ExchangeContext permittedDirectContext = new();
        permittedDirectContext.SetOutboundFetchPolicy(new OutboundFetchPolicy { BlockPrivateAndLoopback = false });
        DiVpProofValidationResult permittedResult = await CredentialProofValidator.ValidateDiVpAsync(
            SerializePresentation(signedPresentation),
            CredentialNonce,
            issuerIdentifier,
            BuildDiVpVerification(webResolver),
            permittedDirectContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(permittedResult.IsValid, $"Expected valid; got {permittedResult.FailureReason}.");
        Assert.AreEqual(holderDidDocument.VerificationMethod![0].Id, permittedResult.AuthenticatedVerificationMethodId,
            "The real loopback did:web resolution must authenticate the holder verification method " +
            "the Credential binds to.");
    }


    //Wires the opt-in di_vp expectation seam: the expected c_nonce plus the DI verification seams.
    private static void WireDiVpExpectationSeam(TestHostShell host, DidResolver resolver)
    {
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().ResolveCredentialProofExpectationAsync =
            (request, accessToken, registration, context, ct) =>
                ValueTask.FromResult<CredentialProofExpectation?>(new CredentialProofExpectation
                {
                    ExpectedNonce = CredentialNonce,
                    IsNonceRequired = true,
                    IsProofRequired = true,
                    DiVpVerification = BuildDiVpVerification(resolver)
                });
    }


    //Composes the di_vp verification seams from the same library primitives the signing side uses.
    //The holder is resolved through the library's DidResolver seam: the validator derives the holder
    //DID from the presentation and resolves it through the supplied resolver, threading the endpoint's
    //ExchangeContext so a remote did:web holder is fetched under the context's SSRF policy.
    private static DiVpProofVerification BuildDiVpVerification(DidResolver resolver) =>
        new()
        {
            Deserialize = DiVpProofJsonExtensions.CreateDiVpPresentationDeserializer(JsonOptions),
            Resolver = resolver,
            Canonicalize = JcsCanonicalizer,
            ContextResolver = null,
            DecodeProofValue = ProofValueDecoder,
            SerializePresentation = SerializePresentation,
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            MemoryPool = Pool
        };


    //Flips a tripwire when issuance runs, proving the di_vp check rejected before the seam.
    private static bool WireSeamTripwire(TestHostShell host)
    {
        bool consulted = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                consulted = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        return consulted;
    }


    //Builds the holder's did:key DID document for signing. The Multikey verification-method type and
    //the suppressed default context match what KeyDidResolver.Build derives on the verify side, so the
    //verification method id the presentation is signed under resolves through the DidResolver seam.
    private async Task<DidDocument> BuildHolderDidDocumentAsync(PublicKeyMemory holderPublic) =>
        await KeyDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    //Serializes a DID document to the did.json bytes a did:web endpoint serves.
    private static string SerializeDidDocument(DidDocument document) =>
        JsonSerializerExtensions.Serialize(document, JsonOptions);


    //Builds a DidResolver whose did:web handler fetches the holder's did.json through the guarded
    //OutboundFetch chokepoint (reading the SSRF OutboundFetchPolicy off the threaded ExchangeContext)
    //and parses it into a DidDocument. WebDidResolver computes the URL; the fetch + parse — the work a
    //network DID method does — lives in test/application code per the library's transport-agnostic
    //discipline. A real deployment supplies this same shape.
    private static DidResolver BuildFetchingWebDidResolver(HttpClient httpClient)
    {
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);

        async ValueTask<DidResolutionResult> ResolveWebDidAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken ct)
        {
            string documentUrl = WebDidResolver.Resolve(did);
            OutboundRequest request = new()
            {
                Target = new Uri(documentUrl),
                Method = "GET"
            };

            OutboundFetchResult fetch;
            try
            {
                fetch = await OutboundFetch
                    .FetchAsync(request, context, transport, ct)
                    .ConfigureAwait(false);
            }
            catch(SsrfBlockedException)
            {
                //The connection-time pin refused the host under the policy: a not-found from the resolver's
                //perspective, which surfaces as HolderUnresolved through the di_vp binding.
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            if(!fetch.IsFetched || fetch.Response is not { StatusCode: 200 } response)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            DidDocument? document = JsonSerializerExtensions.Deserialize<DidDocument>(
                Encoding.UTF8.GetString(response.Body.Memory.Span), JsonOptions);
            if(document is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            return DidResolutionResult.Success(document, DidDocumentMetadata.Empty, "application/did+json");
        }

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, ResolveWebDidAsync)));
    }


    //Resolves a host name to its IP addresses for the connection-time SSRF pin. 'localhost' resolves to the
    //loopback address, which SecureDefault classifies as blocked and the explicit permit allows.
    private static async ValueTask<IReadOnlyList<System.Net.IPAddress>> ResolveHostAsync(
        string host, CancellationToken cancellationToken)
    {
        System.Net.IPAddress[] addresses = await System.Net.Dns
            .GetHostAddressesAsync(host, cancellationToken)
            .ConfigureAwait(false);

        return addresses;
    }


    //Serves the holder did.json at /.well-known/did.json on the loopback Kestrel and 404s any other
    //path — the route a did:web with no path component resolves to (WebDidResolver.Resolve).
    private static MinimalHttpResponse ServeDidJson(MinimalHttpRequest request, string didJson)
    {
        if(!string.Equals(request.Path, "/.well-known/did.json", StringComparison.Ordinal))
        {
            return new MinimalHttpResponse { StatusCode = 404 };
        }

        return new MinimalHttpResponse
        {
            StatusCode = 200,
            ContentType = "application/did+json",
            Body = didJson
        };
    }


    //Builds a DidResolver whose did:web handler dereferences the holder did.json through the genuine
    //OutboundFetch chokepoint over a REAL HTTP socket. WebDidResolver.Resolve computes the canonical
    //https://<authority>/.well-known/did.json URL; the policy on the threaded ExchangeContext gates
    //that genuine URL (so SecureDefault's loopback block fires honestly). The single-hop transport
    //then dials the in-process loopback Kestrel, which serves plain http — the same reason
    //TestHostShell.LoopbackOutboundFetchPolicy exists — so it rewrites the scheme to the listener's
    //before hitting the socket. The fetch + parse — the work a network DID method does — lives in
    //test/application code per the library's transport-agnostic discipline.
    private static DidResolver BuildLoopbackFetchingWebDidResolver(HttpClient httpClient, Uri loopbackBase)
    {
        OutboundTransportDelegate singleHop = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);

        //The resolved did:web URL is https://localhost:<port>/...; the loopback Kestrel listens on plain
        //http. Because the host is a DNS name (localhost), the SecureDefault SSRF block is the connection-time
        //half: resolve the host and reject if any resolved address is loopback/private. Pinning runs first, so
        //a SecureDefault policy refuses the loopback fetch before the socket dial; under the explicit permit it
        //passes. After pinning, rebind the scheme (and only the scheme) to the listener's so the real socket
        //dial reaches the in-process host. The chokepoint has already evaluated the genuine https URL.
        OutboundTransportDelegate transport = async (request, context, ct) =>
        {
            _ = await SsrfHardenedTransport.ResolveAndPinAsync(
                request.Target.Host, context.OutboundFetchPolicy, ResolveHostAsync, ct).ConfigureAwait(false);

            UriBuilder rebased = new(request.Target) { Scheme = loopbackBase.Scheme };
            OutboundRequest rebasedRequest = request with { Target = rebased.Uri };

            return await singleHop(rebasedRequest, context, ct).ConfigureAwait(false);
        };

        async ValueTask<DidResolutionResult> ResolveWebDidAsync(
            string did, DidResolutionOptions options, ExchangeContext context, CancellationToken ct)
        {
            string documentUrl = WebDidResolver.Resolve(did);
            OutboundRequest request = new()
            {
                Target = new Uri(documentUrl),
                Method = "GET"
            };

            OutboundFetchResult fetch;
            try
            {
                fetch = await OutboundFetch
                    .FetchAsync(request, context, transport, ct)
                    .ConfigureAwait(false);
            }
            catch(SsrfBlockedException)
            {
                //The connection-time pin refused the host under the policy: a not-found from the resolver's
                //perspective, which surfaces as HolderUnresolved through the di_vp binding.
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            if(!fetch.IsFetched || fetch.Response is not { StatusCode: 200 } response)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            DidDocument? document = JsonSerializerExtensions.Deserialize<DidDocument>(
                Encoding.UTF8.GetString(response.Body.Memory.Span), JsonOptions);
            if(document is null)
            {
                return DidResolutionResult.Failure(DidResolutionErrors.NotFound);
            }

            return DidResolutionResult.Success(document, DidDocumentMetadata.Empty, "application/did+json");
        }

        return new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.WebDidMethodPrefix, ResolveWebDidAsync)));
    }


    //A canned single-hop transport that serves one did.json at one URL and refuses any other target,
    //so the test exercises the resolve → guarded fetch → parse path with no real network.
    private sealed class CannedDidJsonHandler(string documentUrl, string didJson): HttpMessageHandler
    {
        private string DocumentUrl { get; } = documentUrl;
        private string DidJson { get; } = didJson;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if(!string.Equals(request.RequestUri?.ToString(), DocumentUrl, StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(DidJson)
            });
        }
    }


    //Mints a holder-signed presentation with the given challenge (c_nonce) and domain (issuer id),
    //proofPurpose authentication — the exact SignAsync composition the presentation flow uses.
    private async Task<DataIntegritySecuredPresentation> SignPresentationAsync(
        DidDocument holderDidDocument, PrivateKeyMemory holderPrivate, string challenge, string domain)
    {
        string holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();
        DateTime proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid
        }.SignAsync(
            holderPrivate,
            holderVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            challenge,
            domain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueEncoder,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Mints the access token via the Pre-Authorized Code grant and dispatches a §8.2 Credential
    //Request carrying the di_vp presentation to the Credential Endpoint with a fresh context.
    private async Task<ServerHttpResponse> DispatchDiVpAsync(
        TestHostShell host, VerifierKeyMaterial material, DataIntegritySecuredPresentation presentation) =>
        await DispatchDiVpAsync(host, material, presentation, new ExchangeContext()).ConfigureAwait(false);


    //Mints the access token via the Pre-Authorized Code grant and dispatches a §8.2 Credential
    //Request carrying the di_vp presentation to the Credential Endpoint. The credential call's
    //ExchangeContext is supplied by the caller so a test can place an OutboundFetchPolicy on it —
    //the validator threads exactly this context into DidResolver.ResolveAsync, so the policy
    //governs the holder's did:web fetch through the OutboundFetch SSRF chokepoint.
    private async Task<ServerHttpResponse> DispatchDiVpAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        DataIntegritySecuredPresentation presentation,
        ExchangeContext credentialContext)
    {
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);
        string accessToken = tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        string presentationJson = SerializePresentation(presentation);
        string body = "{\"credential_configuration_id\":\"" + ConfigurationId
            + "\",\"proofs\":{\"di_vp\":[" + presentationJson + "]}}";

        RequestHeaders headers = new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
        });

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential,
            "POST",
            new RequestFields(),
            headers,
            body,
            credentialContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
