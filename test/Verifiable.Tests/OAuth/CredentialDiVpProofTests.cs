using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Outbound;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Json;
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
/// <see cref="MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync"/>.
/// </remarks>
[TestClass]
internal sealed class CredentialDiVpProofTests
{
    /// <summary>The MSTest context, whose cancellation token bounds every dispatch these tests make.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The host's clock, fixed at the canonical epoch.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool the did:key resolver and the verification delegates rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The wallet client identifier the credential issuer tenant is registered under.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the credential issuer tenant is registered under.</summary>
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");

    /// <summary>The end-user subject the pre-authorized code grant is issued for.</summary>
    private const string OfferSubject = "urn:uuid:end-user-42";

    /// <summary>The <c>credential_configuration_id</c> the credential requests name.</summary>
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";

    /// <summary>The <c>c_nonce</c> the server expects as the presentation proof's <c>challenge</c>.</summary>
    private const string CredentialNonce = "c-nonce-di-vp-42";

    /// <summary>The opaque credential the issuance seam returns once the key proof verifies.</summary>
    private const string IssuedCredential = "issued-credential-opaque-42";

    /// <summary>The domain of the did:web holder.</summary>
    private const string DidWebHolderDomain = "holder.web.test";

    /// <summary>The <c>did.json</c> location the did:web method maps the did:web holder to.</summary>
    private const string DidWebHolderDocumentUrl = "https://holder.web.test/.well-known/did.json";

    /// <summary>The capabilities of the credential issuer tenant: the grants and the §8 Credential Endpoint.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> CredentialCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);

    /// <summary>The serializer options every JSON delegate of these tests uses.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds a did:key holder document from its public key.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>Builds a did:web holder document from its public key and domain.</summary>
    private static WebDidBuilder WebDidBuilder { get; } = new(BaseMemoryPool.Shared);

    /// <summary>
    /// The library's DID-resolution seam wired for the did:key holder — the same construction
    /// Oid4VpSchemeFixtures uses for the decentralized_identifier: path. The holder did:key
    /// self-describes, so the resolver derives the holder DID document locally with no network.
    /// </summary>
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    /// <summary>The same delegate sourcing DataIntegrityPresentationFlowTests uses — composed, not re-rolled.</summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    /// <summary>The context the holder signs its presentations under, outside any request.</summary>
    private static ExchangeContext EmptyContext { get; } = [];

    /// <summary>Encodes the holder's proof values as base58btc.</summary>
    private static ProofValueEncoderDelegate ProofValueEncoder { get; } = ProofValueCodecs.EncodeBase58Btc;

    /// <summary>Decodes the base58btc proof values the holder encodes.</summary>
    private static ProofValueDecoderDelegate ProofValueDecoder { get; } = ProofValueCodecs.DecodeBase58Btc;

    /// <summary>Serializes a presentation for signing, verification and the wire.</summary>
    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    /// <summary>Reads a presentation back from its JSON.</summary>
    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    /// <summary>Serializes the proof options a Data Integrity proof hashes.</summary>
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        await WireDiVpExpectationSeamAsync(host, KeyDidResolverSeam).ConfigureAwait(false);
        bool seamIssued = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    seamIssued = true;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        //The presentation is signed with a stale c_nonce; the server expects CredentialNonce.
        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, "c-nonce-STALE", issuerIdentifier).ConfigureAwait(false);

        await WireDiVpExpectationSeamAsync(host, KeyDidResolverSeam).ConfigureAwait(false);
        bool seamConsulted = await WireSeamTripwireAsync(host).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        //The presentation's domain is some other audience, not the resolved Credential Issuer.
        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, "https://attacker.example").ConfigureAwait(false);

        await WireDiVpExpectationSeamAsync(host, KeyDidResolverSeam).ConfigureAwait(false);
        bool seamConsulted = await WireSeamTripwireAsync(host).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

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

        await WireDiVpExpectationSeamAsync(host, KeyDidResolverSeam).ConfigureAwait(false);
        bool seamConsulted = await WireSeamTripwireAsync(host).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

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

        await WireDiVpExpectationSeamAsync(host, KeyDidResolverSeam).ConfigureAwait(false);
        bool seamConsulted = await WireSeamTripwireAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
        Assert.IsFalse(seamConsulted, "A non-authentication di_vp proofPurpose must be rejected before the issuance seam.");
    }


    /// <summary>
    /// Adversarial — controller indirection. The resolved holder document's
    /// <c>authentication</c> verification method is the SAME key that genuinely signs the
    /// presentation (so relationship-scoped resolution and the signature both succeed), but the
    /// resolved method's own <c>controller</c> names a DIFFERENT identity than the presentation's
    /// <c>holder</c> — the <c>did:web</c>-aliasing / controller-indirection shape the ratified
    /// controller-RESOLUTION semantics deliberately reject. Appendix F.2's "signed with a key in the
    /// possession of the Holder" is not enough on its own: the resolved method must also be
    /// CONTROLLED by the claimed holder. The compile-time seam means
    /// <see cref="DiVpProofValidationResult.AuthenticatedVerificationMethodId"/> can only ever be
    /// populated from a <see cref="BoundProvenance"/> the verify path itself minted — there is no
    /// Asserted fallback to smuggle an unbound identity through even at the type level.
    /// </summary>
    [TestMethod]
    public async Task DiVpWithControllerIndirectionHolderIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;

        DidDocument honestHolderDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        //A document identical to the honest one EXCEPT the authentication method's controller names a
        //DIFFERENT identity. The resolved method is genuinely the holder's own document entry (so
        //relationship-scoped resolution succeeds, and the genuine key signs), but controller
        //indirection means it is not actually controlled by the claimed holder -- only a resolver
        //bug/compromise could hand this back for a real did:key, which is exactly the shape the
        //controller check defends against regardless of how the mismatch arose.
        DidDocument controllerIndirectionDocument = new()
        {
            Id = honestHolderDocument.Id,
            VerificationMethod =
            [
                new VerificationMethod
                {
                    Id = honestHolderDocument.VerificationMethod![0].Id,
                    Type = honestHolderDocument.VerificationMethod[0].Type,
                    Controller = "did:example:attacker-controls-this-key",
                    KeyFormat = honestHolderDocument.VerificationMethod[0].KeyFormat
                }
            ],
            Authentication = honestHolderDocument.Authentication
        };

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            honestHolderDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        DidResolver controllerIndirectionResolver = BuildCannedKeyDidResolver(controllerIndirectionDocument);
        await WireDiVpExpectationSeamAsync(host, controllerIndirectionResolver).ConfigureAwait(false);
        bool seamConsulted = await WireSeamTripwireAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiVpAsync(host, material, signedPresentation).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
        Assert.IsFalse(seamConsulted,
            "Controller indirection on the resolved holder document must be rejected before the issuance seam.");

        //Direct check: the same controller-indirection document is refused with the specific reason.
        DiVpProofValidationResult directResult = await CredentialProofValidator.ValidateDiVpAsync(
            SerializePresentation(signedPresentation),
            CredentialNonce,
            issuerIdentifier,
            BuildDiVpVerification(controllerIndirectionResolver),
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(directResult.IsValid, "A controller-indirection holder document must not verify.");
        Assert.AreEqual(DiVpProofValidationFailureReason.HolderControllerMismatch, directResult.FailureReason);
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;
        DidDocument holderDidDocument = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        //No expectation seam at all — the §F.4 / §F.2 check is entirely the issuance seam's job.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
        }).ConfigureAwait(false);

        CredentialRequest? seenRequest = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    seenRequest = request;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

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
        string didJson = DidDocumentWireFixtures.SerializeDidDocument(holderDidDocument, JsonOptions);
        using CannedDidJsonHandler handler = new(DidWebHolderDocumentUrl, didJson);
        using HttpClient httpClient = new(handler, disposeHandler: false);
        DidResolver webResolver = BuildFetchingWebDidResolver(httpClient);

        await WireDiVpExpectationSeamAsync(host, webResolver).ConfigureAwait(false);
        bool seamIssued = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    seamIssued = true;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

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
        didJsonHolder = DidDocumentWireFixtures.SerializeDidDocument(holderDidDocument, JsonOptions);

        //The handler serves the did.json at the path WebDidResolver computes (a did:web with no path
        //component resolves to /.well-known/did.json). Compute it to assert the route lines up.
        string computedDocumentUrl = WebDidResolver.Resolve(holderDidDocument.Id!.ToString());
        Assert.AreEqual("/.well-known/did.json", new Uri(computedDocumentUrl).AbsolutePath,
            "The holder did:web with no path component must resolve to /.well-known/did.json.");

        DataIntegritySecuredPresentation signedPresentation = await SignPresentationAsync(
            holderDidDocument, holderPrivate, CredentialNonce, issuerIdentifier).ConfigureAwait(false);

        //The did:web method handler dereferences the holder document through the genuine OutboundFetch
        //chokepoint, driving a real-HttpClient single-hop transport bound to the loopback Kestrel,
        //pinned to its certificate rather than a CA — there is no CA in this loopback topology.
        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(didWebHost.Certificate);
        DidResolver webResolver = BuildLoopbackFetchingWebDidResolver(httpClient, didWebHost.BaseAddress);

        await WireDiVpExpectationSeamAsync(host, webResolver).ConfigureAwait(false);
        bool seamIssued = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    seamIssued = true;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

        //Assertion A — SSRF blocks. SecureDefault refuses the loopback holder fetch at the chokepoint
        //before any socket contact, so §F.2 verification fails invalid_proof (holder unresolved) and
        //the issuance seam is never consulted. The issuer cannot be made to fetch a loopback URL.
        ExchangeContext blockedContext = [];
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
        ExchangeContext blockedDirectContext = [];
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
        ExchangeContext permittedContext = [];
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
        ExchangeContext permittedDirectContext = [];
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


    /// <summary>
    /// Installs the expected presentation-binding checks on the admitted credential-issuer wiring, verifying di_vp proofs
    /// through <see cref="BuildDiVpVerification(DidResolver)"/> over <paramref name="resolver"/>.
    /// </summary>
    /// <param name="host">The host shell whose credential issuer is wired.</param>
    /// <param name="resolver">The DID resolver the holder is resolved through.</param>
    private static Task WireDiVpExpectationSeamAsync(TestHostShell host, DidResolver resolver) =>
        WireDiVpExpectationSeamAsync(host, BuildDiVpVerification(resolver));


    /// <summary>
    /// Installs the expected presentation-binding checks on the admitted credential-issuer wiring, verifying di_vp proofs
    /// through <paramref name="verification"/>.
    /// </summary>
    /// <param name="host">The host shell whose credential issuer is wired.</param>
    /// <param name="verification">The di_vp verification seams.</param>
    private static async Task WireDiVpExpectationSeamAsync(TestHostShell host, DiVpProofVerification verification)
    {
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();

            candidateIntegration.ResolveCredentialProofExpectationAsync =
                (request, accessToken, registration, context, ct) =>
                    ValueTask.FromResult<CredentialProofExpectation?>(new CredentialProofExpectation
                    {
                        ExpectedNonce = CredentialNonce,
                        IsNonceRequired = true,
                        IsProofRequired = true,
                        DiVpVerification = verification
                    });
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Composes the di_vp verification seams from the same library primitives the signing side uses.
    /// The holder is resolved through the library's DidResolver seam: the validator derives the holder
    /// DID from the presentation and resolves it through the supplied resolver, threading the endpoint's
    /// ExchangeContext so a remote did:web holder is fetched under the context's SSRF policy.
    /// </summary>
    private static DiVpProofVerification BuildDiVpVerification(DidResolver resolver) =>
        new()
        {
            Deserialize = DiVpProofJsonExtensions.CreateDiVpPresentationDeserializer(JsonOptions),
            Resolver = resolver,
            Canonicalize = JcsCanonicalizer,
            ContextResolver = null,
            KnownContext = Context.FromIris(Context.Credentials20),
            DecodeProofValue = ProofValueDecoder,
            SerializePresentation = SerializePresentation,
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            MemoryPool = Pool
        };


    /// <summary>
    /// Installs a rejecting proof-verification seam so a test can detect whether proof processing reaches it.
    /// </summary>
    private static async Task<bool> WireSeamTripwireAsync(TestHostShell host)
    {
        bool consulted = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    consulted = true;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

        return consulted;
    }


    /// <summary>
    /// Builds the holder's did:key DID document for signing. The Multikey verification-method type and
    /// the suppressed default context match what KeyDidResolver.Build derives on the verify side, so the
    /// verification method id the presentation is signed under resolves through the DidResolver seam.
    /// </summary>
    private async Task<DidDocument> BuildHolderDidDocumentAsync(PublicKeyMemory holderPublic) =>
        await KeyDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// A resolver that hands back the SAME supplied document for any did:key lookup, regardless of
    /// whether it is what a real did:key derivation would produce. Used only to inject a
    /// controller-indirection document a genuine did:key resolution could never yield (did:key is
    /// self-describing) -- isolating the controller check from the resolution mechanics.
    /// </summary>
    private static DidResolver BuildCannedKeyDidResolver(DidDocument document) =>
        new(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix,
             (did, options, context, ct) =>
                 ValueTask.FromResult(DidResolutionResult.Success(document, DidDocumentMetadata.Empty, "application/did+json")))));


    /// <summary>
    /// Builds a DidResolver whose did:web handler fetches the holder's did.json through the guarded
    /// OutboundFetch chokepoint (reading the SSRF OutboundFetchPolicy off the threaded ExchangeContext)
    /// and parses it into a DidDocument. WebDidResolver computes the URL; the fetch + parse — the work a
    /// network DID method does — lives in test/application code per the library's transport-agnostic
    /// discipline. A real deployment supplies this same shape.
    /// </summary>
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


    /// <summary>
    /// Resolves a host name to its IP addresses for the connection-time SSRF pin. 'localhost' resolves to the
    /// loopback address, which SecureDefault classifies as blocked and the explicit permit allows.
    /// </summary>
    private static async ValueTask<IReadOnlyList<System.Net.IPAddress>> ResolveHostAsync(
        string host, CancellationToken cancellationToken)
    {
        System.Net.IPAddress[] addresses = await System.Net.Dns
            .GetHostAddressesAsync(host, cancellationToken)
            .ConfigureAwait(false);

        return addresses;
    }


    /// <summary>
    /// Serves the holder did.json at /.well-known/did.json on the loopback Kestrel and 404s any other
    /// path — the route a did:web with no path component resolves to (WebDidResolver.Resolve).
    /// </summary>
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


    /// <summary>
    /// Builds a DidResolver whose did:web handler dereferences the holder did.json through the genuine
    /// OutboundFetch chokepoint over a REAL HTTPS socket. WebDidResolver.Resolve computes the canonical
    /// https://&lt;authority&gt;/.well-known/did.json URL; the policy on the threaded ExchangeContext gates
    /// that genuine URL (so SecureDefault's loopback block fires against the real request, not a stand-in). The
    /// single-hop transport then dials the in-process loopback Kestrel over HTTPS with the pinned handler carried
    /// on httpClient (LoopbackTls.CreatePinnedHttpClient) — the resolved did:web authority is 'localhost:{port}',
    /// which already matches the listener's own https scheme, so no scheme rewrite is needed. The fetch + parse —
    /// the work a network DID method does — lives in test/application code per the library's
    /// transport-agnostic discipline.
    /// </summary>
    private static DidResolver BuildLoopbackFetchingWebDidResolver(HttpClient httpClient, Uri loopbackBase)
    {
        OutboundTransportDelegate singleHop = GuardedHttpClientTransport.BuildSingleHopTransport(httpClient);

        //The resolved did:web URL is https://localhost:<port>/..., matching the loopback Kestrel's own
        //https listener. Because the host is a DNS name (localhost), the SecureDefault SSRF block is the
        //connection-time half: resolve the host and reject if any resolved address is loopback/private.
        //Pinning runs first, so a SecureDefault policy refuses the loopback fetch before the socket dial;
        //under the explicit permit it passes. The scheme rebind below is now a no-op (both sides are
        //https) but stays, since the chokepoint evaluates the resolved URL's scheme independently of
        //whatever the transport ultimately dials.
        async ValueTask<OutboundResponse> transport(OutboundRequest request, ExchangeContext context, CancellationToken ct)
        {
            _ = await SsrfHardenedTransport.ResolveAndPinAsync(
                request.Target.Host, context.OutboundFetchPolicy, ResolveHostAsync, ct).ConfigureAwait(false);

            UriBuilder rebased = new(request.Target) { Scheme = loopbackBase.Scheme };
            OutboundRequest rebasedRequest = request with { Target = rebased.Uri };

            return await singleHop(rebasedRequest, context, ct).ConfigureAwait(false);
        }

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


    /// <summary>
    /// A canned single-hop transport that serves one did.json at one URL and refuses any other target,
    /// so the test exercises the resolve → guarded fetch → parse path with no real network.
    /// </summary>
    private sealed class CannedDidJsonHandler(string documentUrl, string didJson): HttpMessageHandler
    {
        /// <summary>The one absolute URL this handler serves the canned document at.</summary>
        private string DocumentUrl { get; } = documentUrl;

        /// <summary>The canned <c>did.json</c> text served at <see cref="DocumentUrl"/>.</summary>
        private string DidJson { get; } = didJson;

        /// <summary>Serves <see cref="DidJson"/> at <see cref="DocumentUrl"/> and a 404 for any other target.</summary>
        /// <remarks>
        /// Ownership of the returned <see cref="HttpResponseMessage"/> transfers to the caller through the
        /// <see cref="HttpMessageHandler"/> pipeline, the standard shape for this override: the pipeline disposes it,
        /// not this method.
        /// </remarks>
        /// <param name="request">The outgoing request.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
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


    /// <summary>
    /// Mints a holder-signed presentation with the given challenge (c_nonce) and domain (issuer id),
    /// proofPurpose authentication — the exact SignAsync composition the presentation flow uses.
    /// </summary>
    private async Task<DataIntegritySecuredPresentation> SignPresentationAsync(
        DidDocument holderDidDocument, PrivateKeyMemory holderPrivate, string challenge, string domain)
    {
        string holderVerificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();
        DateTime proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await new VerifiablePresentation
        {
            Context = Context.FromIris(Context.Credentials20),
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
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see>:
    /// if one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
    /// an error MUST be raised. The credential endpoint reports invalid_proof before issuance.
    /// </summary>
    [TestMethod]
    [DataRow("type")]
    [DataRow("verificationMethod")]
    [DataRow("proofPurpose")]
    public async Task DiVpMissingProofOptionYieldsInvalidProofOverHttp(string member)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;
        DidDocument holder = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);
        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            holder, holderPrivate, CredentialNonce, material.Registration.IssuerUri!.OriginalString).ConfigureAwait(false);
        System.Text.Json.Nodes.JsonObject document = System.Text.Json.Nodes.JsonNode.Parse(SerializePresentation(presentation))!.AsObject();
        System.Text.Json.Nodes.JsonObject proof = DataIntegrityContextTamperingFixture.FirstProof(document);
        _ = proof.Remove(member);
        bool isResolverConsulted = false;
        DidResolver resolver = new(DidMethodSelectors.FromResolvers((WellKnownDidMethodPrefixes.KeyDidMethodPrefix,
            (did, options, context, cancellationToken) =>
            {
                isResolverConsulted = true;

                return KeyDidResolverSeam.ResolveAsync(did, context, options, cancellationToken);
            }
        )));

        await WireDiVpExpectationSeamAsync(host, resolver).ConfigureAwait(false);
        (int statusCode, string responseBody, bool isIssuanceConsulted) = await PostDiVpCredentialRequestOverHttpAsync(
            host, material, document.ToJsonString()).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, responseBody);
        using JsonDocument error = JsonDocument.Parse(responseBody);
        Assert.AreEqual("invalid_proof", error.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(isIssuanceConsulted, "An incomplete proof must never reach issuance.");
        Assert.IsFalse(isResolverConsulted, "The JSON consumer must reject incomplete proof options before resolution.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.2">OID4VCI 1.0
    /// Appendix F.2</see>: "The Credential Issuer MUST validate that the W3C Verifiable Presentation used as a proof is
    /// actually signed with a key in the possession of the Holder." A di_vp presentation whose Data Integrity proof cannot
    /// be verified, because the JSON-LD context load its transformation needs ended on its own budget and the loader
    /// reported that cancellation inside an exception of its own, was not shown to be so signed: its key proof is invalid,
    /// which <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">§8.3.1.2</see>
    /// names <c>invalid_proof</c>, "The proofs parameter in the Credential Request is invalid: ... (2) one of the provided
    /// key proofs is invalid". The Credential Endpoint answers that over the real wire before issuance, never letting the
    /// cancellation escape.
    /// </summary>
    [TestMethod]
    public async Task DiVpContextLoadEndingOnItsOwnBudgetYieldsInvalidProofOverHttp()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;
        DidDocument holder = await BuildHolderDidDocumentAsync(holderPublic).ConfigureAwait(false);
        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            holder, holderPrivate, CredentialNonce, material.Registration.IssuerUri!.OriginalString).ConfigureAwait(false);

        bool hasLiveCallerToken = false;
        ValueTask<string?> LoadContextOnExpiredBudgetAsync(Uri contextUri, ExchangeContext context, CancellationToken cancellationToken)
        {
            hasLiveCallerToken = !cancellationToken.IsCancellationRequested;

            return ValueTask.FromException<string?>(
                new IOException("private-policy-host/path", new OperationCanceledException("private-policy-host/path")));
        }

        //The RDFC canonicalizer loads the presentation's contexts through the loader, so the transformation reaches it.
        DiVpProofVerification verification = BuildDiVpVerification(KeyDidResolverSeam) with
        {
            Canonicalize = CanonicalizationTestUtilities.CreateRdfcCanonicalizer(),
            ContextResolver = LoadContextOnExpiredBudgetAsync
        };
        await WireDiVpExpectationSeamAsync(host, verification).ConfigureAwait(false);

        (int statusCode, string responseBody, bool isIssuanceConsulted) = await PostDiVpCredentialRequestOverHttpAsync(
            host, material, SerializePresentation(presentation)).ConfigureAwait(false);

        Assert.IsTrue(hasLiveCallerToken, "The context load must end while the request is still live.");
        Assert.AreEqual(400, statusCode, responseBody);
        using JsonDocument error = JsonDocument.Parse(responseBody);
        Assert.AreEqual("invalid_proof", error.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(responseBody.Contains("private-policy-host/path", StringComparison.Ordinal),
            "The loader's cancellation reason must never leak into the response.");
        Assert.IsFalse(isIssuanceConsulted, "A key proof that could not be verified must never reach issuance.");
    }


    /// <summary>
    /// Over the real HTTPS loopback host: grants the pre-authorized code, mints an access token at the token endpoint and
    /// posts a §8.2 Credential Request carrying <paramref name="presentationJson"/> as its one di_vp key proof, returning
    /// the Credential Endpoint's status and body and whether the issuance seam was consulted.
    /// </summary>
    /// <param name="host">The host shell whose credential issuer the di_vp seams are already wired on.</param>
    /// <param name="material">The registered wallet client the request is made for.</param>
    /// <param name="presentationJson">The di_vp presentation JSON the request carries.</param>
    /// <returns>The response status, the response body and whether issuance was consulted.</returns>
    private async Task<(int StatusCode, string Body, bool IsIssuanceConsulted)> PostDiVpCredentialRequestOverHttpAsync(
        TestHostShell host, VerifierKeyMaterial material, string presentationJson)
    {
        bool isIssuanceConsulted = false;
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.ValidatePreAuthorizedCodeAsync = (_, _, _, _, _, _) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));
            integration.IssueCredentialAsync = (_, _, _, _, _) =>
            {
                isIssuanceConsulted = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer serving = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        using FormUrlEncodedContent tokenRequest = new(new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
            [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
        });
        Uri tokenUrl = new(serving.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciPreAuthorizedToken, segment));
        using HttpResponseMessage tokenResponse = await serving.SharedHttpClient!.PostAsync(tokenUrl, tokenRequest, TestContext.CancellationToken).ConfigureAwait(false);
        string tokenBody = await tokenResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)tokenResponse.StatusCode, tokenBody);
        using JsonDocument token = JsonDocument.Parse(tokenBody);
        string body = "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"di_vp\":[" + presentationJson + "]}}";
        Uri credentialUrl = new(serving.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciCredential, segment));
        using HttpRequestMessage request = new(HttpMethod.Post, credentialUrl)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString());
        using HttpResponseMessage response = await serving.SharedHttpClient.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, responseBody, isIssuanceConsulted);
    }


    /// <summary>
    /// Mints the access token via the Pre-Authorized Code grant and dispatches a §8.2 Credential
    /// Request carrying the di_vp presentation to the Credential Endpoint with a fresh context.
    /// </summary>
    private async Task<ServerHttpResponse> DispatchDiVpAsync(
        TestHostShell host, VerifierKeyMaterial material, DataIntegritySecuredPresentation presentation) =>
        await DispatchDiVpAsync(host, material, presentation, []).ConfigureAwait(false);


    /// <summary>
    /// Submits the configured presentation-proof request and returns the credential endpoint response for assertions.
    /// </summary>
    private async Task<ServerHttpResponse> DispatchDiVpAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        DataIntegritySecuredPresentation presentation,
        ExchangeContext credentialContext)
    {
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            [],
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
