using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The OPT-IN library-side Appendix F.4 proof enforcement at the §8 Credential Endpoint, driven
/// through the real dispatch pipeline. With the
/// <see cref="AuthorizationServerIntegration.ResolveCredentialProofExpectationAsync"/> seam wired,
/// the library validates the §8.2 <c>proofs.jwt</c> batch BEFORE the issuance seam: a good proof
/// issues, a bad-nonce proof yields the §8.3.1.2 <c>invalid_nonce</c> error before issuance. The
/// existing default-path Credential Endpoint tests (no expectation seam) stay green — proven there.
/// </summary>
[TestClass]
internal sealed class CredentialProofEnforcementFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string CredentialNonce = "c-nonce-enforcement-42";
    private const string IssuedCredential = "issued-credential-opaque-42";

    private static ImmutableHashSet<CapabilityIdentifier> CredentialCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);

    private static System.Text.Json.JsonSerializerOptions JoseSerializationOptions { get; } =
        new(TestSetup.DefaultSerializationOptions)
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, JoseSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, JoseSerializationOptions);


    /// <summary>
    /// With the proof-expectation seam wired, a Credential Request carrying a production-minted
    /// proof bound to the resolved issuer <c>aud</c> and the expected <c>c_nonce</c> passes §F.4
    /// validation and issues.
    /// </summary>
    [TestMethod]
    public async Task GoodProofPassesLibraryValidationAndIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host).ConfigureAwait(false);
        _ = await WireIssuanceAsync(host).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, CredentialNonce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAsync(host, material, proof).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1">Appendix
    /// F.1</see>: "<c>jwk</c>: OPTIONAL. JOSE Header containing the key material the new Credential is to
    /// be bound to." Through the real dispatch pipeline, an Ed25519 (OKP) holder key proof — whose
    /// header <c>jwk</c> carries <c>kty</c>/<c>crv</c>/<c>x</c>, not the EC-only <c>y</c> member — passes
    /// §F.4 validation and issues.
    /// </summary>
    [TestMethod]
    public async Task GoodProofWithAnEd25519HolderKeyPassesLibraryValidationAndIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host, acceptableAlgorithms: [WellKnownJwaValues.EdDsa]).ConfigureAwait(false);
        _ = await WireIssuanceAsync(host).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        var keys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;
        string proof = await MintProofAsync(holderPrivate, holderPublic, issuerAudience, CredentialNonce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAsync(host, material, proof).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(IssuedCredential,
            doc.RootElement.GetProperty("credentials")[0].GetProperty("credential").GetString());
    }


    /// <summary>
    /// §8.3.1.2: a proof echoing a stale <c>c_nonce</c> is rejected by the library with
    /// <c>invalid_nonce</c> BEFORE the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task BadNonceProofYieldsInvalidNonceBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host).ConfigureAwait(false);

        bool seamConsulted = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    seamConsulted = true;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, "c-nonce-STALE").ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAsync(host, material, proof).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidNonce, response.Body);
        Assert.IsFalse(seamConsulted, "Library §F.4 enforcement must reject the bad nonce before the issuance seam.");
    }


    /// <summary>
    /// §8.3.1.2: a proof whose signature does not verify is rejected by the library with
    /// <c>invalid_proof</c> before the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task TamperedProofYieldsInvalidProofBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host).ConfigureAwait(false);

        bool seamConsulted = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    seamConsulted = true;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, CredentialNonce).ConfigureAwait(false);

        int signatureStart = proof.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((proof.Length - signatureStart) / 2);
        char tampered = proof[tamperIndex] == 'A' ? 'B' : 'A';
        string tamperedProof = string.Concat(
            proof.AsSpan(0, tamperIndex), tampered.ToString(), proof.AsSpan(tamperIndex + 1));

        ServerHttpResponse response = await DispatchAsync(host, material, tamperedProof).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
        Assert.IsFalse(seamConsulted, "Library §F.4 enforcement must reject the bad signature before the issuance seam.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>: "A
    /// recipient using the media type value MUST treat it as if 'application/' were prepended to any
    /// 'typ' value not containing a '/'," and media type values are case insensitive per RFC 2045. A
    /// proof whose <c>typ</c> is spelled as the long <c>application/openid4vci-proof+jwt</c> form, in
    /// any casing, still passes §F.4 validation and issues; a proof naming a genuinely different type
    /// is refused with the <c>invalid_proof</c> error the endpoint gives for a wrong type.
    /// </summary>
    [TestMethod]
    public async Task ProofTypSpelledAsTheLongMediaTypeFormOrAnyCasingStillIssuesAndADifferentTypIsStillRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host).ConfigureAwait(false);
        _ = await WireIssuanceAsync(host).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;

        foreach(string typ in new[]
        {
            "application/" + Oid4VciProofIssuance.ProofJwtType,
            ("application/" + Oid4VciProofIssuance.ProofJwtType).ToUpperInvariant()
        })
        {
            var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PublicKeyMemory holderPublic = keys.PublicKey;
            using PrivateKeyMemory holderPrivate = keys.PrivateKey;
            string proof = await MintProofWithTypAsync(
                holderPrivate, holderPublic, issuerAudience, CredentialNonce, typ).ConfigureAwait(false);

            ServerHttpResponse response = await DispatchAsync(host, material, proof).ConfigureAwait(false);

            Assert.AreEqual(200, response.StatusCode, $"typ '{typ}' should be accepted: {response.Body}");
        }

        var wrongTypeKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongTypePublic = wrongTypeKeys.PublicKey;
        using PrivateKeyMemory wrongTypePrivate = wrongTypeKeys.PrivateKey;
        string wrongTypeProof = await MintProofWithTypAsync(
            wrongTypePrivate, wrongTypePublic, issuerAudience, CredentialNonce, WellKnownMediaTypes.Application.Jwt)
            .ConfigureAwait(false);

        ServerHttpResponse refused = await DispatchAsync(host, material, wrongTypeProof).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, refused.Body);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI
    /// 1.0 Section 8.3.1.2</see> names <c>invalid_proof</c> for a Credential Request one of whose key proofs is
    /// invalid, and <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>
    /// says: "If any of the listed steps fails, then the signature or MAC cannot be validated." The JWK converter
    /// reads every verification key it yields to an algorithm the test registry serves, so the pair this row
    /// presents is the key-agreement reading of a P-256 public key: a proof signed under <c>ES256</c> whose header
    /// <c>jwk</c> carries <c>"use":"enc"</c> names (P-256, key agreement), a pair the registry serves no
    /// verification function for. Sent over the wire, the Credential Request is answered 400 with the error
    /// <c>invalid_proof</c>, never a server fault. The status and the error code are what this row holds; the
    /// description names the reason the Credential Endpoint's key proof validation gives for a proof that does not verify.
    /// </summary>
    [TestMethod]
    public async Task ProofUnderAKeyAgreementPublicKeyIsAnInvalidProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host).ConfigureAwait(false);
        _ = await WireIssuanceAsync(host).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;
        string proof = await MintProofWithTypAsync(
            holderPrivate, holderPublic, issuerAudience, CredentialNonce, Oid4VciProofIssuance.ProofJwtType,
            jwkUse: WellKnownJwkValues.UseEnc).ConfigureAwait(false);

        (HttpStatusCode statusCode, string body) = await PostOverWireAsync(host, material, proof).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_proof", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("A jwt key proof failed validation: SignatureFailed (Appendix F.4).",
            document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI
    /// 1.0 Section 8.3.1.2</see> names <c>invalid_proof</c> for a Credential Request one of whose key proofs is
    /// invalid. A key proof of <see cref="Jws.DefaultMaxJwsLength"/> + 1 characters, longer than the longest
    /// compact JWS this library verifies (its own guard against a large allocation, stated by no
    /// specification), is such a proof: sent over the wire, the Credential Request is answered 400 with the error
    /// <c>invalid_proof</c>, never a server fault. The status and the error code are what this row holds; the
    /// description names the reason the Credential Endpoint's key proof validation gives for a proof that does not verify.
    /// </summary>
    [TestMethod]
    public async Task OversizedProofIsMalformedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host).ConfigureAwait(false);
        _ = await WireIssuanceAsync(host).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, CredentialNonce).ConfigureAwait(false);
        string oversizedProof = proof + new string('A', Jws.DefaultMaxJwsLength + 1 - proof.Length);
        Assert.AreEqual(Jws.DefaultMaxJwsLength + 1, oversizedProof.Length);

        (HttpStatusCode statusCode, string body) = await PostOverWireAsync(host, material, oversizedProof).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_proof", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("A jwt key proof failed validation: SignatureFailed (Appendix F.4).",
            document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see>, step 7:
    /// "Base64url-decode the encoded representation of the JWS Signature, following the restriction that no line
    /// breaks, whitespace, or other additional characters have been used."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">Section 2</see> defines the encoding: "Base64
    /// encoding using the URL- and filename-safe character set defined in Section 5 of RFC 4648 [RFC4648], with all
    /// trailing '=' characters omitted (as permitted by Section 3.2) and without the inclusion of any line breaks,
    /// whitespace, or other additional characters." A correctly signed key proof whose signature segment carries
    /// <c>==</c> after it is no such encoding, so its signature cannot be validated, and
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI
    /// 1.0 Section 8.3.1.2</see> names <c>invalid_proof</c> for a Credential Request one of whose key proofs is
    /// invalid: sent over the wire, the Credential Request is answered 400 with the error <c>invalid_proof</c>.
    /// </summary>
    /// <returns>A task that completes when the answer was asserted.</returns>
    [TestMethod]
    public async Task PaddedProofSignatureIsAnInvalidProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities).ConfigureAwait(false);

        await WireProofExpectationSeamAsync(host).ConfigureAwait(false);
        _ = await WireIssuanceAsync(host).ConfigureAwait(false);

        string issuerAudience = material.Registration.IssuerUri!.OriginalString;
        string proof = await MintProofAsync(issuerAudience, CredentialNonce).ConfigureAwait(false);
        Assert.AreEqual(2, (proof.Length - proof.LastIndexOf('.', StringComparison.Ordinal) - 1) % 4, "The 64-octet signature segment is 86 characters, which padding would end with '=='.");

        (HttpStatusCode statusCode, string body) = await PostOverWireAsync(host, material, proof + "==").ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.BadRequest, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_proof", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// Installs proof-binding expectations through a requested alteration so issuance can enforce them.
    /// </summary>
    /// <param name="host">The test host to alter.</param>
    /// <param name="acceptableAlgorithms">
    /// The §F.4 <c>proof_signing_alg_values_supported</c> set the seam accepts; defaults to the P-256
    /// <c>ES256</c> holder key algorithm the majority of this file's tests mint with.
    /// </param>
    private static async Task WireProofExpectationSeamAsync(TestHostShell host, IReadOnlyCollection<string>? acceptableAlgorithms = null)
    {
        IReadOnlyCollection<string> algorithms = acceptableAlgorithms ?? [WellKnownJwaValues.Es256];

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.ResolveCredentialProofExpectationAsync =
                (request, accessToken, registration, context, ct) =>
                    ValueTask.FromResult<CredentialProofExpectation?>(new CredentialProofExpectation
                    {
                        ExpectedNonce = CredentialNonce,
                        IsNonceRequired = true,
                        AcceptableProofSigningAlgorithms = algorithms,
                        IatSkew = TimeSpan.FromMinutes(5),
                        IsProofRequired = true
                    });
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Installs the credential-issuance delegate that observes whether a proof permits issuance.
    /// </summary>
    private static async Task<bool> WireIssuanceAsync(TestHostShell host)
    {
        bool issued = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync =
                (request, accessToken, registration, context, ct) =>
                {
                    issued = true;

                    return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
                };
        }).ConfigureAwait(false);

        return issued;
    }


    //Mints a §F.1 jwt proof with the production minter, bound to the given aud + nonce, using a fresh
    //P-256 holder key.
    private async Task<string> MintProofAsync(string audience, string nonce)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = keys.PublicKey;
        using PrivateKeyMemory holderPrivate = keys.PrivateKey;

        return await MintProofAsync(holderPrivate, holderPublic, audience, nonce).ConfigureAwait(false);
    }


    //Mints a §F.1 jwt proof with the production minter for a caller-supplied holder key, bound to the
    //given aud + nonce.
    private async Task<string> MintProofAsync(
        PrivateKeyMemory holderPrivate, PublicKeyMemory holderPublic, string audience, string nonce) =>
        await Oid4VciProofIssuance.BuildJwtProofAsync(
            holderPrivate,
            holderPublic,
            audience,
            nonce,
            TimeProvider.GetUtcNow(),
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Mints an Appendix F.1 <c>jwt</c> proof carrying a caller-chosen <c>typ</c>, otherwise built exactly as
    /// <see cref="Oid4VciProofIssuance.BuildJwtProofAsync"/> builds it, to exercise a header the production
    /// minter itself never emits.
    /// </summary>
    /// <param name="holderPrivate">The holder's private key the proof is signed with.</param>
    /// <param name="holderPublic">The holder's public key the header <c>jwk</c> carries.</param>
    /// <param name="audience">The <c>aud</c> claim.</param>
    /// <param name="nonce">The <c>nonce</c> claim.</param>
    /// <param name="typ">The <c>typ</c> header parameter.</param>
    /// <param name="jwkUse">A <c>use</c> member added to the header <c>jwk</c>, or <see langword="null"/> for none.</param>
    /// <returns>The compact proof.</returns>
    private async Task<string> MintProofWithTypAsync(
        PrivateKeyMemory holderPrivate, PublicKeyMemory holderPublic, string audience, string nonce, string typ,
        string? jwkUse = null)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(holderPrivate.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(holderPublic, algorithm, TestSetup.Base64UrlEncoder);

        Dictionary<string, object> jwkHeaderMember = new(jwk.Count + 1, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> member in jwk)
        {
            jwkHeaderMember[member.Key] = member.Value;
        }

        if(jwkUse is not null)
        {
            jwkHeaderMember[WellKnownJwkMemberNames.Use] = jwkUse;
        }

        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = typ,
            [Oid4VciCredentialParameterNames.Jwk] = jwkHeaderMember
        };

        JwtPayload payload = new(capacity: 3)
        {
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Nonce] = nonce,
            [WellKnownJwtClaimNames.Iat] = TimeProvider.GetUtcNow().ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            holderPrivate, HeaderSerializer, PayloadSerializer, TestSetup.Base64UrlEncoder, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Submits a credential request with the supplied proof and returns the endpoint response for assertions.
    /// </summary>
    private async Task<ServerHttpResponse> DispatchAsync(
        TestHostShell host, VerifierKeyMaterial material, string proof)
    {
        string accessToken = await ObtainAccessTokenAsync(host, material).ConfigureAwait(false);

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
            CredentialRequestBody(proof),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Submits a credential request with the supplied proof over the host's HTTPS listener through its pinned
    /// client, the transport a wallet uses, and returns the status and the body the wire carried.
    /// </summary>
    /// <param name="host">The test host whose listener is started and whose Credential Endpoint is posted to.</param>
    /// <param name="material">The registered client the access token is minted for.</param>
    /// <param name="proof">The compact <c>jwt</c> key proof the request carries.</param>
    /// <returns>The HTTP status code and the response body.</returns>
    private async Task<(HttpStatusCode StatusCode, string Body)> PostOverWireAsync(
        TestHostShell host, VerifierKeyMaterial material, string proof)
    {
        string accessToken = await ObtainAccessTokenAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Uri credentialUrl = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciCredential, material.Registration.TenantId.Value));
        using StringContent content = new(CredentialRequestBody(proof), Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, credentialUrl) { Content = content };
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, "Bearer " + accessToken);

        using HttpResponseMessage response = await host.Host("default").SharedHttpClient!
            .SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return (response.StatusCode, body);
    }


    /// <summary>
    /// The JSON Credential Request for <see cref="ConfigurationId"/> carrying <paramref name="proof"/> as its one
    /// <c>proofs.jwt</c> entry.
    /// </summary>
    /// <param name="proof">The compact <c>jwt</c> key proof.</param>
    /// <returns>The request body.</returns>
    private static string CredentialRequestBody(string proof) =>
        "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"" + proof + "\"]}}";


    /// <summary>
    /// Mints a plain bearer access token for <paramref name="material"/>'s client through the pre-authorized
    /// code grant, dispatched in process, so a credential request can present it.
    /// </summary>
    /// <param name="host">The test host whose token endpoint issues the token.</param>
    /// <param name="material">The registered client the token is minted for.</param>
    /// <returns>The access token.</returns>
    private async Task<string> ObtainAccessTokenAsync(TestHostShell host, VerifierKeyMaterial material)
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

        return tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }
}
