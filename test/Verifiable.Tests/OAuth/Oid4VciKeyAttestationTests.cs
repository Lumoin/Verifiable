using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using System.Text.Json;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 Appendix D key attestations: the firewall-safe <see cref="KeyAttestationParser"/>
/// reads a <c>key-attestation+jwt</c> body, and the Credential Endpoint enforces PRESENCE of an
/// attestation (standalone <c>attestation</c> proof or a <c>key_attestation</c>-headed <c>jwt</c>
/// proof) when the requested configuration declares <c>key_attestations_required</c>. Signature
/// and Wallet-Provider trust verification remain the application's, inside the issuance seam.
/// </summary>
[TestClass]
internal sealed class Oid4VciKeyAttestationTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string IssuedCredential = "eyJhbGciOiJFUzI1NiJ9.body.sig";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static ImmutableHashSet<CapabilityIdentifier> IssuanceCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);


    [TestMethod]
    public void ParserReadsKeyAttestationBody()
    {
        string header = "{\"typ\":\"key-attestation+jwt\",\"alg\":\"ES256\"}";
        string body =
            "{\"iat\":1700000000,\"exp\":1700003600,"
            + "\"key_storage\":[\"iso_18045_moderate\"],"
            + "\"user_authentication\":[\"iso_18045_moderate\"],"
            + "\"nonce\":\"c-nonce-42\","
            + "\"attested_keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\","
            + "\"y\":\"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}]}";
        string attestation = BuildJwt(header, body);

        bool parsed = KeyAttestationParser.TryParse(attestation, TestSetup.Base64UrlDecoder, Pool, out KeyAttestation? result);

        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        Assert.AreEqual("c-nonce-42", result.Nonce);
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(1700000000), result.IssuedAt);
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(1700003600), result.ExpiresAt);
        Assert.Contains("iso_18045_moderate", result.KeyStorageJson!);
        Assert.Contains("TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc", result.AttestedKeysJson);
    }


    [TestMethod]
    public void ParserRejectsWrongTypOrMissingAttestedKeys()
    {
        //Wrong typ.
        Assert.IsFalse(KeyAttestationParser.TryParse(
            BuildJwt("{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\"}", "{\"attested_keys\":[{}]}"),
            TestSetup.Base64UrlDecoder, Pool, out _));

        //Right typ but no attested_keys (REQUIRED).
        Assert.IsFalse(KeyAttestationParser.TryParse(
            BuildJwt("{\"typ\":\"key-attestation+jwt\",\"alg\":\"ES256\"}", "{\"iat\":1700000000}"),
            TestSetup.Base64UrlDecoder, Pool, out _));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see>: "A
    /// recipient using the media type value MUST treat it as if 'application/' were prepended to any
    /// 'typ' value not containing a '/'," and media type values are case insensitive per RFC 2045. The
    /// long <c>application/key-attestation+jwt</c> form, in any casing, names the same media type as
    /// the short <c>typ</c> form the parser requires; a genuinely different type such as
    /// <c>application/jwt</c> still does not parse.
    /// </summary>
    [TestMethod]
    public void ParserAcceptsTheKeyAttestationTypSpelledAsItsLongMediaTypeFormOrAnyCasing()
    {
        string body =
            "{\"iat\":1700000000,\"attested_keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\","
            + "\"y\":\"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}]}";

        Assert.IsTrue(KeyAttestationParser.TryParse(
            BuildJwt("{\"typ\":\"application/key-attestation+jwt\",\"alg\":\"ES256\"}", body),
            TestSetup.Base64UrlDecoder, Pool, out KeyAttestation? longForm));
        Assert.IsNotNull(longForm);

        Assert.IsTrue(KeyAttestationParser.TryParse(
            BuildJwt("{\"typ\":\"APPLICATION/KEY-ATTESTATION+JWT\",\"alg\":\"ES256\"}", body),
            TestSetup.Base64UrlDecoder, Pool, out KeyAttestation? upperCasedLongForm));
        Assert.IsNotNull(upperCasedLongForm);

        Assert.IsFalse(KeyAttestationParser.TryParse(
            BuildJwt("{\"typ\":\"application/jwt\",\"alg\":\"ES256\"}", body),
            TestSetup.Base64UrlDecoder, Pool, out KeyAttestation? wrongType));
        Assert.IsNull(wrongType);
    }


    /// <summary>
    /// RFC 7515 §4: "Header Parameter names MUST be unique." A header repeating <c>kid</c> —
    /// the attacker's value first, the honest value last — is refused, while the SAME document
    /// with the repetition removed parses normally: the refusal is attributable to the
    /// repetition alone, not to anything else about the header or body.
    /// </summary>
    [TestMethod]
    public void ParserRejectsDuplicateKidInHeaderButAcceptsTheSameHeaderOnce()
    {
        string body =
            "{\"iat\":1700000000,\"exp\":1700003600,"
            + "\"attested_keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\","
            + "\"y\":\"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}]}";

        string duplicateHeader =
            "{\"typ\":\"key-attestation+jwt\",\"alg\":\"ES256\",\"kid\":\"attacker-key\",\"kid\":\"wallet-key-1\"}";
        Assert.IsFalse(KeyAttestationParser.TryParse(
            BuildJwt(duplicateHeader, body), TestSetup.Base64UrlDecoder, Pool, out KeyAttestation? rejected));
        Assert.IsNull(rejected);

        string singleHeader = "{\"typ\":\"key-attestation+jwt\",\"alg\":\"ES256\",\"kid\":\"wallet-key-1\"}";
        Assert.IsTrue(KeyAttestationParser.TryParse(
            BuildJwt(singleHeader, body), TestSetup.Base64UrlDecoder, Pool, out KeyAttestation? accepted));
        Assert.IsNotNull(accepted);
    }


    [TestMethod]
    public async Task AttestationRequiredWithKeyAttestationHeaderIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, keyAttestationsRequired: true).ConfigureAwait(false);
        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        string attestationJwt = BuildAttestationJwt();
        string jwtProof = BuildJwt(
            "{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\",\"key_attestation\":\"" + attestationJwt + "\"}",
            "{\"aud\":\"x\",\"iat\":1700000000}");

        ServerHttpResponse response = await DispatchAsync(host, material, accessToken,
            CredentialRequestBody("jwt", jwtProof)).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    [TestMethod]
    public async Task AttestationRequiredWithStandaloneAttestationProofIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, keyAttestationsRequired: true).ConfigureAwait(false);
        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchAsync(host, material, accessToken,
            CredentialRequestBody("attestation", BuildAttestationJwt())).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    [TestMethod]
    public async Task AttestationRequiredButMissingIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, keyAttestationsRequired: true).ConfigureAwait(false);
        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //A plain jwt proof with no key_attestation header and no standalone attestation.
        string jwtProof = BuildJwt(
            "{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\"}", "{\"aud\":\"x\",\"iat\":1700000000}");

        ServerHttpResponse response = await DispatchAsync(host, material, accessToken,
            CredentialRequestBody("jwt", jwtProof)).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
    }


    [TestMethod]
    public async Task AttestationNotRequiredAcceptsPlainProof()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, keyAttestationsRequired: false).ConfigureAwait(false);
        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        string jwtProof = BuildJwt(
            "{\"typ\":\"openid4vci-proof+jwt\",\"alg\":\"ES256\"}", "{\"aud\":\"x\",\"iat\":1700000000}");

        ServerHttpResponse response = await DispatchAsync(host, material, accessToken,
            CredentialRequestBody("jwt", jwtProof)).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    private static string BuildJwt(string headerJson, string bodyJson) =>
        TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson))
        + "." + TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(bodyJson))
        + ".sig";


    private static string BuildAttestationJwt() =>
        BuildJwt(
            "{\"typ\":\"key-attestation+jwt\",\"alg\":\"ES256\"}",
            "{\"iat\":1700000000,\"exp\":1700003600,\"attested_keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\","
            + "\"y\":\"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}]}");


    /// <summary>
    /// Registers an issuer with the test capabilities and installs its issuance delegates.
    /// </summary>
    private static async Task<VerifierKeyMaterial> RegisterIssuerAsync(TestHostShell host, bool keyAttestationsRequired)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);

        Dictionary<string, object> jwtProofConfig = new(StringComparer.Ordinal);
        if(keyAttestationsRequired)
        {
            jwtProofConfig["key_attestations_required"] = new Dictionary<string, object>(StringComparer.Ordinal);
        }

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [ConfigurationId] = new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["format"] = "dc+sd-jwt",
                            ["proof_types_supported"] = new Dictionary<string, object>(StringComparer.Ordinal)
                            {
                                ["jwt"] = jwtProofConfig
                            }
                        }
                    }
                });
        }).ConfigureAwait(false);

        return material;
    }


    private static string CredentialRequestBody(string proofType, string proof) =>
        "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
        + "\"proofs\":{\"" + proofType + "\":[\"" + proof + "\"]}}";


    private async Task<ServerHttpResponse> DispatchAsync(
        TestHostShell host, VerifierKeyMaterial material, string accessToken, string jsonBody)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential,
            "POST",
            new RequestFields(),
            new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
            }),
            jsonBody,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Completes the fixture token exchange and returns an access token for the credential endpoint request.
    /// </summary>
    private async Task<string> MintAccessTokenAsync(TestHostShell host, VerifierKeyMaterial material)
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

        Assert.AreEqual((int)HttpStatusCode.OK, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }
}
