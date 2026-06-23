using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side OID4VCI 1.0 §8 Credential Endpoint, driven through the real dispatch pipeline.
/// The Wallet presents the access token the Pre-Authorized Code grant minted plus its key
/// proof(s); the library validates the bearer token (§8.3.1.1), parses the §8.2 request, and
/// hands it to the <see cref="IssueCredentialDelegate"/> seam, which verifies the proofs and
/// mints. The library owns the wire — the §8.3 <c>credentials</c> response and the §8.3.1.2
/// Credential Error Response — while the seam owns the issuance and the §8.3.1.2 distinctions.
/// </summary>
[TestClass]
internal sealed class Oid4VciCredentialEndpointTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The Wallet client identifier registered for the credential tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");

    /// <summary>The End-User the offered Credential is about — the grant-bound subject.</summary>
    private const string OfferSubject = "urn:uuid:end-user-42";

    /// <summary>The requested Credential Configuration id.</summary>
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";

    /// <summary>A representative holder key proof (the library does not verify it; the seam does).</summary>
    private const string HolderProof = "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCJ9.eyJub25jZSI6Im4ifQ.sig";

    /// <summary>The issued SD-JWT VC the seam returns; the library echoes it verbatim.</summary>
    private const string IssuedCredential =
        "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJVbml2ZXJzaXR5RGVncmVlIn0.sig~WyJzYWx0IiwiZGVncmVlIiwiQmFjaGVsb3IiXQ~";

    /// <summary>
    /// The capabilities the Credential Endpoint needs, plus the grant + RFC 9068 producer
    /// capabilities used to mint the access token the endpoint then validates.
    /// </summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> CredentialCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);


    /// <summary>
    /// A wired Credential Endpoint validates the bearer token, parses the §8.2 request, and
    /// returns the seam-minted Credential in the §8.3 <c>credentials</c> array, uncacheable. The
    /// seam receives the validated access-token subject (the grant-bound End-User) and the
    /// parsed request verbatim.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialsBoundToTheValidatedAccessTokenSubject()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        CredentialRequest? seenRequest = null;
        string? seenSubject = null;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seenRequest = request;
                seenSubject = accessToken.TryGetValue("sub", out object? s) ? s as string : null;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, CredentialRequestBody(HolderProof))
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        //§8.3 example carries Cache-Control: no-store.
        Assert.IsTrue(response.Headers.TryGetValue(WellKnownHttpHeaderNames.CacheControl, out string? cacheControl),
            "The Credential Response MUST carry Cache-Control.");
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement credentials = doc.RootElement.GetProperty("credentials");
        Assert.AreEqual(JsonValueKind.Array, credentials.ValueKind);
        Assert.AreEqual(1, credentials.GetArrayLength());
        Assert.AreEqual(IssuedCredential, credentials[0].GetProperty("credential").GetString());

        //§8.3.1.1: the issued Credential is about the End-User the grant bound the token to.
        Assert.AreEqual(OfferSubject, seenSubject, "The seam must receive the validated access-token subject.");

        Assert.IsNotNull(seenRequest);
        Assert.AreEqual(ConfigurationId, seenRequest!.CredentialConfigurationId);
        Assert.IsTrue(seenRequest.Proofs.TryGetValue("jwt", out IReadOnlyList<string>? jwtProofs),
            "The parsed request must carry the jwt proofs.");
        Assert.HasCount(1, jwtProofs!);
        Assert.AreEqual(HolderProof, jwtProofs![0]);
    }


    /// <summary>
    /// §8.2: "The proofs parameter contains exactly one parameter named as the proof type in
    /// Appendix F." A proofs object carrying two proof-type members is malformed and answered
    /// <c>invalid_credential_request</c> before the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task ProofsWithTwoProofTypeMembersIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        bool seamCalled = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string body = "{\"credential_configuration_id\":\"" + ConfigurationId
            + "\",\"proofs\":{\"jwt\":[\"" + HolderProof + "\"],\"attestation\":[\"" + HolderProof + "\"]}}";

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, body).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, response.Body);
        Assert.IsFalse(seamCalled, "A proofs object with two proof-type members must not reach the seam.");
    }


    /// <summary>
    /// §8.2: "the value set for this parameter is a non-empty array." A proofs object whose proof
    /// type carries an empty array is malformed and answered <c>invalid_credential_request</c>; a
    /// single proof type with a non-empty array is accepted.
    /// </summary>
    [TestMethod]
    public async Task ProofsWithEmptyArrayIsRejectedAndNonEmptyIsAccepted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string emptyArrayBody = "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[]}}";

        ServerHttpResponse rejected = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, emptyArrayBody).ConfigureAwait(false);

        Assert.AreEqual(400, rejected.StatusCode, rejected.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, rejected.Body);

        ServerHttpResponse accepted = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, CredentialRequestBody(HolderProof)).ConfigureAwait(false);

        Assert.AreEqual(200, accepted.StatusCode, accepted.Body);
    }


    /// <summary>
    /// OID4VCI 1.0 Appendix F.2 / §8.2 <c>di_vp</c>: "its value being a non-empty array of W3C
    /// Verifiable Presentations ... where each ... W3C Verifiable Presentation is formed as defined
    /// in Appendix F.2." A <c>di_vp</c> proof is an object, not a string; the parser preserves it
    /// into <see cref="CredentialRequest.DiVpProofs"/> rather than dropping it, and the seam sees it.
    /// </summary>
    [TestMethod]
    public async Task DiVpObjectProofSurvivesParsingIntoTheRequestModel()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        CredentialRequest? seenRequest = null;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seenRequest = request;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //An Appendix F.2 di_vp proof — a W3C Verifiable Presentation JSON object — as the single
        //proof type. Before the fix this object-valued entry was silently dropped.
        const string presentation =
            "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],\"type\":[\"VerifiablePresentation\"],"
            + "\"holder\":\"did:example:holder\",\"proof\":{\"type\":\"DataIntegrityProof\","
            + "\"cryptosuite\":\"eddsa-rdfc-2022\",\"challenge\":\"n\",\"domain\":\"https://issuer.example\"}}";
        string body = "{\"credential_configuration_id\":\"" + ConfigurationId
            + "\",\"proofs\":{\"di_vp\":[" + presentation + "]}}";

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, body).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.IsNotNull(seenRequest);
        Assert.HasCount(1, seenRequest!.DiVpProofs);
        Assert.IsEmpty(seenRequest.Proofs, "A di_vp proof surfaces in DiVpProofs, not the string Proofs map.");

        using JsonDocument doc = JsonDocument.Parse(seenRequest.DiVpProofs[0]);
        Assert.AreEqual("VerifiablePresentation", doc.RootElement.GetProperty("type")[0].GetString(),
            "The di_vp presentation object is preserved verbatim into the request model.");
    }


    /// <summary>
    /// Each §8.3.1.2 refusal the seam returns maps to its Credential Error Response code with
    /// HTTP 400 and <c>Cache-Control: no-store</c> — the seam owns the distinctions only it can
    /// make (unknown configuration, invalid proof, invalid nonce, request denied).
    /// </summary>
    [TestMethod]
    public async Task SeamRefusalsMapToTheSpecCredentialErrorResponses()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string bearer = "Bearer " + accessToken;

        await AssertRefusalAsync(host, material, bearer,
            CredentialIssuanceDecision.Deny(CredentialRequestError.UnknownCredentialConfiguration),
            Oid4VciCredentialErrors.UnknownCredentialConfiguration).ConfigureAwait(false);

        await AssertRefusalAsync(host, material, bearer,
            CredentialIssuanceDecision.Deny(CredentialRequestError.UnknownCredentialIdentifier),
            Oid4VciCredentialErrors.UnknownCredentialIdentifier).ConfigureAwait(false);

        await AssertRefusalAsync(host, material, bearer,
            CredentialIssuanceDecision.Deny(CredentialRequestError.InvalidProof),
            Oid4VciCredentialErrors.InvalidProof).ConfigureAwait(false);

        await AssertRefusalAsync(host, material, bearer,
            CredentialIssuanceDecision.Deny(CredentialRequestError.InvalidNonce),
            Oid4VciCredentialErrors.InvalidNonce).ConfigureAwait(false);

        await AssertRefusalAsync(host, material, bearer,
            CredentialIssuanceDecision.Deny(CredentialRequestError.InvalidEncryptionParameters),
            Oid4VciCredentialErrors.InvalidEncryptionParameters).ConfigureAwait(false);

        await AssertRefusalAsync(host, material, bearer,
            CredentialIssuanceDecision.Deny(CredentialRequestError.CredentialRequestDenied),
            Oid4VciCredentialErrors.CredentialRequestDenied).ConfigureAwait(false);
    }


    /// <summary>
    /// §8.3.1.1: a Credential Request with no access token is rejected with RFC 6750
    /// <c>invalid_token</c> (401) before the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task MissingBearerTokenIsUnauthorizedBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        bool seamCalled = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, bearer: null, CredentialRequestBody(HolderProof)).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidToken, response.Body);
        Assert.IsFalse(seamCalled, "The issuance seam must not be consulted without a valid access token.");
    }


    /// <summary>
    /// A structurally malformed bearer token is rejected with <c>invalid_token</c> (401) — the
    /// library validates the AS-issued JWS before any minting.
    /// </summary>
    [TestMethod]
    public async Task MalformedBearerTokenIsUnauthorized()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, "Bearer not.a.valid.jwt", CredentialRequestBody(HolderProof))
            .ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidToken, response.Body);
    }


    /// <summary>
    /// §8.2: <c>credential_configuration_id</c> and <c>credential_identifier</c> are mutually
    /// exclusive and exactly one is required. A request carrying both is rejected with
    /// <c>invalid_credential_request</c> before the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task RequestWithBothIdentifiersIsInvalidBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        bool seamCalled = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        string body = "{\"credential_configuration_id\":\"" + ConfigurationId
            + "\",\"credential_identifier\":\"Degree-2023\",\"proofs\":{\"jwt\":[\"" + HolderProof + "\"]}}";

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, body).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, response.Body);
        Assert.IsFalse(seamCalled, "The seam must not be consulted when the §8.2 identifier shape is invalid.");
    }


    /// <summary>
    /// §8.2: the request body is <c>application/json</c>. A body the parser cannot read yields
    /// <c>invalid_credential_request</c> (400) before the issuance seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task MalformedRequestBodyIsInvalidBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        bool seamCalled = false;
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, "{ this is not valid json").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, response.Body);
        Assert.IsFalse(seamCalled, "The seam must not be consulted when the request body cannot be parsed.");
    }


    /// <summary>
    /// Fail-closed: declaring the Credential Endpoint capability and wiring the request parser
    /// but not the issuance seam leaves the candidate absent from the chain, so the request
    /// 404s rather than an endpoint that cannot mint.
    /// </summary>
    [TestMethod]
    public async Task CredentialEndpointAbsentWhenIssuanceSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CredentialCapabilities);

        //Parse seam wired, issuance seam deliberately not.
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, "Bearer " + accessToken, CredentialRequestBody(HolderProof))
            .ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired issuance seam must leave the Credential Endpoint absent (fail-closed).");
    }


    /// <summary>
    /// Wires the issuance seam to the given <paramref name="decision"/>, dispatches a
    /// well-formed Credential Request, and asserts the §8.3.1.2 error response.
    /// </summary>
    private async Task AssertRefusalAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string bearer,
        CredentialIssuanceDecision decision,
        string expectedError)
    {
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) => ValueTask.FromResult(decision);

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, bearer, CredentialRequestBody(HolderProof)).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(expectedError, response.Body);
        Assert.IsTrue(response.Headers.TryGetValue(WellKnownHttpHeaderNames.CacheControl, out string? cacheControl),
            "A Credential Error Response MUST carry Cache-Control.");
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);
    }


    /// <summary>
    /// Mints a Bearer access token through the OID4VCI Pre-Authorized Code grant, bound to
    /// <see cref="OfferSubject"/> — the token the Credential Endpoint then validates.
    /// </summary>
    private async Task<string> MintAccessTokenAsync(TestHostShell host, VerifierKeyMaterial material)
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
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Dispatches a Credential Request to the §8 Credential Endpoint with the optional
    /// <paramref name="bearer"/> on the <c>Authorization</c> header and the optional
    /// <paramref name="jsonBody"/> as the request body.
    /// </summary>
    private async Task<ServerHttpResponse> DispatchCredentialAsync(
        TestHostShell host, VerifierKeyMaterial material, string? bearer, string? jsonBody)
    {
        RequestHeaders headers = bearer is null
            ? RequestHeaders.Empty
            : new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Authorization] = [bearer]
            });

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential,
            "POST",
            new RequestFields(),
            headers,
            jsonBody,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A §8.2 Credential Request body requesting <see cref="ConfigurationId"/> with the given
    /// <paramref name="proof"/> as the single <c>jwt</c> key proof.
    /// </summary>
    private static string CredentialRequestBody(string proof) =>
        "{\"credential_configuration_id\":\"" + ConfigurationId
        + "\",\"proofs\":{\"jwt\":[\"" + proof + "\"]}}";
}
