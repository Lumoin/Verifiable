using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The flagship real-wire CIMD suite (template: <c>WebFingerCrossWireFlowTests</c>): a genuine
/// Client ID Metadata Document host (<see cref="StaticContentHost"/> or <see cref="CimdServiceHost"/>,
/// both TLS) beside the real <see cref="EndpointServer.DispatchAsync"/> authorization-server path
/// (through <see cref="TestHostShell"/>'s Kestrel host, also TLS, both pinned) — every clause this
/// class proves is exercised by bytes that crossed a real loopback socket, per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html">
/// draft-ietf-oauth-client-id-metadata-document-02</see>.
/// </summary>
/// <remarks>
/// Covers draft-ietf-oauth-client-id-metadata-document-02 clauses 003, 012, 018, 026, 027, 029, 031,
/// 032, 041, 042, 045, 046, 047, 048, 049, 050, 062, 063, 064, 065, 066, 067 — the happy-path half;
/// SSRF/cache/negative-fetch cases belong to the companion suite. Every host uses
/// <see cref="TestHostShell.StartHttpHostAsync(CancellationToken)"/>'s or
/// <see cref="StaticContentHost.StartAsync"/>'s single explicit HTTPS <c>Listen</c> convention — there
/// is no plaintext listener anywhere in this file — and every test builds its own hosts, so the suite
/// is parallel-safe.
/// </remarks>
[TestClass]
internal sealed class ClientIdMetadataDocumentCrossWireFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string SubjectId = "subject-cimd-cross-wire-01";
    private const string ClientSigningKeyId = "cimd-client-signing-key-1";

    /// <summary>
    /// The context entry under which <see cref="StartConfidentialCimdClientAsync"/>'s materialization wrapper notes
    /// the reading of the client credentials the library's materialization left carried on the request's context, so
    /// the client authentication seam's wrapper compares the reading it receives with that instance. An entry of this
    /// class's own, read by its own wrappers alone.
    /// </summary>
    private static string MaterializedReadingEntryName { get; } = "test.materializedClientCredentialReading";


    /// <summary>
    /// The public-client happy path (CIMD-003/012/018/029/032): an unregistered
    /// <c>https://…:{port}/…</c> Client Identifier URL (CIMD-003 — the port is not elided) resolves to
    /// a document served by a real TLS host; the AS fetches it (proving the wire was hit) and the
    /// materialized registration's <c>redirect_uri</c> comes ONLY from that document — a redirect_uri
    /// the document never declared is rejected BEFORE the one it did declare is accepted. PAR →
    /// authorize → callback → token completes over the real wire. A second, HAIP 1.0 client on the
    /// same document host proves RFC 9207 <c>iss</c> continuity survives the CIMD materialization
    /// overlay, byte-exact.
    /// </summary>
    [TestMethod]
    public async Task HappyPath_PublicClient_DocumentSuppliesRedirectUriAndDrivesFullFlow()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Uri redirectUri = new("https://client.example.com/callback");
        const string path = "/app";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, [redirectUri]);

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        //CIMD-012: a redirect_uri the document never declared is rejected — proving the accepted
        //redirect_uri below comes from the fetched document, not a blanket allow.
        AuthCodeFlowEndpointResult wrongRedirect = await client.AuthCode.StartParAsync(
            registration, new Uri("https://not-in-the-document.example/cb"), OAuthFormEncodedFields.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Redirect, wrongRedirect.Outcome,
            "A redirect_uri the CIMD document never declared must not be accepted.");

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        Assert.IsFalse(string.IsNullOrEmpty((string)tokenResult.Body![OAuthRequestParameterNames.AccessToken]));

        Assert.IsTrue(documentHost.WasRequested(path),
            "CIMD-029: the authorization server must have fetched the Client ID Metadata Document over the real wire.");

        //CIMD-041/CIMD-003 note: documentUri carries a port (StaticContentHost's ephemeral Kestrel
        //port), and the fetch above succeeded — the port is not a defect.

        //RFC 9207 continuity under HAIP 1.0 (FAPI 2.0 baseline): the redirect's iss must be byte-exact
        //even though the client identity AND redirect_uri came from a fetched CIMD document.
        const string haip10Path = "/app-haip10";
        Uri haip10Redirect = new("https://client.example.com/haip10-callback");
        Uri haip10DocumentUri = new(documentHost.BaseAddress, haip10Path);
        PublishCimdDocument(documentHost, haip10Path, haip10DocumentUri, [haip10Redirect]);

        ClientRecord haip10Stub = await app.RegisterCimdStubClientAsync(
            haip10DocumentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Haip10).ConfigureAwait(false);

        (OAuthClient haip10Client, ClientRegistration haip10Registration, Dictionary<string, FlowState> haip10FlowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                haip10Stub, haip10Redirect.OriginalString, profile: PolicyProfile.Haip10, TestContext.CancellationToken)
                .ConfigureAwait(false);

        (_, string haip10Location) = await DriveParAndAuthorizeAsync(
            hosted, haip10Client, haip10Registration, haip10FlowStore, haip10Stub.TenantId.Value, haip10Redirect,
            new OAuthFormEncodedFields(new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
            }),
            SubjectId, app.ServerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

        string? iss = TestBrowser.ExtractQueryParam(haip10Location, OAuthRequestParameterNames.Iss);
        Assert.IsNotNull(iss, "HAIP 1.0 (FAPI 2.0 baseline) must emit iss on the authorize redirect (RFC 9207).");
        Assert.AreEqual(haip10Registration.AuthorizationServerIssuer.OriginalString, iss,
            "RFC 9207 §2 continuity: iss must be byte-exact even though the client's identity and redirect_uri came from the fetched CIMD document.");
    }


    /// <summary>
    /// Confidential-client authentication
    /// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see>):
    /// the document declares <c>token_endpoint_auth_method: private_key_jwt</c> plus an inline <c>jwks</c>. Token
    /// exchange with NO client authentication fails 400, since every communication of a confidential client with the
    /// authorization server includes client authentication of its registered type (that section); a TAMPERED
    /// assertion signature fails 400, since that section requires client authentication according to
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 Section 2.2</see> under the public
    /// signing material the client's document publishes; a VALID <c>private_key_jwt</c> assertion authenticates and the exchange completes.
    /// Both failing attempts leave the authorization code unconsumed — client-authentication failure is
    /// checked before the code-redemption PDA transition — so all three attempts share one flow.
    /// </summary>
    [TestMethod]
    public async Task ConfidentialClient_TokenExchangeRequiresAndValidatesPrivateKeyJwtAssertion()
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync().ConfigureAwait(false);
        HttpClient http = cimd.Hosted.SharedHttpClient!;
        Dictionary<string, string> baseFields = cimd.CodeRedemptionFields();

        //No client authentication at all (draft-ietf-oauth-client-id-metadata-document-02 Section 8.2).
        using HttpResponseMessage noAssertion = await OAuthTestTransport.PostFormAsync(
            http, cimd.TokenEndpoint, baseFields, TestContext.CancellationToken).ConfigureAwait(false);
        string noAssertionBody = await noAssertion.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(400, (int)noAssertion.StatusCode, noAssertionBody);
        Assert.Contains(OAuthErrors.InvalidClient, noAssertionBody);

        string validAssertion = await cimd.SignAssertionAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //A tampered assertion signature fails RFC 7523 Section 2.2 verification.
        Dictionary<string, string> tamperedFields = new(baseFields, StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientAssertion] = TamperSignature(validAssertion)
        };
        using HttpResponseMessage tampered = await OAuthTestTransport.PostFormAsync(
            http, cimd.TokenEndpoint, tamperedFields, TestContext.CancellationToken).ConfigureAwait(false);
        string tamperedBody = await tampered.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(400, (int)tampered.StatusCode, tamperedBody);

        //A valid private_key_jwt assertion authenticates and the exchange completes.
        Dictionary<string, string> validFields = new(baseFields, StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientAssertion] = validAssertion
        };
        using HttpResponseMessage ok = await OAuthTestTransport.PostFormAsync(
            http, cimd.TokenEndpoint, validFields, TestContext.CancellationToken).ConfigureAwait(false);
        string okBody = await ok.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)ok.StatusCode, okBody);

        using JsonDocument tokenDoc = JsonDocument.Parse(okBody);
        Assert.IsFalse(string.IsNullOrEmpty(tokenDoc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." A refresh request of a
    /// confidential client whose Client ID Metadata Document declares <c>private_key_jwt</c>, sent over the wire with
    /// <c>client_id=</c> beside <c>client_id=&lt;its URL&gt;</c> and no assertion, names the one client
    /// identifier, so the document is fetched and the client authentication it declares is required:
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see>,
    /// "This establishes this client as a confidential client, and any communication with the authorization server
    /// MUST include client authentication of the registered type." The request is refused 400
    /// <c>invalid_client</c>, no token issued.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyClientIdBesideTheClientUrlAtRefreshRequiresTheDeclaredAuthenticationAsync()
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync().ConfigureAwait(false);
        HttpClient http = cimd.Hosted.SharedHttpClient!;
        string validAssertion = await cimd.SignAssertionAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, string> redemptionFields = new(cimd.CodeRedemptionFields(), StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientAssertion] = validAssertion
        };
        using HttpResponseMessage redeemed = await OAuthTestTransport.PostFormAsync(
            http, cimd.TokenEndpoint, redemptionFields, TestContext.CancellationToken).ConfigureAwait(false);
        string redeemedBody = await redeemed.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemed.StatusCode, redeemedBody);
        using JsonDocument redeemedDocument = JsonDocument.Parse(redeemedBody);
        string refreshToken = redeemedDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

        using HttpResponseMessage refreshed = await OAuthTestTransport.PostFormAsync(
            http, cimd.TokenEndpoint,
            [
                new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.RefreshToken),
                new(OAuthRequestParameterNames.RefreshToken, refreshToken),
                new(OAuthRequestParameterNames.ClientId, string.Empty),
                new(OAuthRequestParameterNames.ClientId, cimd.Registration.ClientId.Value)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);
        string refreshedBody = await refreshed.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)refreshed.StatusCode, refreshedBody);
        Assert.AreEqual("{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", refreshedBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." A code redemption of a
    /// confidential client whose Client ID Metadata Document declares <c>private_key_jwt</c>, sent over the wire with
    /// <c>client_id=</c> beside <c>client_id=&lt;its URL&gt;</c> and no assertion, names the one client
    /// identifier, so the document is fetched and the client authentication it declares is required
    /// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see>):
    /// the request is refused 400 <c>invalid_client</c>, no token issued.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyClientIdBesideTheClientUrlAtCodeRedemptionRequiresTheDeclaredAuthenticationAsync()
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync().ConfigureAwait(false);
        List<KeyValuePair<string, string>> fields =
        [
            .. cimd.CodeRedemptionFields().Where(static field => field.Key != OAuthRequestParameterNames.ClientId),
            new(OAuthRequestParameterNames.ClientId, string.Empty),
            new(OAuthRequestParameterNames.ClientId, cimd.Registration.ClientId.Value)
        ];

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            cimd.Hosted.SharedHttpClient!, cimd.TokenEndpoint, fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.AreEqual("{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Request and
    /// response parameters MUST NOT be included more than once." A code redemption of a confidential client whose
    /// Client ID Metadata Document declares <c>private_key_jwt</c>, sent over the wire with its URL as
    /// <c>client_id</c> twice, is refused 400 <c>invalid_request</c> with the description of a repeated client
    /// authentication parameter, the code
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> names for a
    /// request that repeats a parameter, and no token is issued. The materialization refuses it before the token
    /// endpoint runs and before any document is fetched: the document resolver is not called.
    /// </summary>
    [TestMethod]
    public async Task TheClientUrlTwiceAtTheTokenEndpointIsAnInvalidRequestAsync()
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync().ConfigureAwait(false);
        List<KeyValuePair<string, string>> fields =
        [
            .. cimd.CodeRedemptionFields(),
            new(OAuthRequestParameterNames.ClientId, cimd.Registration.ClientId.Value)
        ];
        int resolutionsBefore = cimd.ResolutionCount;
        int refusalsBefore = cimd.MaterializationRefusalCount;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            cimd.Hosted.SharedHttpClient!, cimd.TokenEndpoint, fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The request repeats a client authentication parameter.\"}",
            body);
        Assert.AreEqual(resolutionsBefore, cimd.ResolutionCount, "A malformed request fetches no document.");
        Assert.AreEqual(refusalsBefore + 1, cimd.MaterializationRefusalCount, "The materialization refuses the request before the token endpoint runs.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see>:
    /// "When a client declares token_endpoint_auth_method as private_key_jwt, the authorization server MUST require
    /// client authentication according to Section 2.2 of [RFC7523] using the corresponding key discovered from the
    /// client's metadata document." A code redemption of a confidential client whose Client ID Metadata Document
    /// declares <c>private_key_jwt</c>, sent over the wire with a valid assertion and no <c>client_id</c>, which a
    /// client that authenticates may omit (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749
    /// Section 4.1.3</see>, <c>client_id</c>: "REQUIRED, if the client is not authenticating with the authorization
    /// server as described in Section 3.2.1."), is judged against the document of the registration it is served
    /// under: the document resolver is called for the request, the assertion verifies under the public signing
    /// material the document publishes, and the code is redeemed, 200 with an access token.
    /// </summary>
    [TestMethod]
    public async Task AnAssertionWithoutClientIdIsJudgedAgainstTheClientsDocumentAsync()
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync().ConfigureAwait(false);
        string validAssertion = await cimd.SignAssertionAsync(TestContext.CancellationToken).ConfigureAwait(false);
        List<KeyValuePair<string, string>> fields =
        [
            .. cimd.CodeRedemptionFields().Where(static field => field.Key != OAuthRequestParameterNames.ClientId),
            new(OAuthRequestParameterNames.ClientAssertionType, WellKnownClientAssertionTypes.JwtBearer),
            new(OAuthRequestParameterNames.ClientAssertion, validAssertion)
        ];
        int resolutionsBefore = cimd.ResolutionCount;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            cimd.Hosted.SharedHttpClient!, cimd.TokenEndpoint, fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(resolutionsBefore + 1, cimd.ResolutionCount, "The request is judged against the client's document.");
        Assert.AreEqual(200, (int)response.StatusCode, body);
        using JsonDocument tokenDocument = JsonDocument.Parse(body);
        Assert.IsFalse(string.IsNullOrEmpty(tokenDocument.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()));
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see>:
    /// "This establishes this client as a confidential client, and any communication with the authorization server
    /// MUST include client authentication of the registered type." A jwt-bearer grant
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 Section 2.1</see>), the grant an
    /// identity assertion authorization grant is redeemed through as well, sent over the wire to the tenant of a client
    /// whose Client ID Metadata Document declares <c>private_key_jwt</c>, with an assertion the application's
    /// assertion-grant seam accepts and with neither <c>client_id</c> nor any client authentication, is judged against
    /// the client's document: the document resolver is called for the request, and the request is refused 400
    /// <c>invalid_client</c> with the fixed description and no <c>WWW-Authenticate</c> (no <c>Authorization</c>
    /// field was attempted and <c>client_secret_basic</c> is not advertised), and no token is issued.
    /// </summary>
    [TestMethod]
    public async Task AJwtBearerGrantWithoutClientIdAndWithoutClientAuthenticationIsRefusedAsync()
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync(isEveryTokenRequestServed: true).ConfigureAwait(false);
        int resolutionsBefore = cimd.ResolutionCount;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            cimd.Hosted.SharedHttpClient!, cimd.TokenEndpoint,
            [
                new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.JwtBearer),
                new(OAuthRequestParameterNames.Assertion, "eyJhbGciOiJFUzI1NiJ9.accepted-by-the-seam.signature")
            ],
            TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(resolutionsBefore + 1, cimd.ResolutionCount, $"The request is judged against the client's document. {(int)response.StatusCode} {body}");
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.AreEqual("{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", body);
        Assert.IsFalse(response.Headers.Contains(WellKnownHttpHeaderNames.WwwAuthenticate), "No Authorization field was attempted.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see>:
    /// "This establishes this client as a confidential client, and any communication with the authorization server
    /// MUST include client authentication of the registered type." A token-family request sent over the wire to the
    /// tenant of a client whose Client ID Metadata Document declares <c>private_key_jwt</c>, with neither
    /// <c>client_id</c> nor any client authentication, is judged against the client's document: the document resolver
    /// is called for the request, and the endpoint answers it on the record the document materialized: 400
    /// <c>invalid_client</c> where the endpoint requires the client authentication the document declares (the code
    /// redemption and the refresh included, which on the stored record answered that <c>client_id</c> is required),
    /// and, at the pre-authorized code grant, whose client authentication the application's seam owns, that seam's
    /// denial.
    /// </summary>
    /// <param name="request">The token-family request sent.</param>
    /// <param name="expectedStatus">The status the endpoint answers.</param>
    /// <param name="expectedBody">The body the endpoint answers.</param>
    [TestMethod]
    [DataRow("client_credentials", 400, "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", DisplayName = "a client credentials grant")]
    [DataRow("token_exchange", 400, "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", DisplayName = "a token exchange")]
    [DataRow("code_redemption", 400, "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", DisplayName = "a code redemption")]
    [DataRow("refresh", 400, "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", DisplayName = "a refresh")]
    [DataRow("pre_authorized_code", 400, "{\"error\":\"invalid_grant\",\"error_description\":\"The pre-authorized_code is invalid or has expired.\"}", DisplayName = "a pre-authorized code grant")]
    [DataRow("revocation", 400, "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", DisplayName = "a revocation")]
    [DataRow("introspection", 400, "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", DisplayName = "an introspection")]
    public async Task ATokenFamilyRequestWithoutClientIdAndWithoutClientAuthenticationIsJudgedAgainstTheClientsDocumentAsync(
        string request, int expectedStatus, string expectedBody)
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync(isEveryTokenRequestServed: true).ConfigureAwait(false);
        HttpClient http = cimd.Hosted.SharedHttpClient!;

        //A refresh token is issued to the client first, through a code redemption it authenticates.
        string refreshToken = string.Empty;
        if(request == "refresh")
        {
            Dictionary<string, string> redemptionFields = new(cimd.CodeRedemptionFields(), StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
                [OAuthRequestParameterNames.ClientAssertion] = await cimd.SignAssertionAsync(TestContext.CancellationToken).ConfigureAwait(false)
            };
            using HttpResponseMessage redeemed = await OAuthTestTransport.PostFormAsync(
                http, cimd.TokenEndpoint, redemptionFields, TestContext.CancellationToken).ConfigureAwait(false);
            string redeemedBody = await redeemed.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)redeemed.StatusCode, redeemedBody);
            using JsonDocument redeemedDocument = JsonDocument.Parse(redeemedBody);
            refreshToken = redeemedDocument.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        (string EndpointName, List<KeyValuePair<string, string>> Fields) target = request switch
        {
            "client_credentials" => (WellKnownEndpointNames.ClientCredentialsToken,
                [new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials)]),
            "token_exchange" => (WellKnownEndpointNames.TokenExchangeToken,
                [
                    new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.TokenExchange),
                    new(OAuthRequestParameterNames.SubjectToken, "subject-token-0123456789"),
                    new(OAuthRequestParameterNames.SubjectTokenType, "urn:ietf:params:oauth:token-type:access_token")
                ]),
            "code_redemption" => (WellKnownEndpointNames.AuthCodeToken,
                [.. cimd.CodeRedemptionFields().Where(static field => field.Key != OAuthRequestParameterNames.ClientId)]),
            "refresh" => (WellKnownEndpointNames.AuthCodeRefreshToken,
                [
                    new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.RefreshToken),
                    new(OAuthRequestParameterNames.RefreshToken, refreshToken)
                ]),
            "pre_authorized_code" => (WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
                [
                    new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.PreAuthorizedCode),
                    new(OAuthRequestParameterNames.PreAuthorizedCode, "pre-authorized-code-0123456789")
                ]),
            "revocation" => (WellKnownEndpointNames.AuthCodeRevoke,
                [new(OAuthRequestParameterNames.Token, "token-0123456789")]),
            "introspection" => (WellKnownEndpointNames.AuthCodeIntrospect,
                [new(OAuthRequestParameterNames.Token, "token-0123456789")]),

            _ => throw new ArgumentOutOfRangeException(nameof(request), request, "No such row.")
        };
        int resolutionsBefore = cimd.ResolutionCount;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            http, cimd.EndpointUri(target.EndpointName), target.Fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(resolutionsBefore + 1, cimd.ResolutionCount, $"The request is judged against the client's document. {(int)response.StatusCode} {body}");
        Assert.AreEqual(expectedStatus, (int)response.StatusCode, body);
        Assert.AreEqual(expectedBody, body);
    }


    /// <summary>
    /// The request's client credentials are read once, and the client authentication seam judges exactly the reading
    /// the library took (<see cref="ValidateClientCredentialsDelegate"/>): a code redemption sent over the wire by a
    /// confidential client whose Client ID Metadata Document declares <c>private_key_jwt</c>, with a valid assertion
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 Section 2.2</see>), is read by the
    /// Client ID Metadata Document materialization, and the reading the client authentication seam receives is the
    /// same instance the materialization left carried on the request's context; the code is redeemed, 200 with an
    /// access token.
    /// </summary>
    [TestMethod]
    public async Task TheClientAuthenticationSeamReceivesTheReadingTheMaterializationTookAsync()
    {
        await using ConfidentialCimdClient cimd = await StartConfidentialCimdClientAsync().ConfigureAwait(false);
        Dictionary<string, string> fields = new(cimd.CodeRedemptionFields(), StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientAssertion] = await cimd.SignAssertionAsync(TestContext.CancellationToken).ConfigureAwait(false)
        };
        int seamReadingsBefore = cimd.SeamReadingCount;
        int carriedSeamReadingsBefore = cimd.CarriedSeamReadingCount;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            cimd.Hosted.SharedHttpClient!, cimd.TokenEndpoint, fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(seamReadingsBefore + 1, cimd.SeamReadingCount, "The client authentication seam judges the request once.");
        Assert.AreEqual(carriedSeamReadingsBefore + 1, cimd.CarriedSeamReadingCount, "The seam receives the reading the materialization took.");
        Assert.AreEqual(200, (int)response.StatusCode, body);
    }


    /// <summary>
    /// The §8.2 canonical confidential-client shape (CIMD-048/050): the document declares
    /// <c>token_endpoint_auth_method: private_key_jwt</c> plus a <c>jwks_uri</c> — NOT an inline
    /// <c>jwks</c> — pointing at a SECOND loopback host distinct from the one serving the CIMD
    /// document itself, exactly the shape
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">
    /// §8.2</see>'s own example advertises. The resolver's Step 9a
    /// (<see cref="ClientIdMetadataDocuments.ResolveAsync"/>) fetches the key set through that
    /// second host over the real wire and folds it into the resolved document's <c>jwks</c>, so
    /// <see cref="PrivateKeyJwtClientAuthentication"/>'s validator resolves the client's key and a
    /// VALID <c>private_key_jwt</c> assertion completes the exchange.
    /// </summary>
    [TestMethod]
    public async Task ConfidentialClientWithJwksUriAuthenticatesOverTheRealWire()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        await using StaticContentHost jwksHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Uri redirectUri = new("https://client.example.com/callback");
        const string documentPath = "/app-jwks-uri";
        const string jwksPath = "/jwks";
        Uri documentUri = new(documentHost.BaseAddress, documentPath);
        Uri jwksUri = new(jwksHost.BaseAddress, jwksPath);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestHostShell.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, ClientSigningKeyId);
            jwksHost.Publish(jwksPath, Encoding.UTF8.GetBytes(jwksJson), "application/json");

            string documentJson = BuildCimdDocumentJson(
                documentUri.OriginalString,
                redirectUris: [redirectUri],
                tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.PrivateKeyJwt,
                jwksJson: null,
                jwksUri: jwksUri.OriginalString);
            documentHost.Publish(documentPath, Encoding.UTF8.GetBytes(documentJson), "application/json");

            await using TestHostShell app = new(timeProvider);
            ClientRecord stub = await app.RegisterCimdStubClientAsync(
                documentUri,
                ImmutableHashSet.Create(
                    WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                    WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
                profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            //WireCimdMaterialization pins the resolver's transport to a SINGLE document host
            //certificate; here the resolver must reach both the CIMD document host and the separate
            //jwks_uri host, so the integration is wired directly, mirroring WireCimdMaterialization's
            //own body over a two-certificate pinned, single-hop client.
            using SocketsHttpHandler resolverHandler =
                LoopbackTls.CreatePinnedHandler([documentHost.Certificate, jwksHost.Certificate]);
            resolverHandler.AllowAutoRedirect = false;
            using HttpClient resolverHttpClient = new(resolverHandler);
            OutboundTransportDelegate resolverTransport =
                GuardedHttpClientTransport.BuildSingleHopTransport(resolverHttpClient);
            ClientMetadataResolutionCache resolverCache = new(
                resolverTransport, new ClientIdMetadataDocumentResolverOptions(), new JwksUriResolverOptions(), timeProvider);
            ResolveClientMetadataDelegate resolve = resolverCache.ResolveDocumentAsync;

            AuthorizationServerIntegration oauth = app.Server.OAuth();
            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();


                candidateIntegration.ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
                {
                    context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

                    return resolve(clientMetadataUri, context, cancellationToken);
                };


                candidateIntegration.ValidateClientCredentialsAsync = PrivateKeyJwtClientAuthentication.BuildValidator();

                //The fetched document declares private_key_jwt (CIMD-047/048); the token endpoint now
                //refuses a declared method it does not advertise before any validator runs (RFC 8414,
                //Section 2), so the advertisement must agree with the document.

                candidateIntegration.ClientAuthenticationMethodsSupported =
                    [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];


                candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [alg];
            }).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
                await app.CreateOAuthClientAndRegistrationAsync(
                    stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                    .ConfigureAwait(false);
            //RFC 9126 §2: the pushed request now authenticates the client exactly as the token
            //endpoint does, so the confidential method the fetched document declares must be
            //presented at PAR too, before any code can be issued.
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = clientKeys
            };
            ClientAssertionOptions parAssertionOptions = new()
            {
                SigningKeyId = ClientSigningKeyId,
                HeaderSerializer = app.Server.OAuth().Codecs.JwtHeaderSerializer!,
                PayloadSerializer = app.Server.OAuth().Codecs.JwtPayloadSerializer!
            };

            HostedAuthorizationServer hosted = app.Host("default");
            string segment = stub.TenantId.Value;

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(app.ServerCertificate);
            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, flowStore, segment, redirectUri, SubjectId, browserClient,
                clientAssertionOptions: parAssertionOptions, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);

            AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)flowStore[flowId];
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string validAssertion = await ClientAssertionSigning.SignAsync(
                registration.ClientId.Value,
                registration.AuthorizationServerIssuer.OriginalString,
                Guid.NewGuid().ToString("N"),
                timeProvider.GetUtcNow(),
                timeProvider.GetUtcNow().AddMinutes(5),
                clientKeys.PrivateKey,
                ClientSigningKeyId,
                app.Server.OAuth().Codecs.JwtHeaderSerializer!,
                app.Server.OAuth().Codecs.JwtPayloadSerializer!,
                app.Server.OAuth().Codecs.Encoder!,
                TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //CIMD-047/048/050: a valid private_key_jwt assertion, authenticated against the key set
            //discovered from the SEPARATE jwks_uri host, completes the exchange.
            Dictionary<string, string> tokenFields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
                [OAuthRequestParameterNames.Code] = codeState.Code,
                //RFC 6749 §4.1.3's identical-value check binds to Uri.OriginalString (the exact
                //string the authorization step captured), never Uri.ToString() — which re-canonicalizes
                //(default-port elision, host casing) and can diverge from the persisted value.
                [OAuthRequestParameterNames.RedirectUri] = codeState.RedirectUri.OriginalString,
                [OAuthRequestParameterNames.CodeVerifier] = codeState.Pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
                [OAuthRequestParameterNames.ClientAssertion] = validAssertion
            };
            using HttpResponseMessage ok = await OAuthTestTransport.PostFormAsync(
                hosted.SharedHttpClient!, tokenEndpoint, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
            string okBody = await ok.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)ok.StatusCode, okBody);

            using JsonDocument tokenDoc = JsonDocument.Parse(okBody);
            Assert.IsFalse(string.IsNullOrEmpty(tokenDoc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()));

            Assert.IsTrue(jwksHost.WasRequested(jwksPath),
                "CIMD-048/050, §8.2: the jwks_uri host must have been fetched over the real wire to discover the client's key set.");
            Assert.IsGreaterThanOrEqualTo(1, jwksHost.TotalRequests,
                "CIMD-048/050: the jwks_uri host must have served at least one request.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The grant-type carve-out (CIMD-026/027): a redirect-less document (no <c>redirect_uris</c> at
    /// all) still identifies its client and still gets its metadata fetched for the
    /// <c>client_credentials</c> grant, which involves no redirect URL at all — the §4.2 redirect
    /// registration requirement simply does not apply to it. The SAME docless client's PAR fails the
    /// redirect check because the fetched document supplied no registered redirect URIs whatsoever.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentials_RedirectlessDocumentGrantsTokens_AuthorizeFlowFailsRedirectCheck()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        const string path = "/app-machine";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, redirectUris: null);

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        Uri tokenEndpoint = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
        using HttpResponseMessage tokenResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenEndpoint, new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
                [OAuthRequestParameterNames.ClientId] = documentUri.OriginalString
            }, TestContext.CancellationToken).ConfigureAwait(false);
        string tokenBody = await tokenResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(200, (int)tokenResponse.StatusCode, tokenBody);
        Assert.IsTrue(documentHost.WasRequested(path),
            "CIMD-027: client identification and metadata discovery apply regardless of grant type.");

        Uri parEndpoint = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        using HttpResponseMessage parResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, parEndpoint, new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ResponseType] = "code",
                [OAuthRequestParameterNames.ClientId] = documentUri.OriginalString,
                [OAuthRequestParameterNames.RedirectUri] = "https://developer.example/callback",
                [OAuthRequestParameterNames.CodeChallenge] = "an-arbitrary-pkce-challenge-value-1234567890",
                [OAuthRequestParameterNames.CodeChallengeMethod] = "S256"
            }, TestContext.CancellationToken).ConfigureAwait(false);
        string parBody = await parResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)parResponse.StatusCode, parBody);
        Assert.Contains("redirect_uri", parBody);
    }


    /// <summary>
    /// Pre-registration (CIMD-031/045/046): the resolver runs ONCE, at the time the Client Identifier
    /// URL is pre-registered — not the request-time <see cref="ClientIdMetadataMaterialization"/> hook,
    /// which is never wired on this host at all. The flow still succeeds, and the document host sees
    /// EXACTLY the one pre-registration-time fetch — zero request-time fetches.
    /// </summary>
    [TestMethod]
    public async Task PreRegistration_ResolvedOnceAtRegistrationTime_FlowSucceedsWithZeroRequestTimeFetches()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Uri redirectUri = new("https://client.example.com/callback");
        const string path = "/app-prereg";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, [redirectUri]);

        using HttpClient pinnedHttpClient = LoopbackTls.CreatePinnedHttpClient(documentHost.Certificate);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(pinnedHttpClient);

        ClientIdMetadataResolution resolution = await ClientIdMetadataDocuments.ResolveAsync(
            documentUri, NewLoopbackContext(), transport, new ClientIdMetadataDocumentResolverOptions(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resolution.IsResolved,
            $"CIMD-046: the document must resolve at pre-registration time. Defect={resolution.Defect}");

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //CIMD-031: the AS associates the Client Identifier URL with client metadata "through other
        //means" — the pre-registration overlay below, applied once — rather than automatically
        //fetching at request time. WireCimdMaterialization is deliberately never called on this host.
        ClientRecord preRegistered = stub with
        {
            AllowedRedirectUris = [.. resolution.Document!.RedirectUris]
        };
        HostedAuthorizationServer host = app.Host("default");
        preRegistered = await host.UpdateClientAsync(stub, preRegistered, [], TestContext.CancellationToken).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                preRegistered, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        string segment = preRegistered.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"The pre-registered flow must succeed without any request-time CIMD fetch. ErrorCode={tokenResult.ErrorCode}");

        Assert.AreEqual(1, documentHost.TotalRequests,
            "Exactly the pre-registration-time fetch must have crossed the wire — zero request-time fetches.");
    }


    /// <summary>
    /// AS metadata advertisement over the real wire (CIMD-041/042): the RFC 8414 default discovery
    /// location carries <c>client_id_metadata_document_supported: true</c> under the dual gate
    /// (capability allowed AND the resolver wired) — and discovery emission never itself triggers a
    /// document fetch (privacy §9.1).
    /// </summary>
    [TestMethod]
    public async Task Discovery_AdvertisesClientIdMetadataDocumentSupportedOverRealWire()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        const string path = "/app-discovery";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, redirectUris: null);

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        Uri discoveryUrl = new(
            hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataOAuthAuthorizationServer, segment));
        using HttpResponseMessage discoveryResponse = await hosted.SharedHttpClient!
            .GetAsync(discoveryUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string discoveryBody = await discoveryResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(200, (int)discoveryResponse.StatusCode, discoveryBody);

        using JsonDocument doc = JsonDocument.Parse(discoveryBody);
        Assert.IsTrue(
            doc.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out JsonElement flag),
            $"client_id_metadata_document_supported must be present over the real wire. Body={discoveryBody}");
        Assert.IsTrue(flag.GetBoolean());

        Assert.AreEqual(0, documentHost.TotalRequests,
            "Discovery emission must never itself trigger a CIMD document fetch (privacy §9.1).");
    }


    /// <summary>
    /// Appendix A CIMD Service, positive half (CIMD-062/064/066/067): a client provisioned through a
    /// <see cref="CimdServiceHost"/> drives a full auth-code flow exactly like a self-hosted document
    /// would, developer-supplied information is recorded, and — negative half (CIMD-065/067/035
    /// interplay) — once the pinned clock advances past the provision's lifetime, the service answers
    /// 404 and a FRESH authorization request aborts rather than proceeding on stale data.
    /// </summary>
    [TestMethod]
    public async Task CimdService_ProvisionedClientDrivesFullFlow_DeveloperInfoRecorded_ExpiryAbortsFreshRequest()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using CimdServiceHost cimdService = await CimdServiceHost.StartAsync(
            timeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        Uri redirectUri = new("https://developer.example/cb");
        Uri clientIdentifierUrl = cimdService.ProvisionClient(
            redirectUris: [redirectUri],
            lifetime: TimeSpan.FromMinutes(10),
            developerInfo: "team-mobile");

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = await app.RegisterCimdStubClientAsync(
            clientIdentifierUrl,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await app.WireCimdMaterializationAsync("default", cimdService.Certificate).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"A CIMD Service-provisioned client must drive a full auth-code flow. ErrorCode={tokenResult.ErrorCode}");

        Assert.IsTrue(cimdService.WasRequested(clientIdentifierUrl),
            "The CIMD Service document must have been fetched over the real wire.");
        Assert.AreEqual("team-mobile", cimdService.DeveloperInfo(clientIdentifierUrl),
            "CIMD-066: developer-supplied information about the client under development must be recorded.");

        //CIMD-065: the service expires the provision, measured against the injected TimeProvider.
        timeProvider.Advance(TimeSpan.FromMinutes(11));

        //CIMD-035/067 interplay: a fresh authorization request against an expired provision aborts —
        //the document now 404s, so materialization's resolver call fails and the request never redirects.
        AuthCodeFlowEndpointResult secondPar = await client.AuthCode.StartParAsync(
            registration, redirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, secondPar.Outcome,
            "A fresh authorization request against an expired CIMD Service provision must abort, not redirect.");
        Assert.AreEqual(OAuthErrors.InvalidClient, secondPar.ErrorCode,
            "A pushed request whose client's document cannot be fetched is a failed client authentication (RFC 9126 Section 2).");
    }


    /// <summary>
    /// Appendix A CIMD Service, the redirect-restriction exemption (CIMD-063): an AS that layers an
    /// additional same-origin-with-<c>client_id</c> restriction on <c>redirect_uris</c> (via the §4
    /// <see cref="ClientIdMetadataDocumentResolverOptions.AdditionalDocumentValidation"/> extension
    /// point, CIMD-020) exempts documents served from a CIMD Service's own origin — proven by
    /// contrasting the SAME cross-origin redirect_uri accepted from the service origin and rejected
    /// from an ordinary (non-service) document host under the identical policy.
    /// </summary>
    [TestMethod]
    public async Task CimdService_AdditionalDocumentValidationExemptsServiceOriginFromRedirectOriginRestriction()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using CimdServiceHost cimdService = await CimdServiceHost.StartAsync(
            timeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        await using StaticContentHost foreignHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Neither host's own origin — a hypothetical AS policy requiring redirect_uris to share the
        //client_id's origin (§8.1) would reject this for an ordinary document.
        Uri crossOriginRedirect = new("https://developer.example/cb");

        Uri serviceClientIdentifierUrl = cimdService.ProvisionClient(redirectUris: [crossOriginRedirect]);

        const string foreignPath = "/app-foreign";
        Uri foreignClientIdentifierUrl = new(foreignHost.BaseAddress, foreignPath);
        PublishCimdDocument(foreignHost, foreignPath, foreignClientIdentifierUrl, [crossOriginRedirect]);

        Uri serviceOrigin = cimdService.BaseAddress;
        ValueTask<bool> sameOriginUnlessServiceOrigin(ClientMetadata document, Uri clientMetadataUri, ExchangeContext context, CancellationToken cancellationToken)
        {
            bool isServiceOrigin = string.Equals(
                clientMetadataUri.Authority, serviceOrigin.Authority, StringComparison.OrdinalIgnoreCase);
            if(isServiceOrigin)
            {
                //CIMD-063: at least one CIMD Service is exempt from the AS's redirect_uri origin
                //restriction, so developers are not blocked by it.
                return ValueTask.FromResult(true);
            }

            bool allSameOrigin = document.RedirectUris.All(uri =>
                string.Equals(uri.Authority, clientMetadataUri.Authority, StringComparison.OrdinalIgnoreCase));

            return ValueTask.FromResult(allSameOrigin);
        }

        using HttpClient pinnedHttpClient =
            LoopbackTls.CreatePinnedHttpClient([cimdService.Certificate, foreignHost.Certificate]);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(pinnedHttpClient);
        ClientIdMetadataDocumentResolverOptions options = new()
        {
            AdditionalDocumentValidation = sameOriginUnlessServiceOrigin
        };

        ClientIdMetadataResolution serviceResolution = await ClientIdMetadataDocuments.ResolveAsync(
            serviceClientIdentifierUrl, NewLoopbackContext(), transport, options, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsTrue(serviceResolution.IsResolved,
            $"CIMD-063: the CIMD Service origin must be exempt from the redirect_uri origin restriction. Defect={serviceResolution.Defect}");

        ClientIdMetadataResolution foreignResolution = await ClientIdMetadataDocuments.ResolveAsync(
            foreignClientIdentifierUrl, NewLoopbackContext(), transport, options, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, foreignResolution.Outcome,
            "A non-service document with the SAME cross-origin redirect_uri must still be rejected by the " +
            "restriction — proving the CIMD-063 exemption is doing real work, not a no-op policy.");
    }


    /// <summary>
    /// Drives PAR (a real wire POST) and the browser's authorize GET (a real wire GET with
    /// auto-redirect disabled and the test subject header standing in for an authenticated session),
    /// returning the flow identifier and the raw redirect <c>Location</c> for the caller to inspect.
    /// </summary>
    private static async Task<(string FlowId, string Location)> DriveParAndAuthorizeAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        Uri redirectUri,
        OAuthFormEncodedFields additionalParFields,
        string subjectId,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken)
    {
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, redirectUri, additionalParFields, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(registration.ClientId.Value)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        using SocketsHttpHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(pinnedCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler) { BaseAddress = hosted.HttpBaseAddress };
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, subjectId);

        using HttpResponseMessage authorizeResponse = await browserClient
            .SendAsync(authorizeRequest, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        return (flowId, authorizeResponse.Headers.Location!.ToString());
    }


    /// <summary>
    /// <see cref="DriveParAndAuthorizeAsync"/> plus the client-local callback state transition,
    /// returning the flow identifier ready for token exchange.
    /// </summary>
    private static async Task<string> DriveParAuthorizeAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        Uri redirectUri,
        string subjectId,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken)
    {
        (string flowId, string location) = await DriveParAndAuthorizeAsync(
            hosted, client, registration, clientFlowStore, segment, redirectUri, OAuthFormEncodedFields.Empty,
            subjectId, pinnedCertificate, cancellationToken).ConfigureAwait(false);

        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId
        };
        if(iss is not null)
        {
            callbackFields[OAuthRequestParameterNames.Iss] = iss;
        }

        AuthCodeFlowEndpointResult callbackResult = await client.AuthCode.HandleCallbackAsync(
            registration, new OAuthFormEncodedFields(callbackFields), cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        return flowId;
    }


    /// <summary>
    /// Publishes a Client ID Metadata Document at <paramref name="host"/>'s <paramref name="path"/>
    /// whose <c>client_id</c> is <paramref name="documentUri"/>'s own <see cref="Uri.OriginalString"/>.
    /// </summary>
    private static void PublishCimdDocument(
        StaticContentHost host, string path, Uri documentUri, IReadOnlyList<Uri>? redirectUris)
    {
        string json = BuildCimdDocumentJson(
            documentUri.OriginalString, redirectUris, tokenEndpointAuthMethod: null, jwksJson: null);
        host.Publish(path, Encoding.UTF8.GetBytes(json), "application/json");
    }


    //Builds a conformant Client ID Metadata Document (§4): client_id is REQUIRED (CIMD-013) and
    //always present; every other member is included only when supplied, so an omitted property stays
    //genuinely absent from the wire JSON. jwksJson is embedded UNQUOTED — it is already a JSON
    //object's text, mirroring PrivateKeyJwtClientAuthenticationTests' BuildJwksJson convention.
    //jwksUri is the §8.2 alternative to jwksJson — a confidential client publishes ONE of the two,
    //never both, so callers pass at most one non-null.
    private static string BuildCimdDocumentJson(
        string clientId,
        IReadOnlyList<Uri>? redirectUris,
        string? tokenEndpointAuthMethod,
        string? jwksJson,
        string? jwksUri = null)
    {
        List<string> members = [$"\"client_id\":\"{clientId}\""];

        if(redirectUris is { Count: > 0 })
        {
            string uris = string.Join(',', redirectUris.Select(static uri => $"\"{uri.OriginalString}\""));
            members.Add($"\"redirect_uris\":[{uris}]");
        }

        if(tokenEndpointAuthMethod is not null)
        {
            members.Add($"\"token_endpoint_auth_method\":\"{tokenEndpointAuthMethod}\"");
        }

        if(jwksJson is not null)
        {
            members.Add($"\"jwks\":{jwksJson}");
        }

        if(jwksUri is not null)
        {
            members.Add($"\"jwks_uri\":\"{jwksUri}\"");
        }

        return "{" + string.Join(',', members) + "}";
    }


    //Hand-built JWKS document text from a DpopJwkUtilities.ToJwk dictionary, mirroring
    //PrivateKeyJwtClientAuthenticationTests.BuildJwksJson.
    private static string BuildJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        StringBuilder sb = new();
        _ = sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            _ = sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        _ = sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }


    //Flips the FIRST character of the compact JWS's signature segment (the part after the final '.').
    //The first base64url character of the signature contributes six full bits to the decoded bytes, so
    //the mutated signature always decodes to a different byte array — unlike flipping the final
    //character, whose two significant bits a lenient base64url decoder can discard, yielding a no-op
    //"tamper" that still verifies. The assertion keeps its header.payload.signature shape but no longer
    //verifies against the client's key.
    private static string TamperSignature(string compactJws)
    {
        int signatureStart = compactJws.LastIndexOf('.', StringComparison.Ordinal) + 1;
        char first = compactJws[signatureStart];
        char replacement = first == 'A' ? 'B' : 'A';

        return string.Concat(compactJws.AsSpan(0, signatureStart), replacement.ToString(), compactJws.AsSpan(signatureStart + 1));
    }


    /// <summary>
    /// Starts the confidential client the confidential rows of this class drive
    /// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">draft-ietf-oauth-client-id-metadata-document-02 Section 8.2</see>):
    /// a document host serving a Client ID Metadata Document that declares <c>private_key_jwt</c> with an inline
    /// <c>jwks</c>, an authorization server that materializes the client from it, judges client assertions through
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// and advertises <c>none</c> and <c>private_key_jwt</c>, and a pushed request, an authorization and a
    /// callback driven over the wire with a valid assertion at the pushed request, so an authorization code
    /// waits at the token endpoint. The server's document resolver seam and its materialization are wrapped so the
    /// client counts each resolution (<see cref="ConfidentialCimdClient.ResolutionCount"/>) and each refusal of the
    /// materialization (<see cref="ConfidentialCimdClient.MaterializationRefusalCount"/>), and the client
    /// authentication seam is wrapped so the client counts each reading it receives
    /// (<see cref="ConfidentialCimdClient.SeamReadingCount"/>) and each that is the instance the materialization left
    /// carried on the request's context (<see cref="ConfidentialCimdClient.CarriedSeamReadingCount"/>).
    /// </summary>
    /// <param name="isEveryTokenRequestServed">
    /// Whether the client is also allowed the jwt-bearer, client credentials, token exchange, pre-authorized code,
    /// revocation and introspection capabilities, with an assertion-grant seam that accepts every assertion, token
    /// exchange seams that accept nothing, a pre-authorized code seam that denies every code, and revocation and
    /// introspection seams, so every token-family request of its tenant reaches its endpoint.
    /// </param>
    /// <returns>The started client; the caller disposes it.</returns>
    private async Task<ConfidentialCimdClient> StartConfidentialCimdClientAsync(bool isEveryTokenRequestServed = false)
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        TestHostShell app = new(timeProvider);
        ConfidentialCimdClient? cimd = null;
        try
        {
            cimd = new()
            {
                DocumentHost = documentHost,
                ClientKeys = clientKeys,
                App = app,
                TimeProvider = timeProvider
            };

            Uri redirectUri = new("https://client.example.com/callback");
            const string path = "/app-confidential";
            Uri documentUri = new(documentHost.BaseAddress, path);

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestHostShell.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, ClientSigningKeyId);

            string documentJson = BuildCimdDocumentJson(
                documentUri.OriginalString,
                redirectUris: [redirectUri],
                tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.PrivateKeyJwt,
                jwksJson: jwksJson);
            documentHost.Publish(path, Encoding.UTF8.GetBytes(documentJson), "application/json");

            ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);
            if(isEveryTokenRequestServed)
            {
                capabilities = capabilities.Union(
                [
                    WellKnownCapabilityIdentifiers.OAuthJwtBearer,
                    WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                    WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                    WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
                    WellKnownCapabilityIdentifiers.OAuthTokenRevocation,
                    WellKnownCapabilityIdentifiers.OAuthTokenIntrospection
                ]);
            }

            ClientRecord stub = await app.RegisterCimdStubClientAsync(
                documentUri, capabilities, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            await app.WireCimdMaterializationAsync("default", documentHost.Certificate).ConfigureAwait(false);
            ConfidentialCimdClient observed = cimd;
            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                //The client authentication seam is observed: each reading it receives is counted, and so is each
                //that is the instance the materialization left carried on the request's context.
                ValidateClientCredentialsDelegate validate = PrivateKeyJwtClientAuthentication.BuildValidator();
                candidateIntegration.ValidateClientCredentialsAsync = (reading, registration, context, cancellationToken) =>
                {
                    bool isCarriedReading = context.TryGetValue(MaterializedReadingEntryName, out object? carried)
                        && ReferenceEquals(carried, reading);
                    observed.CountSeamReading(isCarriedReading);

                    return validate(reading, registration, context, cancellationToken);
                };

                if(isEveryTokenRequestServed)
                {
                    candidateIntegration.ValidateJwtBearerAssertionAsync = static (_, _, _, _, _) =>
                        ValueTask.FromResult<JwtBearerGrant?>(new JwtBearerGrant { Subject = SubjectId, Scope = WellKnownScopes.OpenId });
                    candidateIntegration.ValidateTokenExchangeTokenAsync = static (_, _, _, _, _) =>
                        ValueTask.FromResult<ValidatedSecurityToken?>(null);
                    candidateIntegration.AuthorizeTokenExchangeAsync = static (_, _, _, _, _, _) =>
                        ValueTask.FromResult<TokenExchangeAuthorization?>(null);
                    candidateIntegration.ValidatePreAuthorizedCodeAsync = static (_, _, _, _, _, _) =>
                        ValueTask.FromResult(PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.InvalidCode));
                    candidateIntegration.RevokeTokenAsync = static (_, _, _, _, _) => ValueTask.CompletedTask;
                    candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                        ValueTask.FromResult(new TokenIntrospectionResult { IsActive = false });
                }

                //The document resolver and the library's materialization are observed: each resolution
                //and each refusal of the materialization is counted on the client, and the reading the
                //materialization left carried on the context is noted on the context under an entry of this
                //class, so the client authentication seam's wrapper compares the reading it receives with it.
                ResolveClientMetadataDelegate resolve = candidateIntegration.ResolveClientMetadataAsync!;
                candidateIntegration.ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
                {
                    observed.CountResolution();

                    return resolve(clientMetadataUri, context, cancellationToken);
                };
                MaterializeRegistrationDelegate materialize = candidateIntegration.MaterializeRegistrationAsync!;
                candidateIntegration.MaterializeRegistrationAsync = async (registration, context, cancellationToken) =>
                {
                    RegistrationMaterialization materialization =
                        await materialize(registration, context, cancellationToken).ConfigureAwait(false);
                    if(materialization.Failure is not null)
                    {
                        observed.CountMaterializationRefusal();
                    }

                    if(context.Values.OfType<ClientCredentialReading>().SingleOrDefault() is { } carriedReading)
                    {
                        context[MaterializedReadingEntryName] = carriedReading;
                    }

                    return materialization;
                };

                //The fetched document declares private_key_jwt (draft-ietf-oauth-client-id-metadata-document-02
                //Section 8.2); the token endpoint refuses a declared method it does not advertise before any
                //validator runs (RFC 8414, Section 2), so the advertisement agrees with the document.
                candidateIntegration.ClientAuthenticationMethodsSupported =
                    [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
                candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [alg];
            }).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
                await app.CreateOAuthClientAndRegistrationAsync(
                    stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                    .ConfigureAwait(false);

            //RFC 9126 Section 2: the pushed request authenticates the client exactly as the token
            //endpoint does, so the confidential method the fetched document declares is presented at
            //the pushed request too, before any code is issued.
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = clientKeys
            };
            ClientAssertionOptions parAssertionOptions = new()
            {
                SigningKeyId = ClientSigningKeyId,
                HeaderSerializer = app.Server.OAuth().Codecs.JwtHeaderSerializer!,
                PayloadSerializer = app.Server.OAuth().Codecs.JwtPayloadSerializer!
            };

            HostedAuthorizationServer hosted = app.Host("default");
            string segment = stub.TenantId.Value;

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(app.ServerCertificate);
            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, flowStore, segment, redirectUri, SubjectId, browserClient,
                clientAssertionOptions: parAssertionOptions, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);

            cimd.Hosted = hosted;
            cimd.Segment = segment;
            cimd.Registration = registration;
            cimd.CodeState = (AuthorizationCodeReceivedState)flowStore[flowId];
            cimd.TokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            ConfidentialCimdClient started = cimd;
            cimd = null;

            return started;
        }
        finally
        {
            //A start that did not complete releases what it created; a started client is the caller's.
            if(cimd is not null)
            {
                await cimd.DisposeAsync().ConfigureAwait(false);
            }
        }
    }


    /// <summary>
    /// The confidential client <see cref="StartConfidentialCimdClientAsync"/> starts: its document host, its signing
    /// material, the authorization server serving it, its client-side registration and the authorization code
    /// waiting at the token endpoint. Disposing it stops both hosts and releases the signing material.
    /// </summary>
    private sealed class ConfidentialCimdClient: IAsyncDisposable
    {
        /// <summary>The host serving the client's Client ID Metadata Document.</summary>
        public required StaticContentHost DocumentHost { get; init; }

        /// <summary>The client's signing material, whose public half the document publishes.</summary>
        public required PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ClientKeys { get; init; }

        /// <summary>The authorization server fixture.</summary>
        public required TestHostShell App { get; init; }

        /// <summary>The clock the authorization server and the client's assertions read.</summary>
        public required FakeTimeProvider TimeProvider { get; init; }

        /// <summary>The authorization server's listener.</summary>
        public HostedAuthorizationServer Hosted { get; set; } = null!;

        /// <summary>The path segment of the client's tenant on the listener.</summary>
        public string Segment { get; set; } = null!;

        /// <summary>The client-side registration, carrying the client's URL as its identifier.</summary>
        public ClientRegistration Registration { get; set; } = null!;

        /// <summary>The client-side state holding the authorization code, its redirect URI and its PKCE verifier.</summary>
        public AuthorizationCodeReceivedState CodeState { get; set; } = null!;

        /// <summary>The token endpoint of the client's tenant on the listener.</summary>
        public Uri TokenEndpoint { get; set; } = null!;

        /// <summary>
        /// The calls the server's document resolver seam received. A field, since <see cref="Interlocked"/> counts
        /// through a reference to it while requests run concurrently.
        /// </summary>
        private int resolutionCount;

        /// <summary>
        /// The refusals the server's materialization answered with. A field, since <see cref="Interlocked"/> counts
        /// through a reference to it while requests run concurrently.
        /// </summary>
        private int materializationRefusalCount;

        /// <summary>
        /// The readings the server's client authentication seam received. A field, since <see cref="Interlocked"/>
        /// counts through a reference to it while requests run concurrently.
        /// </summary>
        private int seamReadingCount;

        /// <summary>
        /// The readings the server's client authentication seam received that were the instance the materialization
        /// left carried on the request's context. A field, since <see cref="Interlocked"/> counts through a reference
        /// to it while requests run concurrently.
        /// </summary>
        private int carriedSeamReadingCount;

        /// <summary>The calls the server's document resolver seam has received.</summary>
        public int ResolutionCount => Volatile.Read(ref resolutionCount);

        /// <summary>The refusals the server's materialization has answered with.</summary>
        public int MaterializationRefusalCount => Volatile.Read(ref materializationRefusalCount);

        /// <summary>The readings the server's client authentication seam has received.</summary>
        public int SeamReadingCount => Volatile.Read(ref seamReadingCount);

        /// <summary>
        /// The readings the server's client authentication seam has received that were the instance the
        /// materialization left carried on the request's context.
        /// </summary>
        public int CarriedSeamReadingCount => Volatile.Read(ref carriedSeamReadingCount);


        /// <summary>Counts one call of the server's document resolver seam.</summary>
        public void CountResolution() => _ = Interlocked.Increment(ref resolutionCount);


        /// <summary>Counts one refusal of the server's materialization.</summary>
        public void CountMaterializationRefusal() => _ = Interlocked.Increment(ref materializationRefusalCount);


        /// <summary>Counts one reading the server's client authentication seam received.</summary>
        /// <param name="isCarriedReading">Whether the reading is the instance the materialization left carried on the context.</param>
        public void CountSeamReading(bool isCarriedReading)
        {
            _ = Interlocked.Increment(ref seamReadingCount);
            if(isCarriedReading)
            {
                _ = Interlocked.Increment(ref carriedSeamReadingCount);
            }
        }


        /// <summary>
        /// The URL of the named endpoint of the client's tenant on the listener.
        /// </summary>
        /// <param name="endpointName">The endpoint's name.</param>
        /// <returns>The endpoint's URL.</returns>
        public Uri EndpointUri(string endpointName) =>
            new(Hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(endpointName, Segment));


        /// <summary>
        /// The fields of a code redemption without client authentication: <c>grant_type</c>, the client's URL as
        /// <c>client_id</c>, the code, the <c>redirect_uri</c> as the authorization step captured it
        /// (<see cref="Uri.OriginalString"/>, the value the identical-value check of
        /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 Section 4.1.3</see> binds to) and
        /// the PKCE verifier.
        /// </summary>
        /// <returns>The fields, keyed by name.</returns>
        public Dictionary<string, string> CodeRedemptionFields() => new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.ClientId] = Registration.ClientId.Value,
            [OAuthRequestParameterNames.Code] = CodeState.Code,
            [OAuthRequestParameterNames.RedirectUri] = CodeState.RedirectUri.OriginalString,
            [OAuthRequestParameterNames.CodeVerifier] = CodeState.Pkce.EncodedVerifier
        };


        /// <summary>
        /// Signs a valid <c>private_key_jwt</c> client assertion
        /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.2">RFC 7523 Section 2.2</see>) of the client
        /// for the authorization server's issuer, valid for five minutes from the fixture's clock.
        /// </summary>
        /// <param name="cancellationToken">Cancels the signing.</param>
        /// <returns>The compact assertion.</returns>
        public ValueTask<string> SignAssertionAsync(CancellationToken cancellationToken) =>
            ClientAssertionSigning.SignAsync(
                Registration.ClientId.Value,
                Registration.AuthorizationServerIssuer.OriginalString,
                Guid.NewGuid().ToString("N"),
                TimeProvider.GetUtcNow(),
                TimeProvider.GetUtcNow().AddMinutes(5),
                ClientKeys.PrivateKey,
                ClientSigningKeyId,
                App.Server.OAuth().Codecs.JwtHeaderSerializer!,
                App.Server.OAuth().Codecs.JwtPayloadSerializer!,
                App.Server.OAuth().Codecs.Encoder!,
                TestHostShell.MemoryPool,
                cancellationToken);


        /// <summary>Stops the authorization server and the document host and releases the signing material.</summary>
        /// <returns>A task that completes when everything is released.</returns>
        public async ValueTask DisposeAsync()
        {
            await App.DisposeAsync().ConfigureAwait(false);
            ClientKeys.PublicKey.Dispose();
            ClientKeys.PrivateKey.Dispose();
            await DocumentHost.DisposeAsync().ConfigureAwait(false);
        }
    }


    /// <summary>
    /// A fresh <see cref="ExchangeContext"/> under <see cref="TestHostShell.LoopbackOutboundFetchPolicy"/>
    /// — mirrors <c>WebFingerCrossWireFlowTests.NewLoopbackContext</c> — for standalone resolver calls
    /// this suite drives outside a full AS dispatch (pre-registration, the CIMD-063 demonstration).
    /// </summary>
    private static ExchangeContext NewLoopbackContext()
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        return context;
    }
}
