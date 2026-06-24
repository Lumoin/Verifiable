using System.Buffers;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// HTTP wire tests for the Identity Assertion JWT Authorization Grant (ID-JAG,
/// draft-ietf-oauth-identity-assertion-authz-grant). The IdP mints an ID-JAG via Token Exchange
/// (<c>requested_token_type</c> id-jag, §4.3), and a Resource Authorization Server redeems it as an
/// RFC 7523 JWT Bearer assertion for a Bearer access token (§4.4). The tests pin the §3.1 claim set,
/// the §4.3.4 / §4.4.2 responses, the §4.4.1 / §9.3 redeem rules, the §7 discovery metadata, and the
/// §9.1 confidential-client constraint.
/// </summary>
[TestClass]
internal sealed class IdJagGrantTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";
    private const string SubjectIdentity = "https://user.example/alice";

    //The audience the client names for the ID-JAG — the Resource Authorization Server's issuer
    //identifier — distinct from the IdP issuer so the §9.3 same-trust-domain rule is satisfied.
    private const string ResourceAsIssuer = "https://resource-as.example.com/";

    //A distinct client identifier at the Resource Authorization Server (§3.1: the JAG client_id MAY
    //differ from the requesting client). Used by the mint test that proves the differing client_id.
    private const string ResourceClientId = "resource-client-at-rs";

    //The openid scope maps to this resource-server identifier on every RegisterDpopClient
    //registration (ScopeToAudience[openid]); the redeemed access token carries it as aud.
    private const string ResourceServerAudience = "https://rs.example.com";

    private const string ChatScope = "chat.read chat.history";
    private const string SubjectTokenValue = "id-token-opaque-blob";

    /// <summary>
    /// A Refresh Token previously issued by the IdP, used as the <c>subject_token</c> for the §4.3.2
    /// refresh path. The §4.3.3 validation seam accepts only this value (modelling "issued by the IdP,
    /// bound to the authenticated client, unexpired, not revoked"); any other value is a foreign or
    /// revoked Refresh Token the IdP rejects.
    /// </summary>
    private const string RefreshTokenSubjectValue = "idp-refresh-token-abc";

    /// <summary>
    /// The authorization context (granted scope) the IdP recorded for <see cref="RefreshTokenSubjectValue"/>.
    /// A refresh-token-subject exchange may request a scope within this set (§4.3.3); a request beyond it
    /// is denied.
    /// </summary>
    private const string RefreshTokenAuthorizedScope = "openid chat.read";

    /// <summary>The IdP (issuer) tenant a multi-tenant mint stamps as the §3.1 <c>tenant</c> claim.</summary>
    private const string IssuerTenant = "tenant-acme";

    /// <summary>The Resource Authorization Server tenant a mint stamps as the §3.1 <c>aud_tenant</c> claim.</summary>
    private const string ResourceTenant = "rs-tenant-acme";

    /// <summary>The Resource Authorization Server's own subject identifier (§3.1 <c>aud_sub</c>).</summary>
    private const string ResourceSubject = "rs-user-42";

    /// <summary>The SAML issuer entity id stamped into the <c>saml-nameid</c> <c>sub_id</c> (§3.2.1).</summary>
    private const string SamlIssuer = "https://idp.example.com/saml";

    /// <summary>The SAML &lt;NameID&gt; value carried by the <c>saml-nameid</c> <c>sub_id</c> (§3.2.1).</summary>
    private const string SamlNameId = "alice@example.com";

    /// <summary>The Format attribute of the SAML &lt;NameID&gt; (§3.2.1 <c>nameid_format</c>).</summary>
    private const string SamlNameIdFormatAttribute = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

    /// <summary>The SPNameQualifier of the SAML &lt;NameID&gt; (§3.2.1 <c>sp_name_qualifier</c>).</summary>
    private const string SamlSpNameQualifier = "https://resource-as.example.com/saml/sp";

    /// <summary>A SAML issuer unrelated to the validated ID-JAG issuer, for the §9.5 trust test.</summary>
    private const string UnrelatedSamlIssuer = "https://unrelated-saml.example";

    /// <summary>
    /// A <c>saml-nameid</c> Subject Identifier with the REQUIRED members plus two of the four optional
    /// members (<c>nameid_format</c>, <c>sp_name_qualifier</c>); <c>name_qualifier</c> and
    /// <c>sp_provided_id</c> are omitted so the §3.2.2 exactly-when-present rule is observable.
    /// </summary>
    private static readonly SamlNameIdSubjectIdentifier SamlSubjectId = new()
    {
        Issuer = SamlIssuer,
        NameId = SamlNameId,
        NameIdFormat = SamlNameIdFormatAttribute,
        SpNameQualifier = SamlSpNameQualifier
    };

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>Serialises a client-assertion protected header to UTF-8 JSON bytes for the OAuthClient.IdJag flow test.</summary>
    private static readonly JwtHeaderSerializer ClientAssertionHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>Serialises a client-assertion payload to UTF-8 JSON bytes for the OAuthClient.IdJag flow test.</summary>
    private static readonly JwtPayloadSerializer ClientAssertionPayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// §3.1 + §4.3.4: a Token Exchange with <c>requested_token_type</c> id-jag mints an ID-JAG. The
    /// response carries <c>issued_token_type</c> the id-jag URN, the JAG in <c>access_token</c>,
    /// <c>token_type</c> N_A, <c>expires_in</c>, and the granted <c>scope</c>; the JAG header <c>typ</c>
    /// is <c>oauth-id-jag+jwt</c> and the payload carries the §3.1 REQUIRED claim set.
    /// </summary>
    [TestMethod]
    public async Task MintIssuesIdJagWithRequiredClaimsAndResponseShape()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsTrue(response.Headers.CacheControl?.NoStore ?? false, "§4.3.4: Cache-Control: no-store.");

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        //§4.3.4 response fields.
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.IdJag),
            root.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString(),
            "issued_token_type must be the id-jag URN.");
        Assert.AreEqual("N_A", root.GetProperty("token_type").GetString(), "token_type must be N_A — the JAG is not an access token.");
        Assert.IsGreaterThan(0, root.GetProperty("expires_in").GetInt32());
        Assert.AreEqual(ChatScope, root.GetProperty(OAuthRequestParameterNames.Scope).GetString());

        string jag = root.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //§3.1 typ header.
        using JsonDocument header = DecodeHeader(jag);
        Assert.AreEqual("oauth-id-jag+jwt", header.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString());

        //§3.1 REQUIRED claims: iss, sub, aud, client_id, jti, exp, iat.
        using JsonDocument payload = DecodePayload(jag);
        JsonElement claims = payload.RootElement;
        Assert.AreEqual(idpIssuer, claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
        Assert.AreEqual(SubjectIdentity, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.AreEqual(ResourceAsIssuer, claims.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
        Assert.AreEqual(ClientId, claims.GetProperty(WellKnownJwtClaimNames.ClientId).GetString(), "client_id defaults to the requesting client when the seam names none.");
        Assert.IsFalse(string.IsNullOrEmpty(claims.GetProperty(WellKnownJwtClaimNames.Jti).GetString()));
        Assert.IsTrue(claims.TryGetProperty(WellKnownJwtClaimNames.Exp, out _), "exp is REQUIRED.");
        Assert.IsTrue(claims.TryGetProperty(WellKnownJwtClaimNames.Iat, out _), "iat is REQUIRED.");
        Assert.AreEqual(ChatScope, claims.GetProperty(WellKnownJwtClaimNames.Scope).GetString());
    }


    /// <summary>
    /// §3.1 <c>client_id</c>: the JAG's client_id is the client at the Resource Authorization Server,
    /// which MAY differ from the client that requested the ID-JAG. When the authorization seam names a
    /// distinct resource client, that value — not the requesting client — appears in the JAG.
    /// </summary>
    [TestMethod]
    public async Task MintUsesResourceClientIdFromAuthorizationSeam()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: ResourceClientId);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        Assert.AreEqual(ResourceClientId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.ClientId).GetString());
    }


    /// <summary>
    /// §4.3: <c>audience</c> is REQUIRED for an id-jag exchange — it names the Resource Authorization
    /// Server. A request omitting it is malformed (<c>invalid_request</c>), not a grant failure.
    /// </summary>
    [TestMethod]
    public async Task MintWithoutAudienceIsInvalidRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidRequest, body);
    }


    /// <summary>
    /// §4.3.3 / §4.3.4.3: an id-jag mint whose subject token (the Identity Assertion) fails validation
    /// — for example the §4.3.3 MUST that its audience match the authenticating client — is a grant
    /// failure (<c>invalid_grant</c>), not the base RFC 8693 <c>invalid_request</c>.
    /// </summary>
    [TestMethod]
    public async Task MintWithInvalidSubjectTokenIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(null);
        WireIdJagAuthorization(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §4.3.4.3: a denied id-jag exchange (the authorization seam refuses) is <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task MintDeniedByPolicyIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §9.1: ID-JAG SHOULD only be supported for confidential clients. The id-jag mint rides Token
    /// Exchange, which requires client authentication — an unauthenticated request is
    /// <c>invalid_client</c>, so a public client cannot mint an ID-JAG.
    /// </summary>
    [TestMethod]
    public async Task MintWithoutClientAuthenticationIsInvalidClient()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body);
    }


    /// <summary>
    /// The id-jag mint is gated per-client by the <see cref="WellKnownCapabilityIdentifiers.OAuthIdJag"/>
    /// capability. A client allowed Token Exchange but not id-jag whose authorization seam nonetheless
    /// selects the id-jag issued type is an AS misconfiguration → <c>server_error</c>.
    /// </summary>
    [TestMethod]
    public async Task MintWithoutIdJagCapabilityIsServerError()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        WireMintSeams(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.ServerError, body);
    }


    /// <summary>
    /// End-to-end §4.3 → §4.4: the IdP mints an ID-JAG, the Resource Authorization Server redeems it as
    /// a JWT Bearer assertion — validating §4.4.1 (typ, aud, client_id) over the AS JWKS — and issues a
    /// Bearer access token (§4.4.2) that re-verifies. No refresh token is returned (§4.4.3 SHOULD NOT).
    /// </summary>
    [TestMethod]
    public async Task EndToEndMintRedeemAndUse()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //Wire the redeem: the Resource Authorization Server validates the ID-JAG against the IdP JWKS
        //and the §4.4.1 / §9.3 claim rules, with its own issuer identifier as the expected audience.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //Leg 1 — mint.
        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Leg 2 — redeem.
        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
        Assert.IsTrue(redeemResponse.Headers.CacheControl?.NoStore ?? false, "§4.4.2: Cache-Control: no-store.");

        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        JsonElement redeemRoot = redeemDoc.RootElement;

        //§4.4.2: Bearer access token.
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, redeemRoot.GetProperty("token_type").GetString());
        string accessToken = redeemRoot.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //§4.4.3: SHOULD NOT return a refresh token.
        Assert.IsFalse(redeemRoot.TryGetProperty(WellKnownTokenTypes.RefreshToken, out _), "§4.4.3: no refresh token.");

        //Use: the resource-server validates the issued access token.
        JwsAccessTokenValidationResult use = await VerifyAgainstAsAsync(accessToken, idpIssuer, jwksResolver).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, use.FailureDescription);
        Assert.AreEqual(SubjectIdentity, use.Claims!.Subject, "the access token subject is the ID-JAG subject.");
    }


    /// <summary>
    /// Interop golden vector. The minted ID-JAG and both token responses are pinned to the wire shapes in
    /// the draft's non-normative examples — §3.1 (header <c>typ=oauth-id-jag+jwt</c>; the
    /// <c>iss</c>/<c>sub</c>/<c>aud</c>/<c>client_id</c>/<c>jti</c>/<c>exp</c>/<c>iat</c>/<c>scope</c>/<c>resource</c>
    /// claim set, with <c>aud</c> naming the Resource Authorization Server rather than the client), §4.3.4
    /// (Token Exchange response: <c>issued_token_type</c> the id-jag URN, the JAG in <c>access_token</c>,
    /// <c>token_type=N_A</c>, <c>scope</c>), and §4.4.2 (redeem response: <c>token_type=Bearer</c>,
    /// <c>access_token</c>, <c>scope</c>). This is the same canonical example real Cross-App-Access
    /// deployments (e.g. Okta / Auth0) emit. It deliberately asserts the LITERAL published wire names and
    /// values — not our WellKnown constants — so it pins our output to the external contract independently
    /// of our own name definitions, and it is the drop-in point for captured third-party vectors when a
    /// live interop lane is added.
    /// </summary>
    [TestMethod]
    public async Task WireShapeMatchesPublishedInteropExamples()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        //§3.1 example carries scope "chat.read chat.history" and a single resource (a JSON string).
        const string exampleResource = "https://acme.chat.example/api";
        WireMintSeamsGranting(app, ChatScope, [exampleResource]);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //Leg 1 — mint. §4.3.4 Token Exchange response shape.
        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        JsonElement mint = mintDoc.RootElement;
        Assert.AreEqual("urn:ietf:params:oauth:token-type:id-jag", mint.GetProperty("issued_token_type").GetString());
        Assert.AreEqual("N_A", mint.GetProperty("token_type").GetString());
        Assert.AreEqual(ChatScope, mint.GetProperty("scope").GetString());
        string jag = mint.GetProperty("access_token").GetString()!;

        //§3.1 — ID-JAG header.
        using JsonDocument headerDoc = DecodeHeader(jag);
        Assert.AreEqual("oauth-id-jag+jwt", headerDoc.RootElement.GetProperty("typ").GetString());

        //§3.1 — ID-JAG payload: the claim set with published JSON kinds; aud names the Resource AS, not the client.
        using JsonDocument payloadDoc = DecodePayload(jag);
        JsonElement p = payloadDoc.RootElement;
        Assert.AreEqual(idpIssuer, p.GetProperty("iss").GetString());
        Assert.AreEqual(SubjectIdentity, p.GetProperty("sub").GetString());
        Assert.AreEqual(ResourceAsIssuer, p.GetProperty("aud").GetString());
        Assert.AreEqual(ClientId, p.GetProperty("client_id").GetString());
        Assert.AreEqual(JsonValueKind.String, p.GetProperty("jti").ValueKind);
        Assert.AreEqual(JsonValueKind.Number, p.GetProperty("exp").ValueKind);
        Assert.AreEqual(JsonValueKind.Number, p.GetProperty("iat").ValueKind);
        Assert.AreEqual(ChatScope, p.GetProperty("scope").GetString());
        Assert.AreEqual(exampleResource, p.GetProperty("resource").GetString());

        //Leg 2 — redeem. §4.4.2 access-token response shape.
        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        JsonElement r = redeemDoc.RootElement;
        Assert.AreEqual("Bearer", r.GetProperty("token_type").GetString());
        Assert.AreEqual(ChatScope, r.GetProperty("scope").GetString());
        Assert.AreEqual(JsonValueKind.String, r.GetProperty("access_token").ValueKind);
    }


    /// <summary>
    /// Interop firewall: the redeem path accepts an ID-JAG that was built and signed entirely OUTSIDE our
    /// mint pipeline — raw §3.1 claims signed with a separate "external IdP" key, resolved by its own
    /// in-memory JWKS — so the Resource Authorization Server treats it as genuinely foreign wire bytes
    /// (it shares no code, key, or in-memory state with the producer). It verifies the foreign signature,
    /// applies the §4.4.1 / §9.3 claim rules, issues a Bearer access token, and that token carries the
    /// foreign JAG's subject. This is the exact construction a captured real third-party ID-JAG (e.g. from
    /// Okta's xaa.dev) would drop into for a live interop vector — only the key, claims, and validity
    /// window change.
    /// </summary>
    [TestMethod]
    public async Task RedeemAcceptsForeignMintedIdJag()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireClientAuthentication(app);

        //An "external IdP": its own issuer + signing key, with no relationship to our mint pipeline.
        const string externalIdpIssuer = "https://external-idp.example/";
        const string externalKid = "external-idp-key-1";
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> idpKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory idpPublicKey = idpKey.PublicKey;
        using PrivateKeyMemory idpPrivateKey = idpKey.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string foreignJag = await BuildForeignIdJagAsync(
            idpPrivateKey, externalKid, externalIdpIssuer, SubjectIdentity, ResourceAsIssuer,
            ClientId, ChatScope, now, now.AddMinutes(5)).ConfigureAwait(false);

        //The Resource AS resolves the external IdP's key by kid (an in-memory JWKS for the foreign key)
        //and runs the full §4.4.1 validation — nothing here came from our own mint.
        ServerVerificationKeyResolverDelegate foreignResolver =
            (kid, tenant, ctx, ct) => ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? idpPublicKey : null);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, foreignResolver, ResourceAsIssuer).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        using HttpResponseMessage redeem = await PostFormAsync(http, tokenUrl, BuildRedeemForm(foreignJag)).ConfigureAwait(false);
        string body = await redeem.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeem.StatusCode, body);
        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        //§4.4.2: a Bearer access token is issued for the foreign JAG, and the foreign JAG's scope flowed
        //through to the grant — the foreign claims propagated, not just the signature.
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, root.GetProperty("token_type").GetString());
        Assert.AreEqual(JsonValueKind.String, root.GetProperty("access_token").ValueKind);
        Assert.AreEqual(ChatScope, root.GetProperty("scope").GetString());
    }


    /// <summary>
    /// Adversarial interop / §9 signature trust: a foreign ID-JAG is signed with an attacker's key, but
    /// the Resource Authorization Server resolves that <c>kid</c> to a different (legitimately trusted)
    /// key. The signature must be verified against the RESOLVED key — a key-substitution forgery does not
    /// verify — so redeem rejects with <c>invalid_grant</c>. Exercised through the foreign-construction
    /// path (no shared key/state with the producer), not an our-minted-then-tampered JAG.
    /// </summary>
    [TestMethod]
    public async Task RedeemRejectsForeignJagWithSubstitutedSigningKey()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireClientAuthentication(app);

        const string externalIdpIssuer = "https://external-idp.example/";
        const string externalKid = "external-idp-key-1";

        //The JAG is signed with the attacker's key...
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublicKey = attackerKey.PublicKey;
        using PrivateKeyMemory attackerPrivateKey = attackerKey.PrivateKey;

        //...but the Resource AS resolves that kid to a different, legitimately trusted key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> trustedKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory trustedPublicKey = trustedKey.PublicKey;
        using PrivateKeyMemory trustedPrivateKey = trustedKey.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string foreignJag = await BuildForeignIdJagAsync(
            attackerPrivateKey, externalKid, externalIdpIssuer, SubjectIdentity, ResourceAsIssuer,
            ClientId, ChatScope, now, now.AddMinutes(5)).ConfigureAwait(false);

        ServerVerificationKeyResolverDelegate resolver =
            (kid, tenant, ctx, ct) => ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? trustedPublicKey : null);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, resolver, ResourceAsIssuer).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage redeem = await PostFormAsync(
            host.SharedHttpClient!, tokenUrl, BuildRedeemForm(foreignJag)).ConfigureAwait(false);
        string body = await redeem.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)redeem.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// Adversarial interop / §4.4.1 audience + §9.3 no-reuse: a foreign ID-JAG validly signed by a TRUSTED
    /// external IdP, but whose <c>aud</c> names a different Resource Authorization Server, is rejected with
    /// <c>invalid_grant</c>. A valid signature and an established trust relationship do not let a foreign
    /// minter inject a grant intended for another RS (audience injection / cross-RS replay).
    /// </summary>
    [TestMethod]
    public async Task RedeemRejectsForeignJagWithWrongAudience()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireClientAuthentication(app);

        const string externalIdpIssuer = "https://external-idp.example/";
        const string externalKid = "external-idp-key-1";
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> idpKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory idpPublicKey = idpKey.PublicKey;
        using PrivateKeyMemory idpPrivateKey = idpKey.PrivateKey;

        //Validly signed by a trusted IdP, but aud names a DIFFERENT Resource AS.
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string foreignJag = await BuildForeignIdJagAsync(
            idpPrivateKey, externalKid, externalIdpIssuer, SubjectIdentity, "https://other-rs.example/",
            ClientId, ChatScope, now, now.AddMinutes(5)).ConfigureAwait(false);

        ServerVerificationKeyResolverDelegate resolver =
            (kid, tenant, ctx, ct) => ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? idpPublicKey : null);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, resolver, ResourceAsIssuer).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage redeem = await PostFormAsync(
            host.SharedHttpClient!, tokenUrl, BuildRedeemForm(foreignJag)).ConfigureAwait(false);
        string body = await redeem.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)redeem.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// RFC 7523 §3 (rule 7) replay defense: the surfaced <c>jti</c> lets a Resource Authorization Server
    /// track redeemed grants and refuse reuse. With an app-side jti store wired into the validation seam,
    /// the first redemption of an ID-JAG succeeds and the SECOND redemption of the same grant (same
    /// <c>jti</c>) is rejected with <c>invalid_grant</c>. The library holds no token store — it surfaces
    /// <c>jti</c> on the validation result and the rejection seam; the store and the policy are the app's.
    /// </summary>
    [TestMethod]
    public async Task RedeemRejectsReplayedJti()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //The standard redeem seam surfaces the JAG's iss/jti/exp on the grant; the library's
        //JtiReplayGuard records and enforces replay against the host's shared (issuer, jti) store — the
        //same defense the JAR and DPoP paths use, governed by the default JtiReplayPolicy. No bespoke
        //tracking here: the host wires the store, the library owns the check.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //First redemption — accepted; the library records the jti as first-use.
        using HttpResponseMessage first = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string firstBody = await first.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)first.StatusCode, firstBody);

        //Second redemption of the SAME grant — the shared jti store sees the replay and refuses.
        using HttpResponseMessage second = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string secondBody = await second.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)second.StatusCode, secondBody);
        Assert.Contains(OAuthErrors.InvalidGrant, secondBody);
    }


    /// <summary>
    /// §4.4.1: the redeemed assertion's <c>typ</c> MUST be <c>oauth-id-jag+jwt</c>. Presenting an
    /// ordinary access token (a different typ) as the assertion is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithWrongTypIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //An ordinary RFC 9068 access token — valid signature, wrong typ.
        string accessTokenAsAssertion = await ObtainClientCredentialsAccessTokenAsync(
            http, tokenUrl, ClientId, ClientSecret, WellKnownScopes.OpenId).ConfigureAwait(false);

        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = accessTokenAsAssertion
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §4.4.1: the <c>aud</c> claim MUST name the Resource Authorization Server's issuer. A JAG minted
    /// for a different audience is rejected with <c>invalid_grant</c> (audience injection defense).
    /// </summary>
    [TestMethod]
    public async Task RedeemWithAudienceMismatchIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //Mint a JAG whose aud is a different Resource Authorization Server.
        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, "https://attacker-as.example.com/")
            .ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §4.4.1: the <c>client_id</c> claim MUST match the authenticated client. A JAG minted with a
    /// different resource client_id is rejected with <c>invalid_grant</c> (client continuity).
    /// </summary>
    [TestMethod]
    public async Task RedeemWithClientIdMismatchIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: "a-different-resource-client");

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §9.3: a Resource Authorization Server MUST NOT redeem an ID-JAG issued in its own trust domain.
    /// When the RS issuer equals the JAG <c>iss</c>, redemption is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemSameTrustDomainIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //The Resource Authorization Server's issuer equals the IdP issuer — same trust domain.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, idpIssuer).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §4.4.1 (RFC 7521 §5.2): an expired ID-JAG is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemExpiredIdJagIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Advance past the default 5-minute JAG lifetime plus the 60s redeem skew.
        TimeProvider.Advance(TimeSpan.FromMinutes(6) + TimeSpan.FromSeconds(61));

        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §7.1 / §7.2: discovery advertises the id-jag token type in
    /// <c>identity_chaining_requested_token_types_supported</c>, the id-jag grant profile in
    /// <c>authorization_grant_profiles_supported</c>, and the token-exchange + jwt-bearer grant types
    /// (the latter REQUIRED by §7.2 when the profile is advertised).
    /// </summary>
    [TestMethod]
    public async Task DiscoveryAdvertisesIdJagMetadata()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri metadataUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/openid-configuration");

        using HttpResponseMessage response = await host.SharedHttpClient!.GetAsync(metadataUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        string[] tokenTypes = [.. root.GetProperty(
            AuthorizationServerMetadataParameterNames.IdentityChainingRequestedTokenTypesSupported)
            .EnumerateArray().Select(static e => e.GetString()!)];
        Assert.Contains(TokenTypeNames.GetName(TokenType.IdJag), tokenTypes);

        string[] profiles = [.. root.GetProperty(
            AuthorizationServerMetadataParameterNames.AuthorizationGrantProfilesSupported)
            .EnumerateArray().Select(static e => e.GetString()!)];
        Assert.Contains(WellKnownGrantProfiles.IdJag, profiles);

        string[] grantTypes = [.. root.GetProperty(
            AuthorizationServerMetadataParameterNames.GrantTypesSupported)
            .EnumerateArray().Select(static e => e.GetString()!)];
        Assert.Contains(WellKnownGrantTypes.TokenExchange, grantTypes);
        Assert.Contains(WellKnownGrantTypes.JwtBearer, grantTypes);
    }


    /// <summary>
    /// §4.4.1 (RFC 7521 §5.2): the ID-JAG signature MUST verify. A tampered assertion (its signature
    /// no longer matches the header+payload) is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithTamperedSignatureIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = TamperSignature(jag)
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §9.5 trust ordering: issuer trust is established by resolving the verification key only for
    /// trusted issuers. A JAG whose signing key is not resolvable (an untrusted issuer / unknown
    /// <c>kid</c>) fails closed — the assertion is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithUnresolvableKeyIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        //An empty key resolver — no issuer's key resolves, modelling an untrusted issuer.
        ServerVerificationKeyResolverDelegate emptyResolver =
            static (kid, tenant, ctx, ct) => ValueTask.FromResult<PublicKeyMemory?>(null);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, emptyResolver, ResourceAsIssuer).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §4.3.3: for an ID-Token subject token the IdP MUST validate that the assertion's audience
    /// matches the <c>client_id</c> of the authenticating client. With a seam that enforces this, a
    /// subject token whose audience is a different client is rejected (<c>invalid_grant</c>), while one
    /// whose audience is the authenticating client mints an ID-JAG.
    /// </summary>
    [TestMethod]
    public async Task MintEnforcesSubjectTokenAudienceEqualsClient()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        //The seam models §4.3.3: it accepts the subject token only when the (here, the subject_token
        //value stands in for) Identity Assertion audience equals the authenticated client.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    string.Equals(token, registration.ClientId, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken { Subject = SubjectIdentity }
                        : null);
        WireIdJagAuthorization(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //Audience == authenticated client → mints.
        using HttpResponseMessage matched = await PostMintWithSubjectAsync(http, tokenUrl, ResourceAsIssuer, ClientId)
            .ConfigureAwait(false);
        string matchedBody = await matched.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)matched.StatusCode, matchedBody);

        //Audience != authenticated client → invalid_grant (§4.3.3 / §4.3.4.3).
        using HttpResponseMessage mismatched = await PostMintWithSubjectAsync(http, tokenUrl, ResourceAsIssuer, "https://other-rp.example")
            .ConfigureAwait(false);
        string mismatchedBody = await mismatched.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)mismatched.StatusCode, mismatchedBody);
        Assert.Contains(OAuthErrors.InvalidGrant, mismatchedBody);
    }


    /// <summary>
    /// §4.3: the IdP MAY resolve an implementation-specific <c>audience</c> value to the Resource
    /// Authorization Server's issuer it stamps into <c>aud</c>. When the authorization seam shapes an
    /// audience, that value — not the request's <c>audience</c> — appears in the JAG.
    /// </summary>
    [TestMethod]
    public async Task MintUsesSeamShapedAudienceOverRequest()
    {
        const string seamShapedAudience = "https://seam-resolved-as.example/";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        Audience = [seamShapedAudience]
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //The request names a different audience; the seam-shaped audience must win.
        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        Assert.AreEqual(seamShapedAudience, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
    }


    /// <summary>
    /// §3.1 / §4.3.3: the IdP includes the granted <c>resource</c> (RFC 8707) in the JAG. A single
    /// granted resource appears as a JSON string.
    /// </summary>
    [TestMethod]
    public async Task MintIncludesGrantedResourceClaim()
    {
        const string grantedResource = "https://api.chat.example/files";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGranting(app, ChatScope, [grantedResource]);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        Assert.AreEqual(grantedResource, payload.RootElement.GetProperty(OAuthRequestParameterNames.Resource).GetString());
    }


    /// <summary>
    /// §3.1: multiple granted resources appear as a JSON array of URIs.
    /// </summary>
    [TestMethod]
    public async Task MintIncludesMultipleGrantedResourcesAsArray()
    {
        string[] grantedResources = ["https://api.chat.example/files", "https://api.chat.example/messages"];

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGranting(app, ChatScope, grantedResources);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        string[] resourceClaim = [.. payload.RootElement.GetProperty(OAuthRequestParameterNames.Resource)
            .EnumerateArray().Select(static e => e.GetString()!)];
        CollectionAssert.AreEqual(grantedResources, resourceClaim);
    }


    /// <summary>
    /// §4.3.4: when the granted scope differs from the requested scope (here narrowed to a subset), the
    /// response carries the granted scope, not the requested one.
    /// </summary>
    [TestMethod]
    public async Task MintResponseReflectsGrantedScopeNarrowerThanRequested()
    {
        const string requestedScope = "chat.read chat.history chat.write";
        const string grantedScope = "chat.read";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGranting(app, grantedScope, []);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.Scope] = requestedScope,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(grantedScope, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString());

        //The JAG itself carries the granted scope.
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        Assert.AreEqual(grantedScope, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString());
    }


    /// <summary>
    /// §3.1 / §4.3.3: the IdP includes the granted <c>authorization_details</c> (RFC 9396) in the JAG
    /// as a JSON array of authorization detail objects. When the granted details match the request the
    /// §4.3.4 response omits the field (the client already holds them).
    /// </summary>
    [TestMethod]
    public async Task MintEmbedsGrantedAuthorizationDetailsInJag()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGrantingDetails(app, SampleGrantedDetails(), responseJson: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        //Not changed from the request → response omits authorization_details.
        Assert.IsFalse(doc.RootElement.TryGetProperty(OAuthRequestParameterNames.AuthorizationDetails, out _));

        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        JsonElement details = payload.RootElement.GetProperty(OAuthRequestParameterNames.AuthorizationDetails);
        Assert.AreEqual(JsonValueKind.Array, details.ValueKind);
        Assert.AreEqual("chat_read", details[0].GetProperty("type").GetString());
        Assert.AreEqual("read", details[0].GetProperty("actions")[0].GetString());
    }


    /// <summary>
    /// §4.3.3: the <c>authorization_details</c> the client posts reaches the IdP policy seam verbatim,
    /// the granted result lands in the JAG, and §4.3.4 omits the response field when the IdP did not
    /// change the details.
    /// </summary>
    [TestMethod]
    public async Task MintConveysRequestedAuthorizationDetailsToSeam()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        string? capturedRequestDetails = null;
        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            (subject, actor, request, registration, context, ct) =>
            {
                capturedRequestDetails = request.AuthorizationDetails;

                return ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        AuthorizationDetailsClaim = SampleGrantedDetails()
                    });
            };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken),
            [OAuthRequestParameterNames.AuthorizationDetails] = SampleDetailsJson
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        //§4.3.3: the posted authorization_details reached the policy seam.
        Assert.AreEqual(SampleDetailsJson, capturedRequestDetails);

        using JsonDocument doc = JsonDocument.Parse(body);
        //§4.3.4: the IdP did not signal a change (no response JSON), so the response omits the field.
        Assert.IsFalse(doc.RootElement.TryGetProperty(OAuthRequestParameterNames.AuthorizationDetails, out _));

        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        Assert.AreEqual("chat_read",
            payload.RootElement.GetProperty(OAuthRequestParameterNames.AuthorizationDetails)[0].GetProperty("type").GetString());
    }


    /// <summary>
    /// §4.4.1: redeeming a JAG that carries a granted <c>resource</c>, the Resource Authorization
    /// Server reflects it as the access token's <c>aud</c> (RFC 8707 audience binding).
    /// </summary>
    [TestMethod]
    public async Task RedeemBindsResourceToAccessTokenAudience()
    {
        const string grantedResource = "https://api.chat.example/files";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGranting(app, WellKnownScopes.OpenId, [grantedResource]);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument tokenPayload = DecodePayload(accessToken);
        Assert.AreEqual(grantedResource, tokenPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
    }


    /// <summary>
    /// §4.3.4: when the granted scope narrows to nothing while the client requested a scope, the
    /// response carries an empty <c>scope</c> (the granted value differs from the request, so it is
    /// REQUIRED), and the JAG omits the empty scope claim.
    /// </summary>
    [TestMethod]
    public async Task MintEmitsEmptyScopeWhenGrantNarrowsToNone()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGranting(app, grantedScope: string.Empty, grantedResource: []);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.Scope] = "chat.read chat.history",
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(string.Empty, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString());

        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Scope, out _));
    }


    /// <summary>
    /// §4.3.4: when the IdP changed the authorization details, the token-exchange response includes the
    /// granted <c>authorization_details</c> array.
    /// </summary>
    [TestMethod]
    public async Task MintResponseEchoesAuthorizationDetailsWhenChanged()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGrantingDetails(app, SampleGrantedDetails(), responseJson: SampleDetailsJson);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement details = doc.RootElement.GetProperty(OAuthRequestParameterNames.AuthorizationDetails);
        Assert.AreEqual(JsonValueKind.Array, details.ValueKind);
        Assert.AreEqual("chat_read", details[0].GetProperty("type").GetString());
    }


    /// <summary>
    /// §4.4.1 / §4.4.2: redeeming an ID-JAG that carries <c>authorization_details</c>, the Resource
    /// Authorization Server embeds the granted details in the access token and echoes them in the
    /// token response.
    /// </summary>
    [TestMethod]
    public async Task RedeemEmbedsAndEchoesGrantedAuthorizationDetails()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeamsGrantingDetails(app, SampleGrantedDetails(), responseJson: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //The Resource Authorization Server grants the authorization_details it found on the validated
        //grant (here, verbatim) and echoes them.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
            {
                JwtBearerGrant? grant = await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer)
                    .ConfigureAwait(false);

                //grant.AuthorizationDetailsClaim already carries the details decoded from the JAG; only
                //the response echo (a pre-serialised string) is added here.
                return grant is null
                    ? null
                    : grant with { AuthorizationDetailsResponseJson = SampleDetailsJson };
            };

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }).ConfigureAwait(false);

        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        //§4.4.2 response echo.
        JsonElement responseDetails = redeemDoc.RootElement.GetProperty(OAuthRequestParameterNames.AuthorizationDetails);
        Assert.AreEqual("chat_read", responseDetails[0].GetProperty("type").GetString());
        Assert.AreEqual("read", responseDetails[0].GetProperty("actions")[0].GetString());

        //§4.4.1 access-token claim — the details decoded from the JAG round-tripped into the token,
        //nested arrays intact.
        string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument tokenPayload = DecodePayload(accessToken);
        JsonElement tokenDetails = tokenPayload.RootElement.GetProperty(OAuthRequestParameterNames.AuthorizationDetails);
        Assert.AreEqual("chat_read", tokenDetails[0].GetProperty("type").GetString());
        Assert.AreEqual("read", tokenDetails[0].GetProperty("actions")[0].GetString());
    }


    private const string SampleDetailsJson = """[{"type":"chat_read","actions":["read"]}]""";


    private static List<object> SampleGrantedDetails() =>
    [
        new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["type"] = "chat_read",
            ["actions"] = new object[] { "read" }
        }
    ];


    private static void WireMintSeamsGrantingDetails(TestHostShell app, IReadOnlyList<object> grantedDetails, string? responseJson)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });

        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        AuthorizationDetailsClaim = grantedDetails,
                        AuthorizationDetailsResponseJson = responseJson
                    });
    }


    private static void WireMintSeamsGranting(TestHostShell app, string grantedScope, IReadOnlyList<string> grantedResource)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });

        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = grantedScope,
                        IssuedTokenType = TokenType.IdJag,
                        Resource = grantedResource
                    });
    }


    /// <summary>
    /// §9.8.1.1: when the Token Exchange carries a DPoP proof, the IdP validates it and binds the JAG
    /// by stamping <c>cnf.jkt</c> with the proof's JWK SHA-256 thumbprint.
    /// </summary>
    [TestMethod]
    public async Task MintWithDpopProofBindsJagToCnfJkt()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string expectedJkt = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            string proof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);

            using HttpResponseMessage response = await PostFormWithDpopAsync(
                http, tokenUrl, BuildMintForm(ResourceAsIssuer), proof).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)response.StatusCode, body);

            using JsonDocument doc = JsonDocument.Parse(body);
            string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
            using JsonDocument payload = DecodePayload(jag);
            Assert.AreEqual(expectedJkt,
                payload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §9.8.1.1 rule 2: a Token Exchange with no DPoP proof issues an ID-JAG without a <c>cnf</c> claim.
    /// </summary>
    [TestMethod]
    public async Task MintWithoutDpopProofIssuesNoCnf()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        Assert.IsFalse(payload.RootElement.TryGetProperty("cnf", out _), "An unbound JAG carries no cnf claim.");
    }


    /// <summary>
    /// §9.8.1.2.1: redeeming a key-bound ID-JAG with a matching DPoP proof issues a sender-constrained
    /// (DPoP) access token bound to the same key.
    /// </summary>
    [TestMethod]
    public async Task RedeemBoundJagWithMatchingDpopIssuesDpopBoundToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string expectedJkt = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

            string jag = await MintBoundJagAsync(http, tokenUrl, dpopKey, segment, material).ConfigureAwait(false);

            string redeemProof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);
            using HttpResponseMessage redeemResponse = await PostFormWithDpopAsync(
                http, tokenUrl, BuildRedeemForm(jag), redeemProof).ConfigureAwait(false);
            string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

            using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, redeemDoc.RootElement.GetProperty("token_type").GetString());
            string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
            using JsonDocument tokenPayload = DecodePayload(accessToken);
            Assert.AreEqual(expectedJkt, tokenPayload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §9.8.1.2.2: a key-bound ID-JAG redeemed without a DPoP proof is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemBoundJagWithoutDpopIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string jag = await MintBoundJagAsync(http, tokenUrl, dpopKey, segment, material).ConfigureAwait(false);

            //Redeem with no DPoP header.
            using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag))
                .ConfigureAwait(false);
            string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
            Assert.Contains(OAuthErrors.InvalidGrant, redeemBody);
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §9.8.1.2.1 step 4: a key-bound ID-JAG redeemed with a DPoP proof whose key does not match the
    /// <c>cnf.jkt</c> is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemBoundJagWithMismatchedDpopIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bindingKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> otherKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey bindingKey = new(bindingKeyMaterial, WellKnownJwaValues.Es256);
            DpopKey otherKey = new(otherKeyMaterial, WellKnownJwaValues.Es256);

            string jag = await MintBoundJagAsync(http, tokenUrl, bindingKey, segment, material).ConfigureAwait(false);

            //Redeem with a proof from a DIFFERENT key.
            string redeemProof = await BuildTokenEndpointDpopProofAsync(otherKey, segment, material).ConfigureAwait(false);
            using HttpResponseMessage redeemResponse = await PostFormWithDpopAsync(
                http, tokenUrl, BuildRedeemForm(jag), redeemProof).ConfigureAwait(false);
            string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
            Assert.Contains(OAuthErrors.InvalidGrant, redeemBody);
        }
        finally
        {
            bindingKeyMaterial.PublicKey.Dispose();
            bindingKeyMaterial.PrivateKey.Dispose();
            otherKeyMaterial.PublicKey.Dispose();
            otherKeyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §9.8.1.2.3: an ID-JAG with no <c>cnf</c> claim redeemed with a DPoP proof issues a
    /// sender-constrained (DPoP) access token bound to the proof's key.
    /// </summary>
    [TestMethod]
    public async Task RedeemUnboundJagWithDpopIssuesDpopBoundToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //Mint an unbound JAG (no DPoP proof at the mint → no cnf).
        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string expectedJkt = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

            string redeemProof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);
            using HttpResponseMessage redeemResponse = await PostFormWithDpopAsync(
                http, tokenUrl, BuildRedeemForm(jag), redeemProof).ConfigureAwait(false);
            string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

            using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, redeemDoc.RootElement.GetProperty("token_type").GetString());
            string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
            using JsonDocument tokenPayload = DecodePayload(accessToken);
            Assert.AreEqual(expectedJkt, tokenPayload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §9.8.1.2.4: an unbound ID-JAG redeemed without a DPoP proof at a Resource Server that requires
    /// sender-constrained tokens is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemUnboundJagWithoutDpopWhereConstrainedRequiredIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        //The Resource Server requires sender-constrained tokens.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
            {
                JwtBearerGrant? grant = await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer)
                    .ConfigureAwait(false);

                return grant is null ? null : grant with { RequiresSenderConstrainedToken = true };
            };

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag))
            .ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
        Assert.Contains(OAuthErrors.InvalidGrant, redeemBody);
    }


    /// <summary>
    /// §9.8.1.2.1 step 1: redeeming a key-bound ID-JAG with a present-but-cryptographically-invalid
    /// DPoP proof is hard-rejected (<c>invalid_dpop_proof</c>) before the thumbprint matrix runs — it
    /// is not silently downgraded to a Bearer token.
    /// </summary>
    [TestMethod]
    public async Task RedeemBoundJagWithTamperedDpopIsInvalidDpopProof()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string jag = await MintBoundJagAsync(http, tokenUrl, dpopKey, segment, material).ConfigureAwait(false);

            string redeemProof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);
            using HttpResponseMessage redeemResponse = await PostFormWithDpopAsync(
                http, tokenUrl, BuildRedeemForm(jag), TamperSignature(redeemProof)).ConfigureAwait(false);
            string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
            Assert.Contains(OAuthErrors.InvalidDpopProof, redeemBody);
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §9.8.1.1 rule 1: a present-but-invalid DPoP proof at the mint is refused
    /// (<c>invalid_dpop_proof</c>) — the IdP does not silently issue an unbound JAG.
    /// </summary>
    [TestMethod]
    public async Task MintWithInvalidDpopProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, ChatScope, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string proof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);

            using HttpResponseMessage response = await PostFormWithDpopAsync(
                http, tokenUrl, BuildMintForm(ResourceAsIssuer), TamperSignature(proof)).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, (int)response.StatusCode, body);
            Assert.Contains(OAuthErrors.InvalidDpopProof, body);
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §9.8.1.2.4: at a Resource Server that requires sender-constrained tokens, presenting a valid
    /// DPoP proof on an unbound ID-JAG satisfies the requirement and issues a DPoP-bound token.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithDpopSatisfiesSenderConstraintRequirement()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);
        app.EnableDpop();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
            {
                JwtBearerGrant? grant = await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer)
                    .ConfigureAwait(false);

                return grant is null ? null : grant with { RequiresSenderConstrainedToken = true };
            };

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string redeemProof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);

            using HttpResponseMessage redeemResponse = await PostFormWithDpopAsync(
                http, tokenUrl, BuildRedeemForm(jag), redeemProof).ConfigureAwait(false);
            string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
            using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP,
                redeemDoc.RootElement.GetProperty("token_type").GetString());
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// §4.3.2 / §4.3.3: a Refresh Token previously issued by the IdP is accepted as the
    /// <c>subject_token</c> (<c>subject_token_type</c> = the refresh_token URN) and exchanged for an
    /// ID-JAG without a fresh Identity Assertion. End-to-end: the minted JAG redeems at the Resource
    /// Authorization Server for a Bearer access token whose subject is the Refresh Token's subject, and
    /// no refresh token is returned (§4.4.3 SHOULD NOT).
    /// </summary>
    [TestMethod]
    public async Task MintWithRefreshTokenSubjectMintsIdJagAndRedeems()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireRefreshTokenSubjectMintSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //Leg 1 — exchange the Refresh Token for an ID-JAG (§4.3.2), requesting a scope within the RT's
        //authorization context.
        using HttpResponseMessage mintResponse = await PostRefreshTokenMintAsync(
            http, tokenUrl, ResourceAsIssuer, WellKnownScopes.OpenId, RefreshTokenSubjectValue).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);

        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.IdJag),
            mintDoc.RootElement.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString(),
            "the refresh-token exchange still mints an id-jag.");
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument jagPayload = DecodePayload(jag);
        Assert.AreEqual(SubjectIdentity, jagPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());

        //Leg 2 — redeem the JAG for a Bearer access token (§4.4).
        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, redeemDoc.RootElement.GetProperty("token_type").GetString());

        //§4.4.3: SHOULD NOT return a refresh token.
        Assert.IsFalse(redeemDoc.RootElement.TryGetProperty(WellKnownTokenTypes.RefreshToken, out _), "§4.4.3: no refresh token.");

        string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        JwsAccessTokenValidationResult use = await VerifyAgainstAsAsync(accessToken, idpIssuer, jwksResolver).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, use.FailureDescription);
        Assert.AreEqual(SubjectIdentity, use.Claims!.Subject, "the access token subject is the Refresh Token's subject.");
    }


    /// <summary>
    /// §4.3.3 / §4.3.4.3: a Refresh Token <c>subject_token</c> the IdP cannot validate — not one it
    /// issued, revoked, or bound to a different client — is a grant failure (<c>invalid_grant</c>). The
    /// §4.3.3 validation seam returns null for any Refresh Token other than the one it issued to this
    /// client, mirroring the standard refresh_token-grant validation the IdP would apply.
    /// </summary>
    [TestMethod]
    public async Task MintWithInvalidRefreshTokenSubjectIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireRefreshTokenSubjectMintSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostRefreshTokenMintAsync(
            host.SharedHttpClient!, tokenUrl, ResourceAsIssuer, WellKnownScopes.OpenId, "foreign-or-revoked-refresh-token")
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// §4.3.3: a refresh-token-subject exchange whose requested scope exceeds the Refresh Token's
    /// authorization context is denied with <c>invalid_grant</c> — the issued ID-JAG cannot widen the
    /// authority the Refresh Token carried. The authorization seam sees both the validated subject's
    /// scope (the RT context) and the requested scope and refuses the escalation.
    /// </summary>
    [TestMethod]
    public async Task MintWithRefreshTokenSubjectScopeBeyondContextIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireRefreshTokenSubjectMintSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //chat.write is outside the Refresh Token's authorization context ("openid chat.read").
        using HttpResponseMessage response = await PostRefreshTokenMintAsync(
            host.SharedHttpClient!, tokenUrl, ResourceAsIssuer, "openid chat.write", RefreshTokenSubjectValue)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// Wires the §4.3.2 / §4.3.3 refresh-token-subject mint seams: client authentication, a subject-token
    /// validation that accepts a Refresh Token only when it is the one this IdP issued
    /// (<see cref="RefreshTokenSubjectValue"/>) — modelling "issued by the IdP, bound to the authenticated
    /// client, unexpired, not revoked" — surfacing the RT's authorization context as the validated scope,
    /// and an authorization seam that mints an ID-JAG only when the requested scope stays within that
    /// context (§4.3.3).
    /// </summary>
    private static void WireRefreshTokenSubjectMintSeams(TestHostShell app)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    tokenType == TokenType.RefreshToken
                    && string.Equals(token, RefreshTokenSubjectValue, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken
                        {
                            Subject = SubjectIdentity,
                            Scope = RefreshTokenAuthorizedScope,
                            Audience = [ResourceAsIssuer]
                        }
                        : null);

        app.Server.OAuth().AuthorizeTokenExchangeAsync = static (subject, actor, request, registration, context, ct) =>
        {
            //§4.3.3: the requested scope MUST remain within the Refresh Token's authorization context
            //(the scope surfaced on the validated subject token). A request that exceeds it is denied.
            string[] authorized = (subject.Scope ?? string.Empty).Split(
                ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            string[] requested = (request.Scope ?? string.Empty).Split(
                ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach(string requestedScope in requested)
            {
                if(!authorized.Contains(requestedScope))
                {
                    return ValueTask.FromResult<TokenExchangeAuthorization?>(null);
                }
            }

            return ValueTask.FromResult<TokenExchangeAuthorization?>(
                new TokenExchangeAuthorization
                {
                    Subject = subject.Subject,
                    Scope = request.Scope ?? subject.Scope ?? string.Empty,
                    IssuedTokenType = TokenType.IdJag
                });
        };
    }


    /// <summary>
    /// Posts a Token Exchange that uses a Refresh Token as the <c>subject_token</c>
    /// (<c>subject_token_type</c> = the refresh_token URN) requesting an ID-JAG (§4.3.2).
    /// </summary>
    private Task<HttpResponseMessage> PostRefreshTokenMintAsync(
        HttpClient http, Uri tokenUrl, string audience, string scope, string refreshToken) =>
        PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = audience,
            [OAuthRequestParameterNames.Scope] = scope,
            [OAuthRequestParameterNames.SubjectToken] = refreshToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.RefreshToken)
        });


    /// <summary>
    /// §3.1 / §6: when the authorization seam supplies tenant relationships, the minted ID-JAG carries
    /// the issuer-tenant (<c>tenant</c>) plus the Resource Authorization Server tenant (<c>aud_tenant</c>)
    /// and that server's own subject identifier (<c>aud_sub</c>).
    /// </summary>
    [TestMethod]
    public async Task MintEmitsTenantClaimsWhenSeamSuppliesThem()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireTenantMintSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        JsonElement claims = payload.RootElement;
        Assert.AreEqual(IssuerTenant, claims.GetProperty(WellKnownJwtClaimNames.Tenant).GetString());
        Assert.AreEqual(ResourceTenant, claims.GetProperty(WellKnownJwtClaimNames.AudienceTenant).GetString());
        Assert.AreEqual(ResourceSubject, claims.GetProperty(WellKnownJwtClaimNames.AudienceSubject).GetString());
    }


    /// <summary>
    /// §3.1 / §6: the Resource Authorization Server's redeem validation surfaces the tenant relationships
    /// (<c>tenant</c> / <c>aud_tenant</c> / <c>aud_sub</c>) from a minted JAG so it can scope subject
    /// resolution (<c>iss + tenant + sub</c>) and resolve its own account identifier.
    /// </summary>
    [TestMethod]
    public async Task RedeemSurfacesTenantClaimsForSubjectResolution()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireTenantMintSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //The Resource Authorization Server validates the JAG and reads the tenant claims (§3.1 / §6).
        (JwtHeader header, JwtPayload payload) = ParseJwtParts(jag);
        IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
            header, payload, ResourceAsIssuer, ClientId, TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60));

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(IssuerTenant, result.Tenant);
        Assert.AreEqual(ResourceTenant, result.AudienceTenant);
        Assert.AreEqual(ResourceSubject, result.AudienceSubject);
    }


    /// <summary>
    /// §6.3: a multi-tenant Resource Authorization Server that requires the <c>tenant</c> claim for
    /// subject-identifier scoping rejects a validated-but-tenant-less ID-JAG with <c>invalid_grant</c>.
    /// The library surfaces the (absent) tenant; the Resource Authorization Server's policy enforces the
    /// requirement.
    /// </summary>
    [TestMethod]
    public async Task RedeemRequiringTenantRejectsGrantWithoutTenant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        //A normal mint (no tenant relationships supplied) → the JAG carries no tenant claim.
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
            {
                JwtBearerGrant? grant = await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer)
                    .ConfigureAwait(false);
                if(grant is null)
                {
                    return null;
                }

                //§6.3: this Resource Authorization Server is multi-tenant and requires the tenant claim;
                //a validated grant that carries none cannot be scoped → reject.
                (JwtHeader header, JwtPayload payload) = ParseJwtParts(assertion);
                IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
                    header, payload, ResourceAsIssuer, registration.ClientId, TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60));

                return result.Tenant is null ? null : grant;
            };

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
        Assert.Contains(OAuthErrors.InvalidGrant, redeemBody);
    }


    /// <summary>
    /// Wires the mint seams so the authorization step supplies the §3.1 tenant relationships — the
    /// issuer-tenant, the Resource Authorization Server tenant, and that server's subject identifier.
    /// </summary>
    private static void WireTenantMintSeams(TestHostShell app)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });

        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        Tenant = IssuerTenant,
                        AudienceTenant = ResourceTenant,
                        AudienceSubject = ResourceSubject
                    });
    }


    /// <summary>Decodes the header and payload of a compact JWS for direct redeem-side validation.</summary>
    private static (JwtHeader Header, JwtPayload Payload) ParseJwtParts(string compactJws)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts);

        JwtHeader header;
        using(IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], Pool))
        {
            header = JwsAccessTokenTestSupport.Parser.ParseHeader(headerBytes.Memory);
        }

        JwtPayload payload;
        using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
        {
            payload = JwsAccessTokenTestSupport.Parser.ParseClaims(payloadBytes.Memory);
        }

        return (header, payload);
    }


    /// <summary>
    /// §3.2.1 / §3.2.2: when the authorization seam supplies a SAML NameID Subject Identifier, the minted
    /// JAG carries the <c>sub_id</c> object with <c>format</c> = <c>saml-nameid</c>, the REQUIRED
    /// <c>issuer</c> / <c>nameid</c>, and each optional member exactly when present (the supplied
    /// identifier omits <c>name_qualifier</c> and <c>sp_provided_id</c>, so those are absent).
    /// </summary>
    [TestMethod]
    public async Task MintEmitsSamlNameIdSubjectIdentifier()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireSamlSubjectIdMintSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        JsonElement subId = payload.RootElement.GetProperty(WellKnownJwtClaimNames.SubId);

        Assert.AreEqual(SamlNameIdMemberNames.SamlNameIdFormat, subId.GetProperty(SamlNameIdMemberNames.Format).GetString());
        Assert.AreEqual(SamlIssuer, subId.GetProperty(SamlNameIdMemberNames.Issuer).GetString());
        Assert.AreEqual(SamlNameId, subId.GetProperty(SamlNameIdMemberNames.NameId).GetString());
        Assert.AreEqual(SamlNameIdFormatAttribute, subId.GetProperty(SamlNameIdMemberNames.NameIdFormat).GetString());
        Assert.AreEqual(SamlSpNameQualifier, subId.GetProperty(SamlNameIdMemberNames.SpNameQualifier).GetString());

        //§3.2.2: members absent on the source identifier are absent in the claim.
        Assert.IsFalse(subId.TryGetProperty(SamlNameIdMemberNames.NameQualifier, out _), "name_qualifier omitted when absent.");
        Assert.IsFalse(subId.TryGetProperty(SamlNameIdMemberNames.SpProvidedId, out _), "sp_provided_id omitted when absent.");
    }


    /// <summary>
    /// §3.2: the Resource Authorization Server's redeem validation parses and surfaces the
    /// <c>saml-nameid</c> <c>sub_id</c> (issuer, nameid, and the present optional members) for subject
    /// resolution, leaving the absent optional members null.
    /// </summary>
    [TestMethod]
    public async Task RedeemSurfacesSamlNameIdSubjectIdentifier()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);
        WireSamlSubjectIdMintSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        (JwtHeader header, JwtPayload payload) = ParseJwtParts(jag);
        IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
            header, payload, ResourceAsIssuer, ClientId, TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60));

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNotNull(result.SubjectIdentifier);
        Assert.AreEqual(SamlIssuer, result.SubjectIdentifier!.Issuer);
        Assert.AreEqual(SamlNameId, result.SubjectIdentifier.NameId);
        Assert.AreEqual(SamlNameIdFormatAttribute, result.SubjectIdentifier.NameIdFormat);
        Assert.AreEqual(SamlSpNameQualifier, result.SubjectIdentifier.SpNameQualifier);
        Assert.IsNull(result.SubjectIdentifier.NameQualifier);
        Assert.IsNull(result.SubjectIdentifier.SpProvidedId);
    }


    /// <summary>
    /// §3.2.2: a Resource Authorization Server that requires a SAML NameID Subject Identifier for subject
    /// resolution rejects a validated ID-JAG that carries no (usable) <c>sub_id</c> with
    /// <c>invalid_grant</c>. The library surfaces the (absent) identifier; the server's policy enforces
    /// the requirement.
    /// </summary>
    [TestMethod]
    public async Task RedeemRequiringSamlNameIdRejectsGrantWithoutSubId()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        //A normal mint (no sub_id supplied) → the JAG carries no sub_id claim.
        WireMintSeams(app, WellKnownScopes.OpenId, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
            {
                JwtBearerGrant? grant = await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer)
                    .ConfigureAwait(false);
                if(grant is null)
                {
                    return null;
                }

                //§3.2.2: this Resource Authorization Server resolves users by SAML NameID and requires the
                //sub_id; a validated grant without a usable one cannot be resolved → reject.
                (JwtHeader header, JwtPayload payload) = ParseJwtParts(assertion);
                IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
                    header, payload, ResourceAsIssuer, registration.ClientId, TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60));

                return result.SubjectIdentifier is null ? null : grant;
            };

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
        Assert.Contains(OAuthErrors.InvalidGrant, redeemBody);
    }


    /// <summary>
    /// §9.5: the <c>sub_id.issuer</c> (a SAML issuer) MUST NOT establish trust in the ID-JAG issuer. A JAG
    /// whose <c>sub_id</c> names an unrelated SAML issuer still validates on its own <c>iss</c>, and the
    /// validator surfaces the SAML issuer separately (distinct from the ID-JAG <c>iss</c>) so the Resource
    /// Authorization Server can perform the §9.5 association check itself.
    /// </summary>
    [TestMethod]
    public async Task RedeemDoesNotEstablishTrustFromSubIdIssuer()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        SubjectIdentifier = new SamlNameIdSubjectIdentifier { Issuer = UnrelatedSamlIssuer, NameId = SamlNameId }
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        using HttpResponseMessage mintResponse = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        (JwtHeader header, JwtPayload payload) = ParseJwtParts(jag);
        IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
            header, payload, ResourceAsIssuer, ClientId, TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60));

        //Trust came from the ID-JAG iss (the IdP), not the sub_id.issuer (an unrelated SAML issuer).
        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(idpIssuer, result.Issuer);
        Assert.AreEqual(UnrelatedSamlIssuer, result.SubjectIdentifier!.Issuer);
        Assert.AreNotEqual(result.Issuer, result.SubjectIdentifier.Issuer, "§9.5: the SAML issuer is not the ID-JAG issuer.");
    }


    /// <summary>
    /// §4.5: a SAML 2.0 Assertion is accepted as the <c>subject_token</c> (<c>subject_token_type</c> =
    /// the saml2 URN) for an ID-JAG mint. The §4.5 MUST that the SAML Audience / SPEntityID map to the
    /// authenticated client is enforced by the validation seam — an assertion bound to this client mints;
    /// one bound to a different SP is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task MintWithSamlAssertionSubjectTokenMintsIdJag()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        //The seam models §4.5: it accepts the SAML assertion only when its Audience (the SP entity id,
        //here stood in for by the subject_token value) maps to the authenticated client.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    tokenType == TokenType.Saml2 && string.Equals(token, registration.ClientId, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken { Subject = SubjectIdentity }
                        : null);
        WireIdJagAuthorization(app, ChatScope, resourceClientId: null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //SAML Audience maps to the authenticated client → mints.
        using HttpResponseMessage matched = await PostSamlMintAsync(http, tokenUrl, ClientId).ConfigureAwait(false);
        string matchedBody = await matched.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)matched.StatusCode, matchedBody);
        using JsonDocument matchedDoc = JsonDocument.Parse(matchedBody);
        string jag = matchedDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument jagPayload = DecodePayload(jag);
        Assert.AreEqual(SubjectIdentity, jagPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());

        //SAML Audience maps to a different SP → invalid_grant (§4.5 mapping MUST).
        using HttpResponseMessage mismatched = await PostSamlMintAsync(http, tokenUrl, "https://other-sp.example").ConfigureAwait(false);
        string mismatchedBody = await mismatched.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)mismatched.StatusCode, mismatchedBody);
        Assert.Contains(OAuthErrors.InvalidGrant, mismatchedBody);
    }


    /// <summary>
    /// Wires the mint seams so the authorization step supplies the §3.2 SAML NameID Subject Identifier
    /// (<see cref="SamlSubjectId"/>) on the issued ID-JAG.
    /// </summary>
    private static void WireSamlSubjectIdMintSeams(TestHostShell app)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });

        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        SubjectIdentifier = SamlSubjectId
                    });
    }


    /// <summary>
    /// Posts a Token Exchange that uses a SAML 2.0 Assertion as the <c>subject_token</c>
    /// (<c>subject_token_type</c> = the saml2 URN) requesting an ID-JAG (§4.5).
    /// </summary>
    private Task<HttpResponseMessage> PostSamlMintAsync(HttpClient http, Uri tokenUrl, string subjectToken) =>
        PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = subjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.Saml2)
        });


    /// <summary>
    /// §3.1: an ID-JAG MAY carry optional ID Token identity claims. When the authorization seam supplies
    /// <c>auth_time</c> / <c>acr</c> / <c>amr</c> / <c>email</c> (the latter RECOMMENDED), the minted JAG
    /// carries them verbatim (string, numeric, and array shapes alike).
    /// </summary>
    [TestMethod]
    public async Task MintEmitsAdditionalIdentityClaims()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        AdditionalClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            [WellKnownJwtClaimNames.Email] = "alice@example.com",
                            [WellKnownJwtClaimNames.AuthTime] = 1311280970L,
                            [WellKnownJwtClaimNames.Acr] = "urn:mace:incommon:iap:silver",
                            [WellKnownJwtClaimNames.Amr] = new List<object> { "mfa", "hwk" }
                        }
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        JsonElement claims = payload.RootElement;

        Assert.AreEqual("alice@example.com", claims.GetProperty(WellKnownJwtClaimNames.Email).GetString());
        Assert.AreEqual(1311280970L, claims.GetProperty(WellKnownJwtClaimNames.AuthTime).GetInt64());
        Assert.AreEqual("urn:mace:incommon:iap:silver", claims.GetProperty(WellKnownJwtClaimNames.Acr).GetString());
        string[] expectedAmr = ["mfa", "hwk"];
        string[] amr = [.. claims.GetProperty(WellKnownJwtClaimNames.Amr).EnumerateArray().Select(static e => e.GetString()!)];
        CollectionAssert.AreEqual(expectedAmr, amr);
    }


    /// <summary>
    /// The additional-claims mechanism cannot override the grant-controlled claims: an
    /// <c>AdditionalClaims</c> entry whose key is a reserved name (<c>iss</c> / <c>sub</c> /
    /// <c>resource</c> / …) is ignored, so the mint's §3.1 claims stand, while a non-reserved identity
    /// claim (<c>email</c>) is still emitted.
    /// </summary>
    [TestMethod]
    public async Task MintAdditionalClaimsCannotOverrideCoreClaims()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = ChatScope,
                        IssuedTokenType = TokenType.IdJag,
                        AdditionalClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            [WellKnownJwtClaimNames.Iss] = "https://attacker.example",
                            [WellKnownJwtClaimNames.Sub] = "attacker-subject",
                            [OAuthRequestParameterNames.Resource] = "https://attacker.example/api",
                            [WellKnownJwtClaimNames.Email] = "ok@example.com"
                        }
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(jag);
        JsonElement claims = payload.RootElement;

        //Reserved names from AdditionalClaims are ignored — the mint's claims stand.
        Assert.AreEqual(idpIssuer, claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
        Assert.AreEqual(SubjectIdentity, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        Assert.IsFalse(claims.TryGetProperty(OAuthRequestParameterNames.Resource, out _), "a reserved resource override is ignored.");

        //A non-reserved identity claim is still emitted.
        Assert.AreEqual("ok@example.com", claims.GetProperty(WellKnownJwtClaimNames.Email).GetString());
    }


    /// <summary>
    /// The §4 destination: the full two-leg profile across TWO independent Kestrel hosts in separate
    /// trust domains. The IdP host mints an ID-JAG via Token Exchange; the Resource Authorization Server
    /// host redeems it as an RFC 7523 jwt-bearer assertion — validating the JAG against the IdP host's
    /// JWKS fetched over HTTP, with its own issuer as the expected audience (§9.3, satisfied because the
    /// JAG <c>iss</c> is the IdP host, not the Resource AS) — and issues a Bearer access token the
    /// resource server then verifies. Every leg crosses a real socket; the hosts share nothing but the
    /// client's credential and the IdP signing trust the Resource AS resolves over the wire.
    /// </summary>
    [TestMethod]
    public async Task EndToEndAcrossSeparateIdpAndResourceHosts()
    {
        await using TestHostShell app = new(TimeProvider);

        //The IdP host mints; the Resource Authorization Server is the default host. The client holds an
        //independent registration at each (§5: separate client relationships per trust domain).
        app.AddHost("idp");
        using VerifierKeyMaterial idpClient = app.RegisterDpopClientOnHost(
            "idp", ClientId, new Uri(ClientId), PolicyProfile.Rfc6749WithPkce, IdJagClientCapabilities);
        using VerifierKeyMaterial rsClient = app.RegisterDpopClientOnHost(
            "default", ClientId, new Uri(ClientId), PolicyProfile.Rfc6749WithPkce, IdJagClientCapabilities);

        //IdP host mint seams: authenticate the client, accept its Identity Assertion, mint an id-jag.
        app.Host("idp").Server.OAuth().ValidateClientCredentialsAsync =
            static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(fields.TryGetValue("client_secret", out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        app.Host("idp").Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        app.Host("idp").Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = WellKnownScopes.OpenId,
                        IssuedTokenType = TokenType.IdJag
                    });

        await app.StartHttpHostAsync("idp", TestContext.CancellationToken).ConfigureAwait(false);
        await app.StartHttpHostAsync("default", TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer idpHost = app.Host("idp");
        HostedAuthorizationServer rsHost = app.Host("default");
        HttpClient idpHttp = idpHost.SharedHttpClient!;
        HttpClient rsHttp = rsHost.SharedHttpClient!;
        string idpSegment = idpClient.Registration.TenantId.Value;
        string rsSegment = rsClient.Registration.TenantId.Value;
        string rsIssuer = rsClient.Registration.IssuerUri!.OriginalString;

        Assert.AreNotEqual(idpHost.HttpBaseAddress, rsHost.HttpBaseAddress,
            "IdP and Resource Authorization Server must serve from independent Kestrel listeners.");

        //The Resource AS resolves the IdP's signing keys over HTTP (its JWKS endpoint) and validates the
        //JAG with its own issuer as the expected audience.
        ServerVerificationKeyResolverDelegate idpJwksResolver =
            await BuildJwksKeyResolverAsync(rsHttp, idpHost.HttpBaseAddress!, idpSegment).ConfigureAwait(false);
        rsHost.Server.OAuth().ValidateClientCredentialsAsync =
            static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(fields.TryGetValue("client_secret", out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        rsHost.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, idpJwksResolver, rsIssuer).ConfigureAwait(false);

        //Leg 1 — mint at the IdP host; the audience names the Resource Authorization Server's issuer.
        Uri idpTokenUrl = new(idpHost.HttpBaseAddress!, $"/connect/{idpSegment}/token");
        using HttpResponseMessage mintResponse = await PostFormAsync(idpHttp, idpTokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = rsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Leg 2 — redeem at the Resource Authorization Server host.
        Uri rsTokenUrl = new(rsHost.HttpBaseAddress!, $"/connect/{rsSegment}/token");
        using HttpResponseMessage redeemResponse = await PostFormAsync(rsHttp, rsTokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, redeemDoc.RootElement.GetProperty("token_type").GetString());
        Assert.IsFalse(redeemDoc.RootElement.TryGetProperty(WellKnownTokenTypes.RefreshToken, out _), "§4.4.3: no refresh token.");
        string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //The resource server verifies the access token the Resource Authorization Server issued.
        ServerVerificationKeyResolverDelegate rsJwksResolver =
            await BuildJwksKeyResolverAsync(rsHttp, rsHost.HttpBaseAddress!, rsSegment).ConfigureAwait(false);
        JwsAccessTokenValidationResult use = await VerifyAgainstAsAsync(accessToken, rsIssuer, rsJwksResolver).ConfigureAwait(false);
        Assert.IsTrue(use.IsSuccess, use.FailureDescription);
        Assert.AreEqual(SubjectIdentity, use.Claims!.Subject, "the access token subject is the ID-JAG subject, across hosts.");
    }


    /// <summary>
    /// §4.3 / §4.4 / §9.1 client side: the real <see cref="OAuthClient"/> ID-JAG sub-client drives the
    /// full two-leg flow over the wire — <c>MintAsync</c> obtains an ID-JAG via Token Exchange and
    /// <c>RedeemAsync</c> redeems it via the JWT Bearer grant — authenticating the confidential client at
    /// both endpoints with a <c>private_key_jwt</c> client assertion the Authorization Server verifies.
    /// </summary>
    [TestMethod]
    public async Task ClientDrivesMintAndRedeemViaOAuthClientIdJag()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        //The client's signing key for the private_key_jwt client assertion (its public half is what the
        //Authorization Server verifies the assertion against).
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory clientPublic = clientKey.PublicKey;
        using PrivateKeyMemory clientPrivate = clientKey.PrivateKey;
        const string clientSigningKeyId = "id-jag-client-key";

        //An HTTP-backed OAuthClient + client-side registration wired to the host's token endpoint.
        (OAuthClient oauthClient, ClientRegistration clientRegistration, _) =
            await app.CreateOAuthClientAndRegistrationAsync(
                material.Registration, $"{ClientId}/callback", cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;

        //§9.1 confidential client: the AS authenticates the client by verifying the private_key_jwt
        //client_assertion (signature against the client key; iss == sub == client_id; aud present).
        app.Server.OAuth().ValidateClientCredentialsAsync =
            async (request, fields, registration, context, ct) =>
            {
                if(!fields.TryGetValue(OAuthRequestParameterNames.ClientAssertion, out string? assertion)
                    || string.IsNullOrEmpty(assertion))
                {
                    return false;
                }

                bool signatureValid = await Jws.VerifyAsync(
                    assertion, TestSetup.Base64UrlDecoder, Pool, clientPublic, ct).ConfigureAwait(false);
                if(!signatureValid)
                {
                    return false;
                }

                (_, JwtPayload payload) = ParseJwtParts(assertion);

                return payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? iss) && iss is string issuer
                    && string.Equals(issuer, ClientId, StringComparison.Ordinal)
                    && payload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? sub) && sub is string subject
                    && string.Equals(subject, ClientId, StringComparison.Ordinal)
                    && payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? aud) && aud is string audience
                    && !string.IsNullOrEmpty(audience);
            };

        //Mint seams: accept the subject token, authorize the id-jag exchange.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });
        WireIdJagAuthorization(app, WellKnownScopes.OpenId, resourceClientId: null);

        //Redeem seam: validate the JAG against the IdP JWKS with the Resource AS issuer as the audience.
        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //Leg 1 — the client mints an ID-JAG via Token Exchange.
        IdJagMintOptions mintOptions = new()
        {
            Audience = ResourceAsIssuer,
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.IdToken,
            SigningKey = clientPrivate,
            SigningKeyId = clientSigningKeyId,
            HeaderSerializer = ClientAssertionHeaderSerializer,
            PayloadSerializer = ClientAssertionPayloadSerializer,
            Scope = WellKnownScopes.OpenId
        };

        var mintResult = await oauthClient.IdJag.MintAsync(
            clientRegistration, mintOptions, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(mintResult.IsSuccess, mintResult.Error?.Support.Summary);

        string jag = mintResult.Value.AccessToken;
        using JsonDocument jagPayload = DecodePayload(jag);
        Assert.AreEqual(SubjectIdentity, jagPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());

        //Leg 2 — the client redeems the ID-JAG via the JWT Bearer grant for a Bearer access token.
        IdJagRedeemOptions redeemOptions = new()
        {
            Assertion = jag,
            SigningKey = clientPrivate,
            SigningKeyId = clientSigningKeyId,
            HeaderSerializer = ClientAssertionHeaderSerializer,
            PayloadSerializer = ClientAssertionPayloadSerializer
        };

        var redeemResult = await oauthClient.IdJag.RedeemAsync(
            clientRegistration, redeemOptions, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(redeemResult.IsSuccess, redeemResult.Error?.Support.Summary);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, redeemResult.Value.TokenType);
        Assert.IsFalse(string.IsNullOrEmpty(redeemResult.Value.AccessToken), "an access token must be issued.");
    }


    /// <summary>
    /// §4.5: a SAML 2.0 Assertion is exchanged for a Refresh Token (<c>requested_token_type</c> =
    /// the refresh_token URN) — the protocol-transition step. The Token Exchange response carries the
    /// Refresh Token in <c>access_token</c> with <c>issued_token_type</c> the refresh_token URN and
    /// <c>token_type</c> N_A. The §4.5 MUST that the SAML Audience map to the authenticated client is
    /// enforced by the validation seam — an assertion for a different SP is rejected.
    /// </summary>
    [TestMethod]
    public async Task MintRefreshTokenFromSamlAssertionViaTokenExchange()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    tokenType == TokenType.Saml2 && string.Equals(token, registration.ClientId, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId }
                        : null);
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = WellKnownScopes.OpenId,
                        IssuedTokenType = TokenType.RefreshToken
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //SAML Audience maps to the authenticated client → mints a Refresh Token.
        using HttpResponseMessage response = await PostSamlToRefreshTokenAsync(http, tokenUrl, ClientId).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.RefreshToken),
            doc.RootElement.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString());
        Assert.AreEqual("N_A", doc.RootElement.GetProperty("token_type").GetString());
        Assert.IsFalse(string.IsNullOrEmpty(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()),
            "the Refresh Token is returned in the access_token field.");

        //SAML Audience maps to a different SP → invalid_request (§4.5 mapping MUST, RFC 8693 §2.2.2).
        using HttpResponseMessage mismatch = await PostSamlToRefreshTokenAsync(http, tokenUrl, "https://other-sp.example").ConfigureAwait(false);
        string mismatchBody = await mismatch.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)mismatch.StatusCode, mismatchBody);
        Assert.Contains(OAuthErrors.InvalidRequest, mismatchBody);
    }


    /// <summary>
    /// §4.5 end-to-end: a SAML 2.0 Assertion is exchanged for a Refresh Token, the Refresh Token is then
    /// used as a §4.3.2 <c>subject_token</c> to mint an ID-JAG (no new SSO round trip), and the ID-JAG
    /// redeems at the Resource Authorization Server for a Bearer access token. The full SAML→OAuth
    /// protocol-transition chain over the wire.
    /// </summary>
    [TestMethod]
    public async Task SamlToRefreshTokenToIdJagFullChain()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIdJagClient(app);

        //The Refresh Token minted in leg A, captured so leg B's validation can accept it.
        string? mintedRefreshToken = null;

        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            (token, tokenType, registration, context, ct) =>
            {
                //§4.5 leg A: a SAML assertion whose Audience maps to the authenticated client.
                bool samlOk = tokenType == TokenType.Saml2
                    && string.Equals(token, registration.ClientId, StringComparison.Ordinal);

                //§4.3.2 leg B: the Refresh Token this IdP minted in leg A, presented as the subject_token.
                bool refreshOk = tokenType == TokenType.RefreshToken
                    && mintedRefreshToken is not null
                    && string.Equals(token, mintedRefreshToken, StringComparison.Ordinal);

                return ValueTask.FromResult<ValidatedSecurityToken?>(
                    samlOk || refreshOk
                        ? new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId }
                        : null);
            };
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = WellKnownScopes.OpenId,

                        //leg A (saml2 → refresh_token) vs leg B (refresh_token → id-jag): the requested type drives it.
                        IssuedTokenType = request.RequestedTokenType == TokenType.RefreshToken
                            ? TokenType.RefreshToken
                            : TokenType.IdJag
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (assertion, requestedScope, registration, context, ct) =>
                await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);

        //Leg A — SAML assertion → Refresh Token (§4.5).
        using HttpResponseMessage rtResponse = await PostSamlToRefreshTokenAsync(http, tokenUrl, ClientId).ConfigureAwait(false);
        string rtBody = await rtResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)rtResponse.StatusCode, rtBody);
        using JsonDocument rtDoc = JsonDocument.Parse(rtBody);
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.RefreshToken),
            rtDoc.RootElement.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString());
        mintedRefreshToken = rtDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString();

        //Leg B — Refresh Token → ID-JAG (§4.3.2).
        using HttpResponseMessage jagResponse = await PostRefreshTokenMintAsync(
            http, tokenUrl, ResourceAsIssuer, WellKnownScopes.OpenId, mintedRefreshToken!).ConfigureAwait(false);
        string jagBody = await jagResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)jagResponse.StatusCode, jagBody);
        using JsonDocument jagDoc = JsonDocument.Parse(jagBody);
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.IdJag),
            jagDoc.RootElement.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString());
        string jag = jagDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Leg C — ID-JAG → Bearer access token (§4.4).
        using HttpResponseMessage redeemResponse = await PostFormAsync(http, tokenUrl, BuildRedeemForm(jag)).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, redeemDoc.RootElement.GetProperty("token_type").GetString());
    }


    /// <summary>
    /// Posts a Token Exchange that uses a SAML 2.0 Assertion as the <c>subject_token</c> requesting a
    /// Refresh Token (<c>requested_token_type</c> = the refresh_token URN), per §4.5.
    /// </summary>
    private Task<HttpResponseMessage> PostSamlToRefreshTokenAsync(HttpClient http, Uri tokenUrl, string subjectToken) =>
        PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.RefreshToken),
            [OAuthRequestParameterNames.SubjectToken] = subjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.Saml2)
        });


    private static Dictionary<string, string> BuildMintForm(string audience) =>
        new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = audience,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        };


    private static Dictionary<string, string> BuildRedeemForm(string jag) =>
        new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        };


    /// <summary>Mints a key-bound ID-JAG by posting a DPoP proof for <paramref name="dpopKey"/>.</summary>
    private async Task<string> MintBoundJagAsync(
        HttpClient http, Uri tokenUrl, DpopKey dpopKey, string segment, VerifierKeyMaterial material)
    {
        string mintProof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);
        using HttpResponseMessage mintResponse = await PostFormWithDpopAsync(
            http, tokenUrl, BuildMintForm(ResourceAsIssuer), mintProof).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);

        return mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Builds a token-endpoint DPoP proof (<c>htm=POST</c>, <c>htu=</c> the issuer-authority + token
    /// path the server validates against per RFC 9449 §4.2) for the given key.
    /// </summary>
    private async Task<string> BuildTokenEndpointDpopProofAsync(DpopKey dpopKey, string segment, VerifierKeyMaterial material)
    {
        string htu = $"{material.Registration.IssuerUri!.GetLeftPart(UriPartial.Authority)}/connect/{segment}/token";
        DpopProofClaims claims = new()
        {
            Htm = HttpMethod.Post.Method,
            Htu = htu,
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N")
        };

        return await DpopProofConstruction.BuildAsync(
            claims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<HttpResponseMessage> PostFormWithDpopAsync(
        HttpClient http, Uri url, Dictionary<string, string> fields, string? dpopProof)
    {
        using FormUrlEncodedContent content = new(fields);
        using HttpRequestMessage request = new(HttpMethod.Post, url) { Content = content };
        if(dpopProof is not null)
        {
            request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, dpopProof);
        }

        return await http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string TamperSignature(string compactJws)
    {
        string[] parts = compactJws.Split('.');
        char[] signature = parts[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        parts[2] = new string(signature);

        return string.Join('.', parts);
    }


    /// <summary>The capability set an ID-JAG client needs: token-exchange + jwt-bearer + id-jag, plus discovery/jwks.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> IdJagClientCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthTokenExchange,
            WellKnownCapabilityIdentifiers.OAuthJwtBearer,
            WellKnownCapabilityIdentifiers.OAuthIdJag,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    private static VerifierKeyMaterial RegisterIdJagClient(TestHostShell app) =>
        app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: IdJagClientCapabilities);


    private static void WireClientAuthentication(TestHostShell app) =>
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue("client_secret", out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));


    private static void WireIdJagAuthorization(TestHostShell app, string grantedScope, string? resourceClientId) =>
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = grantedScope,
                        IssuedTokenType = TokenType.IdJag,
                        ResourceClientId = resourceClientId
                    });


    /// <summary>
    /// Wires the three mint seams: client authentication, a subject-token validation that accepts the
    /// fixture's Identity Assertion and surfaces its subject, and an authorization seam that selects the
    /// id-jag issued type with the given granted scope and (optional) resource client_id.
    /// </summary>
    private static void WireMintSeams(TestHostShell app, string grantedScope, string? resourceClientId)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity });

        WireIdJagAuthorization(app, grantedScope, resourceClientId);
    }


    /// <summary>
    /// The Resource Authorization Server's <c>ValidateJwtBearerAssertionAsync</c> wiring: verify the
    /// ID-JAG signature against the IdP JWKS (resolved by <c>kid</c>) and apply the §4.4.1 / §9.3 claim
    /// rules via <see cref="IdJagAssertionValidation"/>. Returns <see langword="null"/> (→
    /// <c>invalid_grant</c>) on any failure, mirroring a real RS.
    /// </summary>
    private async Task<JwtBearerGrant?> ValidateIdJagAsync(
        string assertion,
        ClientRecord registration,
        ServerVerificationKeyResolverDelegate resolver,
        string resourceServerIssuer)
    {
        string[] parts = assertion.Split('.');
        if(parts.Length != 3)
        {
            return null;
        }

        JwtHeader header;
        using(IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], Pool))
        {
            header = JwsAccessTokenTestSupport.Parser.ParseHeader(headerBytes.Memory);
        }

        if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj) || kidObj is not string kid)
        {
            return null;
        }

        PublicKeyMemory? key = await resolver(
            new KeyId(kid), default, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        if(key is null)
        {
            return null;
        }

        bool signatureValid = await Jws.VerifyAsync(
            assertion, TestSetup.Base64UrlDecoder, Pool, key,
            MicrosoftCryptographicFunctions.VerifyP256Async, TestContext.CancellationToken).ConfigureAwait(false);
        if(!signatureValid)
        {
            return null;
        }

        JwtPayload payload;
        using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
        {
            payload = JwsAccessTokenTestSupport.Parser.ParseClaims(payloadBytes.Memory);
        }

        IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
            header, payload, resourceServerIssuer, registration.ClientId,
            TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60));
        if(!result.IsValid)
        {
            return null;
        }

        //Model a Resource Authorization Server that grants what the JAG carried: bind the granted
        //resource to the access token audience (RFC 8707), thread the authorization_details through,
        //surface the grant's bound key (cnf.jkt) so the §9.8.1.2 proof-of-possession matrix runs, and
        //surface iss/jti/exp so the jwt-bearer endpoint's JtiReplayGuard applies the §3 replay defense.
        return new JwtBearerGrant
        {
            Subject = result.Subject!,
            Scope = result.Scope ?? string.Empty,
            Audience = result.Resource,
            AuthorizationDetailsClaim = result.AuthorizationDetails,
            RequiredKeyThumbprint = result.ConfirmationKeyThumbprint,
            Issuer = result.Issuer,
            Jti = result.Jti,
            Expiration = result.Expiration
        };
    }


    private async Task<string> ObtainClientCredentialsAccessTokenAsync(
        HttpClient http, Uri tokenUrl, string clientId, string clientSecret, string scope)
    {
        using HttpResponseMessage response = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.ClientSecret] = clientSecret,
            [OAuthRequestParameterNames.Scope] = scope
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Builds and signs an ID-JAG entirely outside our mint pipeline — raw §3.1 claims (header
    /// <c>typ=oauth-id-jag+jwt</c>; <c>iss</c>/<c>sub</c>/<c>aud</c>/<c>client_id</c>/<c>jti</c>/<c>iat</c>/<c>exp</c>/<c>scope</c>)
    /// signed with the given foreign IdP key via the JCose <see cref="UnsignedJwt"/> primitives — so the
    /// redeem path under test receives foreign wire bytes. This is also the construction a captured real
    /// third-party ID-JAG would replace for a live interop vector.
    /// </summary>
    private async Task<string> BuildForeignIdJagAsync(
        PrivateKeyMemory signingKey,
        string keyId,
        string issuer,
        string subject,
        string audience,
        string clientId,
        string scope,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeader.ForSigning(algorithm, "oauth-id-jag+jwt", keyId);
        JwtPayload payload = new(capacity: 8)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Sub] = subject,
            [WellKnownJwtClaimNames.Aud] = audience,
            ["client_id"] = clientId,
            [WellKnownJwtClaimNames.Jti] = "foreign-jag-jti-1",
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
            ["scope"] = scope
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            ClientAssertionHeaderSerializer,
            ClientAssertionPayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    private async Task<ServerVerificationKeyResolverDelegate> BuildJwksKeyResolverAsync(
        HttpClient http, Uri httpBaseAddress, string segment)
    {
        Uri jwksUrl = new(httpBaseAddress, $"/connect/{segment}/jwks");
        using HttpResponseMessage response = await http.GetAsync(jwksUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Dictionary<string, PublicKeyMemory> keysByKid = new(StringComparer.Ordinal);
        using JsonDocument doc = JsonDocument.Parse(body);
        foreach(JsonElement key in doc.RootElement.GetProperty(WellKnownJwkMemberNames.Keys).EnumerateArray())
        {
            string kid = key.GetProperty(WellKnownJwkMemberNames.Kid).GetString()!;
            Dictionary<string, string> jwk = new(StringComparer.Ordinal);
            foreach(JsonProperty member in key.EnumerateObject())
            {
                if(member.Value.ValueKind == JsonValueKind.String)
                {
                    jwk[member.Name] = member.Value.GetString()!;
                }
            }

            keysByKid[kid] = DpopJwkUtilities.PublicKeyFromJwk(
                jwk, WellKnownJwaValues.Es256, TestSetup.Base64UrlDecoder, Pool);
        }

        return (kid, tenant, ctx, ct) =>
            ValueTask.FromResult(keysByKid.GetValueOrDefault(kid.Value));
    }


    private async Task<JwsAccessTokenValidationResult> VerifyAgainstAsAsync(
        string token, string expectedIssuer, ServerVerificationKeyResolverDelegate resolver) =>
        await JwsAccessTokenValidator.ValidateAsync(
            token,
            expectedIssuer,
            ResourceServerAudience,
            resolver,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            TimeSpan.FromSeconds(60),
            tenantId: default,
            new ExchangeContext(),
            expectedAuthorizedParty: null,
            TestContext.CancellationToken).ConfigureAwait(false);


    private Task<HttpResponseMessage> PostMintAsync(HttpClient http, Uri tokenUrl, string audience) =>
        PostMintWithSubjectAsync(http, tokenUrl, audience, SubjectTokenValue);


    private Task<HttpResponseMessage> PostMintWithSubjectAsync(
        HttpClient http, Uri tokenUrl, string audience, string subjectToken) =>
        PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = audience,
            [OAuthRequestParameterNames.SubjectToken] = subjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        });


    private static JsonDocument DecodeHeader(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);
        byte[] headerBytes = SecurityEventTestJson.DecodeSegment(segments[0], Pool);

        return JsonDocument.Parse(headerBytes);
    }


    private static JsonDocument DecodePayload(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);

        return JsonDocument.Parse(payloadBytes);
    }


    private async Task<HttpResponseMessage> PostFormAsync(
        HttpClient http, Uri url, Dictionary<string, string> fields)
    {
        using FormUrlEncodedContent content = new(fields);

        return await http.PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
