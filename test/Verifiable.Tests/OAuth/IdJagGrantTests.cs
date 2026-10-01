using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Relations;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
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
    /// The <c>kid</c> of signing material the host's published JWKS does not hold, so the redeem's resolver of
    /// signing material answers nothing for a grant that names it.
    /// </summary>
    private static string UnknownSigningKeyId { get; } = "signing-material-the-resolver-does-not-know";

    /// <summary>
    /// A <c>saml-nameid</c> Subject Identifier with the REQUIRED members plus two of the four optional
    /// members (<c>nameid_format</c>, <c>sp_name_qualifier</c>); <c>name_qualifier</c> and
    /// <c>sp_provided_id</c> are omitted so the §3.2.2 exactly-when-present rule is observable.
    /// </summary>
    private static SamlNameIdSubjectIdentifier SamlSubjectId { get; } = new()
    {
        Issuer = SamlIssuer,
        NameId = SamlNameId,
        NameIdFormat = SamlNameIdFormatAttribute,
        SpNameQualifier = SamlSpNameQualifier
    };

    /// <summary>
    /// The SAML NameID identifier an application configures for the fixture's End-User: the SAML issuer, the
    /// &lt;NameID&gt; value and the SPNameQualifier the NameID is scoped to
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>).
    /// </summary>
    private static SamlNameIdSubjectIdentifier ConfiguredSamlIdentifier { get; } = new()
    {
        Issuer = SamlIssuer,
        NameId = SamlNameId,
        SpNameQualifier = SamlSpNameQualifier
    };

    /// <summary>
    /// The one body the token endpoint answers a refused JWT Bearer assertion with, whatever the reason.
    /// </summary>
    private static string JagRefusal { get; } = """{"error":"invalid_grant","error_description":"The JWT assertion is not valid."}""";

    /// <summary>
    /// A party that acted before the client redeeming the grant — the prior actor a nested
    /// <c>act</c> claim records per RFC 8693 §4.1 ("nested 'act' claims represent prior actors").
    /// </summary>
    private const string PriorActorIdentity = "https://svc.example/first-hop";

    /// <summary>
    /// A party that is neither the redeeming client nor the subject, used as the <c>may_act</c>
    /// authorized actor the redeeming client is NOT (RFC 8693 §4.4).
    /// </summary>
    private const string UnauthorizedActorIdentity = "https://svc.example/other-agent";

    /// <summary>
    /// The subject of RFC 8693 §4.1 Figure 6, transcribed verbatim for the nesting known-answer test.
    /// </summary>
    private const string Figure6Subject = "user@example.com";

    /// <summary>
    /// The current (outermost) actor of RFC 8693 §4.1 Figure 6 — in the figure's own narrative, the
    /// service that received a token from another service and exchanged it onward.
    /// </summary>
    private const string Figure6CurrentActor = "https://service16.example.com";

    /// <summary>
    /// The prior (most deeply nested) actor of RFC 8693 §4.1 Figure 6 — "The least recent actor is
    /// the most deeply nested."
    /// </summary>
    private const string Figure6PriorActor = "https://service77.example.com";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>Serialises a client-assertion protected header to UTF-8 JSON bytes for the OAuthClient.IdJag flow test.</summary>
    private static JwtHeaderSerializer ClientAssertionHeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>Serialises a client-assertion payload to UTF-8 JSON bytes for the OAuthClient.IdJag flow test.</summary>
    private static JwtPayloadSerializer ClientAssertionPayloadSerializer { get; } =
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: ResourceClientId).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidRequest, body);
    }


    /// <summary>
    /// §4.3: <c>audience</c> "REQUIRED - The identifier of the Resource Authorization Server ... as the
    /// intended audience for the ID-JAG" names exactly one Resource Authorization Server; the §4.3
    /// profile paragraph likewise speaks of "the Resource Authorization Server to which the ID-JAG is
    /// issued". A request naming more than one <c>audience</c> is malformed against that definition
    /// (RFC 8693 §2.2.2's <c>invalid_request</c> MUST for a request that is not itself valid) and is
    /// refused before the subject token is validated or the authorization seam runs — neither identity
    /// resolution nor the policy decision can be meaningful when the mint does not yet know which single
    /// Resource Authorization Server it is minting for.
    /// </summary>
    [TestMethod]
    public async Task MintWithMultipleAudiencesIsRefusedBeforeIdentityResolutionOrTheSeam()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        int validateCalls = 0;
        int authorizeCalls = 0;
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                {
                    _ = Interlocked.Increment(ref validateCalls);

                    return ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });
                };

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    _ = Interlocked.Increment(ref authorizeCalls);

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = ChatScope,
                            IssuedTokenType = TokenType.IdJag
                        });
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        };
        form.Add(OAuthRequestParameterNames.Audience, ResourceAsIssuer);
        form.Add(OAuthRequestParameterNames.Audience, "https://another-resource-server.example/");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", body, StringComparison.Ordinal, body);
        Assert.DoesNotContain("required when requesting an id-jag token type", body, StringComparison.Ordinal,
            $"Naming two audiences is a different defect than naming none; the description must say so, not reuse the missing-audience wording. Got: {body}");
        Assert.AreEqual(0, validateCalls, "Identity resolution must not run before the audience-count refusal.");
        Assert.AreEqual(0, authorizeCalls, "The authorization seam must not run before the audience-count refusal.");
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(null);
            WireIdJagAuthorization(candidateIntegration, ChatScope, resourceClientId: null);
        }).ConfigureAwait(false);


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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(null);
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

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
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        //Leg 1 — mint.
        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Leg 2 — redeem.
        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "This is
    /// applicable for all access token requests regardless of grant type ... extension grants such
    /// as the JWT authorization grant [RFC7523]." Under a registration whose profile mandates
    /// DPoP-bound access tokens, with DPoP wired on the client infrastructure,
    /// <see cref="IdJagClient.MintAsync(ClientRegistration, IdJagMintOptions, CancellationToken)"/>
    /// answers the token endpoint's <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">§8</see>
    /// <c>use_dpop_nonce</c> challenge and completes on the retry: the client dials the token
    /// endpoint exactly twice. The response's <c>token_type</c> stays <c>N_A</c> — an ID-JAG is
    /// never itself an access token (RFC 8693 §2.2.1), so presenting a DPoP proof at this leg
    /// cannot change it.
    /// </summary>
    [TestMethod]
    public async Task MintCompletesAfterOneNonceRetryOverRealWireUnderMandatingRegistration()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Haip10, capabilities: IdJagClientCapabilities).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        //A placeholder client-authentication validator satisfies the token-exchange feature's
        //composition dependency; StartHostAndWirePrivateKeyJwtClientAuthenticationAsync replaces
        //it with the real private_key_jwt validator once the token endpoint is known.
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(new ValidatedSecurityToken { Subject = SubjectIdentity });
            WireIdJagAuthorization(candidateIntegration, ChatScope, resourceClientId: null);
        }).ConfigureAwait(false);

        (HostedAuthorizationServer host, Uri tokenEndpoint, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys) =
            await StartHostAndWirePrivateKeyJwtClientAuthenticationAsync(app, material).ConfigureAwait(false);
        try
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            try
            {
                int dialCount = 0;
                DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
                InMemoryDpopNonceCache nonceCache = new();
                AuthorizationServerMetadata metadata = new()
                {
                    Issuer = material.Registration.IssuerUri!,
                    TokenEndpoint = tokenEndpoint
                };

                OAuthClientInfrastructure infrastructure = CreateClientInfrastructure(
                    host, metadata, _ => dialCount++, dpopKey, nonceCache);

                ClientRegistration registration = new()
                {
                    ClientId = new ClientId(ClientId),
                    AuthorizationServerIssuer = material.Registration.IssuerUri!,
                    AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                    Profile = PolicyProfile.Haip10
                };

                OAuthClient client = new(infrastructure);

                Result<TokenResponse, OAuthParseError> result = await client.IdJag.MintAsync(
                    registration,
                    new IdJagMintOptions
                    {
                        Audience = ResourceAsIssuer,
                        SubjectToken = SubjectTokenValue,
                        SubjectTokenType = TokenType.IdToken,
                        SigningKey = clientKeys.PrivateKey,
                        SigningKeyId = MintRedeemSigningKeyId,
                        HeaderSerializer = ClientAssertionHeaderSerializer,
                        PayloadSerializer = ClientAssertionPayloadSerializer
                    },
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, result.Error?.Support.Summary);
                Assert.AreEqual("N_A", result.Value.TokenType,
                    "RFC 8693 §2.2.1: an ID-JAG's token_type is always N_A, unaffected by DPoP binding.");
                Assert.AreEqual(2, dialCount,
                    "The client must dial the token endpoint twice: once to receive the use_dpop_nonce challenge, once more with the nonce to complete.");
            }
            finally
            {
                dpopKeys.PublicKey.Dispose();
                dpopKeys.PrivateKey.Dispose();
            }
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">§8</see>: the same nonce-retry
    /// completion as the mint leg, exercised on
    /// <see cref="IdJagClient.RedeemAsync(ClientRegistration, IdJagRedeemOptions, CancellationToken)"/>.
    /// The redeemed assertion is minted entirely outside the mint leg (a foreign IdP key, resolved
    /// by its own in-memory JWKS) so this test's DPoP nonce cache is exercised by the redeem call
    /// alone. Per the draft's proof-of-possession rules (§9.8.1.2.3: "ID-JAG Does Not Contain cnf
    /// Claim and DPoP Proof is Presented" — the redeemed grant carries no <c>cnf</c>, since it was
    /// never minted with one), presenting a valid DPoP proof at this leg sender-constrains the
    /// issued access token: <c>token_type</c> answers <c>DPoP</c>. The assertion is a signed ID-JAG
    /// validated by the library's own ID-JAG validation, and its <c>jti</c> is reported to the replay
    /// guard (RFC 7523 §3 rule 7). The retry RFC 9449 §8 prescribes presents that same assertion, so
    /// the completion proves the challenge was answered before the assertion was consumed.
    /// </summary>
    [TestMethod]
    public async Task RedeemCompletesAfterOneNonceRetryOverRealWireUnderMandatingRegistration()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Haip10, capabilities: IdJagClientCapabilities).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        //The redeemed assertion is a real, signed ID-JAG carrying its own jti (built the same way
        //RedeemRejectsForeignJagWithWrongAudience builds an adversarial one), validated for real
        //against an in-memory JWKS keyed by kid, so the replay guard the retry meets is the library's
        //own, fed by the assertion's real jti.
        const string externalIdpIssuer = "https://external-idp.example/";
        const string externalKid = "external-idp-key-1";
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> idpKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory idpPublicKey = idpKey.PublicKey;
        using PrivateKeyMemory idpPrivateKey = idpKey.PrivateKey;

        DateTimeOffset assertionIssuedAt = TimeProvider.GetUtcNow();
        string jag = await BuildForeignIdJagAsync(
            idpPrivateKey, externalKid, externalIdpIssuer, SubjectIdentity, ResourceAsIssuer,
            ClientId, ChatScope, assertionIssuedAt, assertionIssuedAt.AddMinutes(5)).ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> resolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? idpPublicKey : null);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, resolver, ResourceAsIssuer).ConfigureAwait(false);

            //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience; ChatScope carries
            //no ScopeToAudience mapping, so a fixed resource-server audience stands in, matching the
            //pattern JwtBearerGrantTests and ClientCredentialsGrantTests use under the same profile.
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);

        (HostedAuthorizationServer host, Uri tokenEndpoint, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys) =
            await StartHostAndWirePrivateKeyJwtClientAuthenticationAsync(app, material).ConfigureAwait(false);
        try
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            try
            {
                int dialCount = 0;
                DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
                InMemoryDpopNonceCache nonceCache = new();
                AuthorizationServerMetadata metadata = new()
                {
                    Issuer = material.Registration.IssuerUri!,
                    TokenEndpoint = tokenEndpoint
                };

                OAuthClientInfrastructure infrastructure = CreateClientInfrastructure(
                    host, metadata, _ => dialCount++, dpopKey, nonceCache);

                ClientRegistration registration = new()
                {
                    ClientId = new ClientId(ClientId),
                    AuthorizationServerIssuer = material.Registration.IssuerUri!,
                    AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                    Profile = PolicyProfile.Haip10
                };

                OAuthClient client = new(infrastructure);

                Result<TokenResponse, OAuthParseError> result = await client.IdJag.RedeemAsync(
                    registration,
                    new IdJagRedeemOptions
                    {
                        Assertion = jag,
                        SigningKey = clientKeys.PrivateKey,
                        SigningKeyId = MintRedeemSigningKeyId,
                        HeaderSerializer = ClientAssertionHeaderSerializer,
                        PayloadSerializer = ClientAssertionPayloadSerializer
                    },
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, result.Error?.Support.Summary);
                Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, result.Value.TokenType,
                    "draft §9.8.1.2.3: a redeem presenting a DPoP proof for an unbound grant sender-constrains the issued access token.");
                Assert.AreEqual(2, dialCount,
                    "The client must dial the token endpoint twice: once to receive the use_dpop_nonce challenge, once more with the nonce to complete.");

            }
            finally
            {
                dpopKeys.PublicKey.Dispose();
                dpopKeys.PrivateKey.Dispose();
            }
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>: a proof
    /// bound to the wrong <c>htu</c> is a structural defect the DPoP validator rejects outright, not
    /// a <c>use_dpop_nonce</c> challenge, so it must never reach the assertion seam or the <c>jti</c>
    /// replay guard: the same real, signed ID-JAG presented again with a VALID proof is then served.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithInvalidDpopProofDoesNotConsumeTheAssertion()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Haip10, capabilities: IdJagClientCapabilities).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        const string externalIdpIssuer = "https://external-idp.example/";
        const string externalKid = "external-idp-key-1";
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> idpKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory idpPublicKey = idpKey.PublicKey;
        using PrivateKeyMemory idpPrivateKey = idpKey.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string jag = await BuildForeignIdJagAsync(
            idpPrivateKey, externalKid, externalIdpIssuer, SubjectIdentity, ResourceAsIssuer,
            ClientId, ChatScope, now, now.AddMinutes(5)).ConfigureAwait(false);

        ValueTask<PublicKeyMemory?> resolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? idpPublicKey : null);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, resolver, ResourceAsIssuer).ConfigureAwait(false);
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
            string htu = tokenUrl.GetLeftPart(UriPartial.Path);

            //Haip10 mandates a DPoP nonce; a well-formed proof without one is challenged rather than
            //accepted. Bootstrap the nonce first: that challenge must not touch the assertion either.
            DpopProofClaims noNonceClaims = new()
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = htu,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N")
            };
            string noNonceProof = await DpopProofConstruction.BuildAsync(
                noNonceClaims, dpopKey, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            HttpResponseData bootstrapChallenge = await HttpClientTransport.SendFormPostAsync(
                host.SharedHttpClient!, tokenUrl, BuildRedeemForm(jag),
                OutgoingHeaders.Empty.WithDpop(noNonceProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, bootstrapChallenge.StatusCode, bootstrapChallenge.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, bootstrapChallenge.Body);
            string? freshNonce = bootstrapChallenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
            Assert.IsNotNull(freshNonce, "RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");

            DpopProofClaims wrongHtuClaims = new()
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = "https://wrong.example.test/not-the-token-endpoint",
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = freshNonce
            };
            string wrongHtuProof = await DpopProofConstruction.BuildAsync(
                wrongHtuClaims, dpopKey, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            HttpResponseData rejected = await HttpClientTransport.SendFormPostAsync(
                host.SharedHttpClient!, tokenUrl, BuildRedeemForm(jag),
                OutgoingHeaders.Empty.WithDpop(wrongHtuProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, rejected.StatusCode, rejected.Body);
            Assert.Contains(OAuthErrors.InvalidDpopProof, rejected.Body);

            DpopProofClaims validClaims = new()
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = htu,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = freshNonce
            };
            string validProof = await DpopProofConstruction.BuildAsync(
                validClaims, dpopKey, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            HttpResponseData served = await HttpClientTransport.SendFormPostAsync(
                host.SharedHttpClient!, tokenUrl, BuildRedeemForm(jag),
                OutgoingHeaders.Empty.WithDpop(validProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, served.StatusCode, served.Body);
        }
        finally
        {
            dpopKeys.PublicKey.Dispose();
            dpopKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: the DPoP-
    /// retrying send must present a FRESHLY-SIGNED <c>private_key_jwt</c> client assertion (a new
    /// <c>jti</c>) on the retry, not the same one — proved here by wiring the authorization server's
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// WITH the client-assertion replay delegate: a second presentation of the SAME assertion is
    /// refused, so the retry can only complete by presenting a different one.
    /// </summary>
    [TestMethod]
    public async Task RedeemCompletesAfterOneNonceRetryWithFreshClientAssertionUnderReplayCheckedRegistration()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Haip10, capabilities: IdJagClientCapabilities).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                static (assertion, requestedScope, registration, context, ct) =>
                    ValueTask.FromResult<JwtBearerGrant?>(new JwtBearerGrant { Subject = SubjectIdentity, Scope = ChatScope });
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);

        (HostedAuthorizationServer host, Uri tokenEndpoint, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys) =
            await StartHostAndWirePrivateKeyJwtClientAuthenticationAsync(app, material).ConfigureAwait(false);
        try
        {
            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString],
                        checkJtiReplayAsync: JtiReplayGuard.ConsultClientAssertionAsync);
            }).ConfigureAwait(false);

            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            try
            {
                DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
                InMemoryDpopNonceCache nonceCache = new();
                AuthorizationServerMetadata metadata = new()
                {
                    Issuer = material.Registration.IssuerUri!,
                    TokenEndpoint = tokenEndpoint
                };

                List<string> dialedAssertions = [];
                OAuthClientInfrastructure infrastructure = CreateClientInfrastructure(
                    host,
                    metadata,
                    fields => dialedAssertions.Add(fields.First(
                        field => string.Equals(field.Key, OAuthRequestParameterNames.ClientAssertion, StringComparison.Ordinal)).Value),
                    dpopKey,
                    nonceCache);

                ClientRegistration registration = new()
                {
                    ClientId = new ClientId(ClientId),
                    AuthorizationServerIssuer = material.Registration.IssuerUri!,
                    AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                    Profile = PolicyProfile.Haip10
                };

                OAuthClient client = new(infrastructure);

                Result<TokenResponse, OAuthParseError> result = await client.IdJag.RedeemAsync(
                    registration,
                    new IdJagRedeemOptions
                    {
                        Assertion = "opaque-id-jag-the-accepting-validator-does-not-inspect",
                        SigningKey = clientKeys.PrivateKey,
                        SigningKeyId = MintRedeemSigningKeyId,
                        HeaderSerializer = ClientAssertionHeaderSerializer,
                        PayloadSerializer = ClientAssertionPayloadSerializer
                    },
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, result.Error?.Support.Summary);
                Assert.HasCount(2, dialedAssertions,
                    "The client must dial the token endpoint twice: once to receive the use_dpop_nonce challenge, once more with the nonce to complete.");
                Assert.AreNotEqual(dialedAssertions[0], dialedAssertions[1],
                    "RFC 9449 §8's retry must present a freshly-signed client_assertion (a new jti), not the same one a client-assertion replay defense would refuse.");
            }
            finally
            {
                dpopKeys.PublicKey.Dispose();
                dpopKeys.PrivateKey.Dispose();
            }
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: under a
    /// registration whose profile mandates DPoP, a client infrastructure with NO DPoP wired
    /// (<c>ConstructDpopProofAsync</c>/<c>DpopKey</c> both absent) sends the ID-JAG mint and redeem
    /// requests with no DPoP proof at all, as an unwired infrastructure sends every token request. The
    /// server's <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">§8</see>
    /// <c>use_dpop_nonce</c> refusal for a missing-but-mandated proof (the same refusal
    /// <c>RegistrationRequiringDpopWithoutAProofIsRefused</c> pins for every other grant) surfaces as
    /// the typed <see cref="OAuthProtocolError"/> failure, carrying that error code, rather than
    /// being retried or thrown.
    /// </summary>
    [TestMethod]
    public async Task MintAndRedeemWithoutDpopWiredUnderMandatingRegistrationReturnTypedFailure()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Haip10, capabilities: IdJagClientCapabilities).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        //A placeholder client-authentication validator satisfies the token-exchange feature's
        //composition dependency; StartHostAndWirePrivateKeyJwtClientAuthenticationAsync replaces
        //it with the real private_key_jwt validator once the token endpoint is known. The grant
        //validators below are never expected to run — the §8 mandate refuses the request first —
        //but must be wired for the token-exchange and jwt-bearer grants to dispatch at all.
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(new ValidatedSecurityToken { Subject = SubjectIdentity });
            WireIdJagAuthorization(candidateIntegration, ChatScope, resourceClientId: null);

            //Accepts any assertion so the §8 mandate gate — not assertion validation — is what
            //refuses the redeem call: the gate applies only once the assertion itself is accepted
            //(mirroring JwtBearerGrantTests' own WireAcceptingValidator for the same pinned refusal).
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                static (assertion, requestedScope, registration, context, ct) =>
                    ValueTask.FromResult<JwtBearerGrant?>(new JwtBearerGrant { Subject = SubjectIdentity, Scope = ChatScope });
        }).ConfigureAwait(false);

        (HostedAuthorizationServer host, Uri tokenEndpoint, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys) =
            await StartHostAndWirePrivateKeyJwtClientAuthenticationAsync(app, material).ConfigureAwait(false);
        try
        {
            AuthorizationServerMetadata metadata = new()
            {
                Issuer = material.Registration.IssuerUri!,
                TokenEndpoint = tokenEndpoint
            };

            //No dpopKey: DPoP is NOT wired on this infrastructure.
            OAuthClientInfrastructure infrastructure = CreateClientInfrastructure(host, metadata);

            ClientRegistration registration = new()
            {
                ClientId = new ClientId(ClientId),
                AuthorizationServerIssuer = material.Registration.IssuerUri!,
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                Profile = PolicyProfile.Haip10
            };

            OAuthClient client = new(infrastructure);

            Result<TokenResponse, OAuthParseError> mintResult = await client.IdJag.MintAsync(
                registration,
                new IdJagMintOptions
                {
                    Audience = ResourceAsIssuer,
                    SubjectToken = SubjectTokenValue,
                    SubjectTokenType = TokenType.IdToken,
                    SigningKey = clientKeys.PrivateKey,
                    SigningKeyId = MintRedeemSigningKeyId,
                    HeaderSerializer = ClientAssertionHeaderSerializer,
                    PayloadSerializer = ClientAssertionPayloadSerializer
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(mintResult.IsSuccess, "A mandating registration must refuse a proof-less mint.");
            OAuthProtocolError mintFailure = Assert.IsInstanceOfType<OAuthProtocolError>(mintResult.Error);
            Assert.AreEqual(OAuthErrors.UseDpopNonce, mintFailure.ErrorCode);

            Result<TokenResponse, OAuthParseError> redeemResult = await client.IdJag.RedeemAsync(
                registration,
                new IdJagRedeemOptions
                {
                    Assertion = "opaque-id-jag-not-inspected-before-the-dpop-mandate-gate",
                    SigningKey = clientKeys.PrivateKey,
                    SigningKeyId = MintRedeemSigningKeyId,
                    HeaderSerializer = ClientAssertionHeaderSerializer,
                    PayloadSerializer = ClientAssertionPayloadSerializer
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(redeemResult.IsSuccess, "A mandating registration must refuse a proof-less redeem.");
            OAuthProtocolError redeemFailure = Assert.IsInstanceOfType<OAuthProtocolError>(redeemResult.Error);
            Assert.AreEqual(OAuthErrors.UseDpopNonce, redeemFailure.ErrorCode);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        //§3.1 example carries scope "chat.read chat.history" and a single resource (a JSON string).
        const string exampleResource = "https://acme.chat.example/api";
        await WireMintSeamsGrantingAsync(app, ChatScope, [exampleResource]).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

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
        ValueTask<PublicKeyMemory?> foreignResolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) => ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? idpPublicKey : null);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, foreignResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        using HttpResponseMessage redeem = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(foreignJag), TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

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

        ValueTask<PublicKeyMemory?> resolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) => ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? trustedPublicKey : null);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, resolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage redeem = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, BuildRedeemForm(foreignJag), TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

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

        ValueTask<PublicKeyMemory?> resolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) => ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, externalKid, StringComparison.Ordinal) ? idpPublicKey : null);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, resolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage redeem = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, BuildRedeemForm(foreignJag), TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

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
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //First redemption — accepted; the library records the jti as first-use.
        using HttpResponseMessage first = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
        string firstBody = await first.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)first.StatusCode, firstBody);

        //Second redemption of the SAME grant — the shared jti store sees the replay and refuses.
        using HttpResponseMessage second = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
        string secondBody = await second.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)second.StatusCode, secondBody);
        Assert.Contains(OAuthErrors.InvalidGrant, secondBody);
    }


    /// <summary>
    /// RFC 7523 §3 rule 7 over the real HTTP wire: a store that records the assertion <c>jti</c> but
    /// never resolves what it saved under <c>FlowKind.JtiReplay</c> cannot maintain the used-<c>jti</c>
    /// set, so <see cref="JtiReplayGuard"/> answers <see cref="JtiReplayOutcome.StoreUnavailable"/> and
    /// the jwt-bearer redemption refuses the very FIRST redemption with <c>server_error</c> — the silent
    /// no-op the half-wiring would otherwise produce is caught rather than admitted.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public async Task RedeemFailsClosedWhenStoreCannotProveItself()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        await HalfWireJtiReplayStoreAsync(app.Server).ConfigureAwait(false);

        //The store saves the assertion jti but never resolves it under FlowKind.JtiReplay, so the guard
        //cannot prove the replay defense ran and the first redemption fails closed.
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.ServerError, body);
    }


    /// <summary>
    /// Rewires the host's replay store so it saves normally but never resolves anything under
    /// <c>FlowKind.JtiReplay</c>, while every other correlation kind still resolves through the host's
    /// real resolver. This is the half-wired store the guard's post-save self-check must catch.
    /// </summary>
    /// <param name="server">The hosted server whose OAuth integration resolver is wrapped.</param>
    private static async Task HalfWireJtiReplayStoreAsync(EndpointServer server)
    {
        ResolveCorrelationKeyDelegate original = server.OAuth().ResolveCorrelationKeyAsync!;
        await TestHostShell.AlterAsync(server, candidateIntegration =>
        {
            candidateIntegration.ResolveCorrelationKeyAsync = (tenantId, flowKind, externalHandle, ctx, ct) =>
                flowKind == FlowKind.JtiReplay
                    ? ValueTask.FromResult<string?>(null)
                    : original(tenantId, flowKind, externalHandle, ctx, ct);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// §4.4.1: the redeemed assertion's <c>typ</c> MUST be <c>oauth-id-jag+jwt</c>. Presenting an
    /// ordinary access token (a different typ) as the assertion is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithWrongTypIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        //An ordinary RFC 9068 access token — valid signature, wrong typ.
        string accessTokenAsAssertion = await ObtainClientCredentialsAccessTokenAsync(
            http, tokenUrl, ClientId, ClientSecret, WellKnownScopes.OpenId).ConfigureAwait(false);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = accessTokenAsAssertion
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// RFC 7515 §4.1.9: "A recipient using the media type value MUST treat it as if "application/"
    /// were prepended to any "typ" value not containing a '/'," and media type values are case
    /// insensitive per RFC 2045. A fresh ID-JAG assertion redeems successfully whichever of the three
    /// equivalent <c>typ</c> spellings it carries; a <c>typ</c> that names a genuinely different media
    /// type is still refused with the same <c>invalid_grant</c> the endpoint already gives for a wrong
    /// type.
    /// </summary>
    [TestMethod]
    public async Task RedeemAcceptsTypSpelledAsAnyEquivalentMediaType()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        foreach(string typ in new[]
        {
            "oauth-id-jag+jwt",
            "application/oauth-id-jag+jwt",
            "APPLICATION/OAUTH-ID-JAG+JWT"
        })
        {
            string jag = await BuildIdJagWithTypAsync(
                material.SigningPrivateKey, material.SigningKeyId.Value, idpIssuer, typ).ConfigureAwait(false);

            using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
                http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(200, (int)response.StatusCode, $"typ '{typ}' should redeem: {body}");
        }

        string wrongTypeJag = await BuildIdJagWithTypAsync(
            material.SigningPrivateKey, material.SigningKeyId.Value, idpIssuer, "application/jwt").ConfigureAwait(false);
        using HttpResponseMessage refused = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, BuildRedeemForm(wrongTypeJag), TestContext.CancellationToken).ConfigureAwait(false);
        string refusedBody = await refused.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)refused.StatusCode, refusedBody);
        Assert.Contains(OAuthErrors.InvalidGrant, refusedBody);
    }


    /// <summary>
    /// §4.4.1: the <c>aud</c> claim MUST name the Resource Authorization Server's issuer. A JAG minted
    /// for a different audience is rejected with <c>invalid_grant</c> (audience injection defense).
    /// </summary>
    [TestMethod]
    public async Task RedeemWithAudienceMismatchIsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        //Mint a JAG whose aud is a different Resource Authorization Server.
        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, "https://attacker-as.example.com/")
            .ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: "a-different-resource-client").ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //The Resource Authorization Server's issuer equals the IdP issuer — same trust domain.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, idpIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Advance past the default 5-minute JAG lifetime plus the 60s redeem skew.
        TimeProvider.Advance(TimeSpan.FromMinutes(6) + TimeSpan.FromSeconds(61));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                static (assertion, requestedScope, registration, context, ct) =>
                    ValueTask.FromResult<JwtBearerGrant?>(null);
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = TamperSignature(jag)
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        //An empty key resolver — no issuer's key resolves, modelling an untrusted issuer.
        static ValueTask<PublicKeyMemory?> emptyResolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) => ValueTask.FromResult<PublicKeyMemory?>(null);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, emptyResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        //The seam models §4.3.3: it accepts the subject token only when the (here, the subject_token
        //value stands in for) Identity Assertion audience equals the authenticated client.

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        string.Equals(token, registration.ClientId, StringComparison.Ordinal)
                            ? new ValidatedSecurityToken { Subject = SubjectIdentity }
                            : null);
            WireIdJagAuthorization(candidateIntegration, ChatScope, resourceClientId: null);
        }).ConfigureAwait(false);


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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = ChatScope,
                            IssuedTokenType = TokenType.IdJag,
                            Audience = [seamShapedAudience]
                        });
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingAsync(app, ChatScope, [grantedResource]).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingAsync(app, ChatScope, grantedResources).ConfigureAwait(false);

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
        Assert.AreSequenceEqual(grantedResources, resourceClaim);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingAsync(app, grantedScope, []).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.Scope] = requestedScope,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingDetailsAsync(app, SampleGrantedDetails(), responseJson: null).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        string? capturedRequestDetails = null;
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken),
            [OAuthRequestParameterNames.AuthorizationDetails] = SampleDetailsJson
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingAsync(app, WellKnownScopes.OpenId, [grantedResource]).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument tokenPayload = DecodePayload(accessToken);

        //RFC 7519 §4.1.3's general representation of aud is an array of StringOrURI values; this
        //producer (Rfc9068AccessTokenProducer via JwtPayloadExtensions.ForAccessToken) always emits
        //it as a JSON array, including a single audience.
        JsonElement aud = tokenPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.Array, aud.ValueKind);
        Assert.HasCount(1, aud.EnumerateArray().ToList());
        Assert.AreEqual(grantedResource, aud[0].GetString());
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingAsync(app, grantedScope: string.Empty, grantedResource: []).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.Scope] = "chat.read chat.history",
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingDetailsAsync(app, SampleGrantedDetails(), responseJson: SampleDetailsJson).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsGrantingDetailsAsync(app, SampleGrantedDetails(), responseJson: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //The Resource Authorization Server grants the authorization_details it found on the validated
        //grant (here, verbatim) and echoes them.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
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
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        }, TestContext.CancellationToken).ConfigureAwait(false);
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


    /// <summary>
    /// Installs assertion minting and authorization delegates that grant the supplied authorization details.
    /// </summary>
    private static async Task WireMintSeamsGrantingDetailsAsync(TestHostShell app, IReadOnlyList<object> grantedDetails, string? responseJson)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });


            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Installs assertion minting and authorization delegates that grant the requested scope.
    /// </summary>
    private static async Task WireMintSeamsGrantingAsync(TestHostShell app, string grantedScope, IReadOnlyList<string> grantedResource)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });


            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = grantedScope,
                            IssuedTokenType = TokenType.IdJag,
                            Resource = grantedResource
                        });
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// §9.8.1.1: when the Token Exchange carries a DPoP proof, the IdP validates it and binds the JAG
    /// by stamping <c>cnf.jkt</c> with the proof's JWK SHA-256 thumbprint.
    /// </summary>
    [TestMethod]
    public async Task MintWithDpopProofBindsJagToCnfJkt()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

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

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                http, tokenUrl, BuildMintForm(ResourceAsIssuer),
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);

                using JsonDocument doc = JsonDocument.Parse(body);
                string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                using JsonDocument payload = DecodePayload(jag);
                Assert.AreEqual(expectedJkt,
                    payload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 7515 §4.1.9's implicit "application/" prefix and RFC 2045 case insensitivity apply to
    /// every JOSE <c>typ</c> header, the DPoP proof's included: a proof whose <c>typ</c> is spelled
    /// <c>application/dpop+jwt</c> (RFC 9449 §10.2's own IANA media-type registration) still binds the
    /// JAG, the same as the canonical short form.
    /// </summary>
    [TestMethod]
    public async Task MintWithDpopProofTypSpelledAsTheLongMediaTypeStillBindsJagToCnfJkt()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

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

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                http, tokenUrl, BuildMintForm(ResourceAsIssuer),
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, "application/dpop+jwt", nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);

                using JsonDocument doc = JsonDocument.Parse(body);
                string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                using JsonDocument payload = DecodePayload(jag);
                Assert.AreEqual(expectedJkt,
                    payload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
            }
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string expectedJkt = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

            string jag = await MintBoundJagAsync(http, tokenUrl, dpopKey, segment, material).ConfigureAwait(false);

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage redeemResponse, string redeemBody) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                http, tokenUrl, BuildRedeemForm(jag),
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(redeemResponse)
            {
                Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

                using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
                Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, redeemDoc.RootElement.GetProperty("token_type").GetString());
                string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                using JsonDocument tokenPayload = DecodePayload(accessToken);
                Assert.AreEqual(expectedJkt, tokenPayload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
            }
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string jag = await MintBoundJagAsync(http, tokenUrl, dpopKey, segment, material).ConfigureAwait(false);

            //Redeem with no DPoP header.
            using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken)
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bindingKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> otherKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey bindingKey = new(bindingKeyMaterial, WellKnownJwaValues.Es256);
            DpopKey otherKey = new(otherKeyMaterial, WellKnownJwaValues.Es256);

            string jag = await MintBoundJagAsync(http, tokenUrl, bindingKey, segment, material).ConfigureAwait(false);

            //Redeem with a proof from a DIFFERENT key. RFC 9449 §8: the server's single nonce
            //policy challenges the first, nonce-less proof; the retry (still the wrong key) still
            //fails the ID-JAG binding comparison.
            (HttpResponseMessage redeemResponse, string redeemBody) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                http, tokenUrl, BuildRedeemForm(jag),
                nonce => BuildTokenEndpointDpopProofAsync(otherKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(redeemResponse)
            {
                Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
                Assert.Contains(OAuthErrors.InvalidGrant, redeemBody);
            }
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

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

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage redeemResponse, string redeemBody) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                http, tokenUrl, BuildRedeemForm(jag),
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(redeemResponse)
            {
                Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);

                using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
                Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, redeemDoc.RootElement.GetProperty("token_type").GetString());
                string accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                using JsonDocument tokenPayload = DecodePayload(accessToken);
                Assert.AreEqual(expectedJkt, tokenPayload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString());
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: the nonce
    /// requirement is the SERVER's, never the grant's — proven here by ASSERTING the challenge
    /// itself, rather than tolerating either outcome the way
    /// <see cref="RedeemUnboundJagWithDpopIssuesDpopBoundToken"/>'s permissive retry helper does.
    /// Under <see cref="PolicyProfile.Rfc6749WithPkce"/> — a profile
    /// <see cref="ClientPolicyProfiles.RequiresDpop"/> does NOT mandate — a nonce-less proof still
    /// answers 400 <c>use_dpop_nonce</c> with a non-empty <c>DPoP-Nonce</c> header at ID-JAG
    /// redemption, and the retry carrying that exact nonce succeeds.
    /// </summary>
    [TestMethod]
    public async Task NonceLessProofUnderOptionalDpopProfileIsChallengedThenSucceedsAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

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

            (HttpResponseMessage redeemResponse, string redeemBody) = await OAuthTestTransport.PostFormWithMandatoryDpopNonceChallengeAsync(
                http, tokenUrl, BuildRedeemForm(jag),
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(redeemResponse)
            {
                Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
            }
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        //The Resource Server requires sender-constrained tokens.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                {
                    JwtBearerGrant? grant = await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer)
                        .ConfigureAwait(false);

                    return grant is null ? null : grant with { RequiresSenderConstrainedToken = true };
                };
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken)
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                {
                    JwtBearerGrant? grant = await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer)
                        .ConfigureAwait(false);

                    return grant is null ? null : grant with { RequiresSenderConstrainedToken = true };
                };
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage redeemResponse, string redeemBody) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                http, tokenUrl, BuildRedeemForm(jag),
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(redeemResponse)
            {
                Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
                using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
                Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP,
                    redeemDoc.RootElement.GetProperty("token_type").GetString());
            }
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireRefreshTokenSubjectMintSeamsAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireRefreshTokenSubjectMintSeamsAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireRefreshTokenSubjectMintSeamsAsync(app).ConfigureAwait(false);

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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "This is
    /// applicable for all access token requests regardless of grant type." A Refresh Token
    /// <c>subject_token</c> whose validated claims surface a <c>cnf.jkt</c> binding
    /// (<see cref="ValidatedSecurityToken.RequiredKeyThumbprint"/>) presented with no DPoP proof at
    /// all must not be exchanged for an ID-JAG — the mint is refused rather than silently issuing an
    /// unbound grant.
    /// </summary>
    [TestMethod]
    public async Task MintFromBoundRefreshTokenSubjectWithoutProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey boundKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string boundThumbprint = boundKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundRefreshTokenSubjectMintSeamsAsync(app, boundThumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

            using HttpResponseMessage response = await PostRefreshTokenMintAsync(
                host.SharedHttpClient!, tokenUrl, ResourceAsIssuer, WellKnownScopes.OpenId, RefreshTokenSubjectValue)
                .ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, (int)response.StatusCode, body);
            Assert.Contains(OAuthErrors.InvalidGrant, body);
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The refresh-token-subject mint's mismatched-key counterpart to
    /// <see cref="MintFromBoundRefreshTokenSubjectWithoutProofIsRefused"/>.
    /// </summary>
    [TestMethod]
    public async Task MintFromBoundRefreshTokenSubjectWithMismatchedProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> boundKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> presentedKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey boundKey = new(boundKeyMaterial, WellKnownJwaValues.Es256);
            DpopKey presentedKey = new(presentedKeyMaterial, WellKnownJwaValues.Es256);
            string boundThumbprint = boundKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundRefreshTokenSubjectMintSeamsAsync(app, boundThumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry (still the wrong key) still fails the bound-subject key comparison.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, RefreshTokenMintForm(ResourceAsIssuer, WellKnownScopes.OpenId, RefreshTokenSubjectValue),
                nonce => BuildTokenEndpointDpopProofAsync(presentedKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(400, (int)response.StatusCode, body);
                Assert.Contains(OAuthErrors.InvalidGrant, body);
            }
        }
        finally
        {
            boundKeyMaterial.PublicKey.Dispose();
            boundKeyMaterial.PrivateKey.Dispose();
            presentedKeyMaterial.PublicKey.Dispose();
            presentedKeyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 §9.8.1.1 combined with RFC 9449 §5: a Refresh
    /// Token <c>subject_token</c> bound to a key, presented with a matching DPoP proof, mints an ID-JAG
    /// whose own <c>cnf.jkt</c> equals that key — the subject token's binding carries into the issued
    /// grant.
    /// </summary>
    [TestMethod]
    public async Task MintFromBoundRefreshTokenSubjectWithMatchingProofBindsIssuedJag()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string thumbprint = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundRefreshTokenSubjectMintSeamsAsync(app, thumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, RefreshTokenMintForm(ResourceAsIssuer, WellKnownScopes.OpenId, RefreshTokenSubjectValue),
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);

                using JsonDocument doc = JsonDocument.Parse(body);
                string jag = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                using JsonDocument payload = DecodePayload(jag);
                Assert.AreEqual(thumbprint,
                    payload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString(),
                    "The issued ID-JAG's cnf.jkt must equal the Refresh Token subject's bound key.");
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Wires the §4.3.2 / §4.3.3 refresh-token-subject mint seams: client authentication, a subject-token
    /// validation that accepts a Refresh Token only when it is the one this IdP issued
    /// (<see cref="RefreshTokenSubjectValue"/>) — modelling "issued by the IdP, bound to the authenticated
    /// client, unexpired, not revoked" — surfacing the RT's authorization context as the validated scope,
    /// and an authorization seam that mints an ID-JAG only when the requested scope stays within that
    /// context (§4.3.3).
    /// </summary>
    private static async Task WireRefreshTokenSubjectMintSeamsAsync(TestHostShell app)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
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


            candidateIntegration.AuthorizeTokenExchangeAsync = static (subject, actor, request, registration, context, ct) =>
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
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Wires the §4.3.2 / §4.3.3 refresh-token-subject mint seams like
    /// <see cref="WireRefreshTokenSubjectMintSeamsAsync"/>, but surfaces
    /// <paramref name="requiredKeyThumbprint"/> as the validated Refresh Token subject's
    /// <see cref="ValidatedSecurityToken.RequiredKeyThumbprint"/> — the RFC 9449 §5 sender-constraint
    /// enforcement under test on the §4.3.2 refresh-token-subject mint.
    /// </summary>
    private static async Task WireBoundRefreshTokenSubjectMintSeamsAsync(TestHostShell app, string? requiredKeyThumbprint)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        tokenType == TokenType.RefreshToken
                        && string.Equals(token, RefreshTokenSubjectValue, StringComparison.Ordinal)
                            ? new ValidatedSecurityToken
                            {
                                Subject = SubjectIdentity,
                                Scope = RefreshTokenAuthorizedScope,
                                Audience = [ResourceAsIssuer],
                                RequiredKeyThumbprint = requiredKeyThumbprint
                            }

                            : null);

            WireIdJagAuthorization(candidateIntegration, RefreshTokenAuthorizedScope, resourceClientId: null);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Posts a Token Exchange that uses a Refresh Token as the <c>subject_token</c>
    /// (<c>subject_token_type</c> = the refresh_token URN) requesting an ID-JAG (§4.3.2), optionally
    /// carrying a DPoP proof for the RFC 9449 §5 sender-constraint enforcement.
    /// </summary>
    private Task<HttpResponseMessage> PostRefreshTokenMintAsync(
        HttpClient http, Uri tokenUrl, string audience, string scope, string refreshToken, string? dpopProof = null) =>
        OAuthTestTransport.PostFormAsync(http, tokenUrl, RefreshTokenMintForm(audience, scope, refreshToken),
            dpopProof is null ? null : OutgoingHeaders.Empty.WithDpop(dpopProof), TestContext.CancellationToken);


    /// <summary>Builds the refresh-token-subject ID-JAG mint request's form fields.</summary>
    private static Dictionary<string, string> RefreshTokenMintForm(string audience, string scope, string refreshToken) =>
        new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = audience,
            [OAuthRequestParameterNames.Scope] = scope,
            [OAuthRequestParameterNames.SubjectToken] = refreshToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.RefreshToken)
        };


    /// <summary>
    /// §3.1 / §6: when the authorization seam supplies tenant relationships, the minted ID-JAG carries
    /// the issuer-tenant (<c>tenant</c>) plus the Resource Authorization Server tenant (<c>aud_tenant</c>)
    /// and that server's own subject identifier (<c>aud_sub</c>).
    /// </summary>
    [TestMethod]
    public async Task MintEmitsTenantClaimsWhenSeamSuppliesThem()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireTenantMintSeamsAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireTenantMintSeamsAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        //A normal mint (no tenant relationships supplied) → the JAG carries no tenant claim.
        await WireMintSeamsAsync(app, WellKnownScopes.OpenId, resourceClientId: null).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
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
        }).ConfigureAwait(false);

        using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)redeemResponse.StatusCode, redeemBody);
        Assert.Contains(OAuthErrors.InvalidGrant, redeemBody);
    }


    /// <summary>
    /// Wires the mint seams so the authorization step supplies the §3.1 tenant relationships — the
    /// issuer-tenant, the Resource Authorization Server tenant, and that server's subject identifier.
    /// </summary>
    private static async Task WireTenantMintSeamsAsync(TestHostShell app)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });


            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireSamlSubjectIdMintSeamsAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireSamlSubjectIdMintSeamsAsync(app).ConfigureAwait(false);

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
        Assert.IsNotNull(result.SamlNameIdSubjectIdentifier);
        Assert.AreEqual(SamlIssuer, result.SamlNameIdSubjectIdentifier!.Issuer);
        Assert.AreEqual(SamlNameId, result.SamlNameIdSubjectIdentifier.NameId);
        Assert.AreEqual(SamlNameIdFormatAttribute, result.SamlNameIdSubjectIdentifier.NameIdFormat);
        Assert.AreEqual(SamlSpNameQualifier, result.SamlNameIdSubjectIdentifier.SpNameQualifier);
        Assert.IsNull(result.SamlNameIdSubjectIdentifier.NameQualifier);
        Assert.IsNull(result.SamlNameIdSubjectIdentifier.SpProvidedId);
    }


    /// <summary>
    /// An <c>iss_sub</c> <c>sub_id</c> whose <c>iss</c> is the grant's validated issuer and whose <c>sub</c> is
    /// the grant's validated subject names the End-User the grant names, and the equality holds by the claim's
    /// own values.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "When both sub and sub_id are present, they MUST identify the same End-User."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">RFC 9493 Section 3.2.3</see>:
    /// "These members MUST follow the formats of the "iss" member and "sub" member defined by [RFC7519],
    /// respectively. Both the "iss" member and the "sub" member are REQUIRED and MUST NOT be null or empty."
    /// </summary>
    [TestMethod]
    public async Task EqualityHoldsForAnIssSubRestatingTheValidatedSubjectAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, string idpIssuer) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            mintedSubjectIdentifier: static idpIssuer => SubjectIdentifier.IssuerSubject(idpIssuer, SubjectIdentity)).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        Assert.IsNotNull(recorded);
        Assert.IsTrue(recorded.IsValid, recorded.FailureDescription);
        AssertComparison(
            recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Holds, ComparisonBasis.ProfileRule, ComparisonDecision.Permit);
        ComparisonRecord<SubjectIdentifier, IdJagSubjectContext> comparison = recorded.SubjectIdentifierComparison!;
        Assert.AreEqual("iss_sub", comparison.Candidate.Format);
        Assert.AreEqual(idpIssuer, comparison.Reference.Issuer);
        Assert.IsNull(comparison.Reference.Tenant);
        Assert.AreEqual(SubjectIdentity, comparison.Reference.Subject);
    }


    /// <summary>
    /// An <c>iss_sub</c> <c>sub_id</c> of the grant's validated issuer that names another subject does not
    /// name the End-User the grant names, and with no association wired the grant is refused.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "When both sub and sub_id are present, they MUST identify the same End-User." and "A public subject
    /// identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer". No clause
    /// states the refusal: it is this library's reading of the two sentences, under which two subjects of one
    /// issuer are two End-Users unless the application's association says they are one.
    /// </summary>
    [TestMethod]
    public async Task EqualityFailsForAnIssSubNamingAnotherSubjectOfTheValidatedIssuerAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            mintedSubjectIdentifier: static idpIssuer => SubjectIdentifier.IssuerSubject(idpIssuer, "another-end-user")).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierMismatch, recorded.FailureReason);
        AssertComparison(
            recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Fails, ComparisonBasis.ProfileRule, ComparisonDecision.Deny);
    }


    /// <summary>
    /// A pairwise <c>iss_sub</c> <c>sub_id</c> of the grant's validated issuer names the End-User by another
    /// <c>sub</c>. With the application's association wired, the association decides it and the grant is
    /// redeemed. Without one, the claim fails as another subject of the grant's issuer: this library reads
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>,
    /// "When both sub and sub_id are present, they MUST identify the same End-User." with "A public subject
    /// identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer", as two subjects
    /// of one issuer being two End-Users unless the application says they are one; no clause states that
    /// refusal.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.2">RFC 9493 Section 4.2</see>: "Similarly,
    /// the JWT's "sub" Claim and the Subject Identifier's "sub" member MAY be different."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// refuses a grant when "the sub_id claim is not authorized by local policy for the validated ID-JAG
    /// issuer."
    /// </summary>
    /// <param name="caseName">Whether the rule wires the association: <c>withAssociation</c> or <c>withoutAssociation</c>.</param>
    [TestMethod]
    [DataRow("withAssociation", DisplayName = "the association maps the pairwise identifier")]
    [DataRow("withoutAssociation", DisplayName = "no association is wired")]
    public async Task APairwiseSubjectIsDecidedByTheAssociationAsync(string caseName)
    {
        Func<string, IdJagSubjectIdentifierRule> rule = caseName switch
        {
            "withAssociation" => static idpIssuer => new IdJagSubjectIdentifierRule
            {
                Relation = ComparisonRelation.Equal,
                Association = (candidate, reference, relation, cancellationToken) => ValueTask.FromResult(candidate switch
                {
                    _ when IsSameIdentifier(candidate, SubjectIdentifier.IssuerSubject(idpIssuer, "pairwise-7f3a"))
                        && IsGrantSubject(reference, idpIssuer) => ComparisonOutcome.Holds,
                    _ when SubjectIdentifierFormats.IsIssuerSubject(candidate.Format)
                        && candidate.Members.GetValueOrDefault("iss") is string issuer
                        && string.Equals(issuer, idpIssuer, StringComparison.Ordinal) => ComparisonOutcome.Fails,
                    _ => ComparisonOutcome.Indeterminate
                })
            },
            "withoutAssociation" => static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            rule,
            mintedSubjectIdentifier: static idpIssuer => SubjectIdentifier.IssuerSubject(idpIssuer, "pairwise-7f3a")).ConfigureAwait(false);

        Assert.IsNotNull(recorded, body);
        if(caseName == "withAssociation")
        {
            Assert.AreEqual(200, statusCode, body);
            AssertComparison(
                recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Holds, ComparisonBasis.ApplicationRule, ComparisonDecision.Permit);
        }
        else
        {
            Assert.AreEqual(400, statusCode, body);
            Assert.AreEqual(JagRefusal, body);
            Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierMismatch, recorded.FailureReason);
            AssertComparison(
                recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Fails, ComparisonBasis.ProfileRule, ComparisonDecision.Deny);
        }
    }


    /// <summary>
    /// An <c>iss_sub</c> <c>sub_id</c> in another issuer's namespace, with no association wired, is a
    /// comparison nothing can decide; the claim is OPTIONAL, so the grant is redeemed and the record keeps that
    /// nothing decided it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "The sub_id claim MAY be used to identify the same End-User as the sub claim using a different
    /// identifier namespace from the ID-JAG iss and sub."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.1">RFC 9493 Section 4.1</see>: "When
    /// processing a JWT with both JWT "sub" and "sub_id" Claims, implementations MUST NOT rely on both claims to
    /// determine the JWT Subject. An implementation MAY attempt to determine the JWT Subject from one claim and
    /// fall back to using the other if it determines it does not understand the format of the first claim."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.2">RFC 9493 Section 4.2</see>: "The JWT
    /// "sub_id" Claim MAY contain an "iss_sub" Subject Identifier. In this case, the JWT's "iss" Claim and the
    /// Subject Identifier's "iss" member MAY be different."
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier (pic-prover-verifier-02) Section 4.2</see>:
    /// "a Verifier MUST reject a PCA whose profile is unknown or does not define a deterministic comparison."
    /// Redeeming the grant is this library's rule for the OPTIONAL claim of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>,
    /// where it does not follow that sentence; <see cref="IdJagSubjectIdentifierRule.Presence"/> states the
    /// choice.
    /// </summary>
    [TestMethod]
    public async Task AnotherNamespaceWithoutAnAssociationIsIndeterminateWhileOptionalAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            mintedSubjectIdentifier: static _ => SubjectIdentifier.IssuerSubject("https://other-idp.example", "alice-at-other")).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        Assert.IsNotNull(recorded);
        AssertComparison(
            recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Indeterminate, ComparisonBasis.None, ComparisonDecision.Permit);
    }


    /// <summary>
    /// A server that requires the <c>sub_id</c> claim and wires no association cannot say whether the claim is
    /// authorized by its local policy, even when the claim restates the grant's own subject, so the grant is
    /// refused as undecided.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "If the Resource Authorization Server requires a SAML NameID Subject Identifier for subject resolution,
    /// it MUST reject the token request with an invalid_grant error as defined in Section 5.2 of [RFC6749] if
    /// any of the following is true" and one of them is "the sub_id claim is not authorized by local policy for
    /// the validated ID-JAG issuer."
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-lineage-guardrail-spec.txt">PIC Sandboxed Execution (pic-sandboxed-execution-02) Section 2.6</see>:
    /// "An input required by policy that is unauthenticated, ambiguously bound, semantically unmapped,
    /// inconsistent with the presented continuity state, unavailable, or controlled only by the proposing
    /// executor MUST produce deny or indeterminate-deny."
    /// </summary>
    /// <param name="caseName">The claim: <c>anotherNamespace</c> or <c>theGrantSubject</c>.</param>
    [TestMethod]
    [DataRow("anotherNamespace", DisplayName = "an iss_sub of another issuer")]
    [DataRow("theGrantSubject", DisplayName = "the iss_sub of the grant's own issuer and subject")]
    public async Task ARequiredIdentifierWithoutAnAssociationIsAnIndeterminateDenyAsync(string caseName)
    {
        Func<string, SubjectIdentifier?> identifier = caseName switch
        {
            "anotherNamespace" => static _ => SubjectIdentifier.IssuerSubject("https://other-idp.example", "alice-at-other"),
            "theGrantSubject" => static idpIssuer => SubjectIdentifier.IssuerSubject(idpIssuer, SubjectIdentity),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Presence = IdJagSubjectIdentifierPresence.Required },
            mintedSubjectIdentifier: identifier).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierUndetermined, recorded.FailureReason);
        AssertComparison(
            recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Indeterminate, ComparisonBasis.None, ComparisonDecision.IndeterminateDeny);
    }


    /// <summary>
    /// A deny and an indeterminate-deny leave the server as one and the same wire answer, byte for byte; only
    /// the recorded result tells them apart. The one wire answer is this library's rule.
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-lineage-guardrail-spec.txt">PIC Sandboxed Execution (pic-sandboxed-execution-02) Section 2.4</see>:
    /// "A permit MAY appear in an authorizing outer advancement; a deny MUST NOT authorize continuation. A
    /// profile MAY record a denial for audit, but MUST NOT introduce a denial artifact that is interpreted as
    /// permission to cross the governed boundary."
    /// The deny is an <c>iss_sub</c> of the grant's own issuer naming another subject, with no association
    /// wired: its refusal is this library's reading of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>,
    /// "When both sub and sub_id are present, they MUST identify the same End-User." with "A public subject
    /// identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer", under which two
    /// subjects of one issuer are two End-Users unless the application says they are one; no clause states that
    /// refusal. The indeterminate-deny is a required claim that no association decides.
    /// </summary>
    [TestMethod]
    public async Task ADenyAndAnIndeterminateDenyAnswerTheWireIdenticallyAsync()
    {
        (int denyStatusCode, string denyBody, IdJagAssertionValidationResult? denyRecorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            mintedSubjectIdentifier: static idpIssuer => SubjectIdentifier.IssuerSubject(idpIssuer, "another-end-user")).ConfigureAwait(false);
        (int undeterminedStatusCode, string undeterminedBody, IdJagAssertionValidationResult? undeterminedRecorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Presence = IdJagSubjectIdentifierPresence.Required },
            mintedSubjectIdentifier: static _ => SubjectIdentifier.IssuerSubject("https://other-idp.example", "alice-at-other")).ConfigureAwait(false);

        Assert.AreEqual(400, denyStatusCode, denyBody);
        Assert.AreEqual(400, undeterminedStatusCode, undeterminedBody);
        Assert.AreEqual(denyBody, undeterminedBody);
        Assert.AreEqual(JagRefusal, denyBody);

        Assert.IsNotNull(denyRecorded);
        Assert.IsNotNull(undeterminedRecorded);
        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierMismatch, denyRecorded.FailureReason);
        Assert.AreEqual(ComparisonDecision.Deny, denyRecorded.SubjectIdentifierComparison?.Decision);
        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierUndetermined, undeterminedRecorded.FailureReason);
        Assert.AreEqual(ComparisonDecision.IndeterminateDeny, undeterminedRecorded.SubjectIdentifierComparison?.Decision);
    }


    /// <summary>
    /// A SAML NameID <c>sub_id</c> is in the SAML issuer's namespace, which only the application's association
    /// maps, and the association decides it by the complete configured identifier: a different
    /// <c>nameid</c>, a different <c>sp_name_qualifier</c> or a different SAML issuer is not the configured
    /// End-User.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "The Resource Authorization Server MUST compare every member of the SAML NameID Subject Identifier that is
    /// part of the set of identifier fields it uses for subject resolution for that SAML issuer." and "In
    /// particular, when the SAML Assertion Subject &lt;NameID&gt; is scoped to a Service Provider, the
    /// sp_name_qualifier value is part of the subject namespace."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>:
    /// "The Resource Authorization Server MUST use a SAML NameID sub_id only when the validated ID-JAG issuer is
    /// explicitly associated with the SAML issuer identified by sub_id.issuer through local configuration or
    /// trusted federation metadata."
    /// </summary>
    /// <param name="caseName">
    /// The presented identifier: <c>theConfiguredIdentifier</c>, <c>anotherNameId</c>,
    /// <c>anotherSpNameQualifier</c> or <c>anUnrelatedIssuer</c>.
    /// </param>
    [TestMethod]
    [DataRow("theConfiguredIdentifier", DisplayName = "the complete configured identifier")]
    [DataRow("anotherNameId", DisplayName = "another nameid")]
    [DataRow("anotherSpNameQualifier", DisplayName = "another sp_name_qualifier")]
    [DataRow("anUnrelatedIssuer", DisplayName = "a SAML issuer the association does not know")]
    public async Task TheAssociationDecidesAnotherNamespaceByItsCompleteConfiguredIdentifierAsync(string caseName)
    {
        SamlNameIdSubjectIdentifier presented = caseName switch
        {
            "theConfiguredIdentifier" => ConfiguredSamlIdentifier,
            "anotherNameId" => ConfiguredSamlIdentifier with { NameId = "mallory@example.com" },
            "anotherSpNameQualifier" => ConfiguredSamlIdentifier with { SpNameQualifier = "https://other-sp.example/saml/sp" },
            "anUnrelatedIssuer" => ConfiguredSamlIdentifier with { Issuer = UnrelatedSamlIssuer },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static idpIssuer => new IdJagSubjectIdentifierRule
            {
                Relation = ComparisonRelation.Equal,
                Association = ConfiguredSamlAssociation(idpIssuer)
            },
            mintedSubjectIdentifier: _ => presented.ToSubjectIdentifier()).ConfigureAwait(false);

        Assert.IsNotNull(recorded, body);
        if(caseName == "theConfiguredIdentifier")
        {
            Assert.AreEqual(200, statusCode, body);
            AssertComparison(
                recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Holds, ComparisonBasis.ApplicationRule, ComparisonDecision.Permit);
        }
        else
        {
            Assert.AreEqual(400, statusCode, body);
            Assert.AreEqual(JagRefusal, body);
            Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierMismatch, recorded.FailureReason);
            AssertComparison(
                recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Fails, ComparisonBasis.ApplicationRule, ComparisonDecision.Deny);
        }
    }


    /// <summary>
    /// A server that requires a SAML NameID <c>sub_id</c> refuses one under a SAML issuer its association does
    /// not associate with the grant's validated issuer.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "If the Resource Authorization Server requires a SAML NameID Subject Identifier for subject resolution,
    /// it MUST reject the token request with an invalid_grant error as defined in Section 5.2 of [RFC6749] if
    /// any of the following is true" and the third is "the sub_id claim is not authorized by local policy for
    /// the validated ID-JAG issuer."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>:
    /// "The Resource Authorization Server MUST use a SAML NameID sub_id only when the validated ID-JAG issuer is
    /// explicitly associated with the SAML issuer identified by sub_id.issuer through local configuration or
    /// trusted federation metadata."
    /// </summary>
    [TestMethod]
    public async Task ARequiredSamlIdentifierUnderAnIssuerTheAssociationDoesNotAuthorizeIsRefusedAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static idpIssuer => new IdJagSubjectIdentifierRule
            {
                Presence = IdJagSubjectIdentifierPresence.Required,
                AcceptedFormats = new HashSet<string>(StringComparer.Ordinal) { "saml-nameid" },
                Association = ConfiguredSamlAssociation(idpIssuer)
            },
            mintedSubjectIdentifier: static _ => (ConfiguredSamlIdentifier with { Issuer = UnrelatedSamlIssuer }).ToSubjectIdentifier()).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierMismatch, recorded.FailureReason);
        AssertComparison(
            recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Fails, ComparisonBasis.ApplicationRule, ComparisonDecision.Deny);
    }


    /// <summary>
    /// A server that requires the <c>sub_id</c> claim redeems a grant whose identifier its association
    /// authorizes: the complete configured SAML NameID identifier, and the <c>iss_sub</c> identifier restating
    /// the grant's own subject, which under a required claim is decided by the association like every other
    /// candidate and is put to it exactly once. Deciding the identical claim by the association is this
    /// library's rule for a required claim.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "If the Resource Authorization Server requires a SAML NameID Subject Identifier for subject resolution,
    /// it MUST reject the token request with an invalid_grant error as defined in Section 5.2 of [RFC6749] if
    /// any of the following is true" and the third is "the sub_id claim is not authorized by local policy for
    /// the validated ID-JAG issuer." An identifier the association authorizes meets none of the three.
    /// </summary>
    /// <param name="caseName">
    /// The identifier the grant carries: <c>theConfiguredSamlIdentifier</c> or <c>theGrantsOwnIssSub</c>.
    /// </param>
    [TestMethod]
    [DataRow("theConfiguredSamlIdentifier", DisplayName = "the configured SAML NameID identifier the association holds")]
    [DataRow("theGrantsOwnIssSub", DisplayName = "the iss_sub identifier of the grant's own subject")]
    public async Task ARequiredIdentifierTheAssociationAuthorizesIsRedeemedAsync(string caseName)
    {
        int associationCalls = 0;
        Func<string, IdJagSubjectIdentifierRule> rule = caseName switch
        {
            "theConfiguredSamlIdentifier" => idpIssuer => new IdJagSubjectIdentifierRule
            {
                Presence = IdJagSubjectIdentifierPresence.Required,
                AcceptedFormats = new HashSet<string>(StringComparer.Ordinal) { "saml-nameid" },
                Association = (candidate, reference, relation, cancellationToken) =>
                {
                    _ = Interlocked.Increment(ref associationCalls);

                    return ConfiguredSamlAssociation(idpIssuer)(candidate, reference, relation, cancellationToken);
                }
            },
            "theGrantsOwnIssSub" => idpIssuer => new IdJagSubjectIdentifierRule
            {
                Presence = IdJagSubjectIdentifierPresence.Required,
                Association = (candidate, reference, relation, cancellationToken) =>
                {
                    _ = Interlocked.Increment(ref associationCalls);

                    return ValueTask.FromResult(ComparisonOutcome.Holds);
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            rule,
            mintedSubjectIdentifier: idpIssuer => caseName switch
            {
                "theConfiguredSamlIdentifier" => ConfiguredSamlIdentifier.ToSubjectIdentifier(),
                "theGrantsOwnIssSub" => SubjectIdentifier.IssuerSubject(idpIssuer, SubjectIdentity),
                _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
            }).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        Assert.IsNotNull(recorded);
        AssertComparison(
            recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Holds, ComparisonBasis.ApplicationRule, ComparisonDecision.Permit);
        Assert.AreEqual(1, associationCalls);
    }


    /// <summary>
    /// In a grant of a multi-tenant issuer, <c>iss</c> and <c>sub</c> alone do not name the End-User, so an
    /// <c>iss_sub</c> restating them is decided only by the application's association, which sees the tenant:
    /// undecided without one (redeemed under the OPTIONAL claim, refused where the claim is required), and
    /// held by an association that knows the tenant.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "A public subject identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer
    /// and MUST be unique when scoped with issuer and tenant (iss+tenant+sub) for multi-tenant issuer." The same
    /// section defines the OPTIONAL <c>tenant</c> claim as the tenant identifier of a multi-tenant issuer.
    /// </summary>
    /// <param name="caseName">The rule: <c>equal</c>, <c>required</c> or <c>tenantAssociation</c>.</param>
    [TestMethod]
    [DataRow("equal", DisplayName = "equality without an association")]
    [DataRow("required", DisplayName = "a required claim without an association")]
    [DataRow("tenantAssociation", DisplayName = "equality with an association that knows the tenant")]
    public async Task ATenantQualifiedContextIsDecidedOnlyByTheAssociationAsync(string caseName)
    {
        string? observedTenant = null;
        Func<string, IdJagSubjectIdentifierRule> rule = caseName switch
        {
            "equal" => static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            "required" => static _ => new IdJagSubjectIdentifierRule { Presence = IdJagSubjectIdentifierPresence.Required },
            "tenantAssociation" => _ => new IdJagSubjectIdentifierRule
            {
                Relation = ComparisonRelation.Equal,
                Association = (candidate, reference, relation, cancellationToken) =>
                {
                    observedTenant = reference.Tenant;

                    return ValueTask.FromResult(string.Equals(reference.Tenant, "tenant-acme", StringComparison.Ordinal)
                        ? ComparisonOutcome.Holds
                        : ComparisonOutcome.Fails);
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            rule,
            mintedSubjectIdentifier: static idpIssuer => SubjectIdentifier.IssuerSubject(idpIssuer, SubjectIdentity),
            mintedTenant: IssuerTenant).ConfigureAwait(false);

        Assert.IsNotNull(recorded, body);
        if(caseName == "equal")
        {
            Assert.AreEqual(200, statusCode, body);
            AssertComparison(
                recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Indeterminate, ComparisonBasis.None, ComparisonDecision.Permit);
            Assert.AreEqual("tenant-acme", recorded.SubjectIdentifierComparison!.Reference.Tenant);
        }
        else if(caseName == "required")
        {
            Assert.AreEqual(400, statusCode, body);
            Assert.AreEqual(JagRefusal, body);
            Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierUndetermined, recorded.FailureReason);
        }
        else
        {
            Assert.AreEqual(200, statusCode, body);
            AssertComparison(
                recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Holds, ComparisonBasis.ApplicationRule, ComparisonDecision.Permit);
            Assert.AreEqual("tenant-acme", observedTenant);
        }
    }


    /// <summary>
    /// A grant whose <c>tenant</c>, <c>aud_tenant</c> or <c>aud_sub</c> claim is present and is not a JSON
    /// string with at least one character that is not white space is refused: a tenant relationship the server
    /// cannot read is never taken for one the grant does not carry.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "tenant: OPTIONAL - JSON string that represents the tenant identifier for a multi-tenant issuer" and
    /// "aud_tenant: OPTIONAL - A JSON string that represents a Resource Authorization Server tenant identifier";
    /// the subject is scoped by the tenant: "A public subject identifier MUST be unique when scoped with issuer
    /// (iss+sub) for a single-tenant issuer and MUST be unique when scoped with issuer and tenant
    /// (iss+tenant+sub) for multi-tenant issuer." The same section names no JSON type for <c>aud_sub</c>
    /// ("aud_sub: OPTIONAL - The Resource Authorization Server's identifier for the End-User as defined in
    /// [OpenID.Enterprise]."). The JSON string of <c>tenant</c> and <c>aud_tenant</c> is the draft's; refusing a
    /// present value of any of the three claims that is not a string with at least one character that is not
    /// white space, the empty string included, is this library's fail-closed reading, and no sentence of
    /// Section 3.1,
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// or
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6.3">Section 6.3</see>
    /// states that refusal.
    /// </summary>
    /// <param name="caseName">
    /// The claim the grant carries: <c>tenantNumber</c>, <c>tenantEmpty</c>, <c>tenantObject</c>,
    /// <c>audTenantNumber</c>, <c>audSubNumber</c>, <c>tenantWhiteSpace</c>, <c>audTenantWhiteSpace</c> or
    /// <c>audSubWhiteSpace</c>.
    /// </param>
    [TestMethod]
    [DataRow("tenantNumber", DisplayName = "a tenant that is a number")]
    [DataRow("tenantEmpty", DisplayName = "a tenant that is an empty string")]
    [DataRow("tenantObject", DisplayName = "a tenant that is an object")]
    [DataRow("audTenantNumber", DisplayName = "an aud_tenant that is a number")]
    [DataRow("audSubNumber", DisplayName = "an aud_sub that is a number")]
    [DataRow("tenantWhiteSpace", DisplayName = "a tenant of white space only")]
    [DataRow("audTenantWhiteSpace", DisplayName = "an aud_tenant of white space only")]
    [DataRow("audSubWhiteSpace", DisplayName = "an aud_sub of white space only")]
    public async Task AMalformedTenantRelationshipClaimIsRefusedAsync(string caseName)
    {
        (string ClaimName, object ClaimValue, IdJagValidationFailureReason Reason) malformed = caseName switch
        {
            "tenantNumber" => ("tenant", 5L, IdJagValidationFailureReason.MalformedTenant),
            "tenantEmpty" => ("tenant", "", IdJagValidationFailureReason.MalformedTenant),
            "tenantObject" => ("tenant", new Dictionary<string, object>(StringComparer.Ordinal), IdJagValidationFailureReason.MalformedTenant),
            "audTenantNumber" => ("aud_tenant", 5L, IdJagValidationFailureReason.MalformedAudienceTenant),
            "audSubNumber" => ("aud_sub", 5L, IdJagValidationFailureReason.MalformedAudienceSubject),
            "tenantWhiteSpace" => ("tenant", " ", IdJagValidationFailureReason.MalformedTenant),
            "audTenantWhiteSpace" => ("aud_tenant", " ", IdJagValidationFailureReason.MalformedAudienceTenant),
            "audSubWhiteSpace" => ("aud_sub", " ", IdJagValidationFailureReason.MalformedAudienceSubject),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => IdJagSubjectIdentifierRule.Default,
            signedClaims: _ => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [malformed.ClaimName] = malformed.ClaimValue
            }).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(malformed.Reason, recorded.FailureReason);
    }


    /// <summary>
    /// A grant whose <c>tenant</c> claim is present and unreadable is refused before its <c>sub_id</c> is
    /// compared, so the library's own rule for a grant of a single-tenant issuer never decides it and the
    /// application's association is not asked.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "A public subject identifier MUST be unique when scoped with issuer (iss+sub) for a single-tenant issuer
    /// and MUST be unique when scoped with issuer and tenant (iss+tenant+sub) for multi-tenant issuer."
    /// Refusing a present <c>tenant</c> that is not a JSON string with at least one character that is not white
    /// space is this library's fail-closed reading; no sentence of Section 3.1,
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// or <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6.3">Section 6.3</see>
    /// states it.
    /// </summary>
    [TestMethod]
    public async Task AGrantWithAMalformedTenantIsNeverDecidedByTheLibrarysOwnRuleAsync()
    {
        int associationCalls = 0;
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            _ => new IdJagSubjectIdentifierRule
            {
                Relation = ComparisonRelation.Equal,
                Association = (candidate, reference, relation, cancellationToken) =>
                {
                    associationCalls++;

                    return ValueTask.FromResult(ComparisonOutcome.Fails);
                }
            },
            signedClaims: static idpIssuer => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["tenant"] = 5L,
                ["sub_id"] = SubjectIdentifier.IssuerSubject(idpIssuer, SubjectIdentity).ToWireObject()
            }).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.MalformedTenant, recorded.FailureReason);
        Assert.IsNull(recorded.SubjectIdentifierComparison);
        Assert.AreEqual(0, associationCalls);
    }


    /// <summary>
    /// A server that requires the <c>sub_id</c> claim refuses a grant that carries none, and records no
    /// comparison, since there is no claim to compare.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "If the Resource Authorization Server requires a SAML NameID Subject Identifier for subject resolution,
    /// it MUST reject the token request with an invalid_grant error as defined in Section 5.2 of [RFC6749] if
    /// any of the following is true" and the first is "the ID-JAG does not contain a sub_id claim using the SAML
    /// NameID Subject Identifier Format"
    /// </summary>
    [TestMethod]
    public async Task ARequiredIdentifierThatIsAbsentIsRefusedAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule
            {
                Presence = IdJagSubjectIdentifierPresence.Required,
                AcceptedFormats = new HashSet<string>(StringComparer.Ordinal) { "saml-nameid" }
            }).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierRequired, recorded.FailureReason);
        Assert.IsNull(recorded.SubjectIdentifierComparison);
    }


    /// <summary>
    /// A server that requires the <c>sub_id</c> claim and supports only the SAML NameID format refuses an
    /// identifier of another format.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// refuses a grant when "the sub_id claim is malformed or uses a Subject Identifier Format that the Resource
    /// Authorization Server does not support"
    /// </summary>
    [TestMethod]
    public async Task ARequiredIdentifierOfAFormatTheServerDoesNotAcceptIsRefusedAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule
            {
                Presence = IdJagSubjectIdentifierPresence.Required,
                AcceptedFormats = new HashSet<string>(StringComparer.Ordinal) { "saml-nameid" }
            },
            mintedSubjectIdentifier: static _ => SubjectIdentifier.Email("alice@example.com")).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.UnsupportedSubjectIdentifierFormat, recorded.FailureReason);
        Assert.IsNull(recorded.SubjectIdentifierComparison);
    }


    /// <summary>
    /// Where the <c>sub_id</c> claim is OPTIONAL and compared, an identifier of a format outside the formats the
    /// server supports is surfaced and recorded undecided, basis none, and the application's association is not
    /// asked: the server does not resolve subjects by that format, the identical <c>iss_sub</c> of the grant's
    /// own subject included. Permitting the undecided comparison of an OPTIONAL claim is this library's rule.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "The Resource Authorization Server MAY use sub_id for subject resolution when it supports the indicated
    /// Subject Identifier Format."
    /// </summary>
    /// <param name="caseName">The identifier the grant carries: <c>email</c> or <c>grantSubject</c>.</param>
    [TestMethod]
    [DataRow("email", DisplayName = "an email identifier")]
    [DataRow("grantSubject", DisplayName = "the iss_sub identifier of the grant's own subject")]
    public async Task AnIdentifierOfAFormatTheRuleDoesNotAcceptIsUndecidedWhileOptionalAsync(string caseName)
    {
        int associationCalls = 0;
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            _ => new IdJagSubjectIdentifierRule
            {
                Relation = ComparisonRelation.Equal,
                AcceptedFormats = new HashSet<string>(StringComparer.Ordinal) { "saml-nameid" },
                Association = (candidate, reference, relation, cancellationToken) =>
                {
                    associationCalls++;

                    return ValueTask.FromResult(ComparisonOutcome.Holds);
                }
            },
            mintedSubjectIdentifier: idpIssuer => caseName switch
            {
                "email" => SubjectIdentifier.Email("alice@example.com"),
                "grantSubject" => SubjectIdentifier.IssuerSubject(idpIssuer, SubjectIdentity),
                _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
            }).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        Assert.IsNotNull(recorded);
        Assert.IsNotNull(recorded.SubjectIdentifier, "The claim is surfaced.");
        Assert.AreEqual(caseName == "email" ? "email" : "iss_sub", recorded.SubjectIdentifier.Format);
        AssertComparison(
            recorded.SubjectIdentifierComparison, ComparisonRelation.Equal, ComparisonOutcome.Indeterminate, ComparisonBasis.None, ComparisonDecision.Permit);
        Assert.AreEqual(0, associationCalls);
    }


    /// <summary>
    /// Under the default rule an identifier of any format is surfaced as the claim carries it and judged by
    /// nothing: the claim is OPTIONAL and the server uses it for subject resolution only in a format it
    /// supports.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "The sub_id claim MAY be used to identify the same End-User as the sub claim using a different
    /// identifier namespace from the ID-JAG iss and sub."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>:
    /// "The Resource Authorization Server MAY use sub_id for subject resolution when it supports the indicated
    /// Subject Identifier Format."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.1">RFC 9493 Section 4.1</see>: "An
    /// implementation MAY attempt to determine the JWT Subject from one claim and fall back to using the other
    /// if it determines it does not understand the format of the first claim."
    /// </summary>
    [TestMethod]
    public async Task TheDefaultRuleSurfacesAnIdentifierOfAnyFormatUnjudgedAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => IdJagSubjectIdentifierRule.Default,
            mintedSubjectIdentifier: static _ => SubjectIdentifier.Email("alice@example.com")).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        Assert.IsNotNull(recorded);
        Assert.IsNotNull(recorded.SubjectIdentifier, "The claim is surfaced.");
        Assert.AreEqual("email", recorded.SubjectIdentifier.Format);
        Assert.HasCount(1, recorded.SubjectIdentifier.Members);
        Assert.AreEqual("alice@example.com", recorded.SubjectIdentifier.Members["email"]);
        Assert.IsNull(recorded.SubjectIdentifierComparison);
    }


    /// <summary>
    /// A <c>sub_id</c> that is not a Subject Identifier, or that breaks the rules of its known format, is
    /// refused when the rule judges the claim.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value is
    /// the name of that Identifier Format." and "Every member within a Subject Identifier MUST match the rules
    /// specified for that member by this specification or by a Subject Identifier's Identifier Format. A
    /// Subject Identifier MUST NOT contain any members prohibited or not described by its Identifier Format and
    /// MUST contain all members required by its Identifier Format." The check covers the members present, their
    /// JSON types, the members a format does not describe and the reserved <c>format</c> member, and the rules on
    /// a member's value are the caller's, which <see cref="SubjectIdentifier.IsValidForKnownFormat"/> names.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.4.1</see>:
    /// "If the Resource Authorization Server uses the sub_id claim for subject resolution, it MUST process the
    /// claim according to the indicated Subject Identifier Format. For SAML NameID subject identifiers, the
    /// Resource Authorization Server MUST apply the processing rules in Section 3.2.2."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>: "Subject
    /// Identifiers in this format MUST contain an "identifiers" member whose value is a JSON array containing one
    /// or more Subject Identifiers." and ""aliases" Subject Identifiers MUST NOT be nested, i.e., the
    /// "identifiers" member of an "aliases" Subject Identifier MUST NOT contain a Subject Identifier in the
    /// Aliases Identifier Format."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>:
    /// "A Subject Identifier in this format MUST contain:" <c>format</c>, <c>issuer</c> and <c>nameid</c>, and
    /// "nameid_format: A JSON string containing the value of the Format attribute on the SAML Assertion Subject
    /// &lt;NameID&gt; as defined in [OASIS.saml-core-2.0-os]."
    /// </summary>
    /// <param name="caseName">
    /// The claim value: <c>aString</c>, <c>anArray</c>, <c>anEmptyObject</c>, <c>anUndescribedMember</c>,
    /// <c>aNestedAliases</c>, <c>anEmptyAliases</c>, <c>aSamlNameIdWithoutNameId</c>,
    /// <c>aSamlNameIdWithANumericFormat</c> or <c>aSamlNameIdWithAnUndescribedMember</c>.
    /// </param>
    [TestMethod]
    [DataRow("aString", DisplayName = "a JSON string")]
    [DataRow("anArray", DisplayName = "a JSON array")]
    [DataRow("anEmptyObject", DisplayName = "an object without format")]
    [DataRow("anUndescribedMember", DisplayName = "an iss_sub with a member its format does not describe")]
    [DataRow("aNestedAliases", DisplayName = "an aliases identifier whose one element is an aliases identifier")]
    [DataRow("anEmptyAliases", DisplayName = "an aliases identifier with an empty identifiers array")]
    [DataRow("aSamlNameIdWithoutNameId", DisplayName = "a saml-nameid identifier without nameid")]
    [DataRow("aSamlNameIdWithANumericFormat", DisplayName = "a saml-nameid identifier whose nameid_format is a number")]
    [DataRow("aSamlNameIdWithAnUndescribedMember", DisplayName = "a saml-nameid identifier with a member its format does not describe")]
    public async Task AMalformedIdentifierIsRefusedWhenTheRuleJudgesItAsync(string caseName)
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            signedClaims: idpIssuer => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["sub_id"] = MalformedSubId(caseName, idpIssuer)
            }).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.MalformedSubjectIdentifier, recorded.FailureReason);
        Assert.IsNull(recorded.SubjectIdentifierComparison);
    }


    /// <summary>
    /// Under the default rule a <c>sub_id</c> that is not a Subject Identifier, or that breaks the rules of its
    /// known format, does not refuse the grant and is surfaced as absent, so no reader of the result takes it
    /// for a Subject Identifier.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "Every member
    /// within a Subject Identifier MUST match the rules specified for that member by this specification or by a
    /// Subject Identifier's Identifier Format. A Subject Identifier MUST NOT contain any members prohibited or
    /// not described by its Identifier Format and MUST contain all members required by its Identifier Format."
    /// The check covers the members present, their JSON types, the members a format does not describe and the
    /// reserved <c>format</c> member, and the rules on a member's value are the caller's, which
    /// <see cref="SubjectIdentifier.IsValidForKnownFormat"/> names.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.1">RFC 9493 Section 4.1</see>: "An
    /// implementation MAY attempt to determine the JWT Subject from one claim and fall back to using the other
    /// if it determines it does not understand the format of the first claim."
    /// </summary>
    /// <param name="caseName">
    /// The claim value: <c>aString</c>, <c>anUndescribedMember</c>, <c>aSamlNameIdWithANumericFormat</c> or
    /// <c>aSamlNameIdWithAnUndescribedMember</c>.
    /// </param>
    [TestMethod]
    [DataRow("aString", DisplayName = "a JSON string")]
    [DataRow("anUndescribedMember", DisplayName = "an iss_sub with a member its format does not describe")]
    [DataRow("aSamlNameIdWithANumericFormat", DisplayName = "a saml-nameid identifier whose nameid_format is a number")]
    [DataRow("aSamlNameIdWithAnUndescribedMember", DisplayName = "a saml-nameid identifier with a member its format does not describe")]
    public async Task AMalformedIdentifierIsSurfacedAsAbsentUnderTheDefaultRuleAsync(string caseName)
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => IdJagSubjectIdentifierRule.Default,
            signedClaims: idpIssuer => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["sub_id"] = MalformedSubId(caseName, idpIssuer)
            }).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        Assert.IsNotNull(recorded);
        Assert.IsNull(recorded.SubjectIdentifier);
        Assert.IsNull(recorded.SamlNameIdSubjectIdentifier);
        Assert.IsNull(recorded.SubjectIdentifierComparison);
    }


    /// <summary>
    /// A grant the server cannot verify is refused before its <c>sub_id</c> is read: the claim, however well
    /// formed and however a SAML NameID identifier it names, never establishes trust in the grant's issuer, so
    /// the application's association is not asked. The grant is signed under signing material the server's
    /// resolver of signing material does not know; the fixture's redeem seam resolves the signing material before it validates any
    /// claim, so no validation result is recorded. What the row proves is the order: the application's
    /// validation of the grant's signature runs before the library reads any claim, so a grant the server
    /// cannot verify reaches neither the <c>sub_id</c> rule nor the association. That order is the application's
    /// validation delegate's (the fixture's delegate here), as is the trust in the grant's issuer.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 9.5</see>:
    /// "When the ID-JAG includes a sub_id claim, the Resource Authorization Server MUST NOT use the
    /// sub_id.issuer value to establish trust in the ID-JAG issuer. The ID-JAG MUST first be validated using the
    /// iss claim, signature, audience, expiration, and client binding according to this specification."
    /// </summary>
    [TestMethod]
    public async Task AGrantTheServerCannotVerifyIsRefusedBeforeItsSubIdIsReadAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> unknownKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory unknownPublicKey = unknownKeys.PublicKey;
        using PrivateKeyMemory unknownPrivateKey = unknownKeys.PrivateKey;

        int associationCalls = 0;
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            idpIssuer => new IdJagSubjectIdentifierRule
            {
                Presence = IdJagSubjectIdentifierPresence.Required,
                AcceptedFormats = new HashSet<string>(StringComparer.Ordinal) { "saml-nameid" },
                Association = (candidate, reference, relation, cancellationToken) =>
                {
                    _ = Interlocked.Increment(ref associationCalls);

                    return ConfiguredSamlAssociation(idpIssuer)(candidate, reference, relation, cancellationToken);
                }
            },
            signedClaims: static _ => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["sub_id"] = ConfiguredSamlIdentifier.ToSubjectIdentifier().ToWireObject()
            },
            signingMaterial: unknownPrivateKey).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNull(recorded, "The grant is refused before any claim is validated.");
        Assert.AreEqual(0, associationCalls);
    }


    /// <summary>
    /// A <c>sub</c> of white space only identifies no principal, so the grant is refused as missing its
    /// subject before any <c>sub_id</c> rule runs, and no comparison is recorded.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>, item 2: "The JWT
    /// MUST contain a "sub" (subject) claim identifying the principal that is the subject of the JWT." Reading
    /// a white-space value as identifying no principal is this library's reading of "identifying the
    /// principal": its token factories refuse a white-space subject.
    /// </summary>
    [TestMethod]
    public async Task AWhiteSpaceSubjectIsRefusedAsAValueNotAFaultAsync()
    {
        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.Equal },
            signedClaims: static idpIssuer => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["sub"] = " ",
                ["sub_id"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "iss_sub",
                    ["iss"] = idpIssuer,
                    ["sub"] = " "
                }
            }).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(JagRefusal, body);
        Assert.IsNotNull(recorded);
        Assert.AreEqual(IdJagValidationFailureReason.MissingSubject, recorded.FailureReason);
        Assert.IsNull(recorded.SubjectIdentifierComparison);
    }


    /// <summary>
    /// A rule naming a relation the <c>sub_id</c> profile does not define decides nothing and asks nobody: the
    /// comparison is undecided without calling the association, which redeems the grant under the OPTIONAL
    /// claim and refuses it where the claim is required.
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-prover-verifier-spec.txt">PIC Prover and Verifier (pic-prover-verifier-02) Section 4.2</see>:
    /// "Every profile that introduces an authority representation MUST define its syntax, its equivalence
    /// relation, its attenuation order" and "a deterministic comparison sufficient for non-expansion
    /// validation." The same section: "a Verifier MUST reject a PCA whose profile is unknown or does not define
    /// a deterministic comparison." Redeeming the grant in the optional case is this library's rule for the
    /// OPTIONAL claim of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>,
    /// where it does not follow that sentence; <see cref="IdJagSubjectIdentifierRule.Presence"/> states the
    /// choice.
    /// </summary>
    /// <param name="caseName">The rule: <c>optional</c> or <c>requiredWithAssociation</c>.</param>
    [TestMethod]
    [DataRow("optional", DisplayName = "an optional claim compared under a subset relation")]
    [DataRow("requiredWithAssociation", DisplayName = "a required claim compared under a subset relation with an association")]
    public async Task ARuleNamingAComparisonTheFormatDoesNotDefineDecidesNothingAsync(string caseName)
    {
        int associationCalls = 0;
        Func<string, IdJagSubjectIdentifierRule> rule = caseName switch
        {
            "optional" => static _ => new IdJagSubjectIdentifierRule { Relation = ComparisonRelation.SubsetOf },
            "requiredWithAssociation" => idpIssuer => new IdJagSubjectIdentifierRule
            {
                Presence = IdJagSubjectIdentifierPresence.Required,
                Relation = ComparisonRelation.SubsetOf,
                Association = (candidate, reference, relation, cancellationToken) =>
                {
                    _ = Interlocked.Increment(ref associationCalls);

                    return ValueTask.FromResult(ComparisonOutcome.Holds);
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        (int statusCode, string body, IdJagAssertionValidationResult? recorded, _) = await RedeemSubIdGrantAsync(
            rule,
            mintedSubjectIdentifier: static idpIssuer => SubjectIdentifier.IssuerSubject(idpIssuer, SubjectIdentity)).ConfigureAwait(false);

        Assert.IsNotNull(recorded, body);
        if(caseName == "optional")
        {
            Assert.AreEqual(200, statusCode, body);
            AssertComparison(
                recorded.SubjectIdentifierComparison, ComparisonRelation.SubsetOf, ComparisonOutcome.Indeterminate, ComparisonBasis.None, ComparisonDecision.Permit);
        }
        else
        {
            Assert.AreEqual(400, statusCode, body);
            Assert.AreEqual(JagRefusal, body);
            Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierUndetermined, recorded.FailureReason);
            Assert.AreEqual(0, associationCalls);
        }
    }


    /// <summary>
    /// Section 9.5: the <c>sub_id.issuer</c> (a SAML issuer) MUST NOT establish trust in the ID-JAG issuer. A JAG
    /// whose <c>sub_id</c> names an unrelated SAML issuer validates on its own <c>iss</c>, and the
    /// validator surfaces the SAML issuer separately (distinct from the ID-JAG <c>iss</c>) so the Resource
    /// Authorization Server can perform the Section 9.5 association check itself.
    /// </summary>
    [TestMethod]
    public async Task RedeemDoesNotEstablishTrustFromSubIdIssuer()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = ChatScope,
                            IssuedTokenType = TokenType.IdJag,
                            SubjectIdentifier = new SamlNameIdSubjectIdentifier { Issuer = UnrelatedSamlIssuer, NameId = SamlNameId }.ToSubjectIdentifier()
                        });
        }).ConfigureAwait(false);

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
        Assert.AreEqual(UnrelatedSamlIssuer, result.SamlNameIdSubjectIdentifier!.Issuer);
        Assert.AreNotEqual(result.Issuer, result.SamlNameIdSubjectIdentifier.Issuer, "Section 9.5: the SAML issuer is not the ID-JAG issuer.");
    }


    /// <summary>
    /// The minted grant's <c>sub_id</c> is the Issuer and Subject identifier the authorization seam chose.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "sub_id: OPTIONAL - Subject Identifier as defined in [RFC9493]. The sub_id claim MAY be used to
    /// identify the same End-User as the sub claim using a different identifier namespace from the ID-JAG
    /// iss and sub."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">RFC 9493 Section 3.2.3</see>:
    /// "Both the "iss" member and the "sub" member are REQUIRED and MUST NOT be null or empty. The Issuer
    /// and Subject Identifier Format is identified by the name "iss_sub"."
    /// </summary>
    [TestMethod]
    public async Task MintEmitsAnIssSubSubjectIdentifierTheSeamChoseAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(
            app,
            ChatScope,
            resourceClientId: null,
            subjectIdentifier: SubjectIdentifier.IssuerSubject("https://other-idp.example", "alice-at-other")).ConfigureAwait(false);

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
        Assert.IsTrue(payload.RootElement.TryGetProperty("sub_id", out JsonElement subId), "The grant carries the sub_id the seam chose.");

        Assert.HasCount(3, subId.EnumerateObject());
        Assert.AreEqual("iss_sub", subId.GetProperty("format").GetString());
        Assert.AreEqual("https://other-idp.example", subId.GetProperty("iss").GetString());
        Assert.AreEqual("alice-at-other", subId.GetProperty("sub").GetString());
    }


    /// <summary>
    /// A seam that chooses an identifier that is not well formed, one of a format the library recognizes that
    /// breaks the member rules of that format or one whose format is blank, is answered <c>server_error</c> and
    /// no grant is minted: the identifier is the server's own defect, not the request's, which is a rule of this
    /// library.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "Every
    /// member within a Subject Identifier MUST match the rules specified for that member by this
    /// specification or by a Subject Identifier's Identifier Format. A Subject Identifier MUST NOT contain
    /// any members prohibited or not described by its Identifier Format and MUST contain all members
    /// required by its Identifier Format." The check covers the members present, their JSON types, the members a
    /// format does not describe and the reserved <c>format</c> member, and the rules on a member's value are the
    /// caller's, which <see cref="SubjectIdentifier.IsValidForKnownFormat"/> names.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">RFC 9493 Section 3.2.3</see>:
    /// "Both the "iss" member and the "sub" member are REQUIRED and MUST NOT be null or empty."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value is
    /// the name of that Identifier Format." An empty or white-space format names no format. The refusal comes
    /// before the grant's <c>jti</c> is generated, so no grant identifier is spent on a refused identifier; that
    /// order is this library's.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "The "format"
    /// member is reserved for use as described in this specification; Identifier Formats MUST NOT declare any
    /// rules regarding the "format" member." A known-format identifier whose members also hold an entry named
    /// <c>format</c> carries a member the format does not describe.
    /// </summary>
    /// <param name="caseName">
    /// Which identifier the seam chooses: <c>issSubWithoutSub</c>, <c>issSubWithUndescribedMember</c>,
    /// <c>emptyFormat</c>, <c>whiteSpaceFormat</c> or <c>emailWithAFormatMember</c>.
    /// </param>
    [TestMethod]
    [DataRow("issSubWithoutSub", DisplayName = "an iss_sub identifier without sub")]
    [DataRow("issSubWithUndescribedMember", DisplayName = "an iss_sub identifier with a member its format does not describe")]
    [DataRow("emptyFormat", DisplayName = "an identifier whose format is empty")]
    [DataRow("whiteSpaceFormat", DisplayName = "an identifier whose format is white space")]
    [DataRow("emailWithAFormatMember", DisplayName = "an email identifier whose members also hold an entry named format")]
    public async Task MintRefusesAKnownFormatIdentifierBreakingItsFormatAsync(string caseName)
    {
        SubjectIdentifier identifier = caseName switch
        {
            "emailWithAFormatMember" => new SubjectIdentifier
            {
                Format = "email",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["email"] = "alice@example.com",
                    ["format"] = "email"
                }
            },
            "emptyFormat" => new SubjectIdentifier
            {
                Format = "",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["handle"] = "a-7"
                }
            },
            "whiteSpaceFormat" => new SubjectIdentifier
            {
                Format = " ",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["handle"] = "a-7"
                }
            },
            "issSubWithoutSub" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://other-idp.example"
                }
            },
            "issSubWithUndescribedMember" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://other-idp.example",
                    ["sub"] = "alice-at-other",
                    ["email"] = "alice@other-idp.example"
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await AssertTheMintAnswersNotReadyAsync(subjectIdentifier: identifier).ConfigureAwait(false);
    }


    /// <summary>
    /// An authorization seam that supplies a <c>tenant</c>, an <c>aud_tenant</c> or an <c>aud_sub</c> of white
    /// space only is answered <c>server_error</c> and no grant is minted, and the refusal comes before the grant's
    /// <c>jti</c> is generated: the value is the seam's own defect, and a grant carrying it is one this library's
    /// redeem refuses. The rule is this library's; no sentence of a specification states it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// defines the claims: "tenant: OPTIONAL - JSON string that represents the tenant identifier for a
    /// multi-tenant issuer", "aud_tenant: OPTIONAL - A JSON string that represents a Resource Authorization
    /// Server tenant identifier" and "aud_sub: OPTIONAL - The Resource Authorization Server's identifier for the
    /// End-User as defined in [OpenID.Enterprise]."
    /// </summary>
    /// <param name="caseName">
    /// Which value the seam supplies: <c>tenant</c>, <c>audTenant</c> or <c>audSub</c>, each a single space.
    /// </param>
    [TestMethod]
    [DataRow("tenant", DisplayName = "a tenant of white space only")]
    [DataRow("audTenant", DisplayName = "an aud_tenant of white space only")]
    [DataRow("audSub", DisplayName = "an aud_sub of white space only")]
    public async Task MintRefusesAWhiteSpaceTenantRelationshipValueFromTheSeamAsync(string caseName)
    {
        (string? Tenant, string? AudienceTenant, string? AudienceSubject) supplied = caseName switch
        {
            "tenant" => (" ", null, null),
            "audTenant" => (null, " ", null),
            "audSub" => (null, null, " "),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await AssertTheMintAnswersNotReadyAsync(
            tenant: supplied.Tenant,
            audienceTenant: supplied.AudienceTenant,
            audienceSubject: supplied.AudienceSubject).ConfigureAwait(false);
    }


    /// <summary>
    /// An authorization seam that supplies a <c>tenant</c>, an <c>aud_tenant</c> and an <c>aud_sub</c> that are
    /// all empty is answered 200 and the minted grant carries none of the three claims.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "tenant: OPTIONAL - JSON string that represents the tenant identifier for a multi-tenant issuer".
    /// Omitting a claim whose value the seam leaves empty is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task MintOmitsATenantRelationshipValueThatIsEmptyAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(
            app,
            ChatScope,
            resourceClientId: null,
            tenant: "",
            audienceTenant: "",
            audienceSubject: "").ConfigureAwait(false);

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
        Assert.IsFalse(payload.RootElement.TryGetProperty("tenant", out _), "An empty tenant is omitted.");
        Assert.IsFalse(payload.RootElement.TryGetProperty("aud_tenant", out _), "An empty aud_tenant is omitted.");
        Assert.IsFalse(payload.RootElement.TryGetProperty("aud_sub", out _), "An empty aud_sub is omitted.");
    }


    /// <summary>
    /// An authorization seam that selects the id-jag issued type and names no subject, a
    /// <see cref="TokenExchangeAuthorization.Subject"/> of white space only, is answered <c>server_error</c> with the
    /// fixed description and no grant is minted, and the refusal comes before the grant's <c>jti</c> is generated.
    /// The authorization is the application's decision and names the subject of the grant, so one that names no
    /// subject is the seam's own defect, answered as <see cref="MintRefusesAKnownFormatIdentifierBreakingItsFormatAsync"/>
    /// answers the same seam's <c>sub_id</c> that is not well formed. The answer departs from
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>, whose
    /// <c>invalid_request</c> is the error for a request that is not valid; answering the server's own defect
    /// <c>server_error</c> is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task MintRefusesAnAuthorizationThatNamesNoSubjectAsync()
    {
        await AssertTheMintAnswersNotReadyAsync(authorizedSubject: " ").ConfigureAwait(false);
    }


    /// <summary>
    /// Mints over the loopback listener with an authorization seam that supplies the given values and asserts
    /// that nothing is minted: the answer is 500 with the <c>server_error</c> object alone, carrying the fixed
    /// description, and the host's identifier seam is asked for no grant identifier.
    /// </summary>
    /// <param name="subjectIdentifier">The <c>sub_id</c> identifier the seam supplies, or <see langword="null"/> for none.</param>
    /// <param name="tenant">The issuer <c>tenant</c> the seam supplies, or <see langword="null"/> for none.</param>
    /// <param name="audienceTenant">The <c>aud_tenant</c> the seam supplies, or <see langword="null"/> for none.</param>
    /// <param name="audienceSubject">The <c>aud_sub</c> the seam supplies, or <see langword="null"/> for none.</param>
    /// <param name="authorizedSubject">
    /// The <see cref="TokenExchangeAuthorization.Subject"/> the seam supplies, or <see langword="null"/> for the
    /// validated subject token's subject.
    /// </param>
    private async Task AssertTheMintAnswersNotReadyAsync(
        SubjectIdentifier? subjectIdentifier = null,
        string? tenant = null,
        string? audienceTenant = null,
        string? audienceSubject = null,
        string? authorizedSubject = null)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(
            app,
            ChatScope,
            resourceClientId: null,
            subjectIdentifier: subjectIdentifier,
            tenant: tenant,
            audienceTenant: audienceTenant,
            audienceSubject: audienceSubject,
            authorizedSubject: authorizedSubject).ConfigureAwait(false);

        //The host's identifier seam counts the grant identifiers it is asked for.
        int grantIdentifierCalls = 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            GenerateIdentifierDelegate original = candidateIntegration.GenerateIdentifierAsync!;
            candidateIntegration.GenerateIdentifierAsync = (purpose, context, ct) =>
            {
                if(purpose.Equals(WellKnownIdentifierPurposes.OAuthJti))
                {
                    grantIdentifierCalls++;
                }

                return original(purpose, context, ct);
            };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await PostMintAsync(host.SharedHttpClient!, tokenUrl, ResourceAsIssuer)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string record = $"{(int)response.StatusCode} '{body}' grant identifiers generated {grantIdentifierCalls}";
        Assert.AreEqual(500, (int)response.StatusCode, record);
        Assert.AreEqual(0, grantIdentifierCalls, $"No grant identifier is generated for a refused value of the seam. {record}");

        //The body is the error object alone: no access_token member carries a grant.
        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;
        Assert.HasCount(2, root.EnumerateObject());
        Assert.AreEqual("server_error", root.GetProperty("error").GetString());
        Assert.AreEqual("The server is not ready to serve this request.", root.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// A <c>sub_id</c> placed among the additional claims the seam supplies does not reach the grant: the
    /// claim is the one draft-ietf-oauth-identity-assertion-authz-grant-04
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>
    /// defines, "sub_id: OPTIONAL - Subject Identifier as defined in [RFC9493].", and the mint writes it
    /// only from the identifier the seam chooses, which is a rule of this library.
    /// </summary>
    [TestMethod]
    public async Task MintIgnoresASubIdSmuggledThroughAdditionalClaimsAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = ChatScope,
                            IssuedTokenType = TokenType.IdJag,
                            AdditionalClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                            {
                                ["sub_id"] = new Dictionary<string, object>(StringComparer.Ordinal)
                                {
                                    ["format"] = "email",
                                    ["email"] = "a@example.com"
                                }
                            }
                        });
        }).ConfigureAwait(false);

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
        Assert.IsFalse(payload.RootElement.TryGetProperty("sub_id", out _), "A sub_id among the additional claims does not reach the grant.");
    }


    /// <summary>
    /// An identifier of a format the library does not recognize is written to the grant's <c>sub_id</c>
    /// as the seam gave it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "Every
    /// Identifier Format MUST have a unique name registered in the IANA "Security Event Identifier Formats"
    /// registry established in Section 8.1 or a Collision-Resistant Name as defined in [RFC7519]."
    /// </summary>
    [TestMethod]
    public async Task MintWritesAnUnknownFormatAsGivenAsync()
    {
        SubjectIdentifier identifier = new()
        {
            Format = "urn:example:subject-format",
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["handle"] = "a-7"
            }
        };

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null, subjectIdentifier: identifier).ConfigureAwait(false);

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
        Assert.IsTrue(payload.RootElement.TryGetProperty("sub_id", out JsonElement subId), "The grant carries the sub_id the seam chose.");

        Assert.HasCount(2, subId.EnumerateObject());
        Assert.AreEqual("urn:example:subject-format", subId.GetProperty("format").GetString());
        Assert.AreEqual("a-7", subId.GetProperty("handle").GetString());
    }


    /// <summary>
    /// Section 4.5: a SAML 2.0 Assertion is accepted as the <c>subject_token</c> (<c>subject_token_type</c> =
    /// the saml2 URN) for an ID-JAG mint. The Section 4.5 MUST that the SAML Audience / SPEntityID map to the
    /// authenticated client is enforced by the validation seam: an assertion bound to this client mints;
    /// one bound to a different SP is rejected with <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task MintWithSamlAssertionSubjectTokenMintsIdJag()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        //The seam models Section 4.5: it accepts the SAML assertion only when its Audience (the SP entity id,
        //here stood in for by the subject_token value) maps to the authenticated client.

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        tokenType == TokenType.Saml2 && string.Equals(token, registration.ClientId, StringComparison.Ordinal)
                            ? new ValidatedSecurityToken { Subject = SubjectIdentity }
                            : null);
            WireIdJagAuthorization(candidateIntegration, ChatScope, resourceClientId: null);
        }).ConfigureAwait(false);


        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //SAML Audience maps to the authenticated client, so the grant is minted.
        using HttpResponseMessage matched = await PostSamlMintAsync(http, tokenUrl, ClientId).ConfigureAwait(false);
        string matchedBody = await matched.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)matched.StatusCode, matchedBody);
        using JsonDocument matchedDoc = JsonDocument.Parse(matchedBody);
        string jag = matchedDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument jagPayload = DecodePayload(jag);
        Assert.AreEqual(SubjectIdentity, jagPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());

        //SAML Audience maps to a different SP, so the answer is invalid_grant (Section 4.5 mapping MUST).
        using HttpResponseMessage mismatched = await PostSamlMintAsync(http, tokenUrl, "https://other-sp.example").ConfigureAwait(false);
        string mismatchedBody = await mismatched.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)mismatched.StatusCode, mismatchedBody);
        Assert.Contains(OAuthErrors.InvalidGrant, mismatchedBody);
    }


    /// <summary>
    /// Wires the mint seams so the authorization step supplies the Section 3.2 SAML NameID Subject Identifier
    /// (<see cref="SamlSubjectId"/>) on the issued ID-JAG.
    /// </summary>
    private static async Task WireSamlSubjectIdMintSeamsAsync(TestHostShell app)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });


            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = ChatScope,
                            IssuedTokenType = TokenType.IdJag,
                            SubjectIdentifier = SamlSubjectId.ToSubjectIdentifier()
                        });
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Posts a Token Exchange that uses a SAML 2.0 Assertion as the <c>subject_token</c>
    /// (<c>subject_token_type</c> = the saml2 URN) requesting an ID-JAG (Section 4.5).
    /// </summary>
    private Task<HttpResponseMessage> PostSamlMintAsync(HttpClient http, Uri tokenUrl, string subjectToken) =>
        OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = subjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.Saml2)
        }, TestContext.CancellationToken);


    /// <summary>
    /// Section 3.1: an ID-JAG MAY carry optional ID Token identity claims. When the authorization seam supplies
    /// <c>auth_time</c> / <c>acr</c> / <c>amr</c> / <c>email</c> (the latter RECOMMENDED), the minted JAG
    /// carries them verbatim (string, numeric, and array shapes alike).
    /// </summary>
    [TestMethod]
    public async Task MintEmitsAdditionalIdentityClaims()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);

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
        Assert.AreSequenceEqual(expectedAmr, amr);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);

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
        _ = app.AddHost("idp");
        using VerifierKeyMaterial idpClient = await app.RegisterDpopClientOnHostAsync(
            "idp", ClientId, new Uri(ClientId), PolicyProfile.Rfc6749WithPkce, IdJagClientCapabilities).ConfigureAwait(false);
        using VerifierKeyMaterial rsClient = await app.RegisterDpopClientOnHostAsync(
            "default", ClientId, new Uri(ClientId), PolicyProfile.Rfc6749WithPkce, IdJagClientCapabilities).ConfigureAwait(false);

        //IdP host mint seams: authenticate the client, accept its Identity Assertion, mint an id-jag.
        await TestHostShell.AlterAsync(app.Host("idp").Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync =
                static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(fields.TryGetValue("client_secret", out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.IdJag
                        });
        }).ConfigureAwait(false);

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
        await TestHostShell.AlterAsync(rsHost.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync =
                static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(fields.TryGetValue("client_secret", out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, idpJwksResolver, rsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        //Leg 1 — mint at the IdP host; the audience names the Resource Authorization Server's issuer.
        Uri idpTokenUrl = new(idpHost.HttpBaseAddress!, $"/connect/{idpSegment}/token");
        using HttpResponseMessage mintResponse = await OAuthTestTransport.PostFormAsync(idpHttp, idpTokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = rsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Leg 2 — redeem at the Resource Authorization Server host.
        Uri rsTokenUrl = new(rsHost.HttpBaseAddress!, $"/connect/{rsSegment}/token");
        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(rsHttp, rsTokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

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

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync =
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

            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });
            WireIdJagAuthorization(candidateIntegration, WellKnownScopes.OpenId, resourceClientId: null);
        }).ConfigureAwait(false);


        //Redeem seam: validate the JAG against the IdP JWKS with the Resource AS issuer as the audience.
        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
    /// <see cref="IdJagMintOptions.Resource"/> with more than one entry MUST reach the wire as its OWN
    /// repeated <c>resource</c> occurrence per <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC
    /// 8707 §2</see> — the shape <see cref="Verifiable.OAuth.TokenExchange.TokenExchangeRequestBuilder"/>
    /// already emits (<see cref="OutgoingFormFields.Add(string, string)"/> per entry) — never one
    /// occurrence with the entries space-joined into a single value: the authorization server's own
    /// <c>ReadResource</c> rejects an occurrence carrying embedded whitespace as malformed. This drives
    /// the mint through the library's own <see cref="OAuthClient"/> ID-JAG sub-client and the library's
    /// own hosted authorization server end to end, asserting both the mint succeeds and the
    /// authorization seam observed both resource entries as distinct indicators.
    /// </summary>
    [TestMethod]
    public async Task MintCarriesMultipleResourceEntriesAsRepeatedOccurrences()
    {
        const string FirstResource = "https://api.example.com/orders";
        const string SecondResource = "https://api.example.com/inventory";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory clientPublic = clientKey.PublicKey;
        using PrivateKeyMemory clientPrivate = clientKey.PrivateKey;
        const string clientSigningKeyId = "id-jag-client-key";

        (OAuthClient oauthClient, ClientRegistration clientRegistration, _) =
            await app.CreateOAuthClientAndRegistrationAsync(
                material.Registration, $"{ClientId}/callback", cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);


        //Captures exactly what the authorization seam observed, proving both resource entries arrived
        //as distinct indicators rather than one space-joined (and, upstream, rejected) occurrence.
        IReadOnlyList<string>? seenResources = null;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync =
                async (request, fields, registration, context, ct) =>
                {
                    if(!fields.TryGetValue(OAuthRequestParameterNames.ClientAssertion, out string? assertion)
                        || string.IsNullOrEmpty(assertion))
                    {

                        return false;
                    }

                    return await Jws.VerifyAsync(assertion, TestSetup.Base64UrlDecoder, Pool, clientPublic, ct)
                        .ConfigureAwait(false);
                };


            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    seenResources = request.Resource;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.IdJag
                        });
                };
        }).ConfigureAwait(false);

        IdJagMintOptions mintOptions = new()
        {
            Audience = ResourceAsIssuer,
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.IdToken,
            SigningKey = clientPrivate,
            SigningKeyId = clientSigningKeyId,
            HeaderSerializer = ClientAssertionHeaderSerializer,
            PayloadSerializer = ClientAssertionPayloadSerializer,
            Scope = WellKnownScopes.OpenId,
            Resource = [FirstResource, SecondResource]
        };

        var mintResult = await oauthClient.IdJag.MintAsync(
            clientRegistration, mintOptions, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(mintResult.IsSuccess, mintResult.Error?.Support.Summary);

        Assert.IsNotNull(seenResources, "The authorization seam must have run.");
        Assert.HasCount(2, seenResources);
        Assert.Contains(FirstResource, seenResources);
        Assert.Contains(SecondResource, seenResources);
    }


    /// <summary>
    /// An <see cref="IdJagMintOptions.Scope"/> of white space only is omitted by this library's
    /// normalization at the builder, so the mint sends no <c>scope</c> parameter.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749
    /// section 3.3</see> defines the value as <c>scope = scope-token *( SP scope-token )</c> with
    /// <c>scope-token = 1*( %x21 / %x23-5B / %x5D-7E )</c>, and neither a space (%x20) nor a tab (%x09)
    /// is in a <c>scope-token</c>, so such a value holds no <c>scope-token</c>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 section 3.2</see>'s
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// governs an empty value only, not this one. The mint runs through the library's own
    /// <see cref="OAuthClient"/> ID-JAG sub-client against the hosted token endpoint under a
    /// registration without a DPoP mandate, and the fields the endpoint received are exactly those
    /// of a mint that names no scope.
    /// </summary>
    /// <param name="scope">The white-space-only <see cref="IdJagMintOptions.Scope"/> the mint is given.</param>
    [TestMethod]
    [DataRow(" ")]
    [DataRow("\t")]
    public async Task AMintScopeOfWhiteSpaceOnlyIsSentAsNoScopeAsync(string scope)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireMintSeamsAsync(app, ChatScope, resourceClientId: null).ConfigureAwait(false);

        List<RequestFields> receivedFields = [];
        (HostedAuthorizationServer host, Uri tokenEndpoint, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys) =
            await StartHostAndWirePrivateKeyJwtClientAuthenticationAsync(app, material, receivedFields).ConfigureAwait(false);
        using PublicKeyMemory clientPublic = clientKeys.PublicKey;
        using PrivateKeyMemory clientPrivate = clientKeys.PrivateKey;

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = material.Registration.IssuerUri!,
            TokenEndpoint = tokenEndpoint
        };
        OAuthClientInfrastructure infrastructure = CreateClientInfrastructure(host, metadata);
        ClientRegistration registration = new()
        {
            ClientId = new ClientId(ClientId),
            AuthorizationServerIssuer = material.Registration.IssuerUri!,
            AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
            Profile = PolicyProfile.Rfc6749WithPkce
        };
        OAuthClient client = new(infrastructure);

        Result<TokenResponse, OAuthParseError> result = await client.IdJag.MintAsync(
            registration,
            new IdJagMintOptions
            {
                Audience = ResourceAsIssuer,
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.IdToken,
                SigningKey = clientPrivate,
                SigningKeyId = MintRedeemSigningKeyId,
                HeaderSerializer = ClientAssertionHeaderSerializer,
                PayloadSerializer = ClientAssertionPayloadSerializer,
                Scope = scope
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, result.Error?.Support.Summary);
        Assert.AreEqual("N_A", result.Value.TokenType);
        Assert.IsFalse(string.IsNullOrEmpty(result.Value.AccessToken), "The mint must issue a grant.");
        Assert.HasCount(1, receivedFields);
        Assert.AreSequenceEqual(
            [
                "audience",
                "client_assertion",
                "client_assertion_type",
                "client_id",
                "grant_type",
                "requested_token_type",
                "subject_token",
                "subject_token_type"
            ],
            receivedFields[0].Keys.Order(StringComparer.Ordinal).ToArray());
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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        tokenType == TokenType.Saml2 && string.Equals(token, registration.ClientId, StringComparison.Ordinal)
                            ? new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId }
                            : null);

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken
                        });
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        //The Refresh Token minted in leg A, captured so leg B's validation can accept it.
        string? mintedRefreshToken = null;

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
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

            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

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
        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)redeemResponse.StatusCode, redeemBody);
        using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, redeemDoc.RootElement.GetProperty("token_type").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> at the
    /// redemption boundary, first composition case: the minted ID-JAG already carries an <c>act</c>
    /// chain whose current actor IS the client that redeems it, so the issued access token carries
    /// that chain unchanged. §4.1 fixes the meaning of the shape — "The outermost 'act' claim
    /// represents the current actor while nested 'act' claims represent prior actors" — and the
    /// current actor did not change at this boundary, so nesting the chain under a copy of itself
    /// would record a delegation hop that never happened.
    /// </summary>
    [TestMethod]
    public async Task RedeemingClientAlreadyTheCurrentActorCopiesTheChainUnchanged()
    {
        //The mint's chain: the redeeming client acting, with a prior actor already beneath it.
        Dictionary<string, object> mintedChain = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = ClientId,
            [WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = PriorActorIdentity
            }
        };

        ActorFlowOutcome outcome = await RunActorFlowAsync(
            SubjectIdentity, mintedChain, authorizedActor: null).ConfigureAwait(false);

        //The JAG carries the chain the mint threaded (ID-JAG §3.1 act, RFC 8693 §4.1 shape).
        using JsonDocument jagPayload = DecodePayload(outcome.Jag);
        JsonElement jagAct = jagPayload.RootElement.GetProperty("act");
        Assert.AreEqual(JsonValueKind.Object, jagAct.ValueKind, "RFC 8693 §4.1: the act claim value is a JSON object.");
        Assert.AreEqual(ClientId, jagAct.GetProperty("sub").GetString());
        Assert.AreEqual(PriorActorIdentity, jagAct.GetProperty("act").GetProperty("sub").GetString());

        Assert.AreEqual(200, outcome.RedeemStatusCode, outcome.RedeemBody);
        using JsonDocument tokenPayload = DecodePayload(outcome.AccessToken!);
        Assert.AreEqual(SubjectIdentity, tokenPayload.RootElement.GetProperty("sub").GetString(),
            "RFC 8693 §1.1 delegation: the token's subject stays the principal, never the acting client.");

        JsonElement tokenAct = tokenPayload.RootElement.GetProperty("act");
        Assert.AreEqual(ClientId, tokenAct.GetProperty("sub").GetString(),
            "The current actor is unchanged at this boundary, so it stays the outermost act.");
        JsonElement nested = tokenAct.GetProperty("act");
        Assert.AreEqual(PriorActorIdentity, nested.GetProperty("sub").GetString(),
            "The prior actor stays exactly one level deeper — the chain crossed verbatim.");
        Assert.IsFalse(nested.TryGetProperty("act", out _),
            "No self-nesting: a boundary that changes no actor must add no nesting level.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> at the
    /// redemption boundary, second composition case: the grant's chain names someone else as the
    /// current actor, so the redeeming client becomes the new outermost actor and the grant's chain
    /// nests beneath it — "A chain of delegation can be expressed by nesting one 'act' claim within
    /// another ... The least recent actor is the most deeply nested."
    /// </summary>
    [TestMethod]
    public async Task RedeemingClientDifferingFromTheCurrentActorNestsTheGrantsChain()
    {
        Dictionary<string, object> mintedChain = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = PriorActorIdentity
        };

        ActorFlowOutcome outcome = await RunActorFlowAsync(
            SubjectIdentity, mintedChain, authorizedActor: null).ConfigureAwait(false);

        using JsonDocument jagPayload = DecodePayload(outcome.Jag);
        JsonElement jagAct = jagPayload.RootElement.GetProperty("act");
        Assert.AreEqual(PriorActorIdentity, jagAct.GetProperty("sub").GetString());
        Assert.IsFalse(jagAct.TryGetProperty("act", out _), "The minted chain is a single link.");

        Assert.AreEqual(200, outcome.RedeemStatusCode, outcome.RedeemBody);
        using JsonDocument tokenPayload = DecodePayload(outcome.AccessToken!);
        JsonElement tokenAct = tokenPayload.RootElement.GetProperty("act");
        Assert.AreEqual(ClientId, tokenAct.GetProperty("sub").GetString(),
            "The redeeming client is the new current actor and is therefore the outermost act.");
        Assert.AreEqual(PriorActorIdentity, tokenAct.GetProperty("act").GetProperty("sub").GetString(),
            "The grant's chain becomes the prior actors nested beneath the new current actor.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> at the
    /// redemption boundary, third composition case: the grant records no actor and the redeeming
    /// client is not the grant's subject, so the single delegation step that just occurred is
    /// recorded — <c>act</c> = <c>{ "sub": &lt;redeeming client&gt; }</c>, the shape §4.1 Figure 5
    /// shows. The token's <c>sub</c> stays the subject, which is what
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">§1.1</see> calls delegation
    /// ("principal A still has its own identity separate from B") rather than impersonation.
    /// </summary>
    [TestMethod]
    public async Task RedeemingClientActingForAnotherSubjectIsRecordedAsTheActor()
    {
        ActorFlowOutcome outcome = await RunActorFlowAsync(
            SubjectIdentity, actor: null, authorizedActor: null).ConfigureAwait(false);

        //The grant itself records no delegation — nothing had happened yet when it was minted.
        using JsonDocument jagPayload = DecodePayload(outcome.Jag);
        Assert.IsFalse(jagPayload.RootElement.TryGetProperty("act", out _),
            "A grant minted with no acting party carries no act claim.");

        Assert.AreEqual(200, outcome.RedeemStatusCode, outcome.RedeemBody);
        using JsonDocument tokenPayload = DecodePayload(outcome.AccessToken!);
        Assert.AreEqual(SubjectIdentity, tokenPayload.RootElement.GetProperty("sub").GetString(),
            "RFC 8693 §1.1: delegation keeps sub the subject; overwriting it with the client would be impersonation.");

        JsonElement tokenAct = tokenPayload.RootElement.GetProperty("act");
        Assert.AreEqual(JsonValueKind.Object, tokenAct.ValueKind);
        Assert.AreEqual(ClientId, tokenAct.GetProperty("sub").GetString(),
            "RFC 8693 §4.1: act identifies the acting party to whom authority has been delegated.");
        Assert.IsFalse(tokenAct.TryGetProperty("act", out _),
            "One hop happened, so the chain has exactly one link.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> at the
    /// redemption boundary, fourth composition case — and the declined half of the §1.1 capability:
    /// the grant records no actor and the redeeming client IS the grant's subject, so no party acts
    /// for another and neither the grant nor the redeemed token carries an <c>act</c> byte on the
    /// wire. <see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">§1.1</see>: "When a
    /// principal is acting directly on its own behalf, for example, neither delegation nor
    /// impersonation are in play" — a self-referential actor would assert a delegation that never
    /// occurred.
    /// </summary>
    [TestMethod]
    public async Task ClientActingOnItsOwnBehalfCarriesNoActClaimAnywhere()
    {
        //The grant's subject is the redeeming client itself — a client_credentials-shaped identity.
        ActorFlowOutcome outcome = await RunActorFlowAsync(
            ClientId, actor: null, authorizedActor: null).ConfigureAwait(false);

        using JsonDocument jagPayload = DecodePayload(outcome.Jag);
        Assert.IsFalse(jagPayload.RootElement.TryGetProperty("act", out _),
            "No actor was supplied, so the minted grant carries no act claim byte.");
        Assert.IsFalse(jagPayload.RootElement.TryGetProperty("may_act", out _),
            "No authorized actor was supplied, so the minted grant carries no may_act claim byte.");

        Assert.AreEqual(200, outcome.RedeemStatusCode, outcome.RedeemBody);
        using JsonDocument tokenPayload = DecodePayload(outcome.AccessToken!);
        Assert.AreEqual(ClientId, tokenPayload.RootElement.GetProperty("sub").GetString());
        Assert.IsFalse(tokenPayload.RootElement.TryGetProperty("act", out _),
            "RFC 8693 §1.1: acting directly on one's own behalf is neither delegation nor impersonation, so no act is emitted.");

        //The resource server reads the same absence through the typed surface.
        JwsAccessTokenValidationResult resourceValidation = outcome.ResourceValidation!;
        Assert.IsTrue(resourceValidation.IsSuccess, resourceValidation.FailureDescription);
        Assert.IsNull(resourceValidation.Claims!.Act,
            "A token recording no delegation surfaces no current actor.");
    }


    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>
    /// Figure 6 nesting known-answer test, composed by the real mint and redeem endpoints and read
    /// back through the resource-server validator. Figure 6's own narrative is this exact flow —
    /// "service16 receiving a token in a call from service77 and exchanging it for a token suitable
    /// to call service26 while the authorization server notes the situation in the newly issued
    /// token" — so a grant carrying <c>act = { "sub": service77 }</c>, redeemed by service16, must
    /// yield Figure 6's structure byte for byte: <c>act.sub</c> = service16 and
    /// <c>act.act.sub</c> = service77, "The least recent actor is the most deeply nested."
    /// </summary>
    /// <remarks>
    /// Only the <c>act</c> object is the transcribed vector: Figure 6's <c>iss</c>/<c>aud</c>/
    /// <c>exp</c>/<c>nbf</c> belong to that document's own example authorization server, while this
    /// token is minted by the test host and must verify against the test host's trust anchor.
    /// </remarks>
    [TestMethod]
    public async Task NestedActorChainMatchesTheSection41FigureSixStructure()
    {
        Dictionary<string, object> priorActorChain = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = Figure6PriorActor
        };

        ActorFlowOutcome outcome = await RunActorFlowAsync(
            Figure6Subject, priorActorChain, authorizedActor: null, clientId: Figure6CurrentActor)
            .ConfigureAwait(false);

        Assert.AreEqual(200, outcome.RedeemStatusCode, outcome.RedeemBody);
        using JsonDocument tokenPayload = DecodePayload(outcome.AccessToken!);
        JsonElement root = tokenPayload.RootElement;
        Assert.AreEqual(Figure6Subject, root.GetProperty("sub").GetString());

        JsonElement act = root.GetProperty("act");
        Assert.AreEqual(JsonValueKind.Object, act.ValueKind);
        Assert.AreEqual(Figure6CurrentActor, act.GetProperty("sub").GetString(),
            "Figure 6: the outermost act names service16, the current actor.");
        JsonElement nested = act.GetProperty("act");
        Assert.AreEqual(JsonValueKind.Object, nested.ValueKind);
        Assert.AreEqual(Figure6PriorActor, nested.GetProperty("sub").GetString(),
            "Figure 6: the nested act names service77, the least recent actor and therefore the most deeply nested.");
        Assert.IsFalse(nested.TryGetProperty("act", out _), "Figure 6 nests exactly two levels.");

        //The resource server reads the same structure as a current actor plus its history.
        JwsAccessTokenValidationResult resourceValidation = outcome.ResourceValidation!;
        Assert.IsTrue(resourceValidation.IsSuccess, resourceValidation.FailureDescription);
        CurrentActor currentActor = resourceValidation.Claims!.Act!;
        Assert.AreEqual(Figure6CurrentActor, currentActor.Subject);
        Assert.HasCount(1, currentActor.DelegationHistory);
        Assert.AreEqual(Figure6PriorActor, currentActor.DelegationHistory[0].Subject);
    }


    /// <summary>
    /// The exercised half of the <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC
    /// 8693 §4.4</see> capability: the authorization seam names an authorized actor, the mint emits
    /// it as the grant's <c>may_act</c> claim on the wire, and the client that claim names redeems
    /// the grant successfully — §4.4's own purpose, the claim "can be used by the authorization
    /// server to determine whether the client ... is authorized to engage in the requested
    /// delegation or impersonation."
    /// </summary>
    [TestMethod]
    public async Task MintedMayActPermitsTheAuthorizedActorToRedeem()
    {
        Dictionary<string, object> authorizedActor = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = ClientId
        };

        ActorFlowOutcome outcome = await RunActorFlowAsync(
            SubjectIdentity, actor: null, authorizedActor).ConfigureAwait(false);

        //Capability exercised: the claim is on the grant's wire bytes as a JSON object.
        using JsonDocument jagPayload = DecodePayload(outcome.Jag);
        JsonElement mayAct = jagPayload.RootElement.GetProperty("may_act");
        Assert.AreEqual(JsonValueKind.Object, mayAct.ValueKind,
            "RFC 8693 §4.4: the may_act claim value is a JSON object.");
        Assert.AreEqual(ClientId, mayAct.GetProperty("sub").GetString());

        Assert.AreEqual(200, outcome.RedeemStatusCode, outcome.RedeemBody);
        using JsonDocument tokenPayload = DecodePayload(outcome.AccessToken!);
        Assert.AreEqual(ClientId, tokenPayload.RootElement.GetProperty("act").GetProperty("sub").GetString(),
            "The authorized party became the actor, which is exactly what may_act pre-authorized.");
    }


    /// <summary>
    /// The enforced half of <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693
    /// §4.4</see>: a grant whose <c>may_act</c> names a different party is refused when another
    /// client redeems it. §4.4's members "identify the party that is asserted as being eligible to
    /// act for the party identified by the JWT containing the claim", so a client that is not that
    /// party may not become the actor; the redemption answers the jwt-bearer grant's
    /// <c>invalid_grant</c> with the <c>Cache-Control: no-store</c> the token endpoint's refusal
    /// ladder carries, and no token is issued.
    /// </summary>
    [TestMethod]
    public async Task MintedMayActRefusesAnUnauthorizedActor()
    {
        Dictionary<string, object> authorizedActor = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = UnauthorizedActorIdentity
        };

        ActorFlowOutcome outcome = await RunActorFlowAsync(
            SubjectIdentity, actor: null, authorizedActor).ConfigureAwait(false);

        using JsonDocument jagPayload = DecodePayload(outcome.Jag);
        Assert.AreEqual(UnauthorizedActorIdentity,
            jagPayload.RootElement.GetProperty("may_act").GetProperty("sub").GetString(),
            "The grant authorizes a party that is not the client redeeming it.");

        Assert.AreEqual(400, outcome.RedeemStatusCode, outcome.RedeemBody);
        Assert.Contains(OAuthErrors.InvalidGrant, outcome.RedeemBody);
        Assert.IsTrue(outcome.IsRedeemNoStore, "A refused redemption keeps the endpoint's no-store response discipline.");
        Assert.IsNull(outcome.AccessToken, "No token may be issued to a party the grant never authorized to act.");
    }


    /// <summary>
    /// The declined half of the <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC
    /// 8693 §4.4</see> capability: the authorization seam names no authorized actor, so the minted
    /// grant carries no <c>may_act</c> byte and the redemption is unconstrained by an
    /// authorized-actor statement — §4.4 states who MAY act only when the claim is present, and an
    /// absent claim asserts nothing about who may not.
    /// </summary>
    [TestMethod]
    public async Task AbsentMayActLeavesTheRedeemingClientUnconstrained()
    {
        ActorFlowOutcome outcome = await RunActorFlowAsync(
            SubjectIdentity, actor: null, authorizedActor: null).ConfigureAwait(false);

        using JsonDocument jagPayload = DecodePayload(outcome.Jag);
        Assert.IsFalse(jagPayload.RootElement.TryGetProperty("may_act", out _),
            "With no authorized actor decided, the grant carries no may_act claim byte.");

        Assert.AreEqual(200, outcome.RedeemStatusCode, outcome.RedeemBody);
        Assert.IsNotNull(outcome.AccessToken);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: "the
    /// combination of the two claims 'iss' and 'sub' are sometimes necessary to uniquely identify an
    /// authorized actor." A <c>may_act</c> naming both is satisfied only by a client that is that
    /// subject within that issuer's namespace — the Resource Authorization Server's own issuer, the
    /// namespace a redeeming <c>client_id</c> lives in. The matching combination redeems; the same
    /// subject asserted under a different issuer is a different, unauthorized party and is refused.
    /// </summary>
    [TestMethod]
    public async Task MayActIssuerAndSubjectCombinationIsEnforcedTogether()
    {
        ActorFlowOutcome matching = await RunActorFlowAsync(
            SubjectIdentity,
            actor: null,
            authorizedActor: null,
            authorizedActorFactory: issuer => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = ClientId,
                [WellKnownJwtClaimNames.Iss] = issuer
            }).ConfigureAwait(false);

        Assert.AreEqual(200, matching.RedeemStatusCode, matching.RedeemBody);

        ActorFlowOutcome wrongIssuer = await RunActorFlowAsync(
            SubjectIdentity,
            actor: null,
            authorizedActor: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = ClientId,
                [WellKnownJwtClaimNames.Iss] = "https://issuer.example/elsewhere"
            }).ConfigureAwait(false);

        Assert.AreEqual(400, wrongIssuer.RedeemStatusCode, wrongIssuer.RedeemBody);
        Assert.Contains(OAuthErrors.InvalidGrant, wrongIssuer.RedeemBody);
    }


    /// <summary>
    /// A malformed <c>act</c> claim on the grant fails the redemption closed. The claim value is not
    /// the JSON object <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693
    /// §4.1</see> defines ("The 'act' claim value is a JSON object, and members in the JSON object
    /// are claims that identify the actor"), so no current actor can be identified — and admitting
    /// the grant with the unreadable chain dropped would present a delegated grant as an
    /// undelegated one.
    /// </summary>
    [TestMethod]
    public async Task GrantWithAMalformedActClaimIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        //A grant built outside the mint so its act claim can be a value RFC 8693 §4.1 does not allow.
        //It is signed with the host's own published key so the redeem path fails on the claim shape
        //rather than on key resolution.
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;
        string malformedJag = await BuildIdJagWithActorClaimsAsync(
            material.SigningPrivateKey,
            material.SigningKeyId.Value,
            idpIssuer,
            actor: "not-an-actor-object",
            authorizedActor: null).ConfigureAwait(false);

        using HttpResponseMessage redeem = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, BuildRedeemForm(malformedJag), TestContext.CancellationToken).ConfigureAwait(false);
        string body = await redeem.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)redeem.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
    }


    /// <summary>
    /// The minted ID-JAG's <c>act</c> and <c>may_act</c> claims and the compact-JWS artefacts a test
    /// asserts against: the grant, the redemption's HTTP outcome, and — when the redemption
    /// succeeded — the issued access token plus the resource server's validation of it.
    /// </summary>
    private sealed record ActorFlowOutcome
    {
        /// <summary>The minted ID-JAG as a compact JWS.</summary>
        public required string Jag { get; init; }

        /// <summary>The redemption response's HTTP status code.</summary>
        public required int RedeemStatusCode { get; init; }

        /// <summary>The redemption response body, carried for assertion messages and error-code checks.</summary>
        public required string RedeemBody { get; init; }

        /// <summary>Whether the redemption response carried <c>Cache-Control: no-store</c>.</summary>
        public required bool IsRedeemNoStore { get; init; }

        /// <summary>The redeemed access token, or <see langword="null"/> when the redemption was refused.</summary>
        public string? AccessToken { get; init; }

        /// <summary>
        /// The resource-server validation of <see cref="AccessToken"/> through the project's own
        /// <see cref="JwsAccessTokenValidator"/>, or <see langword="null"/> when no token was issued.
        /// </summary>
        public JwsAccessTokenValidationResult? ResourceValidation { get; init; }
    }


    /// <summary>
    /// Mints an ID-JAG whose <c>act</c>/<c>may_act</c> claims the authorization seam decides, redeems
    /// it as an RFC 7523 JWT Bearer assertion at the same host, and — on success — validates the
    /// issued access token the way a resource server does.
    /// </summary>
    /// <param name="subject">The subject the mint's validation seam surfaces for the subject token.</param>
    /// <param name="actor">The <c>act</c> chain the authorization seam shapes onto the grant, or <see langword="null"/>.</param>
    /// <param name="authorizedActor">The <c>may_act</c> claim the authorization seam shapes onto the grant, or <see langword="null"/>.</param>
    /// <param name="clientId">The client that both mints and redeems, defaulting to the fixture's client.</param>
    /// <param name="authorizedActorFactory">
    /// Builds the <c>may_act</c> claim from the authorization server's own issuer identifier, for the
    /// §4.4 cases whose authorized actor is identified by an <c>iss</c> that is only known once the
    /// host is running. Takes precedence over <paramref name="authorizedActor"/> when supplied.
    /// </param>
    /// <returns>The flow's artefacts.</returns>
    private async Task<ActorFlowOutcome> RunActorFlowAsync(
        string subject,
        IReadOnlyDictionary<string, object>? actor,
        IReadOnlyDictionary<string, object>? authorizedActor,
        string clientId = ClientId,
        Func<string, IReadOnlyDictionary<string, object>>? authorizedActorFactory = null)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            clientId, new Uri(clientId), profile: PolicyProfile.Rfc6749WithPkce, capabilities: IdJagClientCapabilities).ConfigureAwait(false);

        //The issuer identifier is the namespace a may_act iss member names, and it is only settled
        //once the host is listening — so the claim is shaped lazily, when the mint request runs.
        await WireActorMintSeamsAsync(
            app,
            subject,
            actor,
            () => authorizedActorFactory?.Invoke(material.Registration.IssuerUri!.OriginalString) ?? authorizedActor).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;

        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(assertion, registration, jwksResolver, ResourceAsIssuer).ConfigureAwait(false);
        }).ConfigureAwait(false);

        Dictionary<string, string> mintForm = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = ResourceAsIssuer,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        };
        using HttpResponseMessage mintResponse = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, mintForm, TestContext.CancellationToken).ConfigureAwait(false);
        string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        string jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        Dictionary<string, string> redeemForm = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Assertion] = jag
        };
        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, redeemForm, TestContext.CancellationToken).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string? accessToken = null;
        JwsAccessTokenValidationResult? resourceValidation = null;
        if(redeemResponse.StatusCode == System.Net.HttpStatusCode.OK)
        {
            using JsonDocument redeemDoc = JsonDocument.Parse(redeemBody);
            accessToken = redeemDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
            resourceValidation = await VerifyAgainstAsAsync(accessToken, idpIssuer, jwksResolver).ConfigureAwait(false);
        }

        return new ActorFlowOutcome
        {
            Jag = jag,
            RedeemStatusCode = (int)redeemResponse.StatusCode,
            RedeemBody = redeemBody,
            IsRedeemNoStore = redeemResponse.Headers.CacheControl?.NoStore ?? false,
            AccessToken = accessToken,
            ResourceValidation = resourceValidation
        };
    }


    /// <summary>
    /// Wires the mint seams for an actor-bearing exchange: client authentication, a subject-token
    /// validation surfacing <paramref name="subject"/>, and an authorization seam that selects the
    /// id-jag issued type and shapes the grant's <c>act</c> and <c>may_act</c> claims.
    /// </summary>
    /// <param name="app">The host shell.</param>
    /// <param name="subject">The subject the validation seam surfaces.</param>
    /// <param name="actor">The <c>act</c> chain to mint onto the grant, or <see langword="null"/>.</param>
    /// <param name="authorizedActor">
    /// Supplies the <c>may_act</c> claim when the exchange runs — evaluated then rather than at
    /// wiring time because an authorized actor may be identified by the authorization server's own
    /// issuer, which is settled only once the host is listening.
    /// </param>
    private static async Task WireActorMintSeamsAsync(
        TestHostShell app,
        string subject,
        IReadOnlyDictionary<string, object>? actor,
        Func<IReadOnlyDictionary<string, object>?> authorizedActor)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(new ValidatedSecurityToken { Subject = subject });


            candidateIntegration.AuthorizeTokenExchangeAsync =
                (validatedSubject, validatedActor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = validatedSubject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.IdJag,
                            Actor = actor,
                            AuthorizedActor = authorizedActor()
                        });
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs an ID-JAG whose <c>act</c>/<c>may_act</c> claim values are set directly, bypassing the
    /// mint so a value <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 Section 4.1</see>
    /// / <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">Section 4.4</see> does not define can
    /// reach the redeem path as wire bytes; the
    /// claims builder <see cref="BuildIdJagWithClaimsAsync"/> signs it.
    /// </summary>
    /// <param name="signingKey">The IdP signing key.</param>
    /// <param name="keyId">The <c>kid</c> the Resource Authorization Server resolves the key by.</param>
    /// <param name="issuer">The IdP issuer identifier.</param>
    /// <param name="actor">The raw <c>act</c> claim value, or <see langword="null"/> to omit it.</param>
    /// <param name="authorizedActor">The raw <c>may_act</c> claim value, or <see langword="null"/> to omit it.</param>
    /// <returns>The compact JWS.</returns>
    private Task<string> BuildIdJagWithActorClaimsAsync(
        PrivateKeyMemory signingKey,
        string keyId,
        string issuer,
        object? actor,
        object? authorizedActor)
    {
        Dictionary<string, object> claims = new(StringComparer.Ordinal);
        if(actor is not null)
        {
            claims[WellKnownJwtClaimNames.Act] = actor;
        }

        if(authorizedActor is not null)
        {
            claims[WellKnownJwtClaimNames.MayAct] = authorizedActor;
        }

        return BuildIdJagWithClaimsAsync(signingKey, keyId, issuer, claims);
    }


    /// <summary>
    /// Signs an ID-JAG outside the mint, under the host's published signing key, so a claim value the
    /// mint never produces reaches the redeem path as wire bytes. The grant carries the claims every
    /// redeem requires (<c>iss</c>, <c>sub</c>, <c>aud</c>, <c>client_id</c>, a fresh <c>jti</c>,
    /// <c>iat</c>, <c>exp</c> and <c>scope</c>), and each entry of <paramref name="claims"/> is added or
    /// replaces the claim of its name: <c>sub</c>, <c>sub_id</c>, <c>tenant</c>, <c>resource</c>,
    /// <c>act</c> or <c>may_act</c>.
    /// </summary>
    /// <param name="signingKey">The IdP signing key.</param>
    /// <param name="keyId">The <c>kid</c> the Resource Authorization Server resolves the signing key by.</param>
    /// <param name="issuer">The IdP issuer identifier.</param>
    /// <param name="claims">The claims to add or replace, by name, with their raw values.</param>
    /// <returns>The compact JWS.</returns>
    private async Task<string> BuildIdJagWithClaimsAsync(
        PrivateKeyMemory signingKey,
        string keyId,
        string issuer,
        IReadOnlyDictionary<string, object> claims)
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeader.ForSigning(algorithm, "oauth-id-jag+jwt", keyId);
        JwtPayload payload = new(capacity: 8 + claims.Count)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Sub] = SubjectIdentity,
            [WellKnownJwtClaimNames.Aud] = ResourceAsIssuer,
            [WellKnownJwtClaimNames.ClientId] = ClientId,
            [WellKnownJwtClaimNames.Jti] = $"claims-jag-{Guid.NewGuid():N}",
            [WellKnownJwtClaimNames.Iat] = now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddMinutes(5).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Scope] = WellKnownScopes.OpenId
        };

        foreach(KeyValuePair<string, object> claim in claims)
        {
            payload[claim.Key] = claim.Value;
        }

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


    /// <summary>
    /// Builds a valid ID-JAG assertion whose <c>typ</c> header carries exactly the given spelling,
    /// signed by the IdP's own signing key so it verifies against the host's published JWKS. Used to
    /// prove the redeem path accepts every RFC 7515 §4.1.9-equivalent spelling of the ID-JAG typ.
    /// </summary>
    private async Task<string> BuildIdJagWithTypAsync(PrivateKeyMemory signingKey, string keyId, string issuer, string typ)
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeader.ForSigning(algorithm, typ, keyId);
        JwtPayload payload = new(capacity: 7)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Sub] = SubjectIdentity,
            [WellKnownJwtClaimNames.Aud] = ResourceAsIssuer,
            [WellKnownJwtClaimNames.ClientId] = ClientId,
            [WellKnownJwtClaimNames.Jti] = $"typ-spelling-jag-{Guid.NewGuid():N}",
            [WellKnownJwtClaimNames.Iat] = now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddMinutes(5).ToUnixTimeSeconds()
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


    /// <summary>
    /// Posts a Token Exchange that uses a SAML 2.0 Assertion as the <c>subject_token</c> requesting a
    /// Refresh Token (<c>requested_token_type</c> = the refresh_token URN), per §4.5.
    /// </summary>
    private Task<HttpResponseMessage> PostSamlToRefreshTokenAsync(HttpClient http, Uri tokenUrl, string subjectToken) =>
        OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.RefreshToken),
            [OAuthRequestParameterNames.SubjectToken] = subjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.Saml2)
        }, TestContext.CancellationToken);


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


    /// <summary>
    /// Mints a key-bound ID-JAG by posting a DPoP proof for <paramref name="dpopKey"/>. RFC 9449
    /// §8's single server nonce policy always challenges the first, nonce-less proof; the retry
    /// carrying the echoed nonce then succeeds.
    /// </summary>
    private async Task<string> MintBoundJagAsync(
        HttpClient http, Uri tokenUrl, DpopKey dpopKey, string segment, VerifierKeyMaterial material)
    {
        (HttpResponseMessage mintResponse, string mintBody) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
            http, tokenUrl, BuildMintForm(ResourceAsIssuer),
            nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
            TestContext.CancellationToken).ConfigureAwait(false);
        using(mintResponse)
        {
            Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
            using JsonDocument mintDoc = JsonDocument.Parse(mintBody);

            return mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        }
    }


    /// <summary>
    /// Builds a token-endpoint DPoP proof (<c>htm=POST</c>, <c>htu=</c> the issuer-authority + token
    /// path the server validates against per RFC 9449 §4.2) for the given key.
    /// </summary>
    private async Task<string> BuildTokenEndpointDpopProofAsync(
        DpopKey dpopKey, string segment, VerifierKeyMaterial material, string? nonce = null)
    {
        string htu = $"{material.Registration.IssuerUri!.GetLeftPart(UriPartial.Authority)}/connect/{segment}/token";
        DpopProofClaims claims = new()
        {
            Htm = HttpMethod.Post.Method,
            Htu = htu,
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Nonce = nonce
        };

        return await DpopProofConstruction.BuildAsync(
            claims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a token-endpoint DPoP proof with the given <paramref name="typ"/> spelling instead of
    /// the canonical short form <see cref="DpopProofConstruction.BuildAsync"/> always uses, to prove
    /// the validator accepts an RFC 7515 §4.1.9-equivalent spelling of the DPoP proof type.
    /// </summary>
    private async Task<string> BuildTokenEndpointDpopProofAsync(
        DpopKey dpopKey, string segment, VerifierKeyMaterial material, string typ, string? nonce = null)
    {
        string htu = $"{material.Registration.IssuerUri!.GetLeftPart(UriPartial.Authority)}/connect/{segment}/token";
        DpopProofClaims claims = new()
        {
            Htm = HttpMethod.Post.Method,
            Htu = htu,
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Nonce = nonce
        };

        DpopProofHeader header = new()
        {
            Typ = typ,
            Alg = dpopKey.Alg,
            Jwk = DpopJwkUtilities.ToJwk(dpopKey.Material.PublicKey, dpopKey.Alg, TestHostShell.Base64UrlEncoder)
        };

        IReadOnlyDictionary<string, object> headerDict = DpopTestSupport.Serializer.SerializeHeader(header);
        IReadOnlyDictionary<string, object> payloadDict = DpopTestSupport.Serializer.SerializePayload(claims);

        using JwsMessage message = await Jws.SignAsync(
            headerDict,
            payloadDict,
            DpopTestSupport.Serializer.EncodePart,
            TestHostShell.Base64UrlEncoder,
            dpopKey.Material.PrivateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            TestHostShell.MemoryPool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(message, TestHostShell.Base64UrlEncoder);
    }


    private async Task<HttpResponseMessage> PostFormWithDpopAsync(
        HttpClient http, Uri url, Dictionary<string, string> fields, string? dpopProof)
    {
        using FormUrlEncodedContent content = new(fields);
        using HttpRequestMessage request = new(HttpMethod.Post, url) { Content = content };
        if(dpopProof is not null)
        {
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, dpopProof);
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


    /// <summary>
    /// The <c>kid</c> the client-composed mint/redeem tests sign their <c>private_key_jwt</c>
    /// client assertion under, resolved by the published <see cref="BuildClientAssertionJwksJson"/>
    /// document.
    /// </summary>
    private const string MintRedeemSigningKeyId = "id-jag-client-key-1";


    /// <summary>
    /// Starts <paramref name="app"/>'s "default" host, realigns <paramref name="material"/>'s
    /// registration to the listening address, mints a fresh client signing key, publishes it as the
    /// registration's <c>private_key_jwt</c> JWKS, and wires
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// as the client-credentials validator — the authentication method
    /// <see cref="IdJagFlowHandlers"/> always signs, regardless of <see cref="ClientRegistration.AuthenticationMethod"/>.
    /// When <paramref name="receivedFields"/> is supplied, the installed validator appends the form
    /// fields of every request it receives to that list and then delegates to the
    /// <c>private_key_jwt</c> validator.
    /// </summary>
    /// <param name="app">The host shell to start.</param>
    /// <param name="material">The registered client whose token-endpoint authentication method is declared.</param>
    /// <param name="receivedFields">The list that collects the form fields the token endpoint received, or <see langword="null"/> to collect nothing.</param>
    /// <returns>
    /// The started host, its resolved token endpoint, and the fresh client signing key (owned by
    /// the caller).
    /// </returns>
    private async Task<(HostedAuthorizationServer Host, Uri TokenEndpoint, PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ClientKeys)>
        StartHostAndWirePrivateKeyJwtClientAuthenticationAsync(
            TestHostShell app, VerifierKeyMaterial material, List<RequestFields>? receivedFields = null)
    {
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenEndpoint = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(clientKeys.PublicKey, algorithm, TestSetup.Base64UrlEncoder);
        string jwksJson = BuildClientAssertionJwksJson(jwk, MintRedeemSigningKeyId);

        ValidateClientCredentialsDelegate privateKeyJwtValidator =
            PrivateKeyJwtClientAuthentication.BuildValidator(additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = receivedFields is null
                ? privateKeyJwtValidator
                : (request, fields, registration, context, ct) =>
                {
                    receivedFields.Add(fields);

                    return privateKeyJwtValidator(request, fields, registration, context, ct);
                };
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
            candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [algorithm];
        }).ConfigureAwait(false);
        _ = await app.SetTokenEndpointAuthMethodAsync(
            material, ClientAuthenticationMethod.PrivateKeyJwt, jwksJson,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return (host, tokenEndpoint, clientKeys);
    }


    /// <summary>
    /// Composes the client infrastructure the client-composed mint and redeem tests share: form posts
    /// travel over <paramref name="host"/>'s shared HTTP client to the token endpoint that
    /// <paramref name="metadata"/> names, and every other seam is the plain test wiring.
    /// </summary>
    /// <param name="host">The started authorization server host whose HTTP client carries the form posts.</param>
    /// <param name="metadata">The authorization server metadata every resolution answers with.</param>
    /// <param name="onFormPost">Invoked with the form fields of each post before it is sent, or <see langword="null"/> to observe nothing.</param>
    /// <param name="dpopKey">The DPoP key the proofs are signed with, or <see langword="null"/> to wire no DPoP.</param>
    /// <param name="nonceCache">The DPoP nonce cache used together with <paramref name="dpopKey"/>, or <see langword="null"/> to wire no DPoP.</param>
    /// <returns>The composed client infrastructure.</returns>
    private OAuthClientInfrastructure CreateClientInfrastructure(
        HostedAuthorizationServer host,
        AuthorizationServerMetadata metadata,
        Action<IReadOnlyCollection<KeyValuePair<string, string>>>? onFormPost = null,
        DpopKey? dpopKey = null,
        InMemoryDpopNonceCache? nonceCache = null)
    {
        bool isDpopWired = dpopKey is not null && nonceCache is not null;

        return OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
            {
                onFormPost?.Invoke(fields);

                return HttpClientTransport.SendFormPostAsync(host.SharedHttpClient!, endpoint, fields, headers, ct);
            },
            saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("This test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (_, _, _) =>
                ValueTask.FromResult(new AuthorizationServerMetadataResolution
                {
                    Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                    Metadata = metadata
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: TestEntropy.NewCounterStream(),
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared),
            outboundFetchPolicy: TestHostShell.LoopbackOutboundFetchPolicy,
            constructDpopProofAsync: isDpopWired
                ? (claims, key, ct) => DpopProofConstruction.BuildAsync(
                    claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, BaseMemoryPool.Shared, ct)
                : null,
            dpopKey: dpopKey,
            lookupDpopNonce: isDpopWired ? nonceCache!.Lookup : null,
            storeDpopNonce: isDpopWired ? nonceCache!.Store : null);
    }


    /// <summary>
    /// Builds a JWKS JSON document publishing one key under <paramref name="kid"/>, the shape
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// resolves the client's signing key from.
    /// </summary>
    private static string BuildClientAssertionJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        string members = string.Concat(jwk.Select(static member => $"\"{member.Key}\":\"{member.Value}\","));

        return $"{{\"{WellKnownJwkMemberNames.Keys}\":[{{{members}\"{WellKnownJwkMemberNames.Kid}\":\"{kid}\"}}]}}";
    }


    /// <summary>The capability set an ID-JAG client needs: token-exchange + jwt-bearer + id-jag, plus discovery/jwks.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> IdJagClientCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthTokenExchange,
            WellKnownCapabilityIdentifiers.OAuthJwtBearer,
            WellKnownCapabilityIdentifiers.OAuthIdJag,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    private static async Task<VerifierKeyMaterial> RegisterIdJagClientAsync(TestHostShell app) =>
        await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: IdJagClientCapabilities).ConfigureAwait(false);


    /// <summary>
    /// Installs the client-credential validator used by the assertion grant cases.
    /// </summary>
    private static async Task WireClientAuthenticationAsync(TestHostShell app) =>
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue("client_secret", out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);


    /// <summary>
    /// Installs on the editable candidate an authorization operation that selects the id-jag issued type
    /// for the validated subject with the given granted scope and, when supplied, the resource
    /// <c>client_id</c>, the <c>sub_id</c> identifier, the issuer <c>tenant</c>, the granted
    /// <c>resource</c> entries, the <c>aud_tenant</c> and the <c>aud_sub</c>.
    /// </summary>
    /// <param name="candidateIntegration">The editable candidate the operation is installed on.</param>
    /// <param name="grantedScope">The scope the grant carries.</param>
    /// <param name="resourceClientId">The <c>client_id</c> at the Resource Authorization Server, or <see langword="null"/> for the requesting client.</param>
    /// <param name="subjectIdentifier">The <c>sub_id</c> identifier the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="tenant">The issuer <c>tenant</c> the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="resource">The granted <c>resource</c> entries, or <see langword="null"/> for none.</param>
    /// <param name="audienceTenant">The <c>aud_tenant</c> the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="audienceSubject">The <c>aud_sub</c> the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="authorizedSubject">
    /// The subject the authorization names, or <see langword="null"/> for the validated subject token's subject.
    /// </param>
    private static void WireIdJagAuthorization(
        AuthorizationServerIntegration candidateIntegration,
        string grantedScope,
        string? resourceClientId,
        SubjectIdentifier? subjectIdentifier = null,
        string? tenant = null,
        IReadOnlyList<string>? resource = null,
        string? audienceTenant = null,
        string? audienceSubject = null,
        string? authorizedSubject = null)
    {
        candidateIntegration.AuthorizeTokenExchangeAsync =
            (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = authorizedSubject ?? subject.Subject,
                        Scope = grantedScope,
                        IssuedTokenType = TokenType.IdJag,
                        ResourceClientId = resourceClientId,
                        SubjectIdentifier = subjectIdentifier,
                        Tenant = tenant,
                        AudienceTenant = audienceTenant,
                        AudienceSubject = audienceSubject,
                        Resource = resource ?? []
                    });
    }


    /// <summary>
    /// Wires the three mint seams: client authentication, a subject-token validation that accepts the
    /// fixture's Identity Assertion and surfaces its subject, and an authorization seam that selects the
    /// id-jag issued type with the given granted scope, (optional) resource client_id, (optional)
    /// <c>sub_id</c> identifier, (optional) issuer <c>tenant</c>, (optional) <c>aud_tenant</c> and (optional)
    /// <c>aud_sub</c>.
    /// </summary>
    /// <param name="app">The host shell whose server is wired.</param>
    /// <param name="grantedScope">The scope the grant carries.</param>
    /// <param name="resourceClientId">The <c>client_id</c> at the Resource Authorization Server, or <see langword="null"/> for the requesting client.</param>
    /// <param name="subjectIdentifier">The <c>sub_id</c> identifier the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="tenant">The issuer <c>tenant</c> the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="audienceTenant">The <c>aud_tenant</c> the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="audienceSubject">The <c>aud_sub</c> the grant carries, or <see langword="null"/> for none.</param>
    /// <param name="authorizedSubject">
    /// The subject the authorization names, or <see langword="null"/> for the validated subject token's subject.
    /// </param>
    private static async Task WireMintSeamsAsync(
        TestHostShell app,
        string grantedScope,
        string? resourceClientId,
        SubjectIdentifier? subjectIdentifier = null,
        string? tenant = null,
        string? audienceTenant = null,
        string? audienceSubject = null,
        string? authorizedSubject = null)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);


        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity });
            WireIdJagAuthorization(
                candidateIntegration,
                grantedScope,
                resourceClientId,
                subjectIdentifier,
                tenant,
                audienceTenant: audienceTenant,
                audienceSubject: audienceSubject,
                authorizedSubject: authorizedSubject);
        }).ConfigureAwait(false);

    }


    /// <summary>
    /// The Resource Authorization Server's <c>ValidateJwtBearerAssertionAsync</c> wiring: verify the
    /// ID-JAG signature against the IdP JWKS (resolved by <c>kid</c>) and apply the §4.4.1 / §9.3 claim
    /// rules via <see cref="IdJagAssertionValidation"/>. Returns <see langword="null"/> (→
    /// <c>invalid_grant</c>) on any failure, mirroring a real RS.
    /// </summary>
    /// <param name="assertion">The compact JWS the redeem request carries.</param>
    /// <param name="registration">The authenticated client's registration.</param>
    /// <param name="resolver">Resolves the IdP's verification key by <c>kid</c>.</param>
    /// <param name="resourceServerIssuer">The Resource Authorization Server's own issuer identifier.</param>
    /// <param name="rule">
    /// The rule applied to the grant's <c>sub_id</c> through
    /// <see cref="IdJagAssertionValidation.ValidateAsync"/>, or <see langword="null"/> to validate through
    /// <see cref="IdJagAssertionValidation.Validate"/>.
    /// </param>
    /// <param name="recorder">Receives the validation result the seam decides on, or <see langword="null"/>.</param>
    private async Task<JwtBearerGrant?> ValidateIdJagAsync(
        string assertion,
        ClientRecord registration,
        ServerVerificationKeyResolverDelegate resolver,
        string resourceServerIssuer,
        IdJagSubjectIdentifierRule? rule = null,
        Action<IdJagAssertionValidationResult>? recorder = null)
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
            new KeyId(kid), KeyUsageContext.IdTokenIssuance, default, [], TestContext.CancellationToken).ConfigureAwait(false);
        if(key is null)
        {
            return null;
        }

        bool signatureValid = await Jws.VerifyAsync(
            assertion, TestSetup.Base64UrlDecoder, Pool, key,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async, TestContext.CancellationToken).ConfigureAwait(false);
        if(!signatureValid)
        {
            return null;
        }

        JwtPayload payload;
        using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
        {
            payload = JwsAccessTokenTestSupport.Parser.ParseClaims(payloadBytes.Memory);
        }

        IdJagAssertionValidationResult result = rule is null
            ? IdJagAssertionValidation.Validate(
                header, payload, resourceServerIssuer, registration.ClientId,
                TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60))
            : await IdJagAssertionValidation.ValidateAsync(
                header, payload, resourceServerIssuer, registration.ClientId,
                TimeProvider.GetUtcNow(), TimeSpan.FromSeconds(60), rule, TestContext.CancellationToken).ConfigureAwait(false);
        recorder?.Invoke(result);
        if(!result.IsValid)
        {
            return null;
        }

        //Model a Resource Authorization Server that grants what the JAG carried: bind the granted
        //resource to the access token audience (RFC 8707), thread the authorization_details through,
        //surface the grant's bound key (cnf.jkt) so the §9.8.1.2 proof-of-possession matrix runs, and
        //surface iss/jti/exp so the jwt-bearer endpoint's JtiReplayGuard applies the §3 replay defense.
        //RFC 8693 §4.1/§4.4: the grant's delegation chain and its authorized-actor statement cross the
        //seam too — a seam that dropped them would lose the chain and leave the redemption
        //unconstrained, which is why this fixture copies both the way a real deployment must.
        return new JwtBearerGrant
        {
            Subject = result.Subject!,
            Scope = result.Scope ?? string.Empty,
            Audience = result.Resource,
            AuthorizationDetailsClaim = result.AuthorizationDetails,
            RequiredKeyThumbprint = result.ConfirmationKeyThumbprint,
            Issuer = result.Issuer,
            Jti = result.Jti,
            Expiration = result.Expiration,
            Act = result.Act,
            MayAct = result.MayAct
        };
    }


    /// <summary>
    /// Redeems one grant that carries a <c>sub_id</c> claim over the loopback listener, the redeem seam
    /// validating it under <paramref name="rule"/>, and returns the wire answer with the result the seam
    /// recorded. The grant is minted by the host's own token exchange, whose authorization seam chooses the
    /// <c>sub_id</c> and the issuer <c>tenant</c>, unless <paramref name="signedClaims"/> is given: then the
    /// claims builder signs a grant carrying those claims under the host's published signing key, for a claim
    /// value the mint never produces.
    /// </summary>
    /// <param name="rule">Builds the redeem's rule from the host's issuer identifier.</param>
    /// <param name="mintedSubjectIdentifier">
    /// Chooses the minted grant's <c>sub_id</c> from the host's issuer identifier, or <see langword="null"/>
    /// for a grant without one.
    /// </param>
    /// <param name="mintedTenant">The minted grant's issuer <c>tenant</c>, or <see langword="null"/> for none.</param>
    /// <param name="signedClaims">
    /// Builds the claims the claims builder adds or replaces from the host's issuer identifier, or
    /// <see langword="null"/> to mint the grant.
    /// </param>
    /// <param name="signingMaterial">
    /// Signing material the host's published JWKS does not hold, or <see langword="null"/>. When given together
    /// with <paramref name="signedClaims"/> the claims builder signs the grant under it and under the
    /// <c>kid</c> <see cref="UnknownSigningKeyId"/>, instead of under the host's published signing material.
    /// </param>
    /// <returns>
    /// The redemption's status code and body, the validation result the seam recorded (<see langword="null"/>
    /// when the seam recorded none), and the host's issuer identifier.
    /// </returns>
    private async Task<(int StatusCode, string Body, IdJagAssertionValidationResult? Recorded, string IdpIssuer)> RedeemSubIdGrantAsync(
        Func<string, IdJagSubjectIdentifierRule> rule,
        Func<string, SubjectIdentifier?>? mintedSubjectIdentifier = null,
        string? mintedTenant = null,
        Func<string, IReadOnlyDictionary<string, object>>? signedClaims = null,
        PrivateKeyMemory? signingMaterial = null)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIdJagClientAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string idpIssuer = material.Registration.IssuerUri!.OriginalString;
        IdJagSubjectIdentifierRule redeemRule = rule(idpIssuer);

        //The issuer identifier is settled once the host is listening, and a minted sub_id can name it, so the
        //mint seams are wired after the start.
        await WireMintSeamsAsync(
            app, WellKnownScopes.OpenId, resourceClientId: null, mintedSubjectIdentifier?.Invoke(idpIssuer), mintedTenant).ConfigureAwait(false);

        IdJagAssertionValidationResult? recorded = null;
        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateJwtBearerAssertionAsync =
                async (assertion, requestedScope, registration, context, ct) =>
                    await ValidateIdJagAsync(
                        assertion, registration, jwksResolver, ResourceAsIssuer, redeemRule, result => recorded = result).ConfigureAwait(false);
        }).ConfigureAwait(false);

        string jag;
        if(signedClaims is null)
        {
            using HttpResponseMessage mintResponse = await PostMintAsync(http, tokenUrl, ResourceAsIssuer).ConfigureAwait(false);
            string mintBody = await mintResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)mintResponse.StatusCode, mintBody);
            using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
            jag = mintDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        }
        else
        {
            jag = await BuildIdJagWithClaimsAsync(
                signingMaterial ?? material.SigningPrivateKey,
                signingMaterial is null ? material.SigningKeyId.Value : UnknownSigningKeyId,
                idpIssuer,
                signedClaims(idpIssuer)).ConfigureAwait(false);
        }

        using HttpResponseMessage redeemResponse = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, BuildRedeemForm(jag), TestContext.CancellationToken).ConfigureAwait(false);
        string redeemBody = await redeemResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)redeemResponse.StatusCode, redeemBody, recorded, idpIssuer);
    }


    /// <summary>
    /// Asserts that a redeem recorded a comparison of the <c>sub_id</c> claim with the given relation,
    /// outcome, basis and decision.
    /// </summary>
    /// <param name="comparison">The record the redeem's result carries.</param>
    /// <param name="relation">The expected relation.</param>
    /// <param name="outcome">The expected outcome.</param>
    /// <param name="basis">The expected basis.</param>
    /// <param name="decision">The expected decision.</param>
    private static void AssertComparison(
        ComparisonRecord<SubjectIdentifier, IdJagSubjectContext>? comparison,
        ComparisonRelation relation,
        ComparisonOutcome outcome,
        ComparisonBasis basis,
        ComparisonDecision decision)
    {
        Assert.IsNotNull(comparison, "The redeem recorded a comparison of the sub_id claim.");
        Assert.AreEqual(relation, comparison.Relation);
        Assert.AreEqual(outcome, comparison.Outcome);
        Assert.AreEqual(basis, comparison.Basis);
        Assert.AreEqual(decision, comparison.Decision);
    }


    /// <summary>
    /// Whether <paramref name="candidate"/> is the <paramref name="configured"/> identifier: the same
    /// format and the same members, each a string equal ordinally, and no other member.
    /// </summary>
    /// <param name="candidate">The identifier the grant carries.</param>
    /// <param name="configured">The identifier the application configured.</param>
    /// <returns><see langword="true"/> when the two are the same identifier.</returns>
    private static bool IsSameIdentifier(SubjectIdentifier candidate, SubjectIdentifier configured) =>
        string.Equals(candidate.Format, configured.Format, StringComparison.Ordinal)
        && candidate.Members.Count == configured.Members.Count
        && configured.Members.All(member =>
            candidate.Members.GetValueOrDefault(member.Key) is string presented
            && member.Value is string expected
            && string.Equals(presented, expected, StringComparison.Ordinal));


    /// <summary>
    /// Whether <paramref name="reference"/> is the fixture's End-User as the host's issuer names it: the
    /// issuer <paramref name="idpIssuer"/>, no tenant, and the subject <see cref="SubjectIdentity"/>.
    /// </summary>
    /// <param name="reference">The grant's validated subject.</param>
    /// <param name="idpIssuer">The host's issuer identifier.</param>
    /// <returns><see langword="true"/> when the reference names the fixture's End-User.</returns>
    private static bool IsGrantSubject(IdJagSubjectContext reference, string idpIssuer) =>
        string.Equals(reference.Issuer, idpIssuer, StringComparison.Ordinal)
        && reference.Tenant is null
        && string.Equals(reference.Subject, SubjectIdentity, StringComparison.Ordinal);


    /// <summary>
    /// The application's association of the configured SAML NameID identifier
    /// (<see cref="ConfiguredSamlIdentifier"/>) with the fixture's End-User under the host's issuer: the
    /// complete configured identifier holds for that End-User, every other SAML NameID identifier fails, and an
    /// identifier of another format is left undecided.
    /// </summary>
    /// <param name="idpIssuer">The host's issuer identifier, the validated issuer the association is configured for.</param>
    /// <returns>The association.</returns>
    private static CompareDelegate<SubjectIdentifier, IdJagSubjectContext> ConfiguredSamlAssociation(string idpIssuer)
    {
        SubjectIdentifier configured = ConfiguredSamlIdentifier.ToSubjectIdentifier();

        return (candidate, reference, relation, cancellationToken) => ValueTask.FromResult(candidate switch
        {
            _ when IsSameIdentifier(candidate, configured) && IsGrantSubject(reference, idpIssuer) => ComparisonOutcome.Holds,
            _ when SubjectIdentifierFormats.IsSamlNameId(candidate.Format) => ComparisonOutcome.Fails,
            _ => ComparisonOutcome.Indeterminate
        });
    }


    /// <summary>
    /// A <c>sub_id</c> claim value that is not a well-formed Subject Identifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>): a JSON string,
    /// a JSON array, an object without <c>format</c>, an <c>iss_sub</c> object with a member its format
    /// does not describe, an <c>aliases</c> object whose one element is an <c>aliases</c> object or whose
    /// <c>identifiers</c> array is empty, or a <c>saml-nameid</c> object without <c>nameid</c>, with a numeric
    /// <c>nameid_format</c> or with a member the format does not describe.
    /// </summary>
    /// <param name="caseName">
    /// The value: <c>aString</c>, <c>anArray</c>, <c>anEmptyObject</c>, <c>anUndescribedMember</c>,
    /// <c>aNestedAliases</c>, <c>anEmptyAliases</c>, <c>aSamlNameIdWithoutNameId</c>,
    /// <c>aSamlNameIdWithANumericFormat</c> or <c>aSamlNameIdWithAnUndescribedMember</c>.
    /// </param>
    /// <param name="idpIssuer">The host's issuer identifier, named by the <c>iss_sub</c> object.</param>
    /// <returns>The raw claim value.</returns>
    private static object MalformedSubId(string caseName, string idpIssuer) => caseName switch
    {
        "aString" => "a-string",
        "anArray" => new List<object> { "an", "array" },
        "anEmptyObject" => new Dictionary<string, object>(StringComparer.Ordinal),
        "anUndescribedMember" => new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["format"] = "iss_sub",
            ["iss"] = idpIssuer,
            ["sub"] = SubjectIdentity,
            ["extra"] = "x"
        },
        "aNestedAliases" => new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["format"] = "aliases",
            ["identifiers"] = new List<object>
            {
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "aliases",
                    ["identifiers"] = new List<object>
                    {
                        new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["format"] = "email",
                            ["email"] = "alice@example.com"
                        }
                    }
                }
            }
        },
        "anEmptyAliases" => new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["format"] = "aliases",
            ["identifiers"] = new List<object>()
        },
        "aSamlNameIdWithoutNameId" => new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["format"] = "saml-nameid",
            ["issuer"] = SamlIssuer
        },
        "aSamlNameIdWithANumericFormat" => new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["format"] = "saml-nameid",
            ["issuer"] = SamlIssuer,
            ["nameid"] = SamlNameId,
            ["nameid_format"] = 5L
        },
        "aSamlNameIdWithAnUndescribedMember" => new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["format"] = "saml-nameid",
            ["issuer"] = SamlIssuer,
            ["nameid"] = SamlNameId,
            ["extra"] = "x"
        },
        _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
    };


    private async Task<string> ObtainClientCredentialsAccessTokenAsync(
        HttpClient http, Uri tokenUrl, string clientId, string clientSecret, string scope)
    {
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.ClientSecret] = clientSecret,
            [OAuthRequestParameterNames.Scope] = scope
        }, TestContext.CancellationToken).ConfigureAwait(false);
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

        return (kid, usage, tenant, ctx, ct) =>
            ValueTask.FromResult(keysByKid.GetValueOrDefault(kid.Value));
    }


    private async Task<JwsAccessTokenValidationResult> VerifyAgainstAsAsync(
        string token, string expectedIssuer, ServerVerificationKeyResolverDelegate resolver) =>
        await JwsAccessTokenValidator.ValidateAsync(
            token,
            expectedIssuer,
            ResourceServerAudience,
            resolver,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            Pool,
            TimeSpan.FromSeconds(60),
            tenantId: default,
            [],
            expectedAuthorizedParty: null,
            TestContext.CancellationToken).ConfigureAwait(false);


    private Task<HttpResponseMessage> PostMintAsync(HttpClient http, Uri tokenUrl, string audience) =>
        PostMintWithSubjectAsync(http, tokenUrl, audience, SubjectTokenValue);


    private Task<HttpResponseMessage> PostMintWithSubjectAsync(
        HttpClient http, Uri tokenUrl, string audience, string subjectToken) =>
        OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.RequestedTokenType] = TokenTypeNames.GetName(TokenType.IdJag),
            [OAuthRequestParameterNames.Audience] = audience,
            [OAuthRequestParameterNames.SubjectToken] = subjectToken,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken);


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
}
