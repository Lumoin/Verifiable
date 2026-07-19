using System.Buffers;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// HTTP wire tests for the OAuth 2.0 Token Exchange grant
/// (<see href="https://www.rfc-editor.org/rfc/rfc8693">RFC 8693</see>) — both
/// IMPERSONATION (no <c>actor_token</c>) and DELEGATION (an <c>actor_token</c> selects
/// the acting party): a confidential client authenticates at the token endpoint, presents
/// a <c>subject_token</c> (and, for delegation, an <c>actor_token</c>), and the
/// authorization server — through the application's
/// <see cref="AuthorizationServerIntegration.ValidateTokenExchangeTokenAsync"/> and
/// <see cref="AuthorizationServerIntegration.AuthorizeTokenExchangeAsync"/> seams —
/// validates the token(s) and decides the exchange, then mints a Bearer access token
/// whose subject is the subject token's subject (RFC 8693 §1.1) and, for delegation,
/// whose <c>act</c> claim records the acting party (RFC 8693 §4.1).
/// </summary>
/// <remarks>
/// The grant materializes only when the client is allowed the
/// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability AND all
/// three seams are wired (client authentication, subject-token validation, the
/// exchange policy decision); a host missing any seam fails closed — the grant
/// endpoint does not exist and the request never reaches 200.
/// </remarks>
[TestClass]
internal sealed class TokenExchangeGrantTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";
    private const string SubjectTokenValue = "subject-token-opaque-blob";
    private const string ActorTokenValue = "actor-token-opaque-blob";
    private const string SubjectIdentity = "https://user.example/alice";
    private const string ActorIdentity = "https://svc.example/agent";
    private const string PriorActorIdentity = "https://svc.example/first-hop";
    private const string GrantedScope = "read";

    //A second confidential client used by the delegation end-to-end test: it issues the
    //real actor token via its own client_credentials grant, so the actor's sub is a real,
    //distinct AS-issued subject (RFC 9068 §3) verified against its own AS JWKS.
    private const string ActorClientId = "https://agent.example.com";
    private const string ActorClientSecret = "s3cret-of-the-agent";

    //A non-identity scope AddMachineScopeAudienceMapping maps onto ResourceServerAudience: contract
    //wave-4 D4 narrows openid away from every client_credentials grant (client_credentials has no
    //authenticated End-User), so the end-to-end tests mint their real subject/actor tokens under
    //this scope instead, to still reach a concrete audience.
    private const string MachineScope = "machine.telemetry.read";

    //The resource-server identifier AddMachineScopeAudienceMapping maps MachineScope onto; both the
    //client_credentials subject token and the exchanged token carry it as aud, so the real
    //resource-server validator has a concrete audience to match.
    private const string ResourceServerAudience = "https://rs.example.com";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// RFC 8693 Appendix A.1 shape: the client presents a valid <c>subject_token</c>
    /// of type <c>access_token</c>; validation returns the subject's claims and the
    /// impersonation policy permits the exchange. The response carries an
    /// <c>access_token</c> whose <c>sub</c> is the subject token's subject (§1.1
    /// impersonation), plus <c>issued_token_type</c>, <c>token_type</c> Bearer,
    /// <c>expires_in</c>, and the granted <c>scope</c> (§2.2.1). No <c>act</c> claim is
    /// emitted — there is no acting party in an impersonation exchange.
    /// </summary>
    [TestMethod]
    public async Task ImpersonationExchangeIssuesBearerAccessTokenOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireImpersonationSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;
        string accessToken = root.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.AccessToken),
            root.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString(),
            "issued_token_type must be the access-token URI the authorization seam decided.");
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, root.GetProperty("token_type").GetString());
        Assert.IsGreaterThan(0, root.GetProperty("expires_in").GetInt32(), "expires_in must reflect the token's exp-iat.");
        Assert.AreEqual(GrantedScope, root.GetProperty(OAuthRequestParameterNames.Scope).GetString());

        //RFC 8693 §1.1 impersonation: the issued token's subject is the subject token's subject,
        //and there is no acting party, so no act claim is emitted.
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(SubjectIdentity, payload.RootElement.GetProperty("sub").GetString());
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Act, out _),
            "An impersonation exchange must not emit an act claim.");

        //RFC 9068 §2.2: the issued access token's client_id claim identifies the OAuth client the
        //token was issued to — the confidential client that authenticated and ran the exchange.
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.ClientId).GetString(),
            "RFC 9068 §2.2: the exchanged token's client_id is the registered client that ran the exchange.");
    }


    /// <summary>
    /// RFC 8693 Appendix A.2 delegation shape: the client presents a valid <c>subject_token</c>
    /// AND a valid <c>actor_token</c> (with both <c>_type</c>s). Validation branches on the token
    /// string — the subject token's claims for the subject token, the actor token's claims for the
    /// actor token — and the policy permits the exchange. The issued token's <c>sub</c> is the
    /// subject (§1.1) while the <c>act</c> claim is a JSON OBJECT whose <c>sub</c> is the actor
    /// (§4.1: the act claim identifies the acting party to whom authority has been delegated).
    /// </summary>
    [TestMethod]
    public async Task DelegationExchangeRecordsActorInActClaimOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        WireBranchingValidator(app, subjectToken: null);
        WirePermissivePolicy(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(SubjectIdentity, payload.RootElement.GetProperty("sub").GetString(),
            "RFC 8693 §1.1: the delegated token's top-level subject is the subject token's subject.");

        //RFC 8693 §4.1: act is a JSON object whose sub is the current actor.
        JsonElement act = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Act);
        Assert.AreEqual(JsonValueKind.Object, act.ValueKind, "The act claim must be a JSON object.");
        Assert.AreEqual(ActorIdentity, act.GetProperty("sub").GetString(),
            "RFC 8693 §4.1: act.sub identifies the acting party to whom authority was delegated.");
    }


    /// <summary>
    /// RFC 8693 §4.4 <c>may_act</c> enforcement. When the subject token names an authorized actor
    /// (its <see cref="ValidatedSecurityToken.MayActSubject"/>), an <c>actor_token</c> whose subject
    /// equals that value is permitted (200, <c>act.sub</c> is the actor); an <c>actor_token</c> whose
    /// subject does NOT match is rejected with <c>invalid_request</c> before the policy seam runs —
    /// the subject authorized only that party to act for it.
    /// </summary>
    [TestMethod]
    public async Task MayActConstrainsTheAuthorizedActor()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        WirePermissivePolicy(app);

        //The subject token authorizes exactly ActorIdentity to act for it (§4.4 may_act.sub).
        //The actor token's claims are decided by the presented actor-token string.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    string.Equals(token, SubjectTokenValue, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken
                        {
                            Subject = SubjectIdentity,
                            Scope = GrantedScope,
                            MayActSubject = ActorIdentity
                        }
                        : string.Equals(token, ActorTokenValue, StringComparison.Ordinal)
                            ? new ValidatedSecurityToken { Subject = ActorIdentity }
                            : new ValidatedSecurityToken { Subject = "https://svc.example/intruder" });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        //Permitted: the actor token's subject equals the subject's may_act.sub.
        OutgoingFormFields permittedForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage permitted = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, permittedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string permittedBody = await permitted.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)permitted.StatusCode, permittedBody);

        using JsonDocument permittedDoc = JsonDocument.Parse(permittedBody);
        using JsonDocument permittedPayload = DecodePayload(
            permittedDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!);
        Assert.AreEqual(ActorIdentity,
            permittedPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Act).GetProperty("sub").GetString(),
            "When the actor satisfies may_act, the issued token's act.sub is that actor.");

        //Denied: a different actor token whose subject does NOT match the subject's may_act.sub.
        OutgoingFormFields deniedForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = "intruder-token-blob", TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage denied = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, deniedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string deniedBody = await denied.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)denied.StatusCode, deniedBody);
        Assert.Contains(OAuthErrors.InvalidRequest, deniedBody);
    }


    /// <summary>
    /// RFC 8693 §4.4 requires the issuer/subject COMBINATION to identify an authorized actor: "the
    /// combination of the two claims <c>iss</c> and <c>sub</c> are sometimes necessary to uniquely
    /// identify an authorized actor." When the subject token's <c>may_act</c> names both an issuer and
    /// a subject, an <c>actor_token</c> matching BOTH is permitted (200), but an <c>actor_token</c>
    /// whose subject matches while its issuer does NOT is rejected with <c>invalid_request</c> — a
    /// right-subject/wrong-issuer actor is a different, unauthorized party.
    /// </summary>
    [TestMethod]
    public async Task MayActEnforcesIssuerAndSubjectCombination()
    {
        const string MayActIssuer = "https://issuer.example/authorized";
        const string WrongIssuer = "https://issuer.example/other";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        WirePermissivePolicy(app);

        //The subject token authorizes exactly {sub: ActorIdentity, iss: MayActIssuer} to act for it.
        //The presented actor-token string decides the actor's claims, including its issuer.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    string.Equals(token, SubjectTokenValue, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken
                        {
                            Subject = SubjectIdentity,
                            Scope = GrantedScope,
                            MayActSubject = ActorIdentity,
                            MayActIssuer = MayActIssuer
                        }
                        : string.Equals(token, ActorTokenValue, StringComparison.Ordinal)
                            //Right subject AND right issuer — the authorized actor.
                            ? new ValidatedSecurityToken { Subject = ActorIdentity, Issuer = MayActIssuer }
                            //Right subject but WRONG issuer — a different, unauthorized party.
                            : new ValidatedSecurityToken { Subject = ActorIdentity, Issuer = WrongIssuer });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        //(a) Actor matches BOTH may_act.sub and may_act.iss → permitted; act.sub is the actor.
        OutgoingFormFields permittedForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage permitted = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, permittedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string permittedBody = await permitted.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)permitted.StatusCode, permittedBody);

        using JsonDocument permittedDoc = JsonDocument.Parse(permittedBody);
        using JsonDocument permittedPayload = DecodePayload(
            permittedDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!);
        Assert.AreEqual(ActorIdentity,
            permittedPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Act).GetProperty("sub").GetString(),
            "When the actor matches both may_act members, the issued token's act.sub is that actor.");

        //(b) Actor has the right subject but the WRONG issuer → rejected before the policy seam runs.
        OutgoingFormFields deniedForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = "wrong-issuer-actor-blob", TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage denied = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, deniedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string deniedBody = await denied.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)denied.StatusCode, deniedBody);
        Assert.Contains(OAuthErrors.InvalidRequest, deniedBody);
    }


    /// <summary>
    /// RFC 8693 §2.1.1 target binding. When the authorization seam returns an explicit
    /// <see cref="TokenExchangeAuthorization.Audience"/>, that value becomes the issued access token's
    /// <c>aud</c> claim verbatim, bypassing the registration's scope→audience resolver. The override
    /// here names a target the <c>ScopeToAudience</c> map would never produce, proving the explicit
    /// audience — not the resolver — shaped the token.
    /// </summary>
    [TestMethod]
    public async Task ExplicitAuthorizationAudienceBecomesIssuedTokenAud()
    {
        const string ExplicitAudience = "https://api.example/orders";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

        //The policy seam shapes the issued token for an explicit target (§2.1.1). This audience is not
        //in any ScopeToAudience entry, so its presence in aud can only come from the explicit override.
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = GrantedScope,
                        Audience = [ExplicitAudience],
                        IssuedTokenType = TokenType.AccessToken
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields explicitAudienceForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, explicitAudienceForm, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        using JsonDocument payload = DecodePayload(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!);

        //RFC 8693 §2.1.1: the explicit authorization audience is the issued token's aud. A single
        //audience serializes as a JSON string; assert the override value is present.
        JsonElement aud = payload.RootElement.GetProperty("aud");
        string actualAud = aud.ValueKind == JsonValueKind.Array
            ? aud.EnumerateArray().First().GetString()!
            : aud.GetString()!;
        Assert.AreEqual(ExplicitAudience, actualAud,
            "The explicit authorization audience (§2.1.1) must be the issued token's aud, not the scope→audience resolver's value.");
    }


    /// <summary>
    /// RFC 8693 §2.2.1 consistency. The configured producer mints only an RFC 9068 access-token JWT
    /// (response <c>token_type</c> Bearer), so a non-access <c>issued_token_type</c> would be
    /// inconsistent with the token actually returned. When the authorization seam decides a non-access
    /// <see cref="TokenExchangeAuthorization.IssuedTokenType"/>, the grant rejects the exchange as a
    /// <c>server_error</c> (an AS misconfiguration), never returning a mislabeled token.
    /// </summary>
    [TestMethod]
    public async Task NonAccessIssuedTokenTypeIsRejectedAsServerError()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

        //The policy seam decides a JWT issued_token_type the producer cannot honor — only access
        //tokens are minted, so this is an AS misconfiguration (§2.2.1 token_type/issued_token_type
        //consistency).
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = GrantedScope,
                        IssuedTokenType = TokenType.Jwt
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(500, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.ServerError, body);
    }


    /// <summary>
    /// RFC 8707 §2 / RFC 8693 §2.1: the <c>resource</c> parameter MUST be an absolute URI (RFC 3986
    /// §4.3) and MUST NOT include a fragment component. A relative <c>resource</c> and a
    /// fragment-bearing <c>resource</c> are both rejected with <c>invalid_request</c> before the
    /// validation seam runs.
    /// </summary>
    /// <remarks>
    /// Deliberately NOT built via <see cref="TokenExchangeRequestBuilder"/>: both values below are
    /// exactly what <see cref="TokenExchangeRequestBuilderTests.ResourceWithFragmentIsRejectedWithExactError"/>
    /// and <see cref="TokenExchangeRequestBuilderTests.RelativeResourceIsRejectedWithExactError"/> prove
    /// the builder itself rejects client-side before a request is ever built — so this test's hand-built
    /// form is the only way to prove the authorization server ALSO fails closed on the same rule
    /// (defense in depth for callers that do not go through this library's builder).
    /// </remarks>
    [TestMethod]
    public async Task MalformedResourceIsRejectedFailClosed()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireImpersonationSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;
        string accessTokenType = TokenTypeNames.GetName(TokenType.AccessToken);

        //(a) resource with a fragment component — RFC 8707 §2 MUST NOT include a fragment.
        using HttpResponseMessage withFragment = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = accessTokenType,
            [OAuthRequestParameterNames.Resource] = "https://api.example/x#frag"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string withFragmentBody = await withFragment.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)withFragment.StatusCode, withFragmentBody);
        Assert.Contains(OAuthErrors.InvalidRequest, withFragmentBody);

        //(b) relative resource — RFC 8707 §2 MUST be an absolute URI.
        using HttpResponseMessage relative = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = accessTokenType,
            [OAuthRequestParameterNames.Resource] = "/relative"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string relativeBody = await relative.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)relative.StatusCode, relativeBody);
        Assert.Contains(OAuthErrors.InvalidRequest, relativeBody);
    }


    /// <summary>
    /// RFC 8693 §2.1.1 multi-target. Repeated <c>resource</c> parameters indicate the issued token is
    /// intended for multiple resources. The skin collapses them into a single space-delimited
    /// <c>resource</c> field value (the convention the authorization-code path shares); the grant
    /// splits them back into the individual indicators and carries every one into the
    /// <see cref="TokenExchangeRequest.Resource"/> the authorization seam reads — each still validated
    /// as an absolute, fragment-free URI.
    /// </summary>
    [TestMethod]
    public async Task RepeatedResourceCarriesEveryTargetIntoTheAuthorizationSeam()
    {
        const string FirstResource = "https://api.example/orders";
        const string SecondResource = "https://api.example/inventory";

        IReadOnlyList<string>? seenResources = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

        //Capture the resource list the authorization seam observes — it must carry BOTH targets.
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            (subject, actor, request, registration, context, ct) =>
            {
                seenResources = request.Resource;

                return ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = GrantedScope,
                        IssuedTokenType = TokenType.AccessToken
                    });
            };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //The builder's repeated-resource convention: the two indicators arrive space-delimited in the
        //single resource field, exactly as the authorization-code path receives them.
        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = [FirstResource, SecondResource]
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Assert.IsNotNull(seenResources, "The authorization seam must have run.");
        Assert.HasCount(2, seenResources!);
        Assert.Contains(FirstResource, seenResources!);
        Assert.Contains(SecondResource, seenResources!);
    }


    /// <summary>
    /// RFC 8693 §4.1 chain nesting (Figure 6). When the subject token is itself a delegated
    /// (composite) token — its <see cref="ValidatedSecurityToken.Act"/> carries a prior actor's
    /// <c>act</c> object — a further exchange nests that prior <c>act</c> under the new actor: the
    /// issued token's <c>act.sub</c> is the new (current) actor and <c>act.act.sub</c> is the prior
    /// actor. The outermost act is the current actor; nested act claims are prior actors.
    /// </summary>
    [TestMethod]
    public async Task DelegationChainNestsPriorActorUnderNewActor()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        WirePermissivePolicy(app);

        //The subject token already carries an act claim naming a prior actor (it is itself a
        //delegated token). The new exchange adds the current actor on top of that chain.
        Dictionary<string, object> priorAct = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = PriorActorIdentity
        };
        WireBranchingValidator(app, subjectToken: new ValidatedSecurityToken
        {
            Subject = SubjectIdentity,
            Scope = GrantedScope,
            Act = priorAct
        });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        using JsonDocument payload = DecodePayload(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!);
        Assert.AreEqual(SubjectIdentity, payload.RootElement.GetProperty("sub").GetString());

        //RFC 8693 §4.1 Figure 6: act.sub is the current actor; act.act.sub is the prior actor.
        JsonElement act = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Act);
        Assert.AreEqual(ActorIdentity, act.GetProperty("sub").GetString(),
            "The outermost act is the current actor.");
        JsonElement nested = act.GetProperty(WellKnownJwtClaimNames.Act);
        Assert.AreEqual(JsonValueKind.Object, nested.ValueKind, "The nested act must be a JSON object.");
        Assert.AreEqual(PriorActorIdentity, nested.GetProperty("sub").GetString(),
            "The nested act.act.sub is the prior actor (the least recent is the most deeply nested).");
    }


    /// <summary>
    /// A genuine end-to-end RFC 8693 §1.1 impersonation exchange where every token is real and
    /// cryptographically verified — the only stub is the policy permit decision.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The chain mirrors a production deployment exactly:
    /// </para>
    /// <list type="number">
    ///   <item><description>
    ///     The machine client obtains a real RFC 9068 access token from the AS over the wire via the
    ///     <c>client_credentials</c> grant (RFC 6749 §4.4). The token is a P-256-signed JWT whose
    ///     <c>sub</c> is the client itself (RFC 9068 §3) and whose <c>iss</c> is the AS issuer.
    ///   </description></item>
    ///   <item><description>
    ///     The <see cref="AuthorizationServerIntegration.ValidateTokenExchangeTokenAsync"/> seam runs
    ///     the project's real <see cref="JwsAccessTokenValidator"/> over the presented
    ///     <c>subject_token</c> — fetching the AS's JWKS over HTTP and reconstructing the verification
    ///     key by <c>kid</c>, verifying the signature, the <c>iss</c>, and the timing window. A
    ///     forgery or wrong issuer surfaces as <see langword="null"/> (the request is rejected).
    ///   </description></item>
    ///   <item><description>The policy permit (the lone stub) authorizes the impersonation.</description></item>
    ///   <item><description>
    ///     The AS mints the exchanged access token, whose <c>sub</c> impersonates the subject token's
    ///     subject (RFC 8693 §1.1 / Appendix A.1.4).
    ///   </description></item>
    ///   <item><description>
    ///     The resource-server step verifies the exchanged token the same way a resource server would —
    ///     the same <see cref="JwsAccessTokenValidator"/> against the same AS JWKS — and asserts
    ///     <c>iss</c> is the AS, <c>sub</c> is the original subject, and the token is genuinely a fresh
    ///     artefact (a distinct <c>jti</c>), not the subject token re-presented.
    ///   </description></item>
    /// </list>
    /// </remarks>
    [TestMethod]
    public async Task EndToEndRealTokenIsValidatedExchangedAndUsed()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        //The iss the AS stamps on every token it mints for this tenant — the registration's
        //declared canonical URL, resolved by the library's DefaultIssuerResolver. The
        //resource-server validator compares against this by exact string (RFC 9068 / RFC 8414 §3).
        string asIssuer = material.Registration.IssuerUri!.OriginalString;

        //Resolve the AS verification key the way a relying party does: GET /jwks over HTTP and
        //reconstruct the PublicKeyMemory from the published JWK matching the token's kid.
        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //STEP 1 — Issue a real subject token over the wire (client_credentials, RFC 6749 §4.4).
        //sub == ClientId (RFC 9068 §3); MachineScope embeds aud == ResourceServerAudience.
        string subjectToken = await ObtainClientCredentialsAccessTokenAsync(
            http, tokenUrl, ClientId, ClientSecret, MachineScope).ConfigureAwait(false);

        //Prove, before exchanging, that the subject token is itself a real, valid AS token —
        //the same check the validation seam performs below. This pins what "real" means here.
        JwsAccessTokenValidationResult subjectValidation = await VerifyAgainstAsAsync(
            subjectToken, asIssuer, jwksResolver).ConfigureAwait(false);
        Assert.IsTrue(subjectValidation.IsSuccess,
            $"The subject token must be a valid AS-issued token; got {subjectValidation.FailureReason}: {subjectValidation.FailureDescription}");
        Assert.AreEqual(ClientId, subjectValidation.Claims!.Subject,
            "RFC 9068 §3: a client_credentials token's subject is the client itself.");
        string subjectTokenJti = subjectValidation.Claims.JwtId!;

        //STEP 2 — Wire the REAL subject-token validator. It runs the project's resource-server-grade
        //JwsAccessTokenValidator against the AS JWKS: a forged or wrong-issuer token returns null and
        //the exchange is refused. On success it surfaces the validated sub and scope.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            async (token, tokenType, registration, context, ct) =>
            {
                JwsAccessTokenValidationResult result = await VerifyAgainstAsAsync(
                    token, asIssuer, jwksResolver).ConfigureAwait(false);
                if(!result.IsSuccess)
                {
                    return null;
                }

                return new ValidatedSecurityToken
                {
                    Subject = result.Claims!.Subject,
                    Issuer = result.Claims.Issuer,
                    Scope = result.Claims.Scope
                };
            };

        //STEP 3 — Wire the policy permit (the lone stub). The exchanged token impersonates the
        //validated subject and carries its scope (RFC 8693 §1.1 / Appendix A.1.4).
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = subject.Scope ?? "read",
                        IssuedTokenType = TokenType.AccessToken
                    });

        //STEP 4 — Exchange the REAL subject token (RFC 8693 §2.1).
        OutgoingFormFields exchangeForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = subjectToken,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage exchange = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, exchangeForm, TestContext.CancellationToken).ConfigureAwait(false);

        string exchangeBody = await exchange.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)exchange.StatusCode, exchangeBody);

        using JsonDocument exchangeDoc = JsonDocument.Parse(exchangeBody);
        string exchangedToken = exchangeDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.AccessToken),
            exchangeDoc.RootElement.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString());

        //STEP 5 — USE the exchanged token (the resource-server step). Verify its signature against the
        //SAME AS JWKS and enforce iss/aud/timing through the real validator.
        JwsAccessTokenValidationResult exchangedValidation = await VerifyAgainstAsAsync(
            exchangedToken, asIssuer, jwksResolver).ConfigureAwait(false);
        Assert.IsTrue(exchangedValidation.IsSuccess,
            $"The exchanged token must verify as a real AS-issued token; got {exchangedValidation.FailureReason}: {exchangedValidation.FailureDescription}");
        Assert.AreEqual(asIssuer, exchangedValidation.Claims!.Issuer,
            "The exchanged token must be issued by the same AS.");
        Assert.AreEqual(ClientId, exchangedValidation.Claims.Subject,
            "RFC 8693 §1.1 impersonation: the exchanged token's subject is the subject token's subject.");

        //The exchanged token is a genuinely fresh artefact, not the subject token re-presented.
        Assert.AreNotEqual(subjectToken, exchangedToken,
            "The exchanged token must not be the subject token string.");
        Assert.AreNotEqual(subjectTokenJti, exchangedValidation.Claims.JwtId,
            "RFC 8693 mints a new token — the exchanged token's jti must differ from the subject token's.");
    }


    /// <summary>
    /// A genuine end-to-end RFC 8693 DELEGATION exchange where BOTH the subject token and the actor
    /// token are real, cryptographically verified AS-issued tokens with DISTINCT real subjects — the
    /// only stub is the policy permit decision.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two confidential clients are registered. Each is its own tenant (its own AS issuer and JWKS),
    /// so two genuinely distinct, real subjects are available:
    /// </para>
    /// <list type="number">
    ///   <item><description>
    ///     The SUBJECT token is a real <c>client_credentials</c> token from the machine client's tenant
    ///     (<c>sub == ClientId</c>, RFC 9068 §3), P-256-signed by that AS.
    ///   </description></item>
    ///   <item><description>
    ///     The ACTOR token is a real <c>client_credentials</c> token from the agent client's tenant
    ///     (<c>sub == ActorClientId</c>), P-256-signed by THAT AS — a distinct real subject.
    ///   </description></item>
    ///   <item><description>
    ///     The subject-token and actor-token validation seam runs the project's real
    ///     <see cref="JwsAccessTokenValidator"/>, verifying each token against ITS OWN tenant's JWKS
    ///     and issuer. A forgery or wrong issuer surfaces as <see langword="null"/>.
    ///   </description></item>
    ///   <item><description>The policy permit (the lone stub) authorizes the delegation.</description></item>
    ///   <item><description>
    ///     The exchange runs on the machine client's token endpoint; the exchanged token is verified
    ///     against the machine tenant's JWKS and asserts <c>sub</c> == the subject and
    ///     <c>act.sub</c> == the actor (RFC 8693 §1.1 / §4.1) — every token real and cryptographically
    ///     verified.
    ///   </description></item>
    /// </list>
    /// <para>
    /// Two distinct REAL subjects ARE feasible with the harness: each <c>RegisterDpopClient</c> mints
    /// its own tenant (issuer <c>https://issuer.test/{segment}</c> + per-segment JWKS), and a
    /// <c>client_credentials</c> token's subject is the registering client itself. Both tenants are
    /// served by the same HTTP host (path-segmented), so one host issues and verifies both.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task DelegationEndToEndBothTokensRealDistinctSubjectsExchangedAndUsed()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial subjectMaterial = RegisterTokenExchangeClient(app);
        using VerifierKeyMaterial actorMaterial = RegisterActorClient(app);
        WireClientAuthentication(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;

        string subjectSegment = subjectMaterial.Registration.TenantId.Value;
        string actorSegment = actorMaterial.Registration.TenantId.Value;
        Uri subjectTokenUrl = new(host.HttpBaseAddress!, $"/connect/{subjectSegment}/token");
        Uri actorTokenUrl = new(host.HttpBaseAddress!, $"/connect/{actorSegment}/token");

        string subjectIssuer = subjectMaterial.Registration.IssuerUri!.OriginalString;
        string actorIssuer = actorMaterial.Registration.IssuerUri!.OriginalString;

        //Each token is verified against ITS OWN tenant's published JWKS, exactly as a relying party
        //trusting that AS would. These are the real trust anchors — keys come from the AS over HTTP.
        ServerVerificationKeyResolverDelegate subjectJwks =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, subjectSegment).ConfigureAwait(false);
        ServerVerificationKeyResolverDelegate actorJwks =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, actorSegment).ConfigureAwait(false);

        //STEP 1 — Mint TWO real client_credentials tokens with DISTINCT real subjects.
        string subjectToken = await ObtainClientCredentialsAccessTokenAsync(
            http, subjectTokenUrl, ClientId, ClientSecret, MachineScope).ConfigureAwait(false);
        string actorToken = await ObtainClientCredentialsAccessTokenAsync(
            http, actorTokenUrl, ActorClientId, ActorClientSecret, MachineScope).ConfigureAwait(false);

        //Pin "real": both tokens verify against their own AS and carry their own distinct subject.
        JwsAccessTokenValidationResult subjectCheck = await VerifyAgainstAsAsync(subjectToken, subjectIssuer, subjectJwks).ConfigureAwait(false);
        JwsAccessTokenValidationResult actorCheck = await VerifyAgainstAsAsync(actorToken, actorIssuer, actorJwks).ConfigureAwait(false);
        Assert.IsTrue(subjectCheck.IsSuccess, $"subject token must be valid: {subjectCheck.FailureDescription}");
        Assert.IsTrue(actorCheck.IsSuccess, $"actor token must be valid: {actorCheck.FailureDescription}");
        Assert.AreEqual(ClientId, subjectCheck.Claims!.Subject);
        Assert.AreEqual(ActorClientId, actorCheck.Claims!.Subject);
        Assert.AreNotEqual(subjectCheck.Claims.Subject, actorCheck.Claims.Subject,
            "The subject and actor must be genuinely distinct real subjects.");

        //STEP 2 — Wire the REAL validator. It verifies the subject token against the subject tenant's
        //JWKS and the actor token against the actor tenant's JWKS, branching on the validated issuer.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            async (token, tokenType, registration, context, ct) =>
            {
                JwsAccessTokenValidationResult subjectResult = await VerifyAgainstAsAsync(token, subjectIssuer, subjectJwks).ConfigureAwait(false);
                if(subjectResult.IsSuccess)
                {
                    return new ValidatedSecurityToken
                    {
                        Subject = subjectResult.Claims!.Subject,
                        Issuer = subjectResult.Claims.Issuer,
                        Scope = subjectResult.Claims.Scope
                    };
                }

                JwsAccessTokenValidationResult actorResult = await VerifyAgainstAsAsync(token, actorIssuer, actorJwks).ConfigureAwait(false);
                if(actorResult.IsSuccess)
                {
                    return new ValidatedSecurityToken
                    {
                        Subject = actorResult.Claims!.Subject,
                        Issuer = actorResult.Claims.Issuer,
                        Scope = actorResult.Claims.Scope
                    };
                }

                return null;
            };

        //STEP 3 — Wire the policy permit (the lone stub). The exchanged token keeps the subject and
        //the library records the actor in the act claim (§4.1).
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = subject.Scope ?? "read",
                        IssuedTokenType = TokenType.AccessToken
                    });

        //STEP 4 — DELEGATION exchange on the SUBJECT tenant's token endpoint with both real tokens.
        OutgoingFormFields exchangeForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = subjectToken,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = actorToken, TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage exchange = await OAuthTestTransport.PostFormAsync(
            http, subjectTokenUrl, exchangeForm, TestContext.CancellationToken).ConfigureAwait(false);

        string exchangeBody = await exchange.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)exchange.StatusCode, exchangeBody);

        using JsonDocument exchangeDoc = JsonDocument.Parse(exchangeBody);
        string exchangedToken = exchangeDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //STEP 5 — USE the exchanged token: verify against the SUBJECT tenant's JWKS (it was minted by
        //that AS) and assert the composite shape — sub is the subject, act.sub is the actor.
        JwsAccessTokenValidationResult exchangedValidation = await VerifyAgainstAsAsync(
            exchangedToken, subjectIssuer, subjectJwks).ConfigureAwait(false);
        Assert.IsTrue(exchangedValidation.IsSuccess,
            $"The exchanged token must verify as a real AS-issued token; got {exchangedValidation.FailureReason}: {exchangedValidation.FailureDescription}");
        Assert.AreEqual(subjectIssuer, exchangedValidation.Claims!.Issuer);
        Assert.AreEqual(ClientId, exchangedValidation.Claims.Subject,
            "RFC 8693 §1.1: the delegated token's subject is the subject token's subject.");

        //The act claim is in the JWT payload (the validator surfaces the standard claims, not act);
        //decode the payload directly to assert the §4.1 composite shape.
        using JsonDocument payload = DecodePayload(exchangedToken);
        JsonElement act = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Act);
        Assert.AreEqual(JsonValueKind.Object, act.ValueKind, "The act claim must be a JSON object.");
        Assert.AreEqual(ActorClientId, act.GetProperty("sub").GetString(),
            "RFC 8693 §4.1: act.sub is the real, distinct actor subject.");
    }


    /// <summary>
    /// RFC 8693 §2.1/§2.2.2 fail-closed request errors. <c>subject_token</c> and
    /// <c>subject_token_type</c> are REQUIRED and the type must parse; an <c>actor_token</c>
    /// without an <c>actor_token_type</c> is malformed, as is an <c>actor_token_type</c> with no
    /// <c>actor_token</c>; an unparseable <c>requested_token_type</c> is malformed; a subject token
    /// the validation seam rejects (null) and an exchange the policy seam denies (null) with no
    /// named target are <c>invalid_request</c>, while a policy denial against a named <c>resource</c>
    /// target surfaces <c>invalid_target</c>.
    /// </summary>
    /// <remarks>
    /// Cases (a)–(d) are deliberately NOT built via <see cref="TokenExchangeRequestBuilder"/>: each
    /// shape is exactly what the builder makes UNREPRESENTABLE (missing REQUIRED fields do not compile;
    /// an actor token without its type, or vice versa, cannot be constructed per
    /// <see cref="TokenExchangeActor"/>) or client-side build-time-rejected in a way that would never
    /// reach this test's AS-side assertions (an unparseable <c>requested_token_type</c> has no
    /// corresponding <see cref="TokenType"/> value to pass in). Cases (e)–(i) are ordinary well-formed
    /// requests the AS itself refuses for policy/authentication reasons, so they migrate to the builder.
    /// </remarks>
    [TestMethod]
    public async Task MalformedAndUnauthorizedExchangesAreRejectedFailClosed()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireImpersonationSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        string accessTokenType = TokenTypeNames.GetName(TokenType.AccessToken);

        //(a) Missing subject_token — RFC 8693 §2.1 REQUIRED.
        using HttpResponseMessage missingSubject = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.SubjectTokenType] = accessTokenType
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string missingSubjectBody = await missingSubject.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)missingSubject.StatusCode, missingSubjectBody);
        Assert.Contains(OAuthErrors.InvalidRequest, missingSubjectBody);

        //(b) Missing subject_token_type — RFC 8693 §2.1/§3 REQUIRED and must be a known URI.
        using HttpResponseMessage missingType = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string missingTypeBody = await missingType.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)missingType.StatusCode, missingTypeBody);
        Assert.Contains(OAuthErrors.InvalidRequest, missingTypeBody);

        //(c) actor_token present but actor_token_type missing — RFC 8693 §2.1 actor_token_type is
        //REQUIRED when actor_token is present.
        using HttpResponseMessage actorNoType = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = accessTokenType,
            [OAuthRequestParameterNames.ActorToken] = ActorTokenValue
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string actorNoTypeBody = await actorNoType.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)actorNoType.StatusCode, actorNoTypeBody);
        Assert.Contains(OAuthErrors.InvalidRequest, actorNoTypeBody);

        //(c2) actor_token_type present without actor_token — RFC 8693 §2.1 it MUST NOT be present
        //when actor_token is absent.
        using HttpResponseMessage typeNoActor = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = accessTokenType,
            [OAuthRequestParameterNames.ActorTokenType] = accessTokenType
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string typeNoActorBody = await typeNoActor.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)typeNoActor.StatusCode, typeNoActorBody);
        Assert.Contains(OAuthErrors.InvalidRequest, typeNoActorBody);

        //(d) requested_token_type unparseable — RFC 8693 §3 it must be a supported token-type URI.
        using HttpResponseMessage badRequestedType = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = accessTokenType,
            [OAuthRequestParameterNames.RequestedTokenType] = "not-a-uri"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string badRequestedTypeBody = await badRequestedType.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)badRequestedType.StatusCode, badRequestedTypeBody);
        Assert.Contains(OAuthErrors.InvalidRequest, badRequestedTypeBody);

        //(e) The validation seam rejects the subject_token (null) — RFC 8693 §2.2.2 invalid_request.
        await using TestHostShell rejectingApp = new(TimeProvider);
        using VerifierKeyMaterial rejectingMaterial = RegisterTokenExchangeClient(rejectingApp);
        WireClientAuthentication(rejectingApp);
        rejectingApp.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(null);
        rejectingApp.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization { Subject = subject.Subject, Scope = GrantedScope });
        await rejectingApp.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer rejectingHost = rejectingApp.Host("default");
        Uri rejectingTokenUrl = new(rejectingHost.HttpBaseAddress!, $"/connect/{rejectingMaterial.Registration.TenantId.Value}/token");

        OutgoingFormFields subjectRejectedForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage subjectRejected = await OAuthTestTransport.PostFormAsync(
            rejectingHost.SharedHttpClient!, rejectingTokenUrl, subjectRejectedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string subjectRejectedBody = await subjectRejected.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)subjectRejected.StatusCode, subjectRejectedBody);
        Assert.Contains(OAuthErrors.InvalidRequest, subjectRejectedBody);

        //(f) The policy seam denies (null) with NO named resource/audience target —
        //RFC 8693 §2.2.2 the general invalid_request MUST.
        await using TestHostShell denyingApp = new(TimeProvider);
        using VerifierKeyMaterial denyingMaterial = RegisterTokenExchangeClient(denyingApp);
        WireClientAuthentication(denyingApp);
        denyingApp.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });
        denyingApp.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(null);
        await denyingApp.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer denyingHost = denyingApp.Host("default");
        Uri denyingTokenUrl = new(denyingHost.HttpBaseAddress!, $"/connect/{denyingMaterial.Registration.TenantId.Value}/token");

        OutgoingFormFields deniedNoTargetForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage deniedNoTarget = await OAuthTestTransport.PostFormAsync(
            denyingHost.SharedHttpClient!, denyingTokenUrl, deniedNoTargetForm, TestContext.CancellationToken).ConfigureAwait(false);
        string deniedNoTargetBody = await deniedNoTarget.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)deniedNoTarget.StatusCode, deniedNoTargetBody);
        Assert.Contains(OAuthErrors.InvalidRequest, deniedNoTargetBody);

        //(g) The policy seam denies (null) but the request named a resource target —
        //RFC 8693 §2.2.2 invalid_target.
        OutgoingFormFields deniedWithTargetForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = ["https://api.example/orders"]
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage deniedWithTarget = await OAuthTestTransport.PostFormAsync(
            denyingHost.SharedHttpClient!, denyingTokenUrl, deniedWithTargetForm, TestContext.CancellationToken).ConfigureAwait(false);
        string deniedWithTargetBody = await deniedWithTarget.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)deniedWithTarget.StatusCode, deniedWithTargetBody);
        Assert.Contains(OAuthErrors.InvalidTarget, deniedWithTargetBody);

        //(h) Wrong client secret — client authentication fails (RFC 8693 §2.1 normal OAuth client auth).
        OutgoingFormFields badSecretForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes("guessed-wrong"));
        using HttpResponseMessage badSecret = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, badSecretForm, TestContext.CancellationToken).ConfigureAwait(false);
        string badSecretBody = await badSecret.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)badSecret.StatusCode, badSecretBody);
        Assert.Contains(OAuthErrors.InvalidClient, badSecretBody);

        //(i) Fail-closed: a host whose token-exchange seams are NOT wired does not
        //materialize the grant — a well-formed token-exchange request never reaches 200.
        await using TestHostShell bare = new(TimeProvider);
        using VerifierKeyMaterial bareMaterial = RegisterTokenExchangeClient(bare);
        await bare.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer bareHost = bare.Host("default");
        Uri bareTokenUrl = new(bareHost.HttpBaseAddress!, $"/connect/{bareMaterial.Registration.TenantId.Value}/token");

        OutgoingFormFields unwiredForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage unwired = await OAuthTestTransport.PostFormAsync(
            bareHost.SharedHttpClient!, bareTokenUrl, unwiredForm, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(200, (int)unwired.StatusCode,
            "The token-exchange grant must not be reachable without its validation and authorization seams.");
    }


    /// <summary>
    /// RFC 8693 §2.1 L369: "In processing the request, the authorization server MUST perform the
    /// appropriate validation procedures for the indicated token type" — validation cannot happen if no
    /// seam exists to run it. Client authentication AND the authorization-policy seam ARE wired here;
    /// ONLY <see cref="AuthorizationServerIntegration.ValidateTokenExchangeTokenAsync"/> is deliberately
    /// left unconfigured, isolating that single seam as the cause. Per <c>AuthCodeEndpoints.cs</c>'s
    /// capability-and-seam gate (all three token-exchange seams must be present together), the grant
    /// candidate never materializes, so a well-formed exchange request never reaches the grant at all —
    /// the same fail-closed pattern
    /// <see cref="JwtBearerGrantTests.PresentCredentialsWithNoClientAuthSeamAreRejectedAsInvalidClient"/>
    /// proves for the jwt-bearer grant's client-authentication seam.
    /// </summary>
    [TestMethod]
    public async Task WellFormedExchangeWithoutTokenValidationSeamDoesNotActivateTheGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);

        //Client authentication AND the authorization-policy seam are wired; ValidateTokenExchangeTokenAsync
        //is deliberately left unconfigured.
        WireClientAuthentication(app);
        WirePermissivePolicy(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //No candidate matches grant_type=token-exchange when BuildTokenExchange is excluded from the
        //endpoint-candidate set — the dispatcher's unmatched-chain path (the same one
        //RefreshGrantTests.UnsupportedGrantTypeReturnsNotFound exercises for an unknown grant_type).
        Assert.AreEqual(404, (int)response.StatusCode, body);
        Assert.AreNotEqual(200, (int)response.StatusCode,
            "A well-formed exchange must not be accepted when ValidateTokenExchangeTokenAsync is unwired (RFC 8693 §2.1 L369).");
    }


    /// <summary>
    /// A genuine end-to-end RFC 8693 §3-style NEGATIVE rejection: the validation seam runs the
    /// project's real <see cref="JwsAccessTokenValidator"/> against the AS JWKS, so a
    /// <c>subject_token</c> whose signature has been tampered, and one that is untampered but
    /// EXPIRED, are both rejected — the real cryptographic and timing checks fail, the validator
    /// returns <see langword="null"/>, and the grant surfaces RFC 8693 §2.2.2 <c>invalid_request</c>.
    /// This proves the rejection is the real validator's, not a stub returning null.
    /// </summary>
    [TestMethod]
    public async Task EndToEndRealTamperedOrExpiredSubjectTokenIsRejectedAsInvalidRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        string asIssuer = material.Registration.IssuerUri!.OriginalString;

        //Resolve the AS verification key the way a relying party does (GET /jwks), and wire the REAL
        //subject-token validator — a forged, wrong-issuer, or expired token returns null and the
        //exchange is refused (RFC 8693 §2.2.2 invalid_request).
        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            async (token, tokenType, registration, context, ct) =>
            {
                JwsAccessTokenValidationResult result = await VerifyAgainstAsAsync(
                    token, asIssuer, jwksResolver).ConfigureAwait(false);
                if(!result.IsSuccess)
                {
                    return null;
                }

                return new ValidatedSecurityToken
                {
                    Subject = result.Claims!.Subject,
                    Issuer = result.Claims.Issuer,
                    Scope = result.Claims.Scope
                };
            };

        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = subject.Scope ?? "read",
                        IssuedTokenType = TokenType.AccessToken
                    });

        //Mint a real subject token (client_credentials, RFC 6749 §4.4) — sub == ClientId, P-256-signed
        //by the AS. It is, before tampering, a genuinely valid AS-issued token.
        string subjectToken = await ObtainClientCredentialsAccessTokenAsync(
            http, tokenUrl, ClientId, ClientSecret, MachineScope).ConfigureAwait(false);

        //The compact JWS splits into header.payload.signature. Both tamper cases below leave the
        //header and payload intact and corrupt only the signature segment, deterministically — never
        //relying on the random signature value to land in a particular shape.
        string[] segments = subjectToken.Split('.');
        Assert.HasCount(3, segments);

        //(a) TAMPER, well-formed but wrong: flip the FIRST signature character. The segment keeps its
        //length and stays canonical base64url, so it decodes cleanly, but the P-256 signature no
        //longer verifies over the untouched header+payload. The validator's signature check returns
        //false → null → invalid_request (RFC 8693 §2.2.2).
        char firstSignatureChar = segments[2][0];
        char flippedFirst = firstSignatureChar == 'A' ? 'B' : 'A';
        string wrongSignature = string.Concat(flippedFirst.ToString(), segments[2].AsSpan(1));
        string wrongSignatureToken = string.Join('.', segments[0], segments[1], wrongSignature);
        Assert.AreNotEqual(subjectToken, wrongSignatureToken, "The wrong-signature token must differ from the original.");

        OutgoingFormFields wrongSigForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = wrongSignatureToken,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage wrongSig = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, wrongSigForm, TestContext.CancellationToken).ConfigureAwait(false);
        string wrongSigBody = await wrongSig.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)wrongSig.StatusCode, wrongSigBody);
        Assert.Contains(OAuthErrors.InvalidRequest, wrongSigBody);

        //(b) TAMPER, malformed: a P-256 signature is 64 bytes → 86 base64url characters whose final
        //character encodes only 2 significant bits, so a canonical value ends in one of {A,Q,g,w} (the
        //four unused bits zero). Forcing the last character to 'B' sets those unused bits non-zero,
        //yielding a non-canonical base64url the strict decoder rejects. The validator must treat a
        //token whose signature cannot even be decoded as an invalid token (SignatureFailed → null →
        //invalid_request), NOT surface the decoder's exception as a 500.
        string malformedSignature = string.Concat(segments[2].AsSpan(0, segments[2].Length - 1), "B");
        string malformedToken = string.Join('.', segments[0], segments[1], malformedSignature);
        Assert.AreNotEqual(subjectToken, malformedToken, "The malformed-signature token must differ from the original.");

        OutgoingFormFields malformedForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = malformedToken,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage malformed = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, malformedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string malformedBody = await malformed.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)malformed.StatusCode, malformedBody);
        Assert.Contains(OAuthErrors.InvalidRequest, malformedBody);

        //(b) EXPIRED: the subject token is untampered and was valid, but its 1-hour lifetime
        //(Rfc9068AccessTokenProducer default) elapses. Advancing a full day pushes exp past the
        //validator's 60-second skew → the real timing check fails → null → invalid_request.
        TimeProvider.Advance(TimeSpan.FromDays(1));

        OutgoingFormFields expiredForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = subjectToken,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage expired = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, expiredForm, TestContext.CancellationToken).ConfigureAwait(false);
        string expiredBody = await expired.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)expired.StatusCode, expiredBody);
        Assert.Contains(OAuthErrors.InvalidRequest, expiredBody);
    }


    /// <summary>
    /// RFC 8693 §2.1/§2.2.1 scope conveyance. The requested <c>scope</c> reaches the authorization
    /// seam through <see cref="TokenExchangeRequest.Scope"/>; when the seam echoes it into
    /// <see cref="TokenExchangeAuthorization.Scope"/>, that value shapes BOTH the response
    /// <c>scope</c> field (§2.2.1) and the issued access token's <c>scope</c> claim (RFC 9068 §2.2).
    /// </summary>
    [TestMethod]
    public async Task RequestedScopeReachesTheSeamAndShapesTheIssuedToken()
    {
        const string RequestedScope = "urn:example:custom";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

        //The policy seam reads the requested scope off the request and echoes it into the granted
        //authorization — the issued token carries exactly the requested scope (§2.2.1). The custom
        //scope has no ScopeToAudience entry; the registration's AccessTokenAudPolicy is not Required
        //(the impersonation happy path issues with the unmapped "read" scope and no audience), so the
        //custom scope does not force a server_error.
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = request.Scope ?? GrantedScope,
                        IssuedTokenType = TokenType.AccessToken
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Scope = RequestedScope
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(RequestedScope, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "RFC 8693 §2.2.1: the response scope is the scope the authorization seam granted.");

        using JsonDocument payload = DecodePayload(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!);
        Assert.AreEqual(RequestedScope, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString(),
            "RFC 9068 §2.2: the issued token's scope claim is the requested scope the seam granted.");
    }


    /// <summary>
    /// OAuth 2.1 §3.2.3 / RFC 7234 §5.2.2.3: a token-bearing response MUST set
    /// <c>Cache-Control: no-store</c>. A happy-path impersonation exchange's success response carries
    /// it, so a relying-party HTTP cache never stores the issued Bearer access token.
    /// </summary>
    [TestMethod]
    public async Task SuccessResponseCarriesCacheControlNoStore()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireImpersonationSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        //OAuth 2.1 §3.2.3: the token response MUST set Cache-Control: no-store.
        Assert.IsNotNull(response.Headers.CacheControl, "The token-exchange success response must set Cache-Control.");
        Assert.IsTrue(response.Headers.CacheControl!.NoStore,
            "OAuth 2.1 §3.2.3: a token-bearing response MUST carry Cache-Control: no-store.");
    }


    /// <summary>
    /// RFC 8693 §2.2.2 invalid_request error responses MUST NOT leak the subject. When the
    /// validation seam knows the subject token's subject but still rejects it (returns
    /// <see langword="null"/>), the error body carries the OAuth error code only — never the
    /// subject identifier the seam observed.
    /// </summary>
    [TestMethod]
    public async Task ErrorBodyDoesNotLeakTheSubject()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterTokenExchangeClient(app);
        WireClientAuthentication(app);

        //The seam knows the subject (it is the fixture's SubjectIdentity) but rejects the exchange by
        //returning null — RFC 8693 §2.2.2 invalid_request. The error body must not echo the subject.
        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(null);
        WirePermissivePolicy(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidRequest, body);
        Assert.DoesNotContain(SubjectIdentity, body,
            "The error response must not leak the subject identifier the validation seam observed.");
    }


    /// <summary>
    /// Grant-type disjointness. A client allowed the OTHER grant capability
    /// (client_credentials) but NOT
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> — with all three
    /// token-exchange seams wired — does not have its well-formed <c>token-exchange</c> request served
    /// as a successful exchange. The grant materializes only on its own capability; it never falls
    /// through to another grant in the client's capability set.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeGrantTypeDoesNotFallThroughWithoutItsCapability()
    {
        await using TestHostShell app = new(TimeProvider);

        //Register a client allowed the other grant's capability (client_credentials) but NOT OAuthTokenExchange.
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        //Wire ALL THREE token-exchange seams: the only thing missing is the capability. A grant that
        //honored a wired seam regardless of capability would serve this; a disjoint grant does not.
        WireImpersonationSeams(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(200, (int)response.StatusCode, body);
    }


    /// <summary>
    /// Contract wave-4 D3/D4: on a tenant granted the
    /// <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> feature — ruling out D2's
    /// capability gate as the explanation — a token-exchange grant whose authorization seam
    /// legitimately grants <c>openid</c> (the app opting in, per the source-layer contract:
    /// <c>token_exchange</c> honors the app-granted scope, unlike <c>client_credentials</c>) still
    /// never yields an id_token. <see cref="Oidc10IdTokenProducer"/>'s <c>IsApplicable</c>
    /// independently requires <c>GrantType ∈ {authorization_code, refresh_token}</c> — this test
    /// proves that gate holds even when <c>openid</c> survives all the way to the issued access
    /// token's <c>scope</c> claim, which is the non-vacuous case (nothing upstream removed
    /// <c>openid</c> here).
    /// </summary>
    [TestMethod]
    public async Task NoIdTokenIsMintedForTokenExchangeEvenWithOpenidGrantedAndOidcFeatureEnabled()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

        //The policy seam grants openid — an app opting in to vouch that the exchanged subject is an
        //End-User (contract wave-4 D4: token_exchange honors whatever scope the app's authorization
        //seam decides, unlike client_credentials' source-layer narrowing).
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = WellKnownScopes.OpenId,
                        IssuedTokenType = TokenType.AccessToken
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(WellKnownScopes.OpenId, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "Sanity: openid must have actually reached the response scope — otherwise the id_token's "
            + "absence would be trivially explained by scope, not by the grant-type gate under test.");
        Assert.IsFalse(doc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out _),
            "token_exchange must never carry an id_token even when openid survived to the granted "
            + "scope on a tenant with the OidcOpenIdConnect feature granted.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(WellKnownScopes.OpenId, payload.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "The issued access token's own scope claim must also carry openid unchanged.");
    }


    /// <summary>
    /// Contract wave-4 D3/D4 refresh-ladder: a refresh token minted by a token-exchange grant
    /// (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.5's SAML-to-OAuth transition shape —
    /// the authorization seam sets <see cref="TokenExchangeAuthorization.IssuedTokenType"/> to
    /// <see cref="TokenType.RefreshToken"/>) never yields an id_token on redemption via
    /// <c>grant_type=refresh_token</c>, even on a tenant granted
    /// <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> — ruling out D2's capability
    /// gate as the explanation — and even though <c>openid</c> genuinely rode both the exchange
    /// response and the redeemed access token's own <c>scope</c> claim. <see cref="Oidc10IdTokenProducer"/>'s
    /// <c>IsApplicable</c> reads <see cref="IssuanceContext.RefreshTokenOriginatingGrantType"/> — carried
    /// verbatim off <see cref="Verifiable.OAuth.AuthCode.Server.States.ServerRefreshTokenIssuedState.OriginatingGrantType"/>
    /// — which is <c>token_exchange</c> here, not <c>authorization_code</c>, so the absence proves the
    /// origin-grant gate rather than a scope that never reached the refreshed token.
    /// </summary>
    [TestMethod]
    public async Task RefreshTokenMintedByTokenExchangeNeverYieldsIdTokenOnRedemption()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,

                //The refresh_token grant's own endpoint match requires this capability
                //(AuthCodeEndpoints.BuildRefreshToken), independent of the D2 tenant-feature gate under
                //test here — without it the redemption leg below would 404 before ever reaching the
                //id_token producer walk.
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

        //The app opts the exchanged subject into a refresh-token issuance carrying openid — the §4.5
        //SAML-to-OAuth transition shape, where the mint runs through BuildRefreshTokenExchangeResponseAsync
        //and stamps OriginatingGrantType = token_exchange on the stored refresh state.
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
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields exchangeForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage exchangeResponse = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, exchangeForm, TestContext.CancellationToken).ConfigureAwait(false);

        string exchangeBody = await exchangeResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)exchangeResponse.StatusCode, exchangeBody);

        using JsonDocument exchangeDoc = JsonDocument.Parse(exchangeBody);
        Assert.AreEqual(
            TokenTypeNames.GetName(TokenType.RefreshToken),
            exchangeDoc.RootElement.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString(),
            "Sanity: the exchange must have actually minted a refresh token (§4.5), not an access token.");
        Assert.AreEqual(WellKnownScopes.OpenId, exchangeDoc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "Sanity: openid must have actually reached the token-exchange response scope.");
        string refreshToken = exchangeDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //Redeem the token-exchange-minted refresh token through the ordinary grant_type=refresh_token
        //leg — the same endpoint an authorization_code-originated refresh token redeems through.
        using HttpResponseMessage refreshResponse = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = ClientId
        }, TestContext.CancellationToken).ConfigureAwait(false);

        string refreshBody = await refreshResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)refreshResponse.StatusCode, refreshBody);

        using JsonDocument refreshDoc = JsonDocument.Parse(refreshBody);
        Assert.IsFalse(refreshDoc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out _),
            "A refresh token minted by token_exchange must never yield an id_token on redemption, even "
            + "with openid granted and OidcOpenIdConnect enabled — RefreshTokenOriginatingGrantType gates it.");

        string refreshedAccessToken = refreshDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument refreshedPayload = DecodePayload(refreshedAccessToken);
        Assert.AreEqual(WellKnownScopes.OpenId, refreshedPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString(),
            "openid must have ridden the refresh redemption onto the refreshed access token's own scope "
            + "claim — proving the id_token's absence is the origin-grant gate, not a scope that never "
            + "reached the redeemed token.");
    }


    /// <summary>
    /// Registers a truly grant-only confidential client — no
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> — allowed the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability plus
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/> (some end-to-end tests
    /// obtain a real subject/actor token via the client_credentials grant). Grant-only token-exchange
    /// issuance works because <see cref="Rfc9068AccessTokenProducer"/>'s <c>RequiredCapability</c> is
    /// <see langword="null"/> — an optional tenant-feature gate, not a grant-capability proxy
    /// (contract wave-4 D2) — so the endpoint-match capability alone is sufficient. RegisterDpopClient
    /// supplies the AccessTokenIssuance signing keys the producers resolve. The discovery/jwks
    /// capabilities round out the standard surface. <see cref="AddMachineScopeAudienceMapping"/> maps
    /// <see cref="MachineScope"/> onto <see cref="ResourceServerAudience"/> so the real
    /// client_credentials subject/actor tokens minted below still reach a concrete audience —
    /// contract wave-4 D4 narrows <c>openid</c> away from every <c>client_credentials</c> grant.
    /// </summary>
    private static VerifierKeyMaterial RegisterTokenExchangeClient(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        AddMachineScopeAudienceMapping(app, material);

        return material;
    }


    /// <summary>
    /// Registers the second confidential client — the acting party — used by the delegation
    /// end-to-end test. It is its own tenant (its own AS issuer and JWKS) so its
    /// <c>client_credentials</c> token's subject (itself) is a distinct real subject, verified
    /// against its own published JWKS.
    /// </summary>
    private static VerifierKeyMaterial RegisterActorClient(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterDpopClient(
            ActorClientId,
            new Uri(ActorClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        AddMachineScopeAudienceMapping(app, material);

        return material;
    }


    /// <summary>
    /// Adds <see cref="MachineScope"/> to <paramref name="material"/>'s <c>AllowedScopes</c> and maps
    /// it onto <see cref="ResourceServerAudience"/> in <c>ScopeToAudience</c> — the register-then-
    /// upgrade pattern the sibling grant suites use, because the routing dictionaries are
    /// host-internal.
    /// </summary>
    private static void AddMachineScopeAudienceMapping(TestHostShell app, VerifierKeyMaterial material)
    {
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = host.Registrations[segment];
        Dictionary<string, IReadOnlyList<string>> scopeToAudience = previous.ScopeToAudience is null
            ? new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            : new Dictionary<string, IReadOnlyList<string>>(previous.ScopeToAudience, StringComparer.Ordinal);
        scopeToAudience[MachineScope] = [ResourceServerAudience];

        ClientRecord updated = previous with
        {
            AllowedScopes = previous.AllowedScopes.Add(MachineScope),
            ScopeToAudience = scopeToAudience
        };
        host.Registrations[segment] = updated;
        host.Registrations[updated.ClientId] = updated;
        host.Server.UpdateClient(previous, updated, new ExchangeContext());
        material.Registration = updated;
    }


    /// <summary>
    /// Wires the client_secret_post authentication seam (RFC 6749 §2.3.1): the application
    /// owns the secret store and the comparison; this test glue checks the form field against
    /// the secret of whichever client_id the request claims (both registered clients are served).
    /// </summary>
    private static void WireClientAuthentication(TestHostShell app) =>
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue("client_secret", out string? secret)
                && string.Equals(
                    secret,
                    string.Equals(registration.ClientId, ActorClientId, StringComparison.Ordinal)
                        ? ActorClientSecret
                        : ClientSecret,
                    StringComparison.Ordinal));


    /// <summary>
    /// Wires the three seams for the happy-path impersonation exchange: client
    /// authentication, a subject-token validation that accepts the fixture's subject token
    /// and surfaces its subject and scope, and an impersonation policy that permits the
    /// exchange and shapes the issued token to that same subject and scope as an
    /// access token (RFC 8693 §1.1 / Appendix A.1.4).
    /// </summary>
    private static void WireImpersonationSeams(TestHostShell app)
    {
        WireClientAuthentication(app);

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

        WirePermissivePolicy(app);
    }


    /// <summary>
    /// Wires a permissive policy seam: it permits every exchange and shapes the issued token to the
    /// validated subject and the fixture's granted scope as an access token (RFC 8693 §1.1 /
    /// Appendix A.1.4). The library, not this seam, records the actor in the act claim for delegation.
    /// </summary>
    private static void WirePermissivePolicy(TestHostShell app) =>
        app.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = GrantedScope,
                        IssuedTokenType = TokenType.AccessToken
                    });


    /// <summary>
    /// Wires a validation seam that branches on the presented token string: the fixture's subject
    /// token resolves to the subject's claims (or the supplied <paramref name="subjectToken"/> when
    /// a specific subject shape — e.g. a prior <c>act</c> chain — is needed), the fixture's actor
    /// token resolves to the actor's claims. Distinct subjects (<see cref="SubjectIdentity"/> vs
    /// <see cref="ActorIdentity"/>) make the §4.1 actor recording observable.
    /// </summary>
    private static void WireBranchingValidator(TestHostShell app, ValidatedSecurityToken? subjectToken)
    {
        ValidatedSecurityToken subject = subjectToken
            ?? new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope };

        app.Server.OAuth().ValidateTokenExchangeTokenAsync =
            (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    string.Equals(token, ActorTokenValue, StringComparison.Ordinal)
                        ? new ValidatedSecurityToken { Subject = ActorIdentity }
                        : subject);
    }


    /// <summary>
    /// Obtains a real signed access token from the AS over the wire via the
    /// <c>client_credentials</c> grant (RFC 6749 §4.4). The returned compact JWS is a genuine
    /// RFC 9068 access token: <c>sub</c> is the client itself (RFC 9068 §3), <c>iss</c> is the AS
    /// issuer, and it is P-256-signed by the AS's access-token key.
    /// </summary>
    private async Task<string> ObtainClientCredentialsAccessTokenAsync(
        HttpClient http, Uri tokenUrl, string clientId, string clientSecret, string scope)
    {
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = clientId,
            ["client_secret"] = clientSecret,
            [OAuthRequestParameterNames.Scope] = scope
        }, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Decodes the JWT payload (the middle compact-JWS segment) of <paramref name="compactJws"/>
    /// into a parsed <see cref="JsonDocument"/> for claim assertions.
    /// </summary>
    private static JsonDocument DecodePayload(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);

        return JsonDocument.Parse(payloadBytes);
    }


    /// <summary>
    /// Fetches the AS's JWKS over HTTP (GET <c>/connect/{segment}/jwks</c>) and returns a key
    /// resolver that — exactly as a relying party would — looks up the published JWK by <c>kid</c>
    /// and reconstructs a <see cref="PublicKeyMemory"/> from it via
    /// <see cref="DpopJwkUtilities.PublicKeyFromJwk"/>. This is the real trust anchor for the
    /// signature checks: keys come from the AS's published JWKS, not from the host's private store.
    /// </summary>
    private async Task<ServerVerificationKeyResolverDelegate> BuildJwksKeyResolverAsync(
        HttpClient http, Uri httpBaseAddress, string segment)
    {
        Uri jwksUrl = new(httpBaseAddress, $"/connect/{segment}/jwks");
        using HttpResponseMessage response = await http.GetAsync(jwksUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        //Snapshot the published verification keys keyed by kid. Each JWK carries the EC public
        //point (kty/crv/x/y); PublicKeyFromJwk rebuilds the project-native key from those members.
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


    /// <summary>
    /// Runs the project's resource-server-grade <see cref="JwsAccessTokenValidator"/> over a token:
    /// resolves the verification key by <c>kid</c> from the AS JWKS, verifies the P-256 signature,
    /// and enforces <c>iss</c>, <c>aud</c>, and the timing window. The expected audience is the
    /// resource-server identifier the openid scope maps to on this registration.
    /// </summary>
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


    /// <summary>
    /// Builds a well-formed RFC 8693 §2.1 token-exchange request via
    /// <see cref="TokenExchangeRequestBuilder.Build(TokenExchangeBuilderOptions)"/> and asserts the
    /// build succeeded — every call site here supplies a well-formed <paramref name="options"/>, so a
    /// build failure is a test-fixture bug, not something under test.
    /// </summary>
    private static OutgoingFormFields BuildRequest(TokenExchangeBuilderOptions options)
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> built = TokenExchangeRequestBuilder.Build(options);
        Assert.IsTrue(built.IsSuccess, "The builder must accept a well-formed token-exchange request.");

        return built.Value!;
    }
}
