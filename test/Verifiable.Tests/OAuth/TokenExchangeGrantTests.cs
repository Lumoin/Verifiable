using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestDataProviders;
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

    //A non-identity scope AddMachineScopeAudienceMapping maps onto ResourceServerAudience: openid is
    //narrowed away from every client_credentials grant (client_credentials has no
    //authenticated End-User), so the end-to-end tests mint their real subject/actor tokens under
    //this scope instead, to still reach a concrete audience.
    private const string MachineScope = "machine.telemetry.read";

    //The resource-server identifier AddMachineScopeAudienceMapping maps MachineScope onto; both the
    //client_credentials subject token and the exchanged token carry it as aud, so the real
    //resource-server validator has a concrete audience to match.
    private const string ResourceServerAudience = "https://rs.example.com";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await WireBranchingValidatorAsync(app, subjectToken: null).ConfigureAwait(false);
        await WirePermissivePolicyAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);


        //The subject token authorizes exactly ActorIdentity to act for it (§4.4 may_act.sub).
        //The actor token's claims are decided by the presented actor-token string.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
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
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);


        //The subject token authorizes exactly {sub: ActorIdentity, iss: MayActIssuer} to act for it.
        //The presented actor-token string decides the actor's claims, including its issuer.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
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
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });


            //The policy seam shapes the issued token for an explicit target (§2.1.1). This audience is not
            //in any ScopeToAudience entry, so its presence in aud can only come from the explicit override.

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            Audience = [ExplicitAudience],
                            IssuedTokenType = TokenType.AccessToken
                        });
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });


            //The policy seam decides a JWT issued_token_type the producer cannot honor — only access
            //tokens are minted, so this is an AS misconfiguration (§2.2.1 token_type/issued_token_type
            //consistency).

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = TokenType.Jwt
                        });
        }).ConfigureAwait(false);

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
    /// An authorization seam that names no subject for the issued token, a
    /// <see cref="TokenExchangeAuthorization.Subject"/> of white space only, is answered <c>server_error</c> with
    /// the fixed description and nothing is issued: the answer is 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, and
    /// for an exchange whose requested token type is a refresh token no refresh token is stored. The authorization
    /// is the application's decision and names the subject of the issued token, so one that names no subject is the
    /// seam's own defect, answered as
    /// <see cref="IdJagGrantTests.MintRefusesAKnownFormatIdentifierBreakingItsFormatAsync"/> answers the same
    /// seam's <c>sub_id</c> that is not well formed. The answer departs from
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>, whose
    /// <c>invalid_request</c> is the error for a request that is not valid; answering the server's own defect
    /// <c>server_error</c> is this library's rule.
    /// </summary>
    /// <param name="caseName">
    /// The <c>requested_token_type</c> the exchange carries: <c>accessToken</c> or <c>refreshToken</c>; the seam
    /// issues a refresh token when one is requested and an access token otherwise.
    /// </param>
    [TestMethod]
    [DataRow("accessToken", DisplayName = "an exchange that issues an access token")]
    [DataRow("refreshToken", DisplayName = "an exchange whose requested token type is a refresh token")]
    public async Task AnAuthorizationThatNamesNoSubjectIssuesNothingAsync(string caseName)
    {
        TokenType requestedTokenType = caseName switch
        {
            "accessToken" => TokenType.AccessToken,
            "refreshToken" => TokenType.RefreshToken,
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = " ",
                            Scope = GrantedScope,
                            IssuedTokenType = request.RequestedTokenType == TokenType.RefreshToken
                                ? TokenType.RefreshToken
                                : TokenType.AccessToken
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(host.SharedHttpClient!, tokenUrl, requestedTokenType)
            .ConfigureAwait(false);
        string[] storedRefreshSubjects =
        [
            .. host.FlowStates.Values
                .Select(entry => entry.State)
                .OfType<ServerRefreshTokenIssuedState>()
                .Select(state => $"'{state.SubjectId}'")
        ];
        string record = $"{status} '{body}' stored refresh token subjects [{string.Join(", ", storedRefreshSubjects)}]";

        Assert.AreEqual(500, status, record);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            body,
            record);
        Assert.IsEmpty(storedRefreshSubjects, $"An authorization that names no subject stores no refresh token. {record}");
    }


    /// <summary>
    /// A validated <c>actor_token</c> whose <see cref="ValidatedSecurityToken.Subject"/> is white space only names
    /// no actor, and the exchange answers it as an <c>actor_token</c> that is not valid: 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The actor_token is not valid."}</c>, and no token is
    /// issued, so no <c>act</c> claim names a blank actor. The validated token restates the token's claims, and the
    /// library cannot tell an actor token whose subject is blank from a validation that lost it, so it answers the
    /// case a clause governs,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>: "If the
    /// request itself is not valid or if either the "subject_token" or "actor_token" are invalid for any reason, or
    /// are unacceptable based on policy, the authorization server MUST construct an error response, as specified in
    /// Section 5.2 of [RFC6749]. The value of the "error" parameter MUST be the "invalid_request" error code." That
    /// choice is this library's.
    /// </summary>
    [TestMethod]
    public async Task AnActorTokenWhoseSubjectIsBlankIsNoValidActorTokenAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await WireBranchingValidatorAsync(app, subjectToken: null, actorToken: new ValidatedSecurityToken { Subject = " " })
            .ConfigureAwait(false);

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
        string record = DescribeExchangeAnswer((int)response.StatusCode, body);

        Assert.AreEqual(400, (int)response.StatusCode, record);
        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The actor_token is not valid.\"}",
            body,
            record);
    }


    /// <summary>
    /// A validated <c>subject_token</c> whose <see cref="ValidatedSecurityToken.Subject"/> is white space only names
    /// no subject, and the exchange answers it as a <c>subject_token</c> that is not valid even when the
    /// authorization seam copies that subject into the issued token, as an impersonation policy does: an exchange
    /// for an access token, an exchange that asks for an ID-JAG, and an exchange for an access token that presents an
    /// <c>actor_token</c> are each answered 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The subject_token is not valid."}</c>. The ID-JAG
    /// request is answered with the same code:
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3.4.3</see>
    /// reads "On an error condition, the IdP returns an OAuth 2.0 Token Error response as defined in Section 5.2 of
    /// [RFC6749], e.g:", an example that names no code for this case. No token is issued, so the host's
    /// identifier seam is asked for no <c>jti</c>, and the refusal comes before the actor token is validated and
    /// before the authorization seam is called: the actor token's validation and the seam each count no call. The
    /// validated token restates the token's claims, and the library cannot tell a subject token whose subject is
    /// blank from a validation that lost it, so it answers the case a clause governs,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>: "If the
    /// request itself is not valid or if either the "subject_token" or "actor_token" are invalid for any reason, or
    /// are unacceptable based on policy, the authorization server MUST construct an error response, as specified in
    /// Section 5.2 of [RFC6749]. The value of the "error" parameter MUST be the "invalid_request" error code." That
    /// choice is this library's.
    /// </summary>
    /// <param name="caseName">
    /// The token the exchange asks for: <c>accessToken</c> for an access token, <c>idJag</c> for an ID-JAG, or
    /// <c>accessTokenWithActor</c> for an access token with an <c>actor_token</c> presented.
    /// </param>
    [TestMethod]
    [DataRow("accessToken", DisplayName = "an exchange for an access token")]
    [DataRow("idJag", DisplayName = "an exchange for an ID-JAG")]
    [DataRow("accessTokenWithActor", DisplayName = "an exchange for an access token that presents an actor token")]
    public async Task ASubjectTokenWhoseSubjectIsBlankIsNoValidSubjectTokenAsync(string caseName)
    {
        (TokenType requestedTokenType, bool isActorTokenPresented, string expectedBody) = caseName switch
        {
            "accessToken" => (
                TokenType.AccessToken,
                false,
                "{\"error\":\"invalid_request\",\"error_description\":\"The subject_token is not valid.\"}"),
            "idJag" => (
                TokenType.IdJag,
                false,
                "{\"error\":\"invalid_request\",\"error_description\":\"The subject_token is not valid.\"}"),
            "accessTokenWithActor" => (
                TokenType.AccessToken,
                true,
                "{\"error\":\"invalid_request\",\"error_description\":\"The subject_token is not valid.\"}"),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app, isIdJagAllowed: true)
            .ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        //The host's identifier seam, the actor token's validation and the authorization seam count their calls.
        Func<int> countTokenIdentifiers = static () => 0;
        int actorValidationCalls = 0;
        int authorizationCalls = 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                {
                    if(string.Equals(token, ActorTokenValue, StringComparison.Ordinal))
                    {
                        actorValidationCalls++;

                        return ValueTask.FromResult<ValidatedSecurityToken?>(
                            new ValidatedSecurityToken { Subject = ActorIdentity });
                    }

                    return ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = " ", Scope = GrantedScope });
                };

            //The impersonation policy copies the validated subject into the issued token.
            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    authorizationCalls++;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = request.RequestedTokenType == TokenType.IdJag
                                ? TokenType.IdJag
                                : TokenType.AccessToken
                        });
                };

            countTokenIdentifiers = CountTokenIdentifiers(candidateIntegration);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            RequestedTokenType = requestedTokenType,
            Audience = requestedTokenType == TokenType.IdJag ? ResourceServerAudience : null,
            Actor = isActorTokenPresented
                ? new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.AccessToken }
                : null
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string record = $"{DescribeExchangeAnswer((int)response.StatusCode, body)} token identifiers generated "
            + $"{countTokenIdentifiers()} actor validations {actorValidationCalls} authorization calls {authorizationCalls}";

        Assert.AreEqual(400, (int)response.StatusCode, record);
        Assert.AreEqual(expectedBody, body, record);
        Assert.AreEqual(0, countTokenIdentifiers(), $"No token identifier is generated for a subject token that is not valid. {record}");
        Assert.AreEqual(0, actorValidationCalls, $"The actor token is not validated for a subject token that is not valid. {record}");
        Assert.AreEqual(0, authorizationCalls, $"The authorization seam is not called for a subject token that is not valid. {record}");
    }


    /// <summary>
    /// An authorization seam that shapes the actor itself, a
    /// <see cref="TokenExchangeAuthorization.Actor"/> whose <c>sub</c> member is present and is not a string with a
    /// character that is not white space (white space only, null, or a number), names no actor for an <c>act</c>
    /// claim, and the exchange answers it as it answers an authorization that names no subject, whatever the issued
    /// token type: when the seam selects the id-jag issued type, and when it selects the access token issued type,
    /// the answer is 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, and no
    /// token is issued. The shaped actor is the application's decision, so one that names no actor is the
    /// seam's own defect, answered as <see cref="AnAuthorizationThatNamesNoSubjectIssuesNothingAsync"/> answers the
    /// same seam's blank subject. The answer departs from
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>, whose
    /// <c>invalid_request</c> is the error for a request that is not valid; answering the server's own defect
    /// <c>server_error</c> is this library's rule.
    /// </summary>
    /// <param name="caseName">
    /// The value of the shaped actor's <c>sub</c> member at an ID-JAG exchange: <c>blank</c> (one space),
    /// <c>null</c>, or <c>number</c> (the number 5); or <c>accessTokenBlank</c>, one space at an exchange whose seam
    /// issues an access token.
    /// </param>
    [TestMethod]
    [DataRow("blank", DisplayName = "a sub of one space")]
    [DataRow("null", DisplayName = "a sub that is null")]
    [DataRow("number", DisplayName = "a sub that is a number")]
    [DataRow("accessTokenBlank", DisplayName = "an access token exchange with a sub of one space")]
    public async Task AnAuthorizationWhoseActorNamesNoSubjectIssuesNothingAsync(string caseName)
    {
        (object shapedActorSubject, TokenType issuedTokenType) = caseName switch
        {
            "blank" => ((object)" ", TokenType.IdJag),
            "null" => (null!, TokenType.IdJag),
            "number" => (5, TokenType.IdJag),
            "accessTokenBlank" => (" ", TokenType.AccessToken),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app, isIdJagAllowed: true)
            .ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = issuedTokenType,
                            Actor = new Dictionary<string, object>(StringComparer.Ordinal)
                            {
                                [WellKnownJwtClaimNames.Sub] = shapedActorSubject
                            }
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            RequestedTokenType = issuedTokenType,
            Audience = issuedTokenType == TokenType.IdJag ? ResourceServerAudience : null
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string record = DescribeExchangeAnswer((int)response.StatusCode, body);

        Assert.AreEqual(500, (int)response.StatusCode, record);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            body,
            record);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: the
    /// <c>resource</c> parameter's value "MUST be an absolute URI, as specified by Section 4.3 of
    /// [RFC3986]. The URI MUST NOT include a fragment component." A relative <c>resource</c> and a
    /// fragment-bearing <c>resource</c> are both rejected with the fixed <c>invalid_target</c> body
    /// this library answers for every malformed <c>resource</c> value, the token exchange grant
    /// included: a departure from RFC 8693 section 2.2.2's general <c>invalid_request</c> for a
    /// request that is not valid, following
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>, which
    /// provides the code for an access token request: "The following error code is provided for an
    /// authorization server to indicate problems with the requested resource(s) in response to an
    /// authorization request or access token request." The instruction of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see> for a
    /// value the server fails to parse is the authorization request's, and this library applies the
    /// same reading at the token endpoint as its own reading.
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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;
        string accessTokenType = TokenTypeNames.GetName(TokenType.AccessToken);
        const string expectedBody = "{\"error\":\"invalid_target\",\"error_description\":\"The "
            + "resource parameter must be an absolute URI (RFC 3986 section 4.3) without a "
            + "fragment.\"}";

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
        Assert.AreEqual(expectedBody, withFragmentBody);

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
        Assert.AreEqual(expectedBody, relativeBody);
    }


    /// <summary>
    /// The scheme and host of an absolute <c>resource</c> are folded to lower case before the
    /// authorization seam reads them.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 section
    /// 6.2.2.1</see>: "the scheme and host are case-insensitive and therefore should be normalized to
    /// lowercase", and <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section
    /// 2</see>: "The authorization server may use the exact &quot;resource&quot; value as the audience
    /// or it may map from that value to a more general URI or abstract identifier for the given
    /// resource." The authorization seam here copies <see cref="TokenExchangeRequest.Resource"/> into
    /// <see cref="TokenExchangeAuthorization.Audience"/>, so the value it receives is exactly the
    /// value the issued access token's <c>aud</c> carries: both are the lower-case spelling. The row
    /// runs inside a <see cref="ServedCultureScope"/> set to "tr-TR", so a fold that lowered the
    /// ASCII <c>I</c> the Turkish way (to U+0131) would fail it. The second case carries a query
    /// component, which the token exchange admits:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>
    /// says the <c>resource</c> value "MUST be an absolute URI, as specified by Section 4.3 of
    /// [RFC3986], that MAY include a query component and MUST NOT include a fragment component.",
    /// and <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>
    /// gives the reason a query is sometimes needed: "It SHOULD NOT include a query component, but
    /// it is recognized that there are cases that make a query component a useful and necessary part
    /// of the resource parameter, such as when one or more query parameters are used to scope
    /// requests to an application." The query is not the scheme or the host, so it keeps the
    /// spelling it was sent with (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC
    /// 3986 section 6.2.2.1</see>: "The other generic syntax components are assumed to be
    /// case-sensitive unless specifically defined otherwise by the scheme"): the seam receives
    /// <c>https://wiki.rs.example/api?Tenant=A</c> and the issued <c>aud</c> carries it.
    /// </summary>
    /// <param name="requestedResource">The <c>resource</c> the request sends.</param>
    /// <param name="foldedResource">The value the seam receives and the issued <c>aud</c> carries.</param>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("HTTPS://WIKI.RS.EXAMPLE/api", "https://wiki.rs.example/api")]
    [DataRow("HTTPS://WIKI.RS.EXAMPLE/api?Tenant=A", "https://wiki.rs.example/api?Tenant=A")]
    public async Task TokenExchangeResourceIsFoldedAtIngressAsync(string requestedResource, string foldedResource)
    {
        IReadOnlyList<string>? seenResources = null;

        await using TestHostShell app = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            app, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    seenResources = request.Resource;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            Audience = request.Resource,
                            IssuedTokenType = TokenType.AccessToken
                        });
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Resource = [requestedResource]
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Assert.IsNotNull(seenResources, "The authorization seam must have been consulted.");
        Assert.AreSequenceEqual([foldedResource], seenResources);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreSequenceEqual(
            [foldedResource],
            ReadAudience(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!));

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// A <c>resource</c> outside ASCII is refused at the token exchange with the fixed
    /// <c>invalid_target</c> body this library answers for every malformed <c>resource</c> value.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see> defines
    /// <c>invalid_target</c>: "The requested resource is invalid, missing, unknown, or malformed."
    /// It provides the code for an access token request as well: "The following error code is
    /// provided for an authorization server to indicate problems with the requested resource(s) in
    /// response to an authorization request or access token request." The instruction of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see> for a
    /// value the server fails to parse is the authorization request's, and this library applies the
    /// same reading at the token endpoint as its own reading. Last,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>
    /// makes the token exchange's <c>resource</c> the same value: "an absolute URI, as specified by
    /// Section 4.3 of [RFC3986]". The URI syntax defines its terminal values as code points "based on
    /// the US-ASCII coded character set"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 section 2</see>), so
    /// the value naming the Kelvin sign (U+212A) in its host is not one. The row runs inside a
    /// <see cref="ServedCultureScope"/> set to "tr-TR".
    /// </summary>
    /// <remarks>
    /// The form is hand-built, not composed by <see cref="TokenExchangeRequestBuilder"/>, so the
    /// authorization server's own refusal is what the row observes, as in
    /// <see cref="MalformedResourceIsRejectedFailClosed"/>.
    /// </remarks>
    [TestMethod]
    [DoNotParallelize]
    public async Task ANonAsciiResourceIsRefusedAtTheTokenExchangeAsync()
    {
        string resource = "https://" + char.ConvertFromUtf32(0x212A) + "ey.example/";

        await using TestHostShell app = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            app, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken),
            [OAuthRequestParameterNames.Resource] = resource
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.AreEqual(MalformedResourceBody, body);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// A <c>resource</c> occurrence that carries whitespace is refused at the token exchange with the
    /// fixed <c>invalid_target</c> body this library answers for every malformed <c>resource</c>
    /// value. <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>
    /// defines <c>invalid_target</c> as "The requested resource is invalid, missing, unknown, or
    /// malformed", and <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section
    /// 2.1</see> makes the token exchange's <c>resource</c> "an absolute URI, as specified by Section
    /// 4.3 of [RFC3986]", whose grammar
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>)
    /// admits no space. The request trace records one event naming the first part of the occurrence
    /// as received that fails that grammar: a whitespace-only occurrence fails the <c>scheme</c>
    /// production (a space is no <c>ALPHA</c>), a space inside the path fails <c>pchar</c>, a space
    /// inside the host fails <c>reg-name</c>.
    /// </summary>
    /// <param name="resource">The <c>resource</c> occurrence the request carries.</param>
    /// <param name="expectedFaultName">The name of the part the trace records as failing.</param>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("   ", "Scheme")]
    [DataRow("https://api.example/orders v2", "Path")]
    [DataRow("https://api example/orders", "Authority")]
    public async Task AWhitespaceBearingResourceIsRefusedAtTheTokenExchangeAsync(
        string resource, string expectedFaultName)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(AWhitespaceBearingResourceIsRefusedAtTheTokenExchangeAsync));
        _ = root.Start();

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken),
            [OAuthRequestParameterNames.Resource] = resource
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        root.Stop();

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.AreEqual(MalformedResourceBody, body);
        Assert.AreSequenceEqual([expectedFaultName], ReadMalformedResourceFaultNames(capture, root));
    }


    /// <summary>
    /// RFC 8693 §2.1.1 multi-target: RFC 8707 §2's actual multi-resource wire form is the REPEATED
    /// <c>resource</c> parameter (not several URIs packed into one occurrence separated by spaces —
    /// <see cref="TokenExchangeRequestBuilder"/>'s own single-field convention is a client-side
    /// choice this test deliberately bypasses to exercise the wire form directly). The grant reads
    /// every occurrence and carries all of them into the
    /// <see cref="TokenExchangeRequest.Resource"/> the authorization seam reads — each still
    /// validated as an absolute, fragment-free URI.
    /// </summary>
    [TestMethod]
    public async Task RepeatedResourceCarriesEveryTargetIntoTheAuthorizationSeam()
    {
        const string FirstResource = "https://api.example/orders";
        const string SecondResource = "https://api.example/inventory";

        IReadOnlyList<string>? seenResources = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });


            //Capture the resource list the authorization seam observes — it must carry BOTH targets.

            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //RFC 8707 §2's genuine multi-resource wire form: the resource key repeated, built as a raw
        //key/value pair list (OutgoingFormFields carries only one value per key) so the request body
        //carries two distinct resource=... occurrences rather than one space-joined value.
        List<KeyValuePair<string, string>> rawForm =
        [
            new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.TokenExchange),
            new(OAuthRequestParameterNames.SubjectToken, SubjectTokenValue),
            new(OAuthRequestParameterNames.SubjectTokenType, TokenTypeNames.GetName(TokenType.AccessToken)),
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.ClientSecret, ClientSecret),
            new(OAuthRequestParameterNames.Resource, FirstResource),
            new(OAuthRequestParameterNames.Resource, SecondResource)
        ];

        using FormUrlEncodedContent content = new(rawForm);
        using HttpResponseMessage response = await host.SharedHttpClient!
            .PostAsync(tokenUrl, content, TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);


        //The subject token already carries an act claim naming a prior actor (it is itself a
        //delegated token). The new exchange adds the current actor on top of that chain.
        Dictionary<string, object> priorAct = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = PriorActorIdentity
        };
        await WireBranchingValidatorAsync(app, subjectToken: new ValidatedSecurityToken
        {
            Subject = SubjectIdentity,
            Scope = GrantedScope,
            Act = priorAct
        }).ConfigureAwait(false);

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
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 Section 4.1</see>: "The "act"
    /// claim value is a JSON object, and members in the JSON object are claims that identify the actor." An
    /// access token the authorization server issued with an <c>act</c> whose <c>sub</c> is the string
    /// <c>"2026-10-01"</c> is presented as the subject token of a further delegation, its claims decoded by
    /// <see cref="JwtPartJson.Default"/>. The token issued for that exchange nests the subject token's
    /// <c>act</c> under the current actor, and its <c>act.act.sub</c> is the JSON string
    /// <c>"2026-10-01"</c>, the text that identified the actor (a <c>sub</c> is a StringOrURI under
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2">RFC 7519 Section 4.1.2</see>).
    /// </summary>
    [TestMethod]
    public async Task ADateShapedActorSubjectInTheSubjectTokenStaysItsTextInTheIssuedActAsync()
    {
        const string DateShapedActor = "2026-10-01";
        const string CurrentActorToken = "current-actor-token-opaque-blob";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        //The fixture's subject and actor tokens resolve to their claims; the current actor's token to the
        //second actor; any other token is one this server issued, whose claims the seam decodes with the
        //library's JWT part decoder and whose act it carries as the subject token's prior actor chain.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(token switch
                    {
                        SubjectTokenValue => new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope },
                        ActorTokenValue => new ValidatedSecurityToken { Subject = DateShapedActor },
                        CurrentActorToken => new ValidatedSecurityToken { Subject = ActorIdentity },
                        _ => DecodeIssuedSubjectToken(token)
                    });
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields firstForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = ActorTokenValue, TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage firstResponse = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, firstForm, TestContext.CancellationToken).ConfigureAwait(false);
        string firstBody = await firstResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)firstResponse.StatusCode, firstBody);

        using JsonDocument firstDoc = JsonDocument.Parse(firstBody);
        string firstToken = firstDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        OutgoingFormFields secondForm = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = firstToken,
            SubjectTokenType = TokenType.AccessToken,
            Actor = new TokenExchangeActor { Token = CurrentActorToken, TokenType = TokenType.AccessToken }
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage secondResponse = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, secondForm, TestContext.CancellationToken).ConfigureAwait(false);
        string secondBody = await secondResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)secondResponse.StatusCode, secondBody);

        using JsonDocument secondDoc = JsonDocument.Parse(secondBody);
        using JsonDocument payload = DecodePayload(secondDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!);
        JsonElement act = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Act);
        Assert.AreEqual(ActorIdentity, act.GetProperty("sub").GetString(), "The outermost act is the current actor.");
        JsonElement priorSubject = act.GetProperty(WellKnownJwtClaimNames.Act).GetProperty("sub");
        Assert.AreEqual(JsonValueKind.String, priorSubject.ValueKind);
        Assert.AreEqual(DateShapedActor, priorSubject.GetString());
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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

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
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
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

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = subject.Scope ?? "read",
                            IssuedTokenType = TokenType.AccessToken
                        });
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial subjectMaterial = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial actorMaterial = await RegisterActorClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

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
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
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

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = subject.Scope ?? "read",
                            IssuedTokenType = TokenType.AccessToken
                        });
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial rejectingMaterial = await RegisterTokenExchangeClientAsync(rejectingApp).ConfigureAwait(false);
        await WireClientAuthenticationAsync(rejectingApp).ConfigureAwait(false);
        await TestHostShell.AlterAsync(rejectingApp.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(null);

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization { Subject = subject.Subject, Scope = GrantedScope });
        }).ConfigureAwait(false);
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
        using VerifierKeyMaterial denyingMaterial = await RegisterTokenExchangeClientAsync(denyingApp).ConfigureAwait(false);
        await WireClientAuthenticationAsync(denyingApp).ConfigureAwait(false);
        await TestHostShell.AlterAsync(denyingApp.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(null);
        }).ConfigureAwait(false);
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
        Assert.AreEqual(400, (int)badSecret.StatusCode, badSecretBody);
        Assert.Contains(OAuthErrors.InvalidClient, badSecretBody);

        //(i) Fail-closed: a host whose token-exchange seams are NOT wired does not
        //materialize the grant — a well-formed token-exchange request never reaches 200.
        await using TestHostShell bare = new(TimeProvider);
        using VerifierKeyMaterial bareMaterial = await RegisterTokenExchangeClientAsync(bare).ConfigureAwait(false);
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
    /// RFC 8693 §2.1: "In processing the request, the authorization server MUST perform the
    /// appropriate validation procedures for the indicated token type" — validation cannot happen if no
    /// seam exists to run it. Client authentication AND the authorization-policy seam ARE wired here;
    /// ONLY <see cref="AuthorizationServerIntegration.ValidateTokenExchangeTokenAsync"/> is deliberately
    /// left unconfigured, isolating that single seam as the cause. Per <c>AuthCodeEndpoints.cs</c>'s
    /// capability-and-seam gate (all three token-exchange seams must be present together), the grant
    /// candidate never materializes, so a well-formed exchange request never reaches the grant at all —
    /// the same fail-closed pattern
    /// <see cref="JwtBearerGrantTests.PresentCredentialsWithNoClientAuthSeamAreRejectedAsInvalidClient"/>
    /// proves for the jwt-bearer grant's client-authentication seam. RFC 6749 §5.2 defines
    /// <c>unsupported_grant_type</c> as "the authorization grant type is not supported by the
    /// authorization server": with the validation seam unwired, THIS server does not serve
    /// token-exchange at all, regardless of the client's own capability, so that is the refusal this
    /// missing seam earns — not <c>unauthorized_client</c>, which names a grant type the server serves
    /// but this particular client is not registered for.
    /// </summary>
    [TestMethod]
    public async Task WellFormedExchangeWithoutTokenValidationSeamDoesNotActivateTheGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);

        //Client authentication AND the authorization-policy seam are wired; ValidateTokenExchangeTokenAsync
        //is deliberately left unconfigured.
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        InvalidOperationException exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () => await WirePermissivePolicyAsync(app).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.Contains(nameof(AuthorizationServerIntegration.ValidateTokenExchangeTokenAsync), exception.Message, StringComparison.Ordinal);

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
        //endpoint-candidate set. RFC 6749 §5.2: "unsupported_grant_type — The authorization grant type
        //is not supported by the authorization server" — the token endpoint's residual grant_type
        //refusal answers this because the missing validation seam means THIS server's wiring does not
        //serve token-exchange, not the host-generic 404 and not unauthorized_client (which would
        //conflate the server's own missing wiring with a client-registration gap).
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.UnsupportedGrantType, body, StringComparison.Ordinal);
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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

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

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
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


            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = subject.Scope ?? "read",
                            IssuedTokenType = TokenType.AccessToken
                        });
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });


            //The policy seam reads the requested scope off the request and echoes it into the granted
            //authorization — the issued token carries exactly the requested scope (§2.2.1). The custom
            //scope has no ScopeToAudience entry, so the issued token's aud is the issuer, the producer's
            //default.

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = request.Scope ?? GrantedScope,
                            IssuedTokenType = TokenType.AccessToken
                        });
        }).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        //The seam knows the subject (it is the fixture's SubjectIdentity) but rejects the exchange by
        //returning null — RFC 8693 §2.2.2 invalid_request. The error body must not echo the subject.

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(null);
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);


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
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        //Wire ALL THREE token-exchange seams: the only thing missing is the capability. A grant that
        //honored a wired seam regardless of capability would serve this; a disjoint grant does not.
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

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
    /// On a tenant granted the
    /// <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> feature — ruling out the
    /// optional capability gate as the explanation — a token-exchange grant whose authorization seam
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
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });


            //The policy seam grants openid — an app opting in to vouch that the exchanged subject is an
            //End-User (token_exchange honors whatever scope the app's authorization
            //seam decides, unlike client_credentials' source-layer narrowing).

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.AccessToken
                        });
        }).ConfigureAwait(false);

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
    /// Refresh-ladder: a refresh token minted by a token-exchange grant
    /// (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.5's SAML-to-OAuth transition shape —
    /// the authorization seam sets <see cref="TokenExchangeAuthorization.IssuedTokenType"/> to
    /// <see cref="TokenType.RefreshToken"/>) never yields an id_token on redemption via
    /// <c>grant_type=refresh_token</c>, even on a tenant granted
    /// <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> — ruling out the capability
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
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,

                //The refresh_token grant's own endpoint match requires this capability
                //(AuthCodeEndpoints.BuildRefreshToken), independent of the tenant-feature gate under
                //test here — without it the redemption leg below would 404 before ever reaching the
                //id_token producer walk.
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });


            //The app opts the exchanged subject into a refresh-token issuance carrying openid — the §4.5
            //SAML-to-OAuth transition shape, where the mint runs through BuildRefreshTokenExchangeResponseAsync
            //and stamps OriginatingGrantType = token_exchange on the stored refresh state.

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
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 Section 2.2.1</see>: "expires_in
    /// RECOMMENDED. The validity lifetime, in seconds, of the token issued by the authorization server." A registration
    /// whose own refresh-token lifetime is one hour, under a policy of 30 days, is answered <c>expires_in</c> 3600 over
    /// the real wire for the refresh token a token exchange issues.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task AnExchangedRefreshTokensExpiresInStatesTheRegistrationsLifetimeAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterRefreshTokenExchangeClientAsync(app).ConfigureAwait(false);
        (Uri tokenUrl, HttpClient http) =
            await StartRefreshTokenExchangeHostAsync(app, material, TimeSpan.FromHours(1)).ConfigureAwait(false);

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);

        Assert.AreEqual(200, mintStatus, mintBody);
        using JsonDocument mintDoc = JsonDocument.Parse(mintBody);
        Assert.AreEqual(3600L, mintDoc.RootElement.GetProperty("expires_in").GetInt64(), mintBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "invalid_grant The
    /// provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid,
    /// expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another
    /// client." A registration whose own refresh-token lifetime is one hour, under a policy of 30 days, is issued a
    /// refresh token by a token exchange that expires at the hour: presented at the refresh grant over the real wire one
    /// hour and one minute later, it is refused <c>invalid_grant</c>.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task AnExchangedRefreshTokenExpiresAtTheRegistrationsLifetimeAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterRefreshTokenExchangeClientAsync(app).ConfigureAwait(false);
        (Uri tokenUrl, HttpClient http) =
            await StartRefreshTokenExchangeHostAsync(app, material, TimeSpan.FromHours(1)).ConfigureAwait(false);

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, mintStatus, mintBody);
        string refreshToken = ReadMember(mintBody, WellKnownTokenTypes.AccessToken);
        TimeProvider.Advance(TimeSpan.FromHours(1) + TimeSpan.FromMinutes(1));

        (int refreshStatus, string refreshBody) = await PostRefreshAsync(
            http, tokenUrl, refreshToken, resource: null).ConfigureAwait(false);

        Assert.AreEqual(400, refreshStatus, refreshBody);
        Assert.Contains(OAuthErrors.InvalidGrant, refreshBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 Section 2.2.1</see>: "expires_in
    /// RECOMMENDED. The validity lifetime, in seconds, of the token issued by the authorization server." A refresh-token
    /// lifetime that is not positive, set as a policy value of minus one minute through the application's policy
    /// resolver, states no lifetime a token can be issued with. The library's own answer to a lifetime it cannot issue
    /// is 500 <c>server_error</c>: the token exchange over the real wire is answered so and no refresh token is issued.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task AnExchangedRefreshTokenUnderANonPositiveLifetimeIsNotIssuedAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterRefreshTokenExchangeClientAsync(app).ConfigureAwait(false);
        (Uri tokenUrl, HttpClient http) = await StartRefreshTokenExchangeHostAsync(app, material, null).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolvePolicyAsync = async (registration, context, ct) =>
            {
                await PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, context, ct).ConfigureAwait(false);
                context.SetRefreshTokenLifetime(TimeSpan.FromMinutes(-1));
            };
        }).ConfigureAwait(false);

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);

        Assert.AreEqual(500, mintStatus, mintBody);
        Assert.Contains("\"error\":\"server_error\"", mintBody, StringComparison.Ordinal);
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, mintBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// The library's own rule for a lifetime it cannot issue, at the token exchange of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 Section 2.2.1</see>, whose response
    /// states the issued token's lifetime in seconds: an access-token policy value of zero, set by the application's
    /// policy resolver, states no lifetime the exchanged access token can be issued with, and the token endpoint answers
    /// it itself without touching the presented subject token. The subject token is an access token this server issued
    /// at an earlier exchange, held live in the application's token store until the expiry its response stated and
    /// removed from it by the application's revocation seam. An impersonation exchange presenting it over the real wire
    /// is answered with status 500 and exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, the host
    /// records no fault, no token is issued and the store still holds the subject token live; once the resolver sets
    /// no such value the same request, presenting the same subject token, is answered 200 with an access token.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task AnAccessTokenUnderAZeroPolicyLifetimeIsNotIssuedAtTheTokenExchangeAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        Dictionary<string, DateTimeOffset> liveTokens = new(StringComparer.Ordinal)
        {
            [SubjectTokenValue] = DateTimeOffset.MaxValue
        };
        Lock liveTokensLock = new();
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync = (token, tokenType, registration, context, ct) =>
            {
                lock(liveTokensLock)
                {
                    bool isLive = liveTokens.TryGetValue(token, out DateTimeOffset expiresAt) && TimeProvider.GetUtcNow() < expiresAt;

                    return ValueTask.FromResult<ValidatedSecurityToken?>(isLive
                        ? new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope }
                        : null);
                }
            };
            candidateIntegration.RevokeTokenAsync = (token, tokenTypeHint, registration, context, ct) =>
            {
                lock(liveTokensLock)
                {
                    _ = liveTokens.Remove(token);
                }

                return ValueTask.CompletedTask;
            };
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        string issuedSubjectToken;
        using(HttpResponseMessage issued = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, BuildImpersonationForm(SubjectTokenValue), TestContext.CancellationToken).ConfigureAwait(false))
        {
            string issuedBody = await issued.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)issued.StatusCode, issuedBody);
            using JsonDocument issuedDocument = JsonDocument.Parse(issuedBody);
            issuedSubjectToken = issuedDocument.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
            int expiresIn = issuedDocument.RootElement.GetProperty("expires_in").GetInt32();
            lock(liveTokensLock)
            {
                liveTokens[issuedSubjectToken] = TimeProvider.GetUtcNow().AddSeconds(expiresIn);
            }
        }

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolvePolicyAsync = async (registration, context, ct) =>
            {
                await PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, context, ct).ConfigureAwait(false);
                context.SetAccessTokenLifetime(TimeSpan.Zero);
            };
        }).ConfigureAwait(false);
        OutgoingFormFields form = BuildImpersonationForm(issuedSubjectToken);

        string refusedBody;
        int refusedStatusCode;
        using(HttpResponseMessage refused = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false))
        {
            refusedStatusCode = (int)refused.StatusCode;
            refusedBody = await refused.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        }

        Exception[] faults = host.ConsumeHttpFaults();

        Assert.AreEqual(500, refusedStatusCode, refusedBody);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            refusedBody);
        Assert.IsEmpty(faults, string.Join(" | ", faults.Select(static fault => fault.Message)));
        lock(liveTokensLock)
        {
            Assert.IsTrue(liveTokens.ContainsKey(issuedSubjectToken),
                "The refused exchange must leave the presented subject token live in the application's token store.");
        }

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolvePolicyAsync = static (registration, context, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, context, ct);
        }).ConfigureAwait(false);
        using HttpResponseMessage exchanged = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string exchangedBody = await exchanged.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)exchanged.StatusCode, exchangedBody);
        Assert.Contains($"\"{WellKnownTokenTypes.AccessToken}\":", exchangedBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// Builds an impersonation exchange of <paramref name="subjectToken"/>, presented as an access token, with the
    /// fixture client's <c>client_secret_post</c> credentials.
    /// </summary>
    /// <param name="subjectToken">The subject token the exchange presents.</param>
    /// <returns>The token request's form.</returns>
    private static OutgoingFormFields BuildImpersonationForm(string subjectToken) =>
        BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = subjectToken,
            SubjectTokenType = TokenType.AccessToken
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));


    /// <summary>
    /// Registers the fixture's client with token exchange, the code grant (which the refresh grant's endpoint match
    /// requires) and the discovery and key-set endpoints.
    /// </summary>
    /// <param name="app">The test host the client is registered on.</param>
    /// <returns>The registered client's key material.</returns>
    private static Task<VerifierKeyMaterial> RegisterRefreshTokenExchangeClientAsync(TestHostShell app) =>
        app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));


    /// <summary>
    /// Sets <paramref name="material"/>'s registration refresh-token lifetime to <paramref name="refreshTokenLifetime"/>,
    /// wires client authentication and an authorization seam that answers every exchange with a refresh token for
    /// <c>openid</c>, and starts the host.
    /// </summary>
    /// <param name="app">The test host the client is registered on.</param>
    /// <param name="material">The registered client.</param>
    /// <param name="refreshTokenLifetime">
    /// The registration's own refresh-token lifetime, or <see langword="null"/> for a registration that sets none.
    /// </param>
    /// <returns>The token endpoint and the client the host is reached with.</returns>
    private async Task<(Uri TokenUrl, HttpClient Http)> StartRefreshTokenExchangeHostAsync(
        TestHostShell app, VerifierKeyMaterial material, TimeSpan? refreshTokenLifetime)
    {
        if(refreshTokenLifetime is TimeSpan registered)
        {
            await app.SetTokenLifetimeAsync(material, WellKnownTokenTypes.RefreshToken, registered, TestContext.CancellationToken).ConfigureAwait(false);
        }

        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

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
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        return (tokenUrl, host.SharedHttpClient!);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "This is
    /// applicable for all access token requests regardless of grant type." A <c>subject_token</c>
    /// whose validated claims surface a <c>cnf.jkt</c> binding
    /// (<see cref="ValidatedSecurityToken.RequiredKeyThumbprint"/>) presented with no DPoP proof at
    /// all must not be exchanged for an unbound access token — the exchange is refused rather than
    /// silently stripping the sender constraint.
    /// </summary>
    [TestMethod]
    public async Task BoundAccessTokenSubjectWithoutProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey boundKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string boundThumbprint = boundKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundSubjectSeamsAsync(app, boundThumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

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
            Assert.Contains(OAuthErrors.InvalidGrant, body);
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 9449 §5 / §6.1: a bound <c>subject_token</c> presented with a DPoP proof for a DIFFERENT
    /// key than the one it is bound to is refused — the key comparison at
    /// <see cref="Verifiable.OAuth.IdJag.IdJagDpopDecision.Evaluate"/> step §9.8.1.2.1 (4) applies
    /// identically here.
    /// </summary>
    [TestMethod]
    public async Task BoundAccessTokenSubjectWithMismatchedProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> boundKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> presentedKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey boundKey = new(boundKeyMaterial, WellKnownJwaValues.Es256);
            DpopKey presentedKey = new(presentedKeyMaterial, WellKnownJwaValues.Es256);
            string boundThumbprint = boundKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundSubjectSeamsAsync(app, boundThumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce still fails the key-mismatch check.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, form,
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
    /// RFC 9449 §5 / §6.1: a bound <c>subject_token</c> presented with a DPoP proof for the SAME key
    /// it is bound to is accepted, and the issued access token is sender-constrained to that key:
    /// <c>token_type</c> DPoP and a <c>cnf.jkt</c> equal to it.
    /// </summary>
    [TestMethod]
    public async Task BoundAccessTokenSubjectWithMatchingProofIssuesDpopBoundAccessToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string thumbprint = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundSubjectSeamsAsync(app, thumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, form,
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);

                using JsonDocument doc = JsonDocument.Parse(body);
                Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, doc.RootElement.GetProperty("token_type").GetString(),
                    "A subject token's bound key, matched by the presented proof, must sender-constrain the issued token.");

                string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                using JsonDocument payload = DecodePayload(accessToken);
                Assert.AreEqual(thumbprint,
                    payload.RootElement.GetProperty(WellKnownJwtClaimNames.Cnf).GetProperty(WellKnownJwtClaimNames.JwkThumbprint).GetString(),
                    "The issued access token's cnf.jkt must equal the subject token's bound key.");
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Regression control: an unbound <c>subject_token</c> presented with no DPoP proof still issues
    /// an unconstrained Bearer access token — the ordinary, unbound exchange is unaffected by the
    /// RFC 9449 §5 sender-constraint enforcement added for bound subject tokens.
    /// </summary>
    [TestMethod]
    public async Task UnboundSubjectTokenWithoutProofIssuesBearerAccessToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireBoundSubjectSeamsAsync(app, requiredKeyThumbprint: null).ConfigureAwait(false);

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
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, doc.RootElement.GetProperty("token_type").GetString(),
            "An unbound subject token presented with no proof must still issue an unconstrained Bearer token.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Cnf, out _),
            "An unbound exchange must carry no cnf claim.");
    }


    /// <summary>
    /// RFC 9449 §5's binding is a MAY the client opts into per request, not gated on the subject
    /// token's own binding: an unbound <c>subject_token</c> presented WITH a valid DPoP proof still
    /// issues a token sender-constrained to that proof's key.
    /// </summary>
    [TestMethod]
    public async Task UnboundSubjectTokenWithProofIssuesDpopBoundAccessToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireBoundSubjectSeamsAsync(app, requiredKeyThumbprint: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string expectedThumbprint = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, form,
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);

                using JsonDocument doc = JsonDocument.Parse(body);
                Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, doc.RootElement.GetProperty("token_type").GetString());

                string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                using JsonDocument payload = DecodePayload(accessToken);
                Assert.AreEqual(expectedThumbprint,
                    payload.RootElement.GetProperty(WellKnownJwtClaimNames.Cnf).GetProperty(WellKnownJwtClaimNames.JwkThumbprint).GetString());
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
    /// <see cref="UnboundSubjectTokenWithProofIssuesDpopBoundAccessToken"/>'s permissive retry
    /// helper does. Under <see cref="PolicyProfile.Rfc6749WithPkce"/> — a profile
    /// <see cref="ClientPolicyProfiles.RequiresDpop"/> does NOT mandate — a nonce-less proof still
    /// answers 400 <c>use_dpop_nonce</c> with a non-empty <c>DPoP-Nonce</c> header, and the retry
    /// carrying that exact nonce succeeds.
    /// </summary>
    [TestMethod]
    public async Task NonceLessProofUnderOptionalDpopProfileIsChallengedThenSucceedsAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireBoundSubjectSeamsAsync(app, requiredKeyThumbprint: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);

            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithMandatoryDpopNonceChallengeAsync(
                host.SharedHttpClient!, tokenUrl, form,
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "This is
    /// applicable for all access token requests regardless of grant type." A registration whose
    /// profile mandates DPoP-bound access tokens (<see cref="ClientPolicyProfiles.RequiresDpop"/>) is
    /// refused when a Token Exchange request carries no proof at all, even for an unbound
    /// <c>subject_token</c>. The specification text leaves the exact status open; the concrete
    /// refusal the shared validator issues for a missing-but-mandated proof is the §8
    /// <c>use_dpop_nonce</c> challenge, asserted here by error code.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RegistrationRequiringDpopWithoutAProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app, PolicyProfile.Haip10).ConfigureAwait(false);
        await WireBoundSubjectSeamsAsync(app, requiredKeyThumbprint: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

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
        Assert.Contains(OAuthErrors.UseDpopNonce, body,
            "A registration whose profile mandates DPoP must refuse a proof-less Token Exchange request.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">§6.1</see>: under a registration
    /// whose profile mandates DPoP, a Token Exchange request for an unbound <c>subject_token</c>
    /// presenting a valid proof still issues a token sender-constrained to that proof's key —
    /// <c>token_type</c> answers <c>DPoP</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RegistrationRequiringDpopWithAProofAnswersDpopTokenType()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app, PolicyProfile.Haip10).ConfigureAwait(false);
        await WireBoundSubjectSeamsAsync(app, requiredKeyThumbprint: null).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            //A mandating profile also enforces the §8 nonce mechanism on a nonce-less proof — answer
            //the challenge once, exactly as the client road does, before asserting the bound outcome.
            string firstProof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);
            using HttpResponseMessage challenge = await OAuthTestTransport.PostFormAsync(
                host.SharedHttpClient!, tokenUrl, form, OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
            string challengeBody = await challenge.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, (int)challenge.StatusCode, challengeBody);
            Assert.Contains(OAuthErrors.UseDpopNonce, challengeBody);
            Assert.IsTrue(challenge.Headers.TryGetValues(WellKnownHttpHeaderNames.DPoPNonce, out IEnumerable<string>? nonceValues),
                "RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");
            string freshNonce = nonceValues!.First();

            string htu = $"{material.Registration.IssuerUri!.GetLeftPart(UriPartial.Authority)}/connect/{segment}/token";
            DpopProofClaims retryClaims = new()
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = htu,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = freshNonce
            };
            string retryProof = await DpopProofConstruction.BuildAsync(
                retryClaims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
                host.SharedHttpClient!, tokenUrl, form, OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)response.StatusCode, body);

            using JsonDocument doc = JsonDocument.Parse(body);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, doc.RootElement.GetProperty("token_type").GetString(),
                "A registration whose profile mandates DPoP must still bind the token to a presented proof for an unbound subject token.");
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: the
    /// <c>use_dpop_nonce</c> challenge must answer before the subject-token seam is ever consulted —
    /// the seam may carry a side effect (RFC 8693 §2.1's impersonation/delegation policy decision), so
    /// a challenge the client retries must not already have run it once. The retry, presenting the
    /// fresh nonce, consults the seam exactly once.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RegistrationRequiringDpopChallengeDoesNotConsultTheSubjectSeamBeforeTheRetry()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app, PolicyProfile.Haip10).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        int subjectSeamInvocations = 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                {
                    subjectSeamInvocations++;

                    return ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });
                };
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            string firstProof = await BuildTokenEndpointDpopProofAsync(dpopKey, segment, material).ConfigureAwait(false);
            using HttpResponseMessage challenge = await OAuthTestTransport.PostFormAsync(
                host.SharedHttpClient!, tokenUrl, form, OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
            string challengeBody = await challenge.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, (int)challenge.StatusCode, challengeBody);
            Assert.Contains(OAuthErrors.UseDpopNonce, challengeBody);
            Assert.AreEqual(0, subjectSeamInvocations,
                "The use_dpop_nonce challenge must never consult the subject-token seam.");

            Assert.IsTrue(challenge.Headers.TryGetValues(WellKnownHttpHeaderNames.DPoPNonce, out IEnumerable<string>? nonceValues),
                "RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");
            string freshNonce = nonceValues!.First();

            string htu = $"{material.Registration.IssuerUri!.GetLeftPart(UriPartial.Authority)}/connect/{segment}/token";
            DpopProofClaims retryClaims = new()
            {
                Htm = WellKnownHttpMethods.Post,
                Htu = htu,
                Iat = TimeProvider.GetUtcNow(),
                Jti = Guid.NewGuid().ToString("N"),
                Nonce = freshNonce
            };
            string retryProof = await DpopProofConstruction.BuildAsync(
                retryClaims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            using HttpResponseMessage retry = await OAuthTestTransport.PostFormAsync(
                host.SharedHttpClient!, tokenUrl, form, OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);
            string retryBody = await retry.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)retry.StatusCode, retryBody);
            Assert.AreEqual(1, subjectSeamInvocations,
                "The retry with the fresh nonce must succeed and consult the subject-token seam exactly once.");
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 9449 §5 on the §4.5 SAML-to-OAuth Refresh-Token issuance branch: a bound
    /// <c>subject_token</c> presented with no DPoP proof at all must not be exchanged for a Refresh
    /// Token either — the enforcement is not limited to the access-token issuance branch.
    /// </summary>
    [TestMethod]
    public async Task BoundSubjectExchangedForRefreshTokenWithoutProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey boundKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string boundThumbprint = boundKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundSubjectForRefreshIssuanceSeamsAsync(app, boundThumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

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
            Assert.Contains(OAuthErrors.InvalidGrant, body);
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The refresh-token issuance branch's mismatched-key counterpart to
    /// <see cref="BoundSubjectExchangedForRefreshTokenWithoutProofIsRefused"/>.
    /// </summary>
    [TestMethod]
    public async Task BoundSubjectExchangedForRefreshTokenWithMismatchedProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> boundKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> presentedKeyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey boundKey = new(boundKeyMaterial, WellKnownJwaValues.Es256);
            DpopKey presentedKey = new(presentedKeyMaterial, WellKnownJwaValues.Es256);
            string boundThumbprint = boundKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundSubjectForRefreshIssuanceSeamsAsync(app, boundThumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce still fails the key-mismatch check.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, form,
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
    /// RFC 9449 §5: "When an authorization server supporting DPoP issues a refresh token to a public
    /// client that presents a valid DPoP proof at the token endpoint, the refresh token MUST be bound
    /// to the respective public key." A bound <c>subject_token</c> presented with the matching proof
    /// on the §4.5 Refresh-Token issuance branch must therefore itself mint a refresh token bound to
    /// that key — verified against the server's own stored flow state, the same slot the ordinary
    /// <c>refresh_token</c> grant reads to enforce the binding on later use.
    /// </summary>
    [TestMethod]
    public async Task BoundSubjectExchangedForRefreshTokenWithMatchingProofBindsMintedRefreshToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(keyMaterial, WellKnownJwaValues.Es256);
            string thumbprint = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
            await WireBoundSubjectForRefreshIssuanceSeamsAsync(app, thumbprint).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

            OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
            {
                SubjectToken = SubjectTokenValue,
                SubjectTokenType = TokenType.AccessToken
            }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof;
            //the retry carrying the echoed nonce succeeds.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, form,
                nonce => BuildTokenEndpointDpopProofAsync(dpopKey, segment, material, nonce),
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);

                using JsonDocument doc = JsonDocument.Parse(body);
                Assert.AreEqual(
                    TokenTypeNames.GetName(TokenType.RefreshToken),
                    doc.RootElement.GetProperty(OAuthRequestParameterNames.IssuedTokenType).GetString(),
                    "Sanity: the exchange must have minted a refresh token (§4.5).");
                string refreshToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

                ServerRefreshTokenIssuedState storedState = host.FlowStates.Values
                    .Select(entry => entry.State)
                    .OfType<ServerRefreshTokenIssuedState>()
                    .Single(state => state.RefreshToken == refreshToken);
                Assert.IsNotNull(storedState.Confirmation, "The minted refresh token must record the DPoP binding.");
                Assert.AreEqual(thumbprint, storedState.Confirmation!.JwkThumbprint,
                    "The minted refresh token's bound key must equal the subject token's bound key.");
            }
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>: "If the
    /// authorization server is unwilling or unable to issue a token for any target service indicated by the
    /// "resource" or "audience" parameters, the "invalid_target" error code SHOULD be used in the error response."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see> defines an
    /// <c>audience</c> as "The logical name of the target service where the client intends to use the requested
    /// security token", so the authorization seam may authorize a name that is no
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see> resource indicator. A
    /// refresh token is issued only for a grant whose audience a refresh of it issues again, and the refresh state
    /// holds an authorized audience only as entries each an absolute URI with no white space and no fragment
    /// component, the rule this library carries an audience by. An exchange whose authorization seam authorizes a
    /// refresh token for an audience that holds an entry outside that rule is refused before anything is stored:
    /// 400 with exactly the body
    /// <c>{"error":"invalid_target","error_description":"A refresh token cannot be issued for the authorized audience."}</c>,
    /// and the flow store holds no refresh state. The rule is this library's. The rows: a logical name
    /// (<c>billing</c>); a logical name with spaces (<c>internal billing service</c>); a URI-shaped name with a
    /// space (<c>https://api.example.com/orders v2</c>), which <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// reads as absolute by escaping the space; and an absolute URI beside a logical name
    /// (<c>https://billing.example.com/api</c> and <c>billing</c>).
    /// </summary>
    /// <param name="caseName">The audience the seam authorizes, by row name.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("logical-name", DisplayName = "a logical name")]
    [DataRow("logical-name-with-spaces", DisplayName = "a logical name with spaces")]
    [DataRow("uri-shaped-name-with-a-space", DisplayName = "a URI-shaped name with a space")]
    [DataRow("uri-beside-logical-name", DisplayName = "an absolute URI beside a logical name")]
    public async Task AnExchangeForARefreshTokenUnderAnAudienceARefreshCannotIssueIsRefusedAsync(string caseName)
    {
        IReadOnlyList<string> authorizedAudience = caseName switch
        {
            "logical-name" => ["billing"],
            "logical-name-with-spaces" => ["internal billing service"],
            "uri-shaped-name-with-a-space" => ["https://api.example.com/orders v2"],
            "uri-beside-logical-name" => ["https://billing.example.com/api", "billing"],
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken,
                            Audience = authorizedAudience
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(host.SharedHttpClient!, tokenUrl, TokenType.RefreshToken)
            .ConfigureAwait(false);
        string[] storedRefreshResources =
        [
            .. host.FlowStates.Values
                .Select(entry => entry.State)
                .OfType<ServerRefreshTokenIssuedState>()
                .Select(state => $"'{state.Resource}'")
        ];
        string record = $"{status} '{body}' stored refresh states with resource [{string.Join(", ", storedRefreshResources)}]";

        Assert.AreEqual(400, status, record);
        Assert.AreEqual(
            "{\"error\":\"invalid_target\",\"error_description\":\"A refresh token cannot be issued for the authorized audience.\"}",
            body,
            record);
        Assert.IsEmpty(storedRefreshResources, $"A refused exchange stores no refresh state. {record}");
    }


    /// <summary>
    /// An authorization seam that authorizes a refresh token for an audience holding an entry that is null or white
    /// space only, a <see cref="TokenExchangeAuthorization.Audience"/> entry that names no target service, is answered
    /// <c>server_error</c> with the fixed description and nothing is issued: the answer is 500 with the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, the
    /// flow store holds no refresh state, and the identifier seam is never called, so the refusal draws no identifier
    /// for a refresh token or its flow. The authorization is the application's decision and names the audience of
    /// the issued token, so an entry that names none is the seam's own defect, answered as
    /// <see cref="AnAuthorizationThatNamesNoSubjectIssuesNothingAsync"/> answers the same seam's blank subject. The
    /// answer departs from <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section
    /// 2.2.2</see>, whose <c>invalid_target</c> is the error for a target service the server is unwilling or unable to
    /// issue a token for; answering the server's own defect <c>server_error</c> is this library's rule. The rows: a
    /// null entry; an entry of white space beside an absolute URI.
    /// </summary>
    /// <param name="caseName">The audience the seam authorizes, by row name.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("null-entry", DisplayName = "a null entry")]
    [DataRow("white-space-entry", DisplayName = "an entry of white space beside an absolute URI")]
    public async Task AnExchangeForARefreshTokenUnderAnAudienceHoldingAnEntryThatNamesNoTargetIssuesNothingAsync(string caseName)
    {
        IReadOnlyList<string> authorizedAudience = caseName switch
        {
            "null-entry" => [null!],
            "white-space-entry" => ["https://cal.example.com/", " "],
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        Func<int> countIdentifierSeamCalls = static () => 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken,
                            Audience = authorizedAudience
                        });

            countIdentifierSeamCalls = CountIdentifierSeamCalls(candidateIntegration);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(host.SharedHttpClient!, tokenUrl, TokenType.RefreshToken)
            .ConfigureAwait(false);
        int storedRefreshStates = host.FlowStates.Values
            .Select(entry => entry.State)
            .OfType<ServerRefreshTokenIssuedState>()
            .Count();
        int identifierSeamCalls = countIdentifierSeamCalls();
        string record = $"{status} '{body}' stored refresh states {storedRefreshStates} identifier seam calls {identifierSeamCalls}";

        Assert.AreEqual(500, status, record);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            body,
            record);
        Assert.AreEqual(0, storedRefreshStates, $"An exchange that issues nothing stores no refresh state. {record}");
        Assert.AreEqual(0, identifierSeamCalls, $"An exchange that issues nothing draws no identifier. {record}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 Section 2.2</see>: "In the case of a
    /// "refresh_token" or "authorization_code" grant type request, such policy may limit the acceptable resources to
    /// those that were originally granted by the resource owner or a subset thereof." An exchange whose authorization
    /// seam authorizes a refresh token for an audience list that reads differently when it is read again (its first
    /// enumeration yields the absolute URI <c>https://cal.example.com/</c>, every later reading the logical name
    /// <c>billing api</c>) is answered 200 with the refresh token, the stored refresh state's granted resource set is
    /// <c>https://cal.example.com/</c>, the audience the exchange's checks read, the list is read once at the mint
    /// (one enumeration and no read through its indexer), and a refresh of the token naming no <c>resource</c>
    /// issues an access token whose <c>aud</c> is exactly <c>["https://cal.example.com/"]</c>. The authorized
    /// audience is read once and the refresh state holds what was checked; that rule is this library's.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnExchangeForARefreshTokenUnderAnAudienceThatReadsDifferentlyAgainIsIssuedTheAudienceReadOnceAsync()
    {
        const string CheckedAudience = "https://cal.example.com/";
        ShiftingReadOnlyList authorizedAudience = new([CheckedAudience], ["billing api"]);

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken,
                            Audience = authorizedAudience
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, mintStatus, mintBody);
        string mintedRefreshToken = ReadMember(mintBody, WellKnownTokenTypes.AccessToken);
        string[] storedRefreshResources =
        [
            .. host.FlowStates.Values
                .Select(entry => entry.State)
                .OfType<ServerRefreshTokenIssuedState>()
                .Select(state => state.Resource ?? "null")
        ];
        int enumerationsAtTheMint = authorizedAudience.Enumerations;
        int indexerReadsAtTheMint = authorizedAudience.IndexerReads;
        string audienceAtTheMint = authorizedAudience.ToString();

        //The refresh is drawn before any assertion of the stored state, so a red answer renders both.
        (int refreshStatus, string refreshBody) = await PostRefreshAsync(
            http, tokenUrl, mintedRefreshToken, resource: null).ConfigureAwait(false);
        string refreshAudience = "none";
        if(refreshStatus == 200)
        {
            using JsonDocument refreshPayload = DecodePayload(ReadMember(refreshBody, WellKnownTokenTypes.AccessToken));
            refreshAudience = refreshPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetRawText();
        }

        string record = $"stored refresh Resource [{string.Join(", ", storedRefreshResources.Select(static resource => $"'{resource}'"))}]"
            + $" audience at the mint {audienceAtTheMint} refresh {refreshStatus} aud {refreshAudience} '{refreshBody}'";

        Assert.HasCount(1, storedRefreshResources, record);
        Assert.AreEqual(CheckedAudience, storedRefreshResources[0], record);
        Assert.AreEqual(1, enumerationsAtTheMint, record);
        Assert.AreEqual(0, indexerReadsAtTheMint, record);
        Assert.AreEqual(200, refreshStatus, record);
        Assert.AreEqual("[\"https://cal.example.com/\"]", refreshAudience, record);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 Section 2.2</see>: "In the case of a
    /// "refresh_token" or "authorization_code" grant type request, such policy may limit the acceptable resources to
    /// those that were originally granted by the resource owner or a subset thereof." An exchange whose authorization
    /// seam authorizes a refresh token for an audience list that is a collection whose enumerator yields the
    /// absolute URI <c>https://cal.example.com/</c> and whose bulk copy writes the logical name <c>billing api</c> is
    /// answered 200 with the refresh token, the stored refresh state's granted resource set is
    /// <c>https://cal.example.com/</c>, the enumerator's entry, a refresh of the token naming no <c>resource</c>
    /// issues an access token whose <c>aud</c> is exactly <c>["https://cal.example.com/"]</c>, and the list's bulk
    /// copy is never called. The authorized audience is copied by its enumerator into the library's own buffer, never
    /// by a bulk copy that hands that buffer to the application; that rule is this library's.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnExchangeForARefreshTokenUnderAnAudienceCollectionIsIssuedTheEnumeratedAudienceWithoutABulkCopyAsync()
    {
        const string CheckedAudience = "https://cal.example.com/";
        DivergentBulkCopyList authorizedAudience = new([CheckedAudience], ["billing api"]);

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken,
                            Audience = authorizedAudience
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);
        string[] storedRefreshResources =
        [
            .. host.FlowStates.Values
                .Select(entry => entry.State)
                .OfType<ServerRefreshTokenIssuedState>()
                .Select(state => state.Resource ?? "null")
        ];
        int copyToCallsAtTheMint = authorizedAudience.CopyToCalls;

        //The refresh is drawn before any assertion of the stored state, so a red answer renders both.
        int refreshStatus = 0;
        string refreshBody = "none";
        string refreshAudience = "none";
        if(mintStatus == 200)
        {
            string mintedRefreshToken = ReadMember(mintBody, WellKnownTokenTypes.AccessToken);
            (refreshStatus, refreshBody) = await PostRefreshAsync(
                http, tokenUrl, mintedRefreshToken, resource: null).ConfigureAwait(false);
            if(refreshStatus == 200)
            {
                using JsonDocument refreshPayload = DecodePayload(ReadMember(refreshBody, WellKnownTokenTypes.AccessToken));
                refreshAudience = refreshPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud).GetRawText();
            }
        }

        string record = $"mint {mintStatus} '{mintBody}' stored refresh Resource [{string.Join(", ", storedRefreshResources.Select(static resource => $"'{resource}'"))}]"
            + $" audience at the mint {authorizedAudience} refresh {refreshStatus} aud {refreshAudience} '{refreshBody}'";

        Assert.AreEqual(200, mintStatus, record);
        Assert.HasCount(1, storedRefreshResources, record);
        Assert.AreEqual(CheckedAudience, storedRefreshResources[0], record);
        Assert.AreEqual(0, copyToCallsAtTheMint, record);
        Assert.AreEqual(200, refreshStatus, record);
        Assert.AreEqual("[\"https://cal.example.com/\"]", refreshAudience, record);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 Section 2.2</see>: "In the case of a
    /// "refresh_token" or "authorization_code" grant type request, such policy may limit the acceptable resources to
    /// those that were originally granted by the resource owner or a subset thereof." An exchange whose
    /// authorization seam authorizes a refresh token for two absolute URIs (<c>https://cal.example.com/</c> and
    /// <c>https://contacts.example.com/</c>), an audience a refresh issues again, is answered 200 with the refresh
    /// token, and a refresh of it naming no <c>resource</c> issues an access token whose <c>aud</c> is exactly those
    /// two in the authorized order, the grant's audience.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnExchangeForARefreshTokenUnderAbsoluteUriAudiencesIssuesARefreshOfExactlyThoseAsync()
    {
        await AssertARefreshOfAnExchangedRefreshTokenIsIssuedItsGrantAudienceAsync(
            ["https://cal.example.com/", "https://contacts.example.com/"]).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-3">RFC 9068 Section 3</see>: "If the request does
    /// not include a "resource" parameter, the authorization server MUST use a default resource indicator in the
    /// "aud" claim." An exchange whose authorization seam authorizes a refresh token and names no audience is
    /// answered 200 with the refresh token, and a refresh of it naming no <c>resource</c> issues an access token
    /// whose <c>aud</c> is the producer's default resource indicator, the issuer.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnExchangeForARefreshTokenUnderNoAudienceIssuesARefreshOfTheDefaultAudienceAsync()
    {
        await AssertARefreshOfAnExchangedRefreshTokenIsIssuedItsGrantAudienceAsync([]).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives a token exchange over the wire whose authorization seam authorizes a refresh token for
    /// <paramref name="authorizedAudience"/>, asserts the mint's 200 and its refresh token type, then redeems the
    /// refresh token naming no <c>resource</c> and asserts the refresh's 200 and that its access token's <c>aud</c>
    /// is exactly <paramref name="authorizedAudience"/>, or the issuer when that is empty.
    /// </summary>
    /// <param name="authorizedAudience">The audience the seam authorizes for the refresh token.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertARefreshOfAnExchangedRefreshTokenIsIssuedItsGrantAudienceAsync(
        IReadOnlyList<string> authorizedAudience)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken,
                            Audience = authorizedAudience
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;
        string[] expectedAudience = authorizedAudience.Count == 0
            ? [material.Registration.IssuerUri!.OriginalString]
            : [.. authorizedAudience];

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, mintStatus, mintBody);
        Assert.AreEqual(TokenTypeNames.GetName(TokenType.RefreshToken), ReadMember(mintBody, OAuthRequestParameterNames.IssuedTokenType));
        string mintedRefreshToken = ReadMember(mintBody, WellKnownTokenTypes.AccessToken);

        (int refreshStatus, string refreshBody) = await PostRefreshAsync(
            http, tokenUrl, mintedRefreshToken, resource: null).ConfigureAwait(false);
        Assert.AreEqual(200, refreshStatus, refreshBody);
        Assert.AreSequenceEqual(expectedAudience, ReadAudience(ReadMember(refreshBody, WellKnownTokenTypes.AccessToken)));
    }


    /// <summary>
    /// The converse of <see cref="AnExchangeForARefreshTokenUnderAnAudienceARefreshCannotIssueIsRefusedAsync"/>:
    /// when every granted <see cref="TokenExchangeAuthorization.Audience"/> entry IS a well-formed,
    /// whitespace-free absolute URI (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC
    /// 8707 §2</see> shape), the carry populates the minted refresh state's <c>Resource</c>, and a
    /// later <c>resource</c>-narrowing refresh against it succeeds, narrowing the issued access
    /// token's <c>aud</c> to that subset.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RefreshTokenMintedFromUriAudiencesCarriesResourceAndNarrowsOnRefresh()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);


        const string ResourceA = "https://cal.example.com/";
        const string ResourceB = "https://contacts.example.com/";
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken,
                            Audience = [ResourceA, ResourceB]
                        });
        }).ConfigureAwait(false);

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
        string refreshToken = exchangeDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        using HttpResponseMessage narrowedRefresh = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.Resource] = ResourceB
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string narrowedBody = await narrowedRefresh.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)narrowedRefresh.StatusCode, narrowedBody);

        using JsonDocument narrowedDoc = JsonDocument.Parse(narrowedBody);
        string narrowedAccessToken = narrowedDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument narrowedPayload = DecodePayload(narrowedAccessToken);
        JsonElement aud = narrowedPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.Array, aud.ValueKind);
        Assert.HasCount(1, aud.EnumerateArray().ToList(),
            $"The URI-audience carry must have populated Resource so the narrowing refresh can subset "
            + $"it to ResourceB alone. Payload: {narrowedPayload.RootElement}");
        Assert.AreEqual(ResourceB, aud[0].GetString());
    }


    /// <summary>
    /// An audience the exchange's authorization seam decided keeps its spelling in every access token
    /// issued from it, across the exchange, a refresh token minted by a second exchange, and the
    /// rotation of that refresh token.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>
    /// defines an <c>audience</c> as "The logical name of the target service", a name "that both the
    /// client and the authorization server understand", so the server never folds it; and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 section 2.2</see>
    /// makes the resources a <c>refresh_token</c> request may name "those that were originally
    /// granted by the resource owner or a subset thereof", with "any refresh token that is returned"
    /// bound "to the full original grant". One authorization seam answers by
    /// <see cref="TokenExchangeRequest.RequestedTokenType"/>: an access token when one is requested,
    /// a refresh token when one is (the refresh token rides the <c>access_token</c> member of the
    /// response, <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 section
    /// 2.2.1</see>), with the same audience both times. The first case is an upper-case URI-shaped
    /// audience whose two refreshes name it in its own spelling and then in the lower-case host
    /// spelling, which the folded comparison of the granted set admits; the second is a non-ASCII
    /// logical name, an audience no <c>resource</c> can restate, whose two refreshes name no
    /// resource and guard the audience carried into the refresh state. Every <c>aud</c> is the
    /// audience exactly as the seam authorized it. Each case runs inside a
    /// <see cref="ServedCultureScope"/> set to "tr-TR".
    /// </summary>
    /// <param name="shape">The audience the seam authorizes and how the refreshes name it.</param>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(ExchangeAudienceShape.UpperCaseUri)]
    [DataRow(ExchangeAudienceShape.NonAsciiLogicalName)]
    public async Task AnExchangeAuthorizedAudienceKeepsItsSpellingThroughRefreshAndRotationAsync(ExchangeAudienceShape shape)
    {
        string audience = shape switch
        {
            ExchangeAudienceShape.UpperCaseUri => "HTTPS://WIKI.RS.EXAMPLE/Api",
            ExchangeAudienceShape.NonAsciiLogicalName => "https://" + char.ConvertFromUtf32(0x212A) + "ey.example/",
            _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null)
        };
        string? firstRefreshResource = shape switch
        {
            ExchangeAudienceShape.UpperCaseUri => audience,
            _ => null
        };
        string? secondRefreshResource = shape switch
        {
            ExchangeAudienceShape.UpperCaseUri => "https://wiki.rs.example/Api",
            _ => null
        };

        await using TestHostShell app = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            app, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = request.RequestedTokenType == TokenType.RefreshToken
                                ? TokenType.RefreshToken
                                : TokenType.AccessToken,
                            Audience = [audience]
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        (int exchangeStatus, string exchangeBody) = await PostExchangeAsync(http, tokenUrl, TokenType.AccessToken).ConfigureAwait(false);
        Assert.AreEqual(200, exchangeStatus, exchangeBody);
        Assert.AreSequenceEqual([audience], ReadAudience(ReadMember(exchangeBody, WellKnownTokenTypes.AccessToken)));

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, mintStatus, mintBody);
        string mintedRefreshToken = ReadMember(mintBody, WellKnownTokenTypes.AccessToken);

        (int firstStatus, string firstBody) = await PostRefreshAsync(
            http, tokenUrl, mintedRefreshToken, firstRefreshResource).ConfigureAwait(false);
        Assert.AreEqual(200, firstStatus, firstBody);
        Assert.AreSequenceEqual([audience], ReadAudience(ReadMember(firstBody, WellKnownTokenTypes.AccessToken)));
        string rotatedRefreshToken = ReadMember(firstBody, OAuthRequestParameterNames.RefreshToken);
        Assert.AreNotEqual(mintedRefreshToken, rotatedRefreshToken, "The first refresh must rotate the refresh token.");

        (int secondStatus, string secondBody) = await PostRefreshAsync(
            http, tokenUrl, rotatedRefreshToken, secondRefreshResource).ConfigureAwait(false);
        Assert.AreEqual(200, secondStatus, secondBody);
        Assert.AreSequenceEqual([audience], ReadAudience(ReadMember(secondBody, WellKnownTokenTypes.AccessToken)));

        culture.AssertEveryRequestWasServedUnder("tr-TR", 4);
    }


    /// <summary>
    /// Two audiences an exchange's authorization seam authorizes stay two audiences in every access
    /// token a refresh of the minted refresh token issues, although they differ only in the case of
    /// the host and so share a comparison key.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>
    /// defines <c>audience</c> as "The logical name of the target service where the client intends to
    /// use the requested security token", a name whose interpretation "requires that the value be
    /// something that both the client and the authorization server understand", so two spellings the
    /// seam authorized are two names, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 section 2.2</see> binds
    /// "any refresh token that is returned" "to the full original grant". Section 2.2 states that
    /// binding for the <c>authorization_code</c> case; this library applies the same binding to the
    /// <c>refresh_token</c> grant of an exchange-minted refresh token under the section's "such
    /// policy may limit the acceptable resources to those that were originally granted by the
    /// resource owner or a subset thereof", and the rotation that keeps the full set is this
    /// library's rule. The seam authorizes <c>https://API.EXAMPLE/x</c> and
    /// <c>https://api.example/x</c> for an exchange that issues a refresh token. A refresh naming no
    /// <c>resource</c> issues an <c>aud</c> of both spellings in the authorized order; a refresh
    /// naming <c>https://api.example/x</c> issues an <c>aud</c> of that spelling alone; and the
    /// refresh token that narrowed refresh rotated to, refreshed naming no <c>resource</c>, issues
    /// both spellings again. A refresh naming <c>https://API.EXAMPLE/x</c> is answered with
    /// <c>https://api.example/x</c> alone, because the request is folded at its ingress, a rule of
    /// this library.
    /// </summary>
    /// <param name="firstRefreshResource">The <c>resource</c> the first refresh names, or <see langword="null"/> for none.</param>
    /// <param name="isRotatedTokenRefreshed">Whether the rotated refresh token is refreshed again, naming no <c>resource</c>.</param>
    /// <param name="expectedAudience">The <c>aud</c> of the access token the last refresh issues.</param>
    [TestMethod]
    [DataRow(null, false, new[] { "https://API.EXAMPLE/x", "https://api.example/x" })]
    [DataRow("https://api.example/x", false, new[] { "https://api.example/x" })]
    [DataRow("https://api.example/x", true, new[] { "https://API.EXAMPLE/x", "https://api.example/x" })]
    [DataRow("https://API.EXAMPLE/x", false, new[] { "https://api.example/x" })]
    public async Task TwoAuthorizedAudiencesThatShareAComparisonKeyStayTwoThroughRefreshAsync(
        string? firstRefreshResource, bool isRotatedTokenRefreshed, string[] expectedAudience)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = WellKnownScopes.OpenId,
                            IssuedTokenType = TokenType.RefreshToken,
                            Audience = ["https://API.EXAMPLE/x", "https://api.example/x"]
                        });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        (int mintStatus, string mintBody) = await PostExchangeAsync(http, tokenUrl, TokenType.RefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, mintStatus, mintBody);
        string mintedRefreshToken = ReadMember(mintBody, WellKnownTokenTypes.AccessToken);

        (int refreshStatus, string refreshBody) = await PostRefreshAsync(
            http, tokenUrl, mintedRefreshToken, firstRefreshResource).ConfigureAwait(false);
        Assert.AreEqual(200, refreshStatus, refreshBody);

        if(isRotatedTokenRefreshed)
        {
            string rotatedRefreshToken = ReadMember(refreshBody, OAuthRequestParameterNames.RefreshToken);
            Assert.AreNotEqual(mintedRefreshToken, rotatedRefreshToken, "The first refresh must rotate the refresh token.");

            (refreshStatus, refreshBody) = await PostRefreshAsync(
                http, tokenUrl, rotatedRefreshToken, resource: null).ConfigureAwait(false);
            Assert.AreEqual(200, refreshStatus, refreshBody);
        }

        Assert.AreSequenceEqual(expectedAudience, ReadAudience(ReadMember(refreshBody, WellKnownTokenTypes.AccessToken)));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A token exchange form carrying an empty <c>resource</c>
    /// occurrence followed by a well-formed one names exactly that one indicator: the empty
    /// occurrence is dropped, the exchange succeeds, and the authorization seam observes the one
    /// indicator. A blank element inside a request object's <c>resource</c> claim is a different
    /// fact, not a parameter sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeDropsAnEmptyResourceOccurrenceMixedWithValidOne()
    {
        const string Resource = "https://rs.example.com/api";

        IReadOnlyList<string>? seenResources = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Resource, "");
        form.Add(OAuthRequestParameterNames.Resource, Resource);
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsNotNull(seenResources, "The authorization seam must have run.");
        Assert.AreSequenceEqual([Resource], seenResources!);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A token exchange form whose only <c>resource</c> occurrence
    /// is empty is an exchange without a <c>resource</c> parameter: it succeeds and the authorization
    /// seam observes no resource. A blank element inside a request object's <c>resource</c> claim is
    /// a different fact, not a parameter sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeTreatsAnEmptyResourceValueAsOmitted()
    {
        IReadOnlyList<string>? seenResources = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
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
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Resource, "");
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsNotNull(seenResources, "The authorization seam must have run.");
        Assert.IsEmpty(seenResources!);
    }


    /// <summary>
    /// RFC 8693 §2.1: "Multiple "audience" parameters may be used to indicate that the issued token
    /// is intended to be used at the multiple audiences listed." The genuine multi-audience wire form
    /// is the REPEATED <c>audience</c> parameter, exactly as <see cref="OAuthRequestParameterNames.Resource"/>
    /// repeats. The grant reads every occurrence and carries all of them, in order, into the
    /// <see cref="TokenExchangeRequest.Audience"/> the authorization seam reads.
    /// </summary>
    [TestMethod]
    public async Task RepeatedAudienceCarriesEveryTargetIntoTheAuthorizationSeamInOrder()
    {
        const string FirstAudience = "https://svc.example/orders";
        const string SecondAudience = "https://svc.example/inventory";

        IReadOnlyList<string>? seenAudiences = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    seenAudiences = request.Audience;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = TokenType.AccessToken
                        });
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Audience, FirstAudience);
        form.Add(OAuthRequestParameterNames.Audience, SecondAudience);
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Assert.IsNotNull(seenAudiences, "The authorization seam must have run.");
        Assert.HasCount(2, seenAudiences!);
        Assert.AreEqual(FirstAudience, seenAudiences![0]);
        Assert.AreEqual(SecondAudience, seenAudiences[1]);
    }


    /// <summary>
    /// A repeated <c>audience</c> occurrence carrying the SAME value twice names one target, not two:
    /// the grant deduplicates ordinally (the same treatment <see cref="OAuthRequestParameterNames.Resource"/>
    /// gets), so the authorization seam observes it exactly once.
    /// </summary>
    [TestMethod]
    public async Task RepeatedIdenticalAudienceReachesTheAuthorizationSeamOnce()
    {
        const string Audience = "https://svc.example/orders";

        IReadOnlyList<string>? seenAudiences = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    seenAudiences = request.Audience;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = TokenType.AccessToken
                        });
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Audience, Audience);
        form.Add(OAuthRequestParameterNames.Audience, Audience);
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Assert.IsNotNull(seenAudiences, "The authorization seam must have run.");
        Assert.HasCount(1, seenAudiences!);
        Assert.AreEqual(Audience, seenAudiences![0]);
    }


    /// <summary>
    /// The <c>audience</c> parameter is a logical name, not a URI the server normalizes:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>
    /// says it is "The logical name of the target service where the client intends to use the
    /// requested security token" and that "Interpretation of the name requires that the value be
    /// something that both the client and the authorization server understand." A value shaped like a
    /// URI in upper case (<c>HTTPS://SVC.EXAMPLE/Orders</c>) is therefore handed to the authorization
    /// seam exactly as sent, and the seam here returns it as the audience, so the issued access
    /// token's <c>aud</c> carries the same spelling. The scheme and host fold of a
    /// <c>resource</c> (<see cref="TokenExchangeResourceIsFoldedAtIngressAsync"/>) does not apply to it.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task AnAudienceParameterReachesTheAuthorizationSeamAndTheIssuedTokenUnfoldedAsync()
    {
        const string audience = "HTTPS://SVC.EXAMPLE/Orders";

        IReadOnlyList<string>? seenAudiences = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    seenAudiences = request.Audience;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            Audience = request.Audience,
                            IssuedTokenType = TokenType.AccessToken
                        });
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Audience, audience);
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        Assert.IsNotNull(seenAudiences, "The authorization seam must have run.");
        Assert.AreSequenceEqual([audience], seenAudiences);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreSequenceEqual(
            [audience],
            ReadAudience(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A token exchange form carrying a well-formed <c>audience</c>
    /// occurrence followed by an empty one names exactly that one audience
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>'s
    /// <c>audience</c> parameter): the empty occurrence is dropped, the exchange succeeds, the
    /// authorization seam observes the one audience, and the issued access token's <c>aud</c> carries it.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeDropsAnEmptyAudienceOccurrenceMixedWithValidOne()
    {
        const string audience = "https://svc.example/orders";

        IReadOnlyList<string>? seenAudiences = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    seenAudiences = request.Audience;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            Audience = request.Audience,
                            IssuedTokenType = TokenType.AccessToken
                        });
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Audience, audience);
        form.Add(OAuthRequestParameterNames.Audience, "");
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsNotNull(seenAudiences, "The authorization seam must have run.");
        Assert.AreSequenceEqual([audience], seenAudiences!);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreSequenceEqual(
            [audience],
            ReadAudience(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A token exchange form whose only <c>audience</c> occurrence
    /// is empty is an exchange without an <c>audience</c> parameter
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>
    /// makes it OPTIONAL): it succeeds and the authorization seam observes no audience.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeTreatsAnEmptyAudienceValueAsOmitted()
    {
        IReadOnlyList<string>? seenAudiences = null;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    seenAudiences = request.Audience;

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = TokenType.AccessToken
                        });
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Audience, "");
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsNotNull(seenAudiences, "The authorization seam must have run.");
        Assert.IsEmpty(seenAudiences!);
    }


    /// <summary>
    /// A whitespace-only <c>audience</c> occurrence is a value, not a parameter sent without one
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>
    /// omits only a parameter "sent without a value"). It names no logical name for the target
    /// service (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 section 2.1</see>),
    /// so the request is not valid and is refused with the general <c>invalid_request</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 section 2.2.2</see>,
    /// which registers no audience-specific error code.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeRefusesAWhitespaceAudienceOccurrenceAsInvalidRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        form.Add(OAuthRequestParameterNames.Audience, "https://svc.example/orders");
        form.Add(OAuthRequestParameterNames.Audience, "   ");
        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", body, StringComparison.Ordinal,
            $"A whitespace-only audience occurrence is a value and must fail the request closed. Got: {body}");
    }


    /// <summary>
    /// RFC 8693 §2.2.2: "If the authorization server is unwilling or unable to issue a token for any
    /// target service indicated by the "resource" or "audience" parameters, the "invalid_target" error
    /// code SHOULD be used in the error response." A policy denial (<see langword="null"/>) on a plain exchange that named an
    /// <c>audience</c> (no <c>resource</c>) is <c>invalid_target</c>, not the general <c>invalid_request</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyDenialWithNamedAudienceIsInvalidTarget()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(null);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new OutgoingFormFields
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken),
            [OAuthRequestParameterNames.Audience] = "https://svc.example/orders"
        }.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidTarget}\"", body, StringComparison.Ordinal, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>: "If the
    /// request itself is not valid or if either the "subject_token" or "actor_token" are invalid for any reason,
    /// or are unacceptable based on policy, the authorization server MUST construct an error response, as
    /// specified in Section 5.2 of [RFC6749]. The value of the "error" parameter MUST be the "invalid_request"
    /// error code." The application's request seam refuses the request's <c>requested_token_type</c>, the
    /// parameter
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3</see>
    /// defines as "requested_token_type: REQUIRED - The value urn:ietf:params:oauth:token-type:id-jag indicates
    /// that an Identity Assertion JWT Authorization Grant is being requested.", and the exchange is answered 400
    /// <c>invalid_request</c> with the seam's description. The seam runs before the <c>subject_token</c> is
    /// validated (handed to <see cref="ValidateTokenExchangeTokenDelegate"/>), a rule of this library: the
    /// subject-token validator is never called.
    /// </summary>
    [TestMethod]
    public async Task ARequestSeamRefusalAnswersBeforeTheSubjectTokenIsValidatedAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        int subjectTokenValidations = 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                {
                    _ = Interlocked.Increment(ref subjectTokenValidations);

                    return ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });
                };
            WirePermissivePolicy(candidateIntegration);
            candidateIntegration.ValidateTokenExchangeRequestAsync =
                static (request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeRequestRefusal?>(new TokenExchangeRequestRefusal
                    {
                        Parameter = "requested_token_type",
                        Description = "requested_token_type must be urn:ietf:params:oauth:token-type:id-jag."
                    });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(host.SharedHttpClient!, tokenUrl, TokenType.AccessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, status, body);
        Assert.AreEqual(
            """{"error":"invalid_request","error_description":"requested_token_type must be urn:ietf:params:oauth:token-type:id-jag."}""",
            body);
        Assert.AreEqual(0, subjectTokenValidations, "The subject token must not be validated once the request seam has refused the request.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>: "Client
    /// authentication to the authorization server is done using the normal mechanisms provided by OAuth 2.0."
    /// A client that fails form authentication at a server that advertises no <c>client_secret_basic</c> is answered
    /// 400 <c>invalid_client</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>), and the
    /// application's request seam, which this library calls after client authentication, is never called.
    /// </summary>
    [TestMethod]
    public async Task AnUnauthenticatedClientIsRefusedBeforeTheRequestSeamAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

        Func<int> countRequestSeamCalls = static () => 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            countRequestSeamCalls = CountRequestSeamCalls(candidateIntegration);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(
            host.SharedHttpClient!, tokenUrl, TokenType.AccessToken, clientSecret: "not-the-secret-of-the-machine")
            .ConfigureAwait(false);

        Assert.AreEqual(400, status, body);
        Assert.AreEqual("""{"error":"invalid_client","error_description":"Client authentication failed."}""", body);
        Assert.AreEqual(0, countRequestSeamCalls(), "The request seam must not be called for a client that failed authentication.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>:
    /// "requested_token_type OPTIONAL. An identifier, as described in Section 3, for the type of the requested
    /// security token. If the requested type is unspecified, the issued token type is at the discretion of the
    /// authorization server". With no request seam wired, an exchange without <c>requested_token_type</c> is
    /// answered 200 and its <c>issued_token_type</c> is the type the authorization seam chose.
    /// </summary>
    [TestMethod]
    public async Task WithoutTheRequestSeamRequestedTokenTypeStaysOptionalAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(host.SharedHttpClient!, tokenUrl, requestedTokenType: null)
            .ConfigureAwait(false);

        Assert.AreEqual(200, status, body);
        Assert.AreEqual(
            "urn:ietf:params:oauth:token-type:access_token",
            ReadMember(body, OAuthRequestParameterNames.IssuedTokenType),
            "The issued_token_type must be the type the authorization seam chose.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>: "If the
    /// authorization server is unwilling or unable to issue a token for any target service indicated by the
    /// "resource" or "audience" parameters, the "invalid_target" error code SHOULD be used in the error
    /// response." <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see>: "The
    /// following error code is provided for an authorization server to indicate problems with the requested
    /// resource(s) in response to an authorization request or access token request." A refusal of the request seam
    /// that names <c>resource</c> or <c>audience</c> is answered 400 <c>invalid_target</c> with the seam's
    /// description.
    /// </summary>
    /// <param name="parameter">The parameter the seam refuses, which the request names.</param>
    /// <param name="description">The seam's reason.</param>
    [TestMethod]
    [DataRow("resource", "This resource is not served.")]
    [DataRow("audience", "This audience is not served.")]
    public async Task ARefusalOfATargetIsAnsweredInvalidTargetAsync(string parameter, string description)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeRequestAsync =
                (request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeRequestRefusal?>(new TokenExchangeRequestRefusal
                    {
                        Parameter = parameter,
                        Description = description
                    });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        bool isResource = string.Equals(parameter, "resource", StringComparison.Ordinal);
        (int status, string body) = await PostExchangeAsync(
            host.SharedHttpClient!,
            tokenUrl,
            TokenType.AccessToken,
            resource: isResource ? "https://wiki.rs.example/api" : null,
            audience: isResource ? null : "https://svc.example/orders").ConfigureAwait(false);

        Assert.AreEqual(400, status, body);
        Assert.AreEqual($$"""{"error":"invalid_target","error_description":"{{description}}"}""", body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "Values for
    /// the "error_description" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E." A description of the request seam that holds a QUOTATION MARK (U+0022) and a LATIN SMALL LETTER
    /// E WITH ACUTE (U+00E9) is written without them. Reducing the description to the characters the set allows,
    /// rather than refusing it, is a rule of this library:
    /// <see cref="Verifiable.Server.ErrorDescriptionCharset.Sanitize(string?)"/> removes every other character.
    /// </summary>
    [TestMethod]
    public async Task ARefusalDescriptionIsWrittenInsideTheRfc6749CharsetAsync()
    {
        string quotationMark = char.ConvertFromUtf32(0x0022);
        string description = "Refused: " + char.ConvertFromUtf32(0x00E9) + " and " + quotationMark + "quoted" + quotationMark;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeRequestAsync =
                (request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeRequestRefusal?>(new TokenExchangeRequestRefusal
                    {
                        Parameter = "scope",
                        Description = description
                    });
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(host.SharedHttpClient!, tokenUrl, TokenType.AccessToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, status, body);
        Assert.AreEqual("""{"error":"invalid_request","error_description":"Refused:  and quoted"}""", body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see>:
    /// "requested_token_type OPTIONAL. An identifier, as described in Section 3, for the type of the requested
    /// security token. If the requested type is unspecified, the issued token type is at the discretion of the
    /// authorization server and may be dictated by knowledge of the requirements of the service or resource indicated
    /// by the "resource" or "audience" parameter." The type is the server's to choose only when the request leaves it
    /// unspecified, so a stated type the authorization seam does not issue is a request the server does not honor,
    /// and <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see> gives the
    /// answer: "If the request itself is not valid or if either the "subject_token" or "actor_token" are invalid for
    /// any reason, or are unacceptable based on policy, the authorization server MUST construct an error response, as
    /// specified in Section 5.2 of [RFC6749]. The value of the "error" parameter MUST be the "invalid_request" error
    /// code." An exchange that states the access token type while the authorization seam chooses an ID-JAG, and one
    /// that states the ID-JAG type while the seam chooses an access token, are each answered 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The requested_token_type cannot be issued for this request."}</c>,
    /// and the host's identifier seam is asked for no <c>jti</c>.
    /// </summary>
    /// <param name="caseName">
    /// The stated type and the authorization seam's choice: <c>accessTokenStatedIdJagChosen</c> or
    /// <c>idJagStatedAccessTokenChosen</c>.
    /// </param>
    [TestMethod]
    [DataRow("accessTokenStatedIdJagChosen", DisplayName = "the access token type stated, an ID-JAG chosen")]
    [DataRow("idJagStatedAccessTokenChosen", DisplayName = "the ID-JAG type stated, an access token chosen")]
    public async Task AStatedRequestedTokenTypeTheAuthorizationDoesNotIssueIsRefusedAsync(string caseName)
    {
        (TokenType requestedTokenType, TokenType issuedTokenType) = caseName switch
        {
            "accessTokenStatedIdJagChosen" => (TokenType.AccessToken, TokenType.IdJag),
            "idJagStatedAccessTokenChosen" => (TokenType.IdJag, TokenType.AccessToken),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app, isIdJagAllowed: true)
            .ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        Func<int> countTokenIdentifiers = static () => 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = issuedTokenType
                        });

            countTokenIdentifiers = CountTokenIdentifiers(candidateIntegration);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        (int status, string body) = await PostExchangeAsync(
            host.SharedHttpClient!, tokenUrl, requestedTokenType, audience: ResourceServerAudience).ConfigureAwait(false);
        string record = $"{status} '{body}' token identifiers generated {countTokenIdentifiers()}";

        Assert.AreEqual(400, status, record);
        Assert.AreEqual(
            """{"error":"invalid_request","error_description":"The requested_token_type cannot be issued for this request."}""",
            body,
            record);
        Assert.AreEqual(0, countTokenIdentifiers(), $"No token identifier is generated for a type the request did not state. {record}");
    }


    /// <summary>
    /// The token endpoint calls the application's request seam only after its own checks of the request, a rule of
    /// this library, so a request those checks refuse never reaches the seam. A <c>resource</c> with a fragment is
    /// answered 400 with the library's <c>invalid_target</c> body:
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see> reads "The value
    /// of the "resource" parameter MUST be an absolute URI, as specified by Section 4.3 of [RFC3986], that MAY include
    /// a query component and MUST NOT include a fragment component.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see> provides the code: "The
    /// following error code is provided for an authorization server to indicate problems with the requested
    /// resource(s) in response to an authorization request or access token request." An <c>audience</c> of one space
    /// is answered 400 <c>invalid_request</c>, the code
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see> gives a request
    /// that is not valid. A registration whose profile requires a DPoP proof that sends none is answered 400
    /// <c>use_dpop_nonce</c>, the refusal <see cref="RegistrationRequiringDpopWithoutAProofIsRefused"/> proves. In
    /// each case the request seam counts no call.
    /// </summary>
    /// <param name="caseName">
    /// The request the library refuses: <c>resourceWithFragment</c>, <c>audienceOfOneSpace</c> or
    /// <c>missingDpopProof</c>.
    /// </param>
    [TestMethod]
    [DataRow("resourceWithFragment", DisplayName = "a resource with a fragment")]
    [DataRow("audienceOfOneSpace", DisplayName = "an audience of one space")]
    [DataRow("missingDpopProof", DisplayName = "a registration that requires a DPoP proof, with none")]
    public async Task ARequestTheLibraryRefusesNeverReachesTheRequestSeamAsync(string caseName)
    {
        (PolicyProfile? Profile, string? Resource, string? Audience, string ExpectedError, string? ExpectedBody) refusedRequest = caseName switch
        {
            "resourceWithFragment" => (null, "https://api.example/x#frag", null, "invalid_target", MalformedResourceBody),
            "audienceOfOneSpace" => (
                null,
                null,
                " ",
                "invalid_request",
                """{"error":"invalid_request","error_description":"The audience parameter must not contain a whitespace-only occurrence."}"""),
            "missingDpopProof" => (PolicyProfile.Haip10, null, null, "use_dpop_nonce", null),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };
        (PolicyProfile? profile, string? resource, string? audience, string expectedError, string? expectedBody) = refusedRequest;

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app, profile).ConfigureAwait(false);
        await WireImpersonationSeamsAsync(app).ConfigureAwait(false);
        if(profile is not null)
        {
            _ = await app.EnableDpopAsync().ConfigureAwait(false);
        }

        Func<int> countRequestSeamCalls = static () => 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            countRequestSeamCalls = CountRequestSeamCalls(candidateIntegration);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        if(resource is not null)
        {
            form.Add(OAuthRequestParameterNames.Resource, resource);
        }

        if(audience is not null)
        {
            form.Add(OAuthRequestParameterNames.Audience, audience);
        }

        form = form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string record = $"{(int)response.StatusCode} '{body}' request seam calls {countRequestSeamCalls()}";

        Assert.AreEqual(400, (int)response.StatusCode, record);
        Assert.AreEqual(expectedError, ReadMember(body, "error"), record);
        if(expectedBody is not null)
        {
            Assert.AreEqual(expectedBody, body, record);
        }

        Assert.AreEqual(0, countRequestSeamCalls(), $"The request seam must not be called for a request the library refuses. {record}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." An <c>authorization_details</c> of
    /// one space is sent with a value, and the library's own read of the parameter would drop it before either seam,
    /// so neither could parse it as
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3.3</see>
    /// requires: "If authorization_details is present, the IdP MUST parse it as a JSON array and process each
    /// authorization detail object according to [RFC9396]." The token exchange answers it as the token endpoint
    /// answers an <c>authorization_details</c> it cannot parse, 400 with the body
    /// <c>{"error":"invalid_authorization_details","error_description":"authorization_details could not be parsed."}</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9396#section-5">RFC 9396 Section 5</see>: "The AS MUST refuse
    /// to process any unknown authorization details type or authorization details not conforming to the respective
    /// type definition."; <see href="https://www.rfc-editor.org/rfc/rfc9396#section-6">RFC 9396 Section 6</see> names
    /// the code at the token request: "Otherwise, the AS refuses the request with the error code
    /// invalid_authorization_details (similar to invalid_scope)."), before the request seam, the subject token's
    /// validation and the authorization seam, each of which counts no call. Refusing the value, rather than leaving
    /// it to the seams that parse every other value, is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task AnAuthorizationDetailsOfWhiteSpaceIsRefusedBeforeEitherSeamAsync()
    {
        OutgoingFormFields form = ExchangeFormOfTheFixtureSubject();
        form.Add(OAuthRequestParameterNames.AuthorizationDetails, " ");

        (int status, string body, int requestSeamCalls, int tokenValidations, int authorizations, _, _, string record) =
            await PostThroughCountingSeamsAsync(form).ConfigureAwait(false);

        Assert.AreEqual(400, status, record);
        Assert.AreEqual(
            """{"error":"invalid_authorization_details","error_description":"authorization_details could not be parsed."}""",
            body,
            record);
        Assert.AreEqual(0, requestSeamCalls, $"The request seam must not be called. {record}");
        Assert.AreEqual(0, tokenValidations, $"The subject token must not be validated. {record}");
        Assert.AreEqual(0, authorizations, $"The authorization seam must not be called. {record}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." An <c>authorization_details</c>
    /// sent empty is such a parameter: the exchange is answered 200, and the authorization seam receives a request
    /// whose <see cref="TokenExchangeRequest.AuthorizationDetails"/> is <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyAuthorizationDetailsIsOmittedAsync()
    {
        OutgoingFormFields form = ExchangeFormOfTheFixtureSubject();
        form.Add(OAuthRequestParameterNames.AuthorizationDetails, string.Empty);

        (int status, _, _, _, int authorizations, TokenExchangeRequest? authorizedRequest, _, string record) =
            await PostThroughCountingSeamsAsync(form).ConfigureAwait(false);

        Assert.AreEqual(200, status, record);
        Assert.AreEqual(1, authorizations, $"The request must reach the authorization seam once. {record}");
        Assert.IsNotNull(authorizedRequest, record);
        Assert.IsNull(authorizedRequest.AuthorizationDetails, $"An empty authorization_details is omitted. {record}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." and "Request and response
    /// parameters MUST NOT be included more than once."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 Section 2.1</see> lets two of its
    /// parameters repeat, <c>resource</c> and <c>audience</c>, each to name several targets. A token exchange that
    /// sends <c>subject_token</c>, <c>subject_token_type</c>, <c>actor_token</c>, <c>actor_token_type</c>,
    /// <c>requested_token_type</c>, <c>scope</c> or <c>authorization_details</c> with a value more than once is
    /// answered 400 with
    /// <c>{"error":"invalid_request","error_description":"A token exchange parameter was sent more than once."}</c>,
    /// the code <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see> gives
    /// a request that is not valid, before the request seam, the token validation and the authorization seam, each
    /// of which counts no call. An occurrence of white space only is sent with a value, so an <c>actor_token</c> of
    /// one space beside a valued <c>actor_token</c> is such a repeat. Read as absent, a repeated
    /// <c>requested_token_type</c> would leave the issued type to the authorization seam, a repeated
    /// <c>actor_token</c> with its type would turn a delegation into an impersonation, a repeated <c>scope</c> would
    /// hand the authorization seam no requested scope, and a repeated <c>authorization_details</c> would carry no
    /// authorization details into the issued token. Refusing the request is this library's reading of the two
    /// sentences.
    /// </summary>
    /// <param name="caseName">
    /// The repeated parameter: <c>requestedTokenType</c>, <c>actorToken</c> (its type sent once),
    /// <c>actorTokenAndItsType</c> (each sent twice), <c>scope</c>, <c>authorizationDetails</c>, <c>subjectToken</c>
    /// and <c>subjectTokenType</c> (each sent twice), or <c>actorTokenOfWhiteSpace</c> (an <c>actor_token</c> of one
    /// space, then one with a value, its type once).
    /// </param>
    [TestMethod]
    [DataRow("requestedTokenType", DisplayName = "requested_token_type sent twice")]
    [DataRow("actorToken", DisplayName = "actor_token sent twice, actor_token_type once")]
    [DataRow("actorTokenAndItsType", DisplayName = "actor_token and actor_token_type each sent twice")]
    [DataRow("scope", DisplayName = "scope sent twice")]
    [DataRow("authorizationDetails", DisplayName = "authorization_details sent twice")]
    [DataRow("subjectToken", DisplayName = "subject_token sent twice")]
    [DataRow("subjectTokenType", DisplayName = "subject_token_type sent twice")]
    [DataRow("actorTokenOfWhiteSpace", DisplayName = "actor_token of one space beside one with a value")]
    public async Task ASingleValuedParameterSentMoreThanOnceIsRefusedBeforeEitherSeamAsync(string caseName)
    {
        string accessTokenType = TokenTypeNames.GetName(TokenType.AccessToken);
        string authorizationDetails = """[{"type":"example"}]""";

        //The form of the fixture's subject sends subject_token and subject_token_type once each, so one more
        //occurrence of either sends it twice.
        (string Name, string Value, int Times)[] repeated = caseName switch
        {
            "requestedTokenType" => [(OAuthRequestParameterNames.RequestedTokenType, accessTokenType, 2)],
            "actorToken" => [(OAuthRequestParameterNames.ActorToken, ActorTokenValue, 2), (OAuthRequestParameterNames.ActorTokenType, accessTokenType, 1)],
            "actorTokenAndItsType" => [(OAuthRequestParameterNames.ActorToken, ActorTokenValue, 2), (OAuthRequestParameterNames.ActorTokenType, accessTokenType, 2)],
            "scope" => [(OAuthRequestParameterNames.Scope, GrantedScope, 2)],
            "authorizationDetails" => [(OAuthRequestParameterNames.AuthorizationDetails, authorizationDetails, 2)],
            "subjectToken" => [(OAuthRequestParameterNames.SubjectToken, SubjectTokenValue, 1)],
            "subjectTokenType" => [(OAuthRequestParameterNames.SubjectTokenType, accessTokenType, 1)],
            "actorTokenOfWhiteSpace" => [(OAuthRequestParameterNames.ActorToken, " ", 1), (OAuthRequestParameterNames.ActorToken, ActorTokenValue, 1), (OAuthRequestParameterNames.ActorTokenType, accessTokenType, 1)],
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        OutgoingFormFields form = ExchangeFormOfTheFixtureSubject();
        foreach((string name, string value, int times) in repeated)
        {
            for(int i = 0; i < times; i++)
            {
                form.Add(name, value);
            }
        }

        (int status, string body, int requestSeamCalls, int tokenValidations, int authorizations, _, _, string record) =
            await PostThroughCountingSeamsAsync(form).ConfigureAwait(false);

        Assert.AreEqual(400, status, record);
        Assert.AreEqual(
            """{"error":"invalid_request","error_description":"A token exchange parameter was sent more than once."}""",
            body,
            record);
        Assert.AreEqual(0, requestSeamCalls, $"The request seam must not be called. {record}");
        Assert.AreEqual(0, tokenValidations, $"No token must be validated. {record}");
        Assert.AreEqual(0, authorizations, $"The authorization seam must not be called. {record}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." A token exchange that sends
    /// <c>actor_token=</c> and then <c>actor_token</c> with a value, its <c>actor_token_type</c> once, sends
    /// <c>actor_token</c> once: it is answered 200 as the delegation that sends the valued occurrence alone, the
    /// request seam and the authorization seam are each called once, the subject token and the actor token are each
    /// validated, and the authorization seam receives the actor token's value and its type.
    /// </summary>
    [TestMethod]
    public async Task AnActorTokenSentWithoutAValueBesideOneWithAValueIsOneOccurrenceAsync()
    {
        OutgoingFormFields form = ExchangeFormOfTheFixtureSubject();
        form.Add(OAuthRequestParameterNames.ActorToken, string.Empty);
        form.Add(OAuthRequestParameterNames.ActorToken, ActorTokenValue);
        form.Add(OAuthRequestParameterNames.ActorTokenType, TokenTypeNames.GetName(TokenType.AccessToken));

        (int status, _, int requestSeamCalls, int tokenValidations, int authorizations, TokenExchangeRequest? authorizedRequest, _, string record) =
            await PostThroughCountingSeamsAsync(form).ConfigureAwait(false);

        Assert.AreEqual(200, status, record);
        Assert.AreEqual(1, requestSeamCalls, $"The request seam must be called once. {record}");
        Assert.AreEqual(2, tokenValidations, $"The subject token and the actor token must each be validated. {record}");
        Assert.AreEqual(1, authorizations, $"The request must reach the authorization seam once. {record}");
        Assert.IsNotNull(authorizedRequest, record);
        Assert.AreEqual(ActorTokenValue, authorizedRequest.ActorToken, $"The actor token is the valued occurrence. {record}");
        Assert.AreEqual(TokenType.AccessToken, authorizedRequest.ActorTokenType, $"The actor token's type is the one sent. {record}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." A token exchange that sends
    /// <c>requested_token_type=</c> and then
    /// <c>requested_token_type=urn:ietf:params:oauth:token-type:access_token</c> sends <c>requested_token_type</c>
    /// once: it is answered 200 as the request that states that type once, and the authorization seam, called once,
    /// receives the access token type as the requested type.
    /// </summary>
    [TestMethod]
    public async Task ARequestedTokenTypeSentWithoutAValueBesideOneWithAValueIsOneOccurrenceAsync()
    {
        OutgoingFormFields form = ExchangeFormOfTheFixtureSubject();
        form.Add(OAuthRequestParameterNames.RequestedTokenType, string.Empty);
        form.Add(OAuthRequestParameterNames.RequestedTokenType, TokenTypeNames.GetName(TokenType.AccessToken));

        (int status, _, int requestSeamCalls, _, int authorizations, TokenExchangeRequest? authorizedRequest, _, string record) =
            await PostThroughCountingSeamsAsync(form).ConfigureAwait(false);

        Assert.AreEqual(200, status, record);
        Assert.AreEqual(1, requestSeamCalls, $"The request seam must be called once. {record}");
        Assert.AreEqual(1, authorizations, $"The request must reach the authorization seam once. {record}");
        Assert.IsNotNull(authorizedRequest, record);
        Assert.AreEqual(TokenType.AccessToken, authorizedRequest.RequestedTokenType, $"The requested type is the valued occurrence. {record}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." The token exchange treats such an
    /// occurrence as omitted when it reads the request and leaves the request as it was received: a token exchange
    /// that sends <c>actor_token=</c> and then <c>actor_token</c> with a value, its <c>actor_token_type</c> once, is
    /// answered 200, and the incoming request the authorization seam's context carries
    /// (<see cref="Verifiable.Server.IncomingRequest.Fields"/>) holds both occurrences of <c>actor_token</c> as they
    /// were sent, the empty one first. Reading the omission without writing into the request is this library's rule.
    /// </summary>
    [TestMethod]
    public async Task AnOccurrenceSentWithoutAValueStaysInTheRequestTheApplicationSeesAsync()
    {
        OutgoingFormFields form = ExchangeFormOfTheFixtureSubject();
        form.Add(OAuthRequestParameterNames.ActorToken, string.Empty);
        form.Add(OAuthRequestParameterNames.ActorToken, ActorTokenValue);
        form.Add(OAuthRequestParameterNames.ActorTokenType, TokenTypeNames.GetName(TokenType.AccessToken));

        (int status, _, _, _, int authorizations, _, Verifiable.Server.RequestFields? authorizedFields, string record) =
            await PostThroughCountingSeamsAsync(form).ConfigureAwait(false);

        Assert.AreEqual(200, status, record);
        Assert.AreEqual(1, authorizations, $"The request must reach the authorization seam once. {record}");
        Assert.IsNotNull(authorizedFields, $"The authorization seam's context must carry the incoming request. {record}");
        string[] actorTokenOccurrences = [.. authorizedFields.GetValues(OAuthRequestParameterNames.ActorToken)];
        Assert.AreSequenceEqual(
            new[] { string.Empty, ActorTokenValue },
            actorTokenOccurrences,
            $"The request keeps every actor_token occurrence as sent; it holds [{string.Join(", ", actorTokenOccurrences.Select(static value => $"'{value}'"))}]. {record}");
    }


    /// <summary>
    /// Builds the token exchange form of the fixture's subject token: <c>grant_type</c>, <c>subject_token</c> and
    /// <c>subject_token_type</c> (the access token type), each once, without client authentication.
    /// </summary>
    /// <returns>The form, to which a row adds its own parameters.</returns>
    private static OutgoingFormFields ExchangeFormOfTheFixtureSubject() =>
        new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.SubjectToken] = SubjectTokenValue,
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };


    /// <summary>
    /// Posts <paramref name="form"/> with the client's <c>client_secret_post</c> authentication to the token
    /// exchange over the loopback listener, with three counting seams wired: a request seam that refuses nothing, a
    /// token validator that accepts every token as the fixture's subject, and an authorization seam that issues an
    /// access token and keeps the request it receives and the request fields its context carries.
    /// </summary>
    /// <param name="form">The form a row sends, without client authentication.</param>
    /// <returns>
    /// The answer, each seam's call count, the request the authorization seam received and the fields of the
    /// incoming request its context carried.
    /// </returns>
    private async Task<(int StatusCode, string Body, int RequestSeamCalls, int TokenValidations, int Authorizations, TokenExchangeRequest? AuthorizedRequest, Verifiable.Server.RequestFields? AuthorizedFields, string Record)> PostThroughCountingSeamsAsync(OutgoingFormFields form)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterTokenExchangeClientAsync(app).ConfigureAwait(false);
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        int tokenValidations = 0;
        int authorizations = 0;
        TokenExchangeRequest? authorizedRequest = null;
        Verifiable.Server.RequestFields? authorizedFields = null;
        Func<int> countRequestSeamCalls = static () => 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                {
                    _ = Interlocked.Increment(ref tokenValidations);

                    return ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });
                };

            candidateIntegration.AuthorizeTokenExchangeAsync =
                (subject, actor, request, registration, context, ct) =>
                {
                    _ = Interlocked.Increment(ref authorizations);
                    _ = Interlocked.Exchange(ref authorizedRequest, request);
                    _ = Interlocked.Exchange(ref authorizedFields, context.IncomingRequest?.Fields);

                    return ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = TokenType.AccessToken
                        });
                };

            countRequestSeamCalls = CountRequestSeamCalls(candidateIntegration);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!,
            tokenUrl,
            form.WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret)),
            TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        int requestSeamCalls = countRequestSeamCalls();
        int tokenValidationCount = Volatile.Read(ref tokenValidations);
        int authorizationCount = Volatile.Read(ref authorizations);
        string record = $"{(int)response.StatusCode} '{body}' request seam calls {requestSeamCalls} token validations "
            + $"{tokenValidationCount} authorizations {authorizationCount}";

        return (
            (int)response.StatusCode, body, requestSeamCalls, tokenValidationCount, authorizationCount,
            Volatile.Read(ref authorizedRequest), Volatile.Read(ref authorizedFields), record);
    }


    /// <summary>
    /// Installs on the editable candidate an identifier seam that counts the token identifiers
    /// (<see cref="WellKnownIdentifierPurposes.OAuthJti"/>) the host is asked for and hands every request to the seam
    /// it wraps.
    /// </summary>
    /// <param name="candidateIntegration">The editable candidate the seam is installed on.</param>
    /// <returns>Reads how many token identifiers the host has been asked for.</returns>
    private static Func<int> CountTokenIdentifiers(AuthorizationServerIntegration candidateIntegration)
    {
        int tokenIdentifierCalls = 0;
        Verifiable.Server.GenerateIdentifierDelegate original = candidateIntegration.GenerateIdentifierAsync!;
        candidateIntegration.GenerateIdentifierAsync = (purpose, context, ct) =>
        {
            if(purpose.Equals(WellKnownIdentifierPurposes.OAuthJti))
            {
                _ = Interlocked.Increment(ref tokenIdentifierCalls);
            }

            return original(purpose, context, ct);
        };

        return () => Volatile.Read(ref tokenIdentifierCalls);
    }


    /// <summary>
    /// Installs on the editable candidate an identifier seam that counts every identifier the host is asked for,
    /// whatever its purpose, and hands every request to the seam it wraps.
    /// </summary>
    /// <param name="candidateIntegration">The editable candidate the seam is installed on.</param>
    /// <returns>Reads how many identifiers the host has been asked for.</returns>
    private static Func<int> CountIdentifierSeamCalls(AuthorizationServerIntegration candidateIntegration)
    {
        int identifierSeamCalls = 0;
        Verifiable.Server.GenerateIdentifierDelegate original = candidateIntegration.GenerateIdentifierAsync!;
        candidateIntegration.GenerateIdentifierAsync = (purpose, context, ct) =>
        {
            _ = Interlocked.Increment(ref identifierSeamCalls);

            return original(purpose, context, ct);
        };

        return () => Volatile.Read(ref identifierSeamCalls);
    }


    /// <summary>
    /// Installs on the editable candidate a request seam that counts its calls and refuses nothing.
    /// </summary>
    /// <param name="candidateIntegration">The editable candidate the seam is installed on.</param>
    /// <returns>Reads how many times the request seam has been called.</returns>
    private static Func<int> CountRequestSeamCalls(AuthorizationServerIntegration candidateIntegration)
    {
        int requestSeamCalls = 0;
        candidateIntegration.ValidateTokenExchangeRequestAsync =
            (request, registration, context, ct) =>
            {
                _ = Interlocked.Increment(ref requestSeamCalls);

                return ValueTask.FromResult<TokenExchangeRequestRefusal?>(null);
            };

        return () => Volatile.Read(ref requestSeamCalls);
    }


    /// <summary>
    /// Registers a truly grant-only confidential client — no
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> — allowed the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> capability plus
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/> (some end-to-end tests
    /// obtain a real subject/actor token via the client_credentials grant). Grant-only token-exchange
    /// issuance works because <see cref="Rfc9068AccessTokenProducer"/>'s <c>RequiredCapability</c> is
    /// <see langword="null"/> — an optional tenant-feature gate, not a grant-capability proxy —
    /// so the endpoint-match capability alone is sufficient. RegisterDpopClient
    /// supplies the AccessTokenIssuance signing keys the producers resolve. The discovery/jwks
    /// capabilities round out the standard surface. <see cref="AddMachineScopeAudienceMappingAsync"/> maps
    /// <see cref="MachineScope"/> onto <see cref="ResourceServerAudience"/> so the real
    /// client_credentials subject/actor tokens minted below still reach a concrete audience —
    /// <c>openid</c> is narrowed away from every <c>client_credentials</c> grant.
    /// </summary>
    /// <param name="app">The host to register the client on.</param>
    /// <param name="profile">
    /// The client's policy profile — <see cref="PolicyProfile.Rfc6749WithPkce"/> unless a DPoP test
    /// selects a profile <see cref="ClientPolicyProfiles.RequiresDpop"/> mandates against.
    /// </param>
    /// <param name="isIdJagAllowed">
    /// Whether the client is also allowed <see cref="WellKnownCapabilityIdentifiers.OAuthIdJag"/>, so an
    /// authorization seam that selects the id-jag issued type reaches the mint.
    /// </param>
    private static async Task<VerifierKeyMaterial> RegisterTokenExchangeClientAsync(
        TestHostShell app, PolicyProfile? profile = null, bool isIdJagAllowed = false)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthTokenExchange,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);
        if(isIdJagAllowed)
        {
            capabilities = capabilities.Add(WellKnownCapabilityIdentifiers.OAuthIdJag);
        }

        VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: profile ?? PolicyProfile.Rfc6749WithPkce,
            capabilities: capabilities).ConfigureAwait(false);

        await AddMachineScopeAudienceMappingAsync(app, material).ConfigureAwait(false);

        return material;
    }


    /// <summary>
    /// Registers the second confidential client — the acting party — used by the delegation
    /// end-to-end test. It is its own tenant (its own AS issuer and JWKS) so its
    /// <c>client_credentials</c> token's subject (itself) is a distinct real subject, verified
    /// against its own published JWKS.
    /// </summary>
    private static async Task<VerifierKeyMaterial> RegisterActorClientAsync(TestHostShell app)
    {
        VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ActorClientId,
            new Uri(ActorClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        await AddMachineScopeAudienceMappingAsync(app, material).ConfigureAwait(false);

        return material;
    }


    /// <summary>
    /// Adds <see cref="MachineScope"/> to <paramref name="material"/>'s <c>AllowedScopes</c> and maps
    /// it onto <see cref="ResourceServerAudience"/> in <c>ScopeToAudience</c> — the register-then-
    /// upgrade pattern the sibling grant suites use, because the routing dictionaries are
    /// host-internal.
    /// </summary>
    private static async Task AddMachineScopeAudienceMappingAsync(TestHostShell app, VerifierKeyMaterial material)
    {
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = host.Registrations[segment];
        Dictionary<string, IReadOnlyList<string>> scopeToAudience = previous.ScopeToAudience is null
            ? new(StringComparer.Ordinal)
            : new Dictionary<string, IReadOnlyList<string>>(previous.ScopeToAudience, StringComparer.Ordinal);
        scopeToAudience[MachineScope] = [ResourceServerAudience];

        ClientRecord updated = previous with
        {
            AllowedScopes = previous.AllowedScopes.Add(MachineScope),
            ScopeToAudience = scopeToAudience
        };


        updated = await host.UpdateClientAsync(previous, updated, []).ConfigureAwait(false);
        material.Registration = updated;
    }


    /// <summary>
    /// Wires the client_secret_post authentication seam (RFC 6749 §2.3.1): the application
    /// owns the secret store and the comparison; this test glue checks the form field against
    /// the secret of whichever client_id the request claims (both registered clients are served).
    /// </summary>
    private static async Task WireClientAuthenticationAsync(TestHostShell app) =>
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(
                    reading.ClientSecret is string secret
                    && string.Equals(
                        secret,
                        string.Equals(registration.ClientId, ActorClientId, StringComparison.Ordinal)
                            ? ActorClientSecret
                            : ClientSecret,
                        StringComparison.Ordinal));
        }).ConfigureAwait(false);


    /// <summary>
    /// Wires the three seams for the happy-path impersonation exchange: client
    /// authentication, a subject-token validation that accepts the fixture's subject token
    /// and surfaces its subject and scope, and an impersonation policy that permits the
    /// exchange and shapes the issued token to that same subject and scope as an
    /// access token (RFC 8693 §1.1 / Appendix A.1.4).
    /// </summary>
    private static async Task WireImpersonationSeamsAsync(TestHostShell app)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);


        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope });
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);

    }


    /// <summary>
    /// Wires client authentication, a subject-token validation that surfaces
    /// <paramref name="requiredKeyThumbprint"/> as <see cref="ValidatedSecurityToken.RequiredKeyThumbprint"/>,
    /// and a permissive policy that shapes the issued token as an access token — the RFC 9449 §5
    /// sender-constraint enforcement under test on the plain access-token issuance branch.
    /// </summary>
    private static async Task WireBoundSubjectSeamsAsync(TestHostShell app, string? requiredKeyThumbprint)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken
                        {
                            Subject = SubjectIdentity,
                            Scope = GrantedScope,
                            RequiredKeyThumbprint = requiredKeyThumbprint
                        });
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Wires client authentication, a subject-token validation that surfaces
    /// <paramref name="requiredKeyThumbprint"/>, and a policy that selects the §4.5 SAML-to-OAuth
    /// Refresh-Token issuance branch — the RFC 9449 §5 sender-constraint enforcement under test on
    /// the Token Exchange grant's Refresh-Token issuance path.
    /// </summary>
    private static async Task WireBoundSubjectForRefreshIssuanceSeamsAsync(TestHostShell app, string? requiredKeyThumbprint)
    {
        await WireClientAuthenticationAsync(app).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken
                        {
                            Subject = SubjectIdentity,
                            Scope = GrantedScope,
                            RequiredKeyThumbprint = requiredKeyThumbprint
                        });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = GrantedScope,
                            IssuedTokenType = TokenType.RefreshToken
                        });
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Wires a permissive policy seam: it permits every exchange and shapes the issued token to the
    /// validated subject and the fixture's granted scope as an access token (RFC 8693 §1.1 /
    /// Appendix A.1.4). The library, not this seam, records the actor in the act claim for delegation.
    /// </summary>
    private static async Task WirePermissivePolicyAsync(TestHostShell app) =>
        await TestHostShell.AlterAsync(app.Server, candidateIntegration => WirePermissivePolicy(candidateIntegration)).ConfigureAwait(false);


    /// <summary>Installs the authorization operation on the editable candidate.</summary>
    private static void WirePermissivePolicy(AuthorizationServerIntegration candidateIntegration)
    {
        candidateIntegration.AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = GrantedScope,
                        IssuedTokenType = TokenType.AccessToken
                    });
    }


    /// <summary>
    /// Wires a validation seam that branches on the presented token string: the fixture's subject
    /// token resolves to the subject's claims (or the supplied <paramref name="subjectToken"/> when
    /// a specific subject shape — e.g. a prior <c>act</c> chain — is needed), the fixture's actor
    /// token resolves to the actor's claims. Distinct subjects (<see cref="SubjectIdentity"/> vs
    /// <see cref="ActorIdentity"/>) make the §4.1 actor recording observable.
    /// </summary>
    /// <param name="app">The host shell whose server is wired.</param>
    /// <param name="subjectToken">The subject token's validated claims, or <see langword="null"/> for the fixture's subject.</param>
    /// <param name="actorToken">The actor token's validated claims, or <see langword="null"/> for the fixture's actor.</param>
    private static async Task WireBranchingValidatorAsync(
        TestHostShell app, ValidatedSecurityToken? subjectToken, ValidatedSecurityToken? actorToken = null)
    {
        ValidatedSecurityToken subject = subjectToken
            ?? new ValidatedSecurityToken { Subject = SubjectIdentity, Scope = GrantedScope };
        ValidatedSecurityToken actor = actorToken
            ?? new ValidatedSecurityToken { Subject = ActorIdentity };

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateTokenExchangeTokenAsync =
                (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        string.Equals(token, ActorTokenValue, StringComparison.Ordinal)
                            ? actor
                            : subject);
            WirePermissivePolicy(candidateIntegration);
        }).ConfigureAwait(false);
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
    /// Reads an access token this server issued as a validated subject token: its claims (the middle
    /// compact-JWS segment) are decoded by <see cref="JwtPartJson.Default"/>, the JWT part decoder a
    /// deployment wires, and its <c>sub</c> and <c>act</c> become the validated subject and the subject
    /// token's prior actor chain
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 Section 4.1</see>).
    /// </summary>
    /// <param name="compactJws">The issued access token, three dot-separated segments.</param>
    /// <returns>The validated subject token.</returns>
    private static ValidatedSecurityToken DecodeIssuedSubjectToken(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);
        IReadOnlyDictionary<string, object> claims = JwtPartJson.Default(payloadBytes);

        return new ValidatedSecurityToken
        {
            Subject = (string)claims[WellKnownJwtClaimNames.Sub],
            Scope = GrantedScope,
            Act = (IReadOnlyDictionary<string, object>)claims[WellKnownJwtClaimNames.Act]
        };
    }


    /// <summary>
    /// The fixed token endpoint body this library answers for every malformed <c>resource</c> value:
    /// <c>invalid_target</c> with the description that the value "must be an absolute URI (RFC 3986
    /// section 4.3) without a fragment".
    /// </summary>
    private static string MalformedResourceBody =>
        "{\"error\":\"invalid_target\",\"error_description\":\"The resource parameter must be an "
        + "absolute URI (RFC 3986 section 4.3) without a fragment.\"}";


    /// <summary>
    /// Reads the fault names the request trace recorded, in the order the spans stopped, from every
    /// <see cref="OAuthEventNames.MalformedResourceIndicator"/> event's
    /// <see cref="OAuthEventNames.ResourceIndicatorFaultTagName"/> tag, over the spans of
    /// <paramref name="root"/>'s trace and <paramref name="root"/> itself.
    /// </summary>
    /// <param name="capture">The capture that listened while the request ran.</param>
    /// <param name="root">The stopped activity the request ran under.</param>
    /// <returns>The recorded fault names.</returns>
    private static string[] ReadMalformedResourceFaultNames(TraceTreeCapture capture, Activity root) =>
    [
        .. TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId)
            .Append(root)
            .SelectMany(activity => activity.Events)
            .Where(activityEvent => string.Equals(
                activityEvent.Name, OAuthEventNames.MalformedResourceIndicator, StringComparison.Ordinal))
            .Select(activityEvent => activityEvent.Tags.Single(tag => string.Equals(
                tag.Key, OAuthEventNames.ResourceIndicatorFaultTagName, StringComparison.Ordinal)).Value?.ToString()
                ?? string.Empty)
    ];


    /// <summary>
    /// Reads the <c>aud</c> claim of <paramref name="compactJws"/> as its list of values: a JSON
    /// string is a list of one, a JSON array is its elements in order.
    /// </summary>
    /// <param name="compactJws">The compact-serialized access token.</param>
    /// <returns>The audience values exactly as the token carries them.</returns>
    private static string[] ReadAudience(string compactJws)
    {
        using JsonDocument payload = DecodePayload(compactJws);
        JsonElement aud = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);

        return aud.ValueKind == JsonValueKind.Array
            ? [.. aud.EnumerateArray().Select(static element => element.GetString()!)]
            : [aud.GetString()!];
    }


    /// <summary>Reads the string member <paramref name="name"/> of the JSON object <paramref name="body"/>.</summary>
    /// <param name="body">The token endpoint's JSON response body.</param>
    /// <param name="name">The member to read.</param>
    private static string ReadMember(string body, string name)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(name).GetString()!;
    }


    /// <summary>
    /// Renders a token endpoint answer for an assertion message: its status, its body, and the <c>act</c> claim of
    /// the token a 200 body issues, so a row whose refusal was answered with a token shows the actor that token
    /// names.
    /// </summary>
    /// <param name="status">The response's status code.</param>
    /// <param name="body">The response's body.</param>
    /// <returns>The rendered answer.</returns>
    private static string DescribeExchangeAnswer(int status, string body)
    {
        string issuedAct = "none";
        if(status == 200)
        {
            using JsonDocument doc = JsonDocument.Parse(body);
            if(doc.RootElement.TryGetProperty(WellKnownTokenTypes.AccessToken, out JsonElement issued))
            {
                using JsonDocument payload = DecodePayload(issued.GetString()!);
                issuedAct = payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Act, out JsonElement act)
                    ? act.GetRawText()
                    : "none";
            }
        }

        return $"{status} '{body}' issued act {issuedAct}";
    }


    /// <summary>
    /// Posts an RFC 8693 section 2.1 impersonation exchange asking for <paramref name="requestedTokenType"/>,
    /// naming <paramref name="resource"/> and <paramref name="audience"/> when they are given, authenticated by
    /// <paramref name="clientSecret"/> through <c>client_secret_post</c>, and returns the response's status code
    /// and body.
    /// </summary>
    /// <param name="http">The client the host is reached with.</param>
    /// <param name="tokenUrl">The token endpoint.</param>
    /// <param name="requestedTokenType">The <c>requested_token_type</c> the request carries, or <see langword="null"/> for none.</param>
    /// <param name="resource">The <c>resource</c> the request names, or <see langword="null"/> for none.</param>
    /// <param name="audience">The <c>audience</c> the request names, or <see langword="null"/> for none.</param>
    /// <param name="clientSecret">The secret the client presents; the fixture's own secret by default.</param>
    private async Task<(int StatusCode, string Body)> PostExchangeAsync(
        HttpClient http,
        Uri tokenUrl,
        TokenType? requestedTokenType,
        string? resource = null,
        string? audience = null,
        string clientSecret = ClientSecret)
    {
        OutgoingFormFields form = BuildRequest(new TokenExchangeBuilderOptions
        {
            SubjectToken = SubjectTokenValue,
            SubjectTokenType = TokenType.AccessToken,
            RequestedTokenType = requestedTokenType,
            Resource = resource is null ? [] : [resource],
            Audience = audience
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(clientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body);
    }


    /// <summary>
    /// Posts an RFC 6749 section 6 refresh request for <paramref name="refreshToken"/>, naming
    /// <paramref name="resource"/> when it is not <see langword="null"/>, and returns the response's
    /// status code and body.
    /// </summary>
    /// <param name="http">The client the host is reached with.</param>
    /// <param name="tokenUrl">The token endpoint.</param>
    /// <param name="refreshToken">The refresh token presented.</param>
    /// <param name="resource">The <c>resource</c> the request names, or <see langword="null"/> for none.</param>
    private async Task<(int StatusCode, string Body)> PostRefreshAsync(
        HttpClient http, Uri tokenUrl, string refreshToken, string? resource)
    {
        Dictionary<string, string> fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        if(resource is not null)
        {
            fields[OAuthRequestParameterNames.Resource] = resource;
        }

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body);
    }


    /// <summary>
    /// The audience shapes an exchange's authorization seam can decide, and how a refresh names them:
    /// each names one row of
    /// <see cref="AnExchangeAuthorizedAudienceKeepsItsSpellingThroughRefreshAndRotationAsync"/>.
    /// </summary>
    internal enum ExchangeAudienceShape
    {
        /// <summary>An upper-case URI-shaped audience; the refreshes name it as a <c>resource</c>.</summary>
        UpperCaseUri,

        /// <summary>A logical audience naming the Kelvin sign (U+212A); the refreshes name no <c>resource</c>.</summary>
        NonAsciiLogicalName
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

        return (kid, usage, tenant, ctx, ct) =>
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

        return built.Value;
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
}
