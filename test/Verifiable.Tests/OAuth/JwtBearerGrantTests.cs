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
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// HTTP wire tests for the JWT Bearer authorization grant
/// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see> /
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.1">§3.1</see>): a client presents an
/// <c>assertion</c> (a single JWT) and the authorization server — through the application's
/// <see cref="AuthorizationServerIntegration.ValidateJwtBearerAssertionAsync"/> seam, which is the
/// trust authority for the §3 processing rules (signature rule 9, trusted <c>iss</c> rule 1, the
/// <c>aud</c>-names-this-AS check rule 3, and the <c>exp</c>/<c>nbf</c> window rules 4–5) — validates
/// it and mints a Bearer access token whose <c>sub</c> is the assertion's subject (§3 rule 2.A).
/// </summary>
/// <remarks>
/// The grant materializes only when the client is allowed the
/// <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/> capability AND the assertion-validation
/// seam is wired; client AUTHENTICATION is OPTIONAL (§2.1/§3.1), so the client-authentication seam is
/// NOT required for the grant to exist — but when the request carries client credentials they MUST be
/// validated (§3.1), and when the effective registration declares a non-<c>none</c>
/// <c>token_endpoint_auth_method</c> a credential-less request is refused with <c>401 invalid_client</c>
/// (draft-ietf-oauth-client-id-metadata-document-02 §8.2, CIMD-049). A host with the capability but no
/// validation seam fails closed: the grant endpoint does not exist and a well-formed request never
/// reaches 200.
/// </remarks>
[TestClass]
internal sealed class JwtBearerGrantTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";
    private const string AssertionSubject = "https://user.example/alice";
    private const string GrantedScope = "read";

    //A non-identity scope RegisterJwtBearerClient maps onto ResourceServerAudience: contract
    //wave-4 D4 narrows openid away from every client_credentials grant (client_credentials has no
    //authenticated End-User), so the end-to-end tests mint their real assertion under this scope
    //instead, to still reach a concrete audience for the §3 rule-3 aud == this AS check.
    private const string MachineScope = "machine.telemetry.read";

    //The resource-server identifier RegisterJwtBearerClient maps MachineScope onto; a real
    //AS-issued client_credentials token carries it as aud, so the end-to-end test has a concrete
    //audience to perform the §3 rule-3 aud == this AS check against, and the exchanged jwt-bearer
    //access token carries it too.
    private const string ResourceServerAudience = "https://rs.example.com";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// RFC 7523 §2.1 happy path: the client presents a non-empty <c>assertion</c> and client
    /// credentials. The seam (the trust authority) validates the assertion and returns the granted
    /// token shape. The response carries an <c>access_token</c> whose <c>sub</c> is the assertion's
    /// subject (§3 rule 2.A), <c>token_type</c> Bearer, <c>expires_in</c>, and the granted
    /// <c>scope</c> (RFC 6749 §5.1) — and NO <c>issued_token_type</c> (a token-exchange field).
    /// </summary>
    [TestMethod]
    public async Task ValidAssertionIssuesBearerAccessTokenOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;
        string accessToken = root.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, root.GetProperty("token_type").GetString());
        Assert.IsGreaterThan(0, root.GetProperty("expires_in").GetInt32(), "expires_in must reflect the token's exp-iat.");
        Assert.AreEqual(GrantedScope, root.GetProperty(OAuthRequestParameterNames.Scope).GetString());
        Assert.IsFalse(root.TryGetProperty(OAuthRequestParameterNames.IssuedTokenType, out _),
            "The jwt-bearer grant emits a plain RFC 6749 §5.1 response, not a token-exchange §2.2.1 response with issued_token_type.");

        //RFC 7523 §3 rule 2.A: the issued token's subject is the assertion's subject.
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(AssertionSubject, payload.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// RFC 7523 §2.1: the <c>assertion</c> parameter is REQUIRED and must contain a single JWT. A
    /// request with no <c>assertion</c>, and one with an empty <c>assertion</c>, are both rejected
    /// with <c>invalid_request</c> before the validation seam runs.
    /// </summary>
    /// <remarks>
    /// Case (a) is deliberately NOT built via <see cref="JwtBearerRequestBuilder"/>: omitting
    /// <see cref="JwtBearerBuilderOptions.Assertion"/> entirely does not compile (it is
    /// <see langword="required"/>), so a missing <c>assertion</c> is exactly what the builder makes
    /// unrepresentable — this hand-built form is the only way to prove the AS ALSO fails closed on the
    /// same rule. Case (b) — an assertion that is present but the empty string — is representable
    /// (<see langword="required"/> only forbids omission, not an empty value) and migrates.
    /// </remarks>
    [TestMethod]
    public async Task MissingOrEmptyAssertionIsRejectedAsInvalidRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        //(a) Missing assertion — RFC 7523 §2.1 REQUIRED.
        using HttpResponseMessage missing = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string missingBody = await missing.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)missing.StatusCode, missingBody);
        Assert.Contains(OAuthErrors.InvalidRequest, missingBody);

        //(b) Empty assertion — still a missing single JWT.
        OutgoingFormFields emptyForm = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = string.Empty
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage empty = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, emptyForm, TestContext.CancellationToken).ConfigureAwait(false);
        string emptyBody = await empty.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)empty.StatusCode, emptyBody);
        Assert.Contains(OAuthErrors.InvalidRequest, emptyBody);
    }


    /// <summary>
    /// RFC 7523 §3.1 MUST: "if the JWT is not valid ... the value of the error parameter MUST be the
    /// invalid_grant error code." When the validation seam returns <see langword="null"/> (a §3
    /// processing failure), the endpoint rejects the request with <c>invalid_grant</c> — NOT
    /// <c>invalid_request</c>.
    /// </summary>
    [TestMethod]
    public async Task RejectedAssertionIsInvalidGrantNotInvalidRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);

        //The seam rejects every assertion (a stand-in for a §3 failure: bad signature, untrusted iss,
        //wrong aud, expired window).
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.tampered.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body);
        Assert.DoesNotContain(OAuthErrors.InvalidRequest, body,
            "RFC 7523 §3.1 mandates invalid_grant for an invalid assertion, not invalid_request.");
    }


    /// <summary>
    /// RFC 7523 §3 rule 3 (the <c>aud</c> MUST): "the authorization server MUST reject any JWT that
    /// does not contain its own identity as the intended audience." Only the application knows the
    /// AS's identity, so the check lives behind the validation seam. A realistic validator that
    /// returns the grant only when the assertion names this AS as audience, and <see langword="null"/>
    /// otherwise, drives a mis-audienced assertion to <c>invalid_grant</c> — demonstrating the §3
    /// rule-3 rejection flows to the §3.1 error code.
    /// </summary>
    [TestMethod]
    public async Task AssertionNotNamingThisAsAsAudienceIsRejectedAsInvalidGrant()
    {
        //A marker the test validator branches on to simulate the §3 rule-3 audience comparison the
        //application performs: an assertion whose audience is this AS is accepted, any other is null.
        const string AsAudienceMarker = "aud=this-as";
        const string WrongAudienceMarker = "aud=some-other-as";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);

        //RFC 7523 §3 rule 3: accept only when the assertion's intended audience is THIS AS.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(
                    assertion.Contains(AsAudienceMarker, StringComparison.Ordinal)
                        ? new JwtBearerGrant { Subject = AssertionSubject, Scope = GrantedScope }
                        : null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        //(a) Assertion naming THIS AS as audience → accepted.
        OutgoingFormFields acceptedForm = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = $"eyJhbGciOiJFUzI1NiJ9.{AsAudienceMarker}.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage accepted = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, acceptedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string acceptedBody = await accepted.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)accepted.StatusCode, acceptedBody);

        //(b) Assertion naming a DIFFERENT AS as audience → rejected per §3 rule 3, surfaced as §3.1
        //invalid_grant.
        OutgoingFormFields rejectedForm = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = $"eyJhbGciOiJFUzI1NiJ9.{WrongAudienceMarker}.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage rejected = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, rejectedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string rejectedBody = await rejected.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)rejected.StatusCode, rejectedBody);
        Assert.Contains(OAuthErrors.InvalidGrant, rejectedBody);
    }


    /// <summary>
    /// RFC 9068 / RFC 7523 §2.1: client IDENTIFICATION is required even though authentication is
    /// optional — a JWT access token needs a <c>client_id</c>. A request whose tenant resolves no
    /// client registration cannot be tied to a <c>client_id</c>, so the grant cannot issue a token: a
    /// well-formed request to an unregistered tenant never reaches 200. (The handler's defensive
    /// <c>registration is null</c> guard maps to <c>401 invalid_client</c>, mirroring the sibling
    /// grants; over HTTP an unregistered tenant resolves no endpoints, so the request is refused before
    /// the handler — either way no token is minted for an unidentified client.)
    /// </summary>
    [TestMethod]
    public async Task UnidentifiedClientCannotObtainAToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        //A tenant segment that resolves no registration — the request cannot be tied to a client_id.
        Uri unknownTenantUrl = new(host.HttpBaseAddress!, "/connect/unregistered-tenant/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, unknownTenantUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(200, (int)response.StatusCode, body);
    }


    /// <summary>
    /// RFC 7523 §3.1: "if client credentials are present in the request, the authorization server MUST
    /// validate them." A request that carries a <c>client_secret</c> the seam rejects is refused with
    /// <c>401 invalid_client</c> — the credentials were present, so they were validated and failed —
    /// even though authentication is otherwise optional for this grant.
    /// </summary>
    [TestMethod]
    public async Task PresentButInvalidClientCredentialsAreRejectedAsInvalidClient()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes("guessed-wrong"));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body);
    }


    /// <summary>
    /// Fail-closed materialization. A host whose client is allowed the jwt-bearer capability but whose
    /// <see cref="AuthorizationServerIntegration.ValidateJwtBearerAssertionAsync"/> seam is NOT wired
    /// does not materialize the grant: a well-formed jwt-bearer request never reaches 200. An
    /// advertised grant with no validation seam would mint tokens for any assertion string.
    /// </summary>
    [TestMethod]
    public async Task UnwiredValidationSeamDoesNotMaterializeTheGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);

        //Client authentication is wired, but the assertion-validation seam is deliberately absent.
        WireClientAuthentication(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(200, (int)response.StatusCode,
            "The jwt-bearer grant must not be reachable without its assertion-validation seam.");
    }


    /// <summary>
    /// A genuine end-to-end RFC 7523 grant where the <c>assertion</c> is a REAL, cryptographically
    /// verified AS-issued JWT and the validation seam REALLY performs the §3 processing — the only
    /// stub-free path the harness allows.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The chain mirrors a production deployment as closely as the harness allows:
    /// </para>
    /// <list type="number">
    ///   <item><description>
    ///     A REAL signed JWT to serve as the <c>assertion</c> is obtained from the AS over the wire via
    ///     the <c>client_credentials</c> grant (RFC 6749 §4.4) — a P-256-signed RFC 9068 JWT whose
    ///     <c>iss</c> is the AS issuer and whose <c>aud</c> (from the openid scope) is
    ///     <see cref="ResourceServerAudience"/>. The project's signing surface mints it; no crypto is
    ///     hand-rolled.
    ///   </description></item>
    ///   <item><description>
    ///     The <see cref="AuthorizationServerIntegration.ValidateJwtBearerAssertionAsync"/> seam runs
    ///     the project's real <see cref="JwsAccessTokenValidator"/> over the presented assertion —
    ///     fetching the AS JWKS over HTTP and reconstructing the verification key by <c>kid</c>,
    ///     verifying the P-256 signature (§3 rule 9), the <c>iss</c> (§3 rule 1), and the timing window
    ///     (§3 rules 4–5) — AND enforces §3 rule 3 by requiring the assertion's <c>aud</c> to be this
    ///     AS's identity (<see cref="ResourceServerAudience"/>). A forgery, wrong issuer, or wrong
    ///     audience surfaces as <see langword="null"/> (the grant is refused with <c>invalid_grant</c>).
    ///   </description></item>
    ///   <item><description>The AS mints the jwt-bearer access token, whose <c>sub</c> is the assertion's subject.</description></item>
    ///   <item><description>
    ///     The resource-server step verifies the issued access token the same way a resource server
    ///     would — the same <see cref="JwsAccessTokenValidator"/> against the same AS JWKS — and asserts
    ///     <c>iss</c> is the AS and <c>sub</c> is the assertion's subject, and that it is a genuinely
    ///     fresh artefact (a distinct <c>jti</c>), not the assertion re-presented.
    ///   </description></item>
    /// </list>
    /// <para>
    /// Minting a distinct assertion whose <c>aud</c> equals the AS's own identity is feasible here: the
    /// real <c>client_credentials</c> token's <c>aud</c> (<see cref="ResourceServerAudience"/>) is
    /// adopted as the AS's audience identity for the §3 rule-3 comparison (RFC 7523 §3 rule 3 lets the
    /// AS use any out-of-band-agreed audience string for itself, and the token endpoint URL is only one
    /// permitted choice). Verification is therefore real, not faked.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task EndToEndRealAssertionIsValidatedExchangedAndUsed()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        //The iss the AS stamps on every token it mints for this tenant — the registration's declared
        //canonical URL, resolved by the library's DefaultIssuerResolver.
        string asIssuer = material.Registration.IssuerUri!.OriginalString;

        //Resolve the AS verification key the way a relying party does: GET /jwks over HTTP and
        //reconstruct the PublicKeyMemory from the published JWK matching the token's kid.
        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //STEP 1 — Mint a REAL signed JWT to serve as the assertion (client_credentials, RFC 6749 §4.4).
        //iss == asIssuer; MachineScope embeds aud == ResourceServerAudience (the AS's audience identity
        //for the §3 rule-3 check) — contract wave-4 D4 narrows openid away from every
        //client_credentials grant, so RegisterJwtBearerClient maps this non-identity scope instead.
        //The project's signing surface mints it — no hand-rolled crypto.
        string assertion = await ObtainClientCredentialsAccessTokenAsync(
            http, tokenUrl, ClientId, ClientSecret, MachineScope).ConfigureAwait(false);

        //Pin "real": the assertion is itself a valid AS-issued, correctly-audienced token before we
        //present it as the grant — the same check the validation seam performs below.
        JwsAccessTokenValidationResult assertionCheck = await VerifyAgainstAsAsync(
            assertion, asIssuer, jwksResolver).ConfigureAwait(false);
        Assert.IsTrue(assertionCheck.IsSuccess,
            $"The assertion must be a valid AS-issued token; got {assertionCheck.FailureReason}: {assertionCheck.FailureDescription}");
        Assert.AreEqual(ClientId, assertionCheck.Claims!.Subject,
            "RFC 9068 §3: a client_credentials token's subject is the client itself; it becomes the grant's subject here.");
        string assertionJti = assertionCheck.Claims.JwtId!;

        //STEP 2 — Wire the REAL assertion validator. It runs the project's resource-server-grade
        //JwsAccessTokenValidator against the AS JWKS — signature (§3 rule 9), iss (§3 rule 1), timing
        //(§3 rules 4–5) — AND enforces §3 rule 3 by requiring aud == this AS (ResourceServerAudience).
        //A forgery, wrong issuer, or wrong audience returns null and the grant is refused.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (presentedAssertion, requestedScope, registration, context, ct) =>
            {
                JwsAccessTokenValidationResult result = await VerifyAgainstAsAsync(
                    presentedAssertion, asIssuer, jwksResolver).ConfigureAwait(false);
                if(!result.IsSuccess)
                {
                    return null;
                }

                //RFC 7523 §3 rule 3 (the aud MUST): the assertion must name THIS AS as its intended
                //audience. VerifyAgainstAsAsync already enforced aud == ResourceServerAudience (the AS's
                //audience identity), so a success here means the audience check passed.
                return new JwtBearerGrant
                {
                    Subject = result.Claims!.Subject,
                    Scope = result.Claims.Scope ?? GrantedScope
                };
            };

        //STEP 3 — Present the REAL assertion to the jwt-bearer grant (RFC 7523 §2.1).
        OutgoingFormFields grantForm = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = assertion,
            Scope = WellKnownScopes.OpenId
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage grantResponse = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, grantForm, TestContext.CancellationToken).ConfigureAwait(false);

        string grantBody = await grantResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)grantResponse.StatusCode, grantBody);

        using JsonDocument grantDoc = JsonDocument.Parse(grantBody);
        string issuedToken = grantDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, grantDoc.RootElement.GetProperty("token_type").GetString());

        //STEP 4 — USE the issued token (the resource-server step). Verify its signature against the SAME
        //AS JWKS and enforce iss/aud/timing through the real validator.
        JwsAccessTokenValidationResult issuedValidation = await VerifyAgainstAsAsync(
            issuedToken, asIssuer, jwksResolver).ConfigureAwait(false);
        Assert.IsTrue(issuedValidation.IsSuccess,
            $"The issued token must verify as a real AS-issued token; got {issuedValidation.FailureReason}: {issuedValidation.FailureDescription}");
        Assert.AreEqual(asIssuer, issuedValidation.Claims!.Issuer,
            "The issued token must be issued by the same AS.");
        Assert.AreEqual(ClientId, issuedValidation.Claims.Subject,
            "RFC 7523 §3 rule 2.A: the issued token's subject is the assertion's subject.");

        //The issued token is a genuinely fresh artefact, not the assertion re-presented.
        Assert.AreNotEqual(assertion, issuedToken,
            "The issued token must not be the assertion string.");
        Assert.AreNotEqual(assertionJti, issuedValidation.Claims.JwtId,
            "RFC 7523 mints a new token — the issued token's jti must differ from the assertion's.");
    }


    /// <summary>
    /// RFC 7523 §2.1 / §3.1: client AUTHENTICATION is OPTIONAL — the assertion itself is the
    /// authorization grant. A request that carries NO client credentials (only the <c>client_id</c> that
    /// identifies the client, no <c>client_secret</c>, no <c>Authorization</c> header) and whose
    /// assertion the seam accepts is issued a token. This proves the §2.1 anonymous path issues a
    /// token even though the client-authentication seam is not wired.
    /// </summary>
    [TestMethod]
    public async Task AnonymousRequestWithoutClientCredentialsIssuesToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);

        //No WireClientAuthentication — the anonymous path must not depend on the client-auth seam.
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //client_id identifies the client (required for a conformant RFC 9068 token), but NO
        //client_secret and NO Authorization header — the request carries no credentials at all.
        //RFC 6749 §2.3.1: "the client MAY omit the parameter if the client secret is an empty string" —
        //an empty secret through WithClientSecretPost sets client_id and omits client_secret entirely,
        //the same wire shape as never mentioning it.
        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature"
        }).WithClientSecretPost(ClientId, ReadOnlySpan<byte>.Empty);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, doc.RootElement.GetProperty("token_type").GetString());

        //RFC 7523 §3 rule 2.A: the issued token's subject is the assertion's subject.
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(AssertionSubject, payload.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// RFC 7523 §3.1 MUST: "if client credentials are present in the request, the authorization server
    /// MUST validate them." When a request presents a <c>client_secret</c> but the authorization server
    /// has NOT configured the client-authentication seam, the credentials cannot be validated — and
    /// proceeding as anonymous would silently ignore them, a §3.1 MUST bypass. The endpoint therefore
    /// refuses the request with <c>401 invalid_client</c> rather than minting a token.
    /// </summary>
    [TestMethod]
    public async Task PresentCredentialsWithNoClientAuthSeamAreRejectedAsInvalidClient()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);

        //Only the assertion validator is wired. The client-authentication seam is deliberately absent,
        //so presented credentials cannot be validated.
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //A client_secret IS present — §3.1 requires it be validated, but no seam exists to do so.
        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body,
            StringComparison.Ordinal);
        Assert.AreNotEqual(200, (int)response.StatusCode,
            "Presented credentials with no client-authentication seam must not be silently ignored (RFC 7523 §3.1).");
    }


    /// <summary>
    /// RFC 7523 §3.1 composed with draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-049): a
    /// registration that declares a non-<c>none</c> <c>token_endpoint_auth_method</c> is a confidential
    /// client, and "any communication with the authorization server MUST include client authentication
    /// of the registered type." A jwt-bearer request carrying a valid assertion but NO client
    /// credentials at all is refused with <c>401 invalid_client</c> — the §3.1 anonymous path is open
    /// only to clients that declared no authentication method.
    /// </summary>
    [TestMethod]
    public async Task DeclaredConfidentialClientWithoutCredentialsIsRejectedAsInvalidClient()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        DeclareTokenEndpointAuthMethod(app, material, ClientAuthenticationMethod.ClientSecretPost);
        WireClientAuthentication(app);
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        //client_id identifies the client but NO client_secret and NO Authorization header — the same
        //credential-less wire shape the anonymous test uses, now against a DECLARED confidential client.
        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature"
        }).WithClientSecretPost(ClientId, ReadOnlySpan<byte>.Empty);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body, StringComparison.Ordinal);
    }


    /// <summary>
    /// CIMD-049 fail-closed: a registration that declares a non-<c>none</c>
    /// <c>token_endpoint_auth_method</c> on an authorization server whose
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> seam is NOT wired
    /// cannot authenticate anything, so a credential-less jwt-bearer request is refused with
    /// <c>401 invalid_client</c> — never silently passed through as anonymous.
    /// </summary>
    [TestMethod]
    public async Task DeclaredConfidentialClientWithUnwiredAuthSeamFailsClosed()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        DeclareTokenEndpointAuthMethod(app, material, ClientAuthenticationMethod.ClientSecretPost);

        //Only the assertion validator is wired — the client-authentication seam is deliberately absent.
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, ReadOnlySpan<byte>.Empty);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 7523 §3.1 + CIMD-049 composition, the credential-bearing leg: a declared confidential
    /// client that presents its valid <c>client_secret</c> is authenticated on the §3.1
    /// validate-if-present path and the grant proceeds to a token. The seam invocation count proves the
    /// two enforcement branches are disjoint — the credentials are validated exactly ONCE, never a
    /// second time by the declared-method requirement.
    /// </summary>
    [TestMethod]
    public async Task DeclaredConfidentialClientWithValidCredentialsIsIssuedTokenWithoutDoubleValidation()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        DeclareTokenEndpointAuthMethod(app, material, ClientAuthenticationMethod.ClientSecretPost);
        WireAcceptingValidator(app);

        int validationCallCount = 0;
        app.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            validationCallCount++;

            return ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.AreEqual(1, validationCallCount,
            "The presented credentials must be validated exactly once — the declared-method requirement (CIMD-049) must not re-run the §3.1 validate-if-present check.");

        using JsonDocument doc = JsonDocument.Parse(body);
        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //RFC 7523 §3 rule 2.A: the issued token's subject is the assertion's subject.
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(AssertionSubject, payload.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// The declared PUBLIC-client shape: a registration whose <c>token_endpoint_auth_method</c> is
    /// explicitly <c>none</c> keeps the RFC 7523 §2.1/§3.1 anonymous path open — a credential-less
    /// request with an accepted assertion is issued a token, with no client-authentication seam wired
    /// at all. Together with <see cref="AnonymousRequestWithoutClientCredentialsIssuesToken"/> (the
    /// UNDECLARED shape) this pins that only a non-<c>none</c> declaration closes the anonymous path
    /// (CIMD-049 gates on confidential declarations, nothing else).
    /// </summary>
    [TestMethod]
    public async Task DeclaredNoneClientWithoutCredentialsIssuesToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        DeclareTokenEndpointAuthMethod(app, material, ClientAuthenticationMethod.None);

        //No WireClientAuthentication — a declared-none public client must not require the seam.
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature"
        }).WithClientSecretPost(ClientId, ReadOnlySpan<byte>.Empty);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //RFC 7523 §3 rule 2.A: the issued token's subject is the assertion's subject.
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(AssertionSubject, payload.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// A real, stub-free negative end-to-end: a genuine AS-issued assertion is TAMPERED (its signature
    /// segment is corrupted) and presented. The wired validator runs the project's real
    /// <see cref="JwsAccessTokenValidator"/>, whose P-256 signature check (RFC 7523 §3 rule 9) rejects
    /// the forgery, returning <see langword="null"/> — the grant is refused with <c>invalid_grant</c>
    /// (§3.1). An <b>expired</b> variant advances the <see cref="TimeProvider"/> past the assertion's
    /// <c>exp</c> so the real timing check (§3 rules 4–5) rejects it, also as <c>invalid_grant</c>.
    /// </summary>
    [TestMethod]
    public async Task RealTamperedOrExpiredAssertionIsRejectedAsInvalidGrant()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        string asIssuer = material.Registration.IssuerUri!.OriginalString;
        ServerVerificationKeyResolverDelegate jwksResolver =
            await BuildJwksKeyResolverAsync(http, host.HttpBaseAddress!, segment).ConfigureAwait(false);

        //Mint a REAL signed JWT (client_credentials) to serve as the assertion — same as the positive
        //end-to-end. iss == asIssuer; MachineScope embeds aud == ResourceServerAudience (contract
        //wave-4 D4 narrows openid away from every client_credentials grant).
        string realAssertion = await ObtainClientCredentialsAccessTokenAsync(
            http, tokenUrl, ClientId, ClientSecret, MachineScope).ConfigureAwait(false);

        //Wire the REAL assertion validator — it runs JwsAccessTokenValidator (signature §3 rule 9, iss
        //§3 rule 1, timing §3 rules 4–5, and aud == this AS §3 rule 3). A forgery or expired window
        //returns null and the grant is refused with invalid_grant.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            async (presentedAssertion, requestedScope, registration, context, ct) =>
            {
                JwsAccessTokenValidationResult result = await VerifyAgainstAsAsync(
                    presentedAssertion, asIssuer, jwksResolver).ConfigureAwait(false);

                return result.IsSuccess
                    ? new JwtBearerGrant { Subject = result.Claims!.Subject, Scope = result.Claims.Scope ?? GrantedScope }
                    : null;
            };

        //The compact JWS splits into header.payload.signature. Both tamper cases below leave the header
        //and payload intact and corrupt only the signature segment, deterministically — never relying on
        //the random signature value to land in a particular shape.
        string[] segments = realAssertion.Split('.');
        Assert.HasCount(3, segments);
        string signatureSegment = segments[2];

        //(a) TAMPERED, well-formed but wrong — flip the FIRST signature character. The segment keeps its
        //length and stays canonical base64url, so it decodes cleanly, but the P-256 signature no longer
        //verifies. The real validator returns null → §3.1 invalid_grant.
        char firstSignatureChar = signatureSegment[0];
        char flippedFirst = firstSignatureChar == 'A' ? 'B' : 'A';
        string wrongAssertion = string.Join('.', segments[0], segments[1], flippedFirst + signatureSegment[1..]);
        Assert.AreNotEqual(realAssertion, wrongAssertion, "The tamper must change the assertion string.");

        OutgoingFormFields wrongForm = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = wrongAssertion
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage wrongResponse = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, wrongForm, TestContext.CancellationToken).ConfigureAwait(false);
        string wrongBody = await wrongResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)wrongResponse.StatusCode, wrongBody);
        Assert.Contains(OAuthErrors.InvalidGrant, wrongBody, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuthErrors.InvalidRequest, wrongBody, StringComparison.Ordinal,
            "A failed real signature check is §3.1 invalid_grant, not invalid_request.");

        //(b) TAMPERED, malformed — a P-256 signature is 64 bytes → 86 base64url characters whose final
        //character carries only 2 significant bits, so a canonical value ends in one of {A,Q,g,w} (the
        //four unused bits zero). Forcing the last character to 'B' sets those unused bits non-zero,
        //yielding a non-canonical base64url the strict decoder rejects. The validator must treat the
        //undecodable assertion as invalid (null → §3.1 invalid_grant), NOT surface the decoder's
        //exception as a 500.
        string malformedAssertion = string.Join('.', segments[0], segments[1], signatureSegment[..^1] + "B");
        Assert.AreNotEqual(realAssertion, malformedAssertion, "The tamper must change the assertion string.");

        OutgoingFormFields malformedForm = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = malformedAssertion
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage malformedResponse = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, malformedForm, TestContext.CancellationToken).ConfigureAwait(false);
        string malformedBody = await malformedResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)malformedResponse.StatusCode, malformedBody);
        Assert.Contains(OAuthErrors.InvalidGrant, malformedBody, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuthErrors.InvalidRequest, malformedBody, StringComparison.Ordinal,
            "An undecodable real signature is §3.1 invalid_grant, not invalid_request.");

        //(b) EXPIRED — present the untampered real assertion but advance time past its exp. The real
        //timing check (§3 rules 4–5) rejects it → §3.1 invalid_grant.
        TimeProvider.Advance(TimeSpan.FromDays(1));
        OutgoingFormFields expiredForm = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = realAssertion
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        using HttpResponseMessage expiredResponse = await OAuthTestTransport.PostFormAsync(
            http, tokenUrl, expiredForm, TestContext.CancellationToken).ConfigureAwait(false);
        string expiredBody = await expiredResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)expiredResponse.StatusCode, expiredBody);
        Assert.Contains(OAuthErrors.InvalidGrant, expiredBody, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 7523 §2.1 / RFC 7521 §4.1: the <c>scope</c> parameter is OPTIONAL and indicates the
    /// requested scope. It must reach the validation seam so the application can shape the grant. A
    /// validator that echoes the requested scope into <see cref="JwtBearerGrant.Scope"/> drives a
    /// custom <c>scope</c> through to both the §5.1 response <c>scope</c> and the issued token's
    /// <c>scope</c> claim.
    /// </summary>
    [TestMethod]
    public async Task RequestedScopeReachesTheValidationSeamAndShapesTheToken()
    {
        const string RequestedScope = "urn:example:custom";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);

        //The seam echoes the requestedScope parameter it was handed into the granted scope, proving the
        //request's scope reaches the trust authority verbatim.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(
                    new JwtBearerGrant { Subject = AssertionSubject, Scope = requestedScope ?? GrantedScope });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature",
            Scope = RequestedScope
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(RequestedScope, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "The requested scope, echoed by the seam, must be the §5.1 response scope.");

        //The issued token carries the same scope — the request's scope reached the seam and shaped the token.
        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(RequestedScope, payload.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "The issued token's scope claim must reflect the requested scope.");
    }


    /// <summary>
    /// RFC 7523 §6 least-privilege: a non-empty <see cref="JwtBearerGrant.Audience"/> confines the
    /// issued access token to the named target(s) verbatim — its <c>aud</c> claim — bypassing the
    /// registration's scope→audience resolver. A validator returning an explicit audience that the
    /// registration's <c>ScopeToAudience</c> map would never produce proves the confinement reaches the
    /// issued token (mirrors the token-exchange explicit-audience test).
    /// </summary>
    [TestMethod]
    public async Task ExplicitGrantAudienceConfinesTheIssuedTokenAud()
    {
        const string ConfinedAudience = "https://api.example/orders";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);

        //The seam confines the issued token to an explicit target. This audience is not in any
        //ScopeToAudience entry, so its presence in aud can only come from the explicit grant override.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(
                    new JwtBearerGrant
                    {
                        Subject = AssertionSubject,
                        Scope = GrantedScope,
                        Audience = [ConfinedAudience]
                    });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        using JsonDocument payload = DecodePayload(doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!);

        //A single audience serializes as a JSON string; multiple as a JSON array. Assert the confined
        //value is the issued token's aud, not whatever the scope→audience resolver would produce.
        JsonElement aud = payload.RootElement.GetProperty("aud");
        string actualAud = aud.ValueKind == JsonValueKind.Array
            ? aud.EnumerateArray().First().GetString()!
            : aud.GetString()!;
        Assert.AreEqual(ConfinedAudience, actualAud,
            "The explicit grant audience (§6 least-privilege) must be the issued token's aud, not the resolver's value.");
    }


    /// <summary>
    /// RFC 7523 §3.1 / OAuth 2.1 §3.2.3: a token-bearing response is sensitive and uncacheable, so the
    /// success response MUST carry <c>Cache-Control: no-store</c>. Asserts the directive traverses the
    /// real HTTP wire on the happy path.
    /// </summary>
    [TestMethod]
    public async Task SuccessResponseCarriesCacheControlNoStore()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        //The Cache-Control: no-store directive lands on the HttpResponseMessage's typed Cache-Control
        //header (RFC 7234) — the success response is uncacheable.
        Assert.IsNotNull(response.Headers.CacheControl,
            "A token-bearing success response must carry a Cache-Control header.");
        Assert.IsTrue(response.Headers.CacheControl.NoStore,
            "The success response's Cache-Control must contain no-store (RFC 7523 §3.1 / OAuth 2.1 §3.2.3).");
    }


    /// <summary>
    /// RFC 7523 §7 privacy: an error response MUST NOT leak the subject of the (rejected) assertion. A
    /// validator that knows the subject yet rejects the assertion (returns <see langword="null"/>) drives
    /// an <c>invalid_grant</c> response whose body must not contain the assertion-subject identifier.
    /// </summary>
    [TestMethod]
    public async Task InvalidGrantErrorBodyDoesNotLeakAssertionSubject()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJwtBearerClient(app);
        WireClientAuthentication(app);

        //The seam knows the subject (it is the fixture AssertionSubject) but rejects the assertion. The
        //error body must not echo that subject — a §3 failure surfaces only as the invalid_grant code.
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(null);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.tampered.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidGrant, body, StringComparison.Ordinal);
        Assert.DoesNotContain(AssertionSubject, body, StringComparison.Ordinal,
            "RFC 7523 §7: the error response must not leak the assertion subject.");
    }


    /// <summary>
    /// Grant disjointness: the jwt-bearer <c>grant_type</c> is served ONLY as the jwt-bearer grant. A
    /// host that does NOT allow the <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/>
    /// capability does not materialize the grant, so a well-formed jwt-bearer request is never served as
    /// a successful jwt-bearer token issuance (never reaches 200) — the grant_type does not fall through
    /// to another grant.
    /// </summary>
    [TestMethod]
    public async Task JwtBearerGrantTypeIsNotServedWhenCapabilityIsNotAllowed()
    {
        await using TestHostShell app = new(TimeProvider);

        //Register a client allowed the client_credentials grant capability (plus discovery/jwks, neither
        //a grant capability) but NOT jwt-bearer — the capability that materializes the grant. The seam
        //is wired so the only reason a token could not issue is the missing capability.
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        WireClientAuthentication(app);
        WireAcceptingValidator(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque.signature"
        }).WithClientSecretPost(ClientId, Encoding.UTF8.GetBytes(ClientSecret));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.SharedHttpClient!, tokenUrl, form, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(200, (int)response.StatusCode, body,
            "A jwt-bearer grant_type must not be served as a successful token issuance when the jwt-bearer capability is not allowed.");
    }


    /// <summary>
    /// Registers a truly grant-only confidential client — no
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> — allowed
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/> plus
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/> (the end-to-end test
    /// obtains a real assertion via the client_credentials grant). Grant-only jwt-bearer issuance
    /// works because <see cref="Rfc9068AccessTokenProducer"/>'s <c>RequiredCapability</c> is
    /// <see langword="null"/> — an optional tenant-feature gate, not a grant-capability proxy
    /// (contract wave-4 D2) — so the endpoint-match capability alone is sufficient. RegisterDpopClient
    /// supplies the AccessTokenIssuance signing keys the producers resolve; the discovery/jwks
    /// capabilities round out the standard surface. <see cref="MachineScope"/> is added to
    /// <c>AllowedScopes</c> and mapped onto <see cref="ResourceServerAudience"/> in
    /// <c>ScopeToAudience</c> (the register-then-upgrade pattern — the routing dictionaries are
    /// host-internal) so <see cref="ObtainClientCredentialsAccessTokenAsync"/> can mint a correctly
    /// audienced real assertion without requesting <c>openid</c> — contract wave-4 D4 narrows
    /// <c>openid</c> away from every <c>client_credentials</c> grant, so such a grant cannot carry the
    /// audience mapping the end-to-end tests rely on.
    /// </summary>
    private static VerifierKeyMaterial RegisterJwtBearerClient(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthJwtBearer,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

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

        return material;
    }


    /// <summary>
    /// Contract wave-4 D3/D4: on a tenant granted the
    /// <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> feature — ruling out D2's
    /// capability gate as the explanation — a jwt-bearer grant whose seam legitimately grants
    /// <c>openid</c> (the app opting in per the source-layer contract: <c>jwt_bearer</c> honors the
    /// app-granted scope, unlike <c>client_credentials</c>) still never yields an id_token.
    /// <see cref="Oidc10IdTokenProducer"/>'s <c>IsApplicable</c> independently requires
    /// <c>GrantType ∈ {authorization_code, refresh_token}</c> — this test proves that gate holds even
    /// when <c>openid</c> survives all the way to the issued access token's <c>scope</c> claim,
    /// which is the non-vacuous case (nothing upstream removed <c>openid</c> here).
    /// </summary>
    [TestMethod]
    public async Task NoIdTokenIsMintedForJwtBearerEvenWithOpenidGrantedAndOidcFeatureEnabled()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthJwtBearer,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        WireClientAuthentication(app);

        //The seam grants openid — an app opting in to vouch that the exchanged subject is an
        //End-User (contract wave-4 D4: jwt_bearer honors whatever scope the app's authorization
        //seam decides, unlike client_credentials' source-layer narrowing).
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(
                    new JwtBearerGrant { Subject = AssertionSubject, Scope = WellKnownScopes.OpenId });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        OutgoingFormFields form = BuildRequest(new JwtBearerBuilderOptions
        {
            Assertion = "eyJhbGciOiJFUzI1NiJ9.opaque-assertion-blob.signature",
            Scope = WellKnownScopes.OpenId
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
            "jwt_bearer must never carry an id_token even when openid survived to the granted scope "
            + "on a tenant with the OidcOpenIdConnect feature granted.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        using JsonDocument payload = DecodePayload(accessToken);
        Assert.AreEqual(WellKnownScopes.OpenId, payload.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "The issued access token's own scope claim must also carry openid unchanged.");
    }


    /// <summary>
    /// Wires the client_secret_post authentication seam (RFC 6749 §2.3.1): the application owns the
    /// secret store and the comparison; this test glue checks the form field against the registered
    /// client's secret. Required only because some tests present credentials (§3.1) — the grant itself
    /// does not require this seam.
    /// </summary>
    private static void WireClientAuthentication(TestHostShell app) =>
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));


    /// <summary>
    /// Wires an assertion-validation seam that accepts any non-empty assertion and returns the fixture
    /// subject and granted scope — the trust-authority stand-in for the happy-path tests where the
    /// §3 processing is not the unit under test.
    /// </summary>
    private static void WireAcceptingValidator(TestHostShell app) =>
        app.Server.OAuth().ValidateJwtBearerAssertionAsync =
            static (assertion, requestedScope, registration, context, ct) =>
                ValueTask.FromResult<JwtBearerGrant?>(
                    new JwtBearerGrant { Subject = AssertionSubject, Scope = GrantedScope });


    /// <summary>
    /// Re-registers <paramref name="material"/>'s client with
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> set to <paramref name="method"/> — the
    /// declared-client shape draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-049) gates on.
    /// Uses the same register-then-upgrade pattern as
    /// <see cref="TestHostShell.SetAccessTokenLifetime"/>, because the routing dictionaries are
    /// host-internal.
    /// </summary>
    private static void DeclareTokenEndpointAuthMethod(
        TestHostShell app, VerifierKeyMaterial material, ClientAuthenticationMethod method)
    {
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = host.Registrations[segment];
        ClientRecord updated = previous with
        {
            TokenEndpointAuthMethod = method
        };

        host.Registrations[segment] = updated;
        host.Registrations[updated.ClientId] = updated;

        host.Server.UpdateClient(previous, updated, new ExchangeContext());

        material.Registration = updated;
    }


    /// <summary>
    /// Obtains a real signed access token from the AS over the wire via the <c>client_credentials</c>
    /// grant (RFC 6749 §4.4). The returned compact JWS is a genuine RFC 9068 token: <c>sub</c> is the
    /// client itself (RFC 9068 §3), <c>iss</c> is the AS issuer, and it is P-256-signed by the AS's
    /// access-token key. The end-to-end test presents it as a real <c>assertion</c>.
    /// </summary>
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
    /// Decodes the JWT payload (the middle compact-JWS segment) of <paramref name="compactJws"/> into a
    /// parsed <see cref="JsonDocument"/> for claim assertions.
    /// </summary>
    private static JsonDocument DecodePayload(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);

        return JsonDocument.Parse(payloadBytes);
    }


    /// <summary>
    /// Fetches the AS's JWKS over HTTP (GET <c>/connect/{segment}/jwks</c>) and returns a key resolver
    /// that — exactly as a relying party would — looks up the published JWK by <c>kid</c> and
    /// reconstructs a <see cref="PublicKeyMemory"/> from it. This is the real trust anchor for the
    /// signature checks: keys come from the AS's published JWKS, not from the host's private store.
    /// </summary>
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


    /// <summary>
    /// Runs the project's resource-server-grade <see cref="JwsAccessTokenValidator"/> over a token:
    /// resolves the verification key by <c>kid</c> from the AS JWKS, verifies the P-256 signature, and
    /// enforces <c>iss</c>, <c>aud</c>, and the timing window. The expected audience is the
    /// resource-server identifier the openid scope maps to on this registration — which the end-to-end
    /// test treats as the AS's own audience identity for the RFC 7523 §3 rule-3 check.
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
    /// Builds a well-formed RFC 7523 §2.1 JWT Bearer request via
    /// <see cref="JwtBearerRequestBuilder.Build(JwtBearerBuilderOptions)"/> and asserts the build
    /// succeeded — every call site here supplies a well-formed <paramref name="options"/>, so a build
    /// failure is a test-fixture bug, not something under test.
    /// </summary>
    private static OutgoingFormFields BuildRequest(JwtBearerBuilderOptions options)
    {
        Result<OutgoingFormFields, TokenRequestBuilderError> built = JwtBearerRequestBuilder.Build(options);
        Assert.IsTrue(built.IsSuccess, "The builder must accept a well-formed jwt-bearer request.");

        return built.Value!;
    }
}
