using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// HTTP wire tests for the <c>client_credentials</c> grant (RFC 6749 §4.4):
/// a machine client authenticates through the application's
/// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
/// seam and receives a Bearer access token scoped to its allowed scopes — the
/// flow a Shared Signals Receiver uses to obtain <c>ssf.manage</c> from a
/// Transmitter's authorization server.
/// </summary>
[TestClass]
internal sealed class ClientCredentialsGrantTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";

    //A non-identity scope, granted alongside RegisterDpopClient's fixed OIDC identity scope set
    //(RegisterMachineClient patches it in) so a happy-path request has SOMETHING left to retain
    //once RFC 6749 §3.3 narrowing (contract wave-4 D4) removes openid/profile/email/address/phone
    //from every client_credentials grant.
    private const string MachineScope = "telemetry.read";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public async Task IssuesBearerAccessTokenOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterMachineClient(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = MachineScope
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;
        string accessToken = root.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, root.GetProperty("token_type").GetString());
        Assert.IsGreaterThan(0, root.GetProperty("expires_in").GetInt32(), "expires_in must reflect the token's exp-iat.");
        Assert.AreEqual(MachineScope, root.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "A non-identity scope survives RFC 6749 §3.3 narrowing unchanged (contract wave-4 D4 "
            + "narrows only openid and the OIDC identity scopes).");

        //RFC 9068 §3: with no end-user involved, the subject is the client itself.
        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty("sub").GetString());
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty("client_id").GetString());
    }


    [TestMethod]
    public async Task WrongSecretAndDisallowedScopeAreRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterMachineClient(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        //A wrong secret fails client authentication — 401 invalid_client.
        using HttpResponseMessage badSecret = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = "guessed-wrong"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)badSecret.StatusCode);

        //A scope outside the registration's allowed set — 400 invalid_scope.
        using HttpResponseMessage badScope = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.SsfManage
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string badScopeBody = await badScope.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)badScope.StatusCode, badScopeBody);
        Assert.Contains(OAuthErrors.InvalidScope, badScopeBody);
    }


    [TestMethod]
    public async Task GrantAdvertisesAndFailsClosedWithoutTheSeam()
    {
        //With the seam wired, the discovery document advertises client_credentials.
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterMachineClient(app);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;

        Uri discoveryUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/openid-configuration");
        using HttpResponseMessage discovery = await host.SharedHttpClient!
            .GetAsync(discoveryUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string discoveryBody = await discovery.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)discovery.StatusCode, discoveryBody);
        Assert.Contains(WellKnownGrantTypes.ClientCredentials, discoveryBody,
            "grant_types_supported must advertise client_credentials when the grant is active.");

        //Without the seam, the grant endpoint does not exist — fail-closed: an
        //unauthenticated client-credentials grant would mint tokens for anyone.
        await using TestHostShell bare = new(TimeProvider);
        using VerifierKeyMaterial bareMaterial = bare.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials));
        await bare.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer bareHost = bare.Host("default");
        Uri bareTokenUrl = new(bareHost.HttpBaseAddress!, $"/connect/{bareMaterial.Registration.TenantId.Value}/token");

        using HttpResponseMessage unmatched = await OAuthTestTransport.PostFormAsync(bareHost.SharedHttpClient!, bareTokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret
        }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(200, (int)unmatched.StatusCode,
            "The client_credentials grant must not be reachable without the client-authentication seam.");
    }


    /// <summary>
    /// RFC 9396 §6: a <c>client_credentials</c> token request carrying
    /// <c>authorization_details</c> MUST NOT have the parameter silently dropped. Malformed JSON
    /// and an unknown type each surface the §5 <c>invalid_authorization_details</c> error from the
    /// same shape-validation path the other grants use; a shape-valid <c>openid_credential</c>
    /// object is refused with <c>invalid_authorization_details</c> because this grant has no policy
    /// through which an authorization-details-bound token can be allowed; and a request with no
    /// <c>authorization_details</c> is issued exactly as before.
    /// </summary>
    [TestMethod]
    public async Task AuthorizationDetailsAreValidatedAndRefusedNotSilentlyDropped()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterMachineClient(app);
        app.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        HttpClient http = host.SharedHttpClient!;

        //(a) Malformed JSON — §5 "not conforming to the respective type definition".
        using HttpResponseMessage malformed = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] = "{ not json"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string malformedBody = await malformed.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)malformed.StatusCode, malformedBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, malformedBody);

        //(b) Unknown type — §5 "contains an unknown authorization details type value".
        using HttpResponseMessage unknownType = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] =
                """[{"type":"no_such_type_for_this_server"}]"""
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string unknownTypeBody = await unknownType.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)unknownType.StatusCode, unknownTypeBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, unknownTypeBody);

        //(c) Shape-valid openid_credential — §6: the grant's policy cannot allow the issuance, so
        //the request is refused, not silently dropped.
        using HttpResponseMessage shapeValid = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] =
                """[{"type":"openid_credential","credential_configuration_id":"UniversityDegree_dc_sd_jwt"}]"""
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string shapeValidBody = await shapeValid.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)shapeValid.StatusCode, shapeValidBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, shapeValidBody);
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, shapeValidBody,
            "A shape-valid authorization_details request must be refused, never minted into a token.");

        //(d) No authorization_details — the grant is issued exactly as before.
        using HttpResponseMessage plain = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string plainBody = await plain.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)plain.StatusCode, plainBody);
        using JsonDocument plainDoc = JsonDocument.Parse(plainBody);
        Assert.IsTrue(plainDoc.RootElement.TryGetProperty(WellKnownTokenTypes.AccessToken, out _));
        Assert.IsFalse(plainDoc.RootElement.TryGetProperty(OAuthRequestParameterNames.AuthorizationDetails, out _),
            "A client_credentials response carries no authorization_details.");
    }


    /// <summary>
    /// Registers a truly client-credentials-only confidential machine client (no
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/>) and wires a
    /// client_secret_post validator. Grant-only issuance works because
    /// <see cref="Rfc9068AccessTokenProducer"/>'s <c>RequiredCapability</c> is
    /// <see langword="null"/> — an optional tenant-feature gate, not a grant-capability proxy
    /// (contract wave-4 D2) — so every token-issuing grant's own endpoint-match capability
    /// (here <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/>) is sufficient
    /// on its own.
    /// </summary>
    private static VerifierKeyMaterial RegisterMachineClient(TestHostShell app)
    {
        //RegisterDpopClient supplies the AccessTokenIssuance signing keys the
        //token producers resolve; the plain RegisterClient helper does not.
        VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        //RegisterDpopClient fixes AllowedScopes to the OIDC identity scope set; add MachineScope
        //(the register-then-upgrade pattern — the routing dictionaries are host-internal) so a
        //happy-path request retains something once the identity scopes are narrowed away.
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = host.Registrations[segment];
        ClientRecord updated = previous with
        {
            AllowedScopes = previous.AllowedScopes.Add(MachineScope)
        };
        host.Registrations[segment] = updated;
        host.Registrations[updated.ClientId] = updated;
        host.Server.UpdateClient(previous, updated, new ExchangeContext());
        material.Registration = updated;

        //client_secret_post (RFC 6749 §2.3.1): the application owns the secret
        //store and the comparison; this test glue checks the form field.
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue("client_secret", out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        return material;
    }


    /// <summary>
    /// Contract wave-4 D3/D4: even though this tenant is granted the
    /// <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> feature — ruling out D2's
    /// capability gate as the explanation — a <c>client_credentials</c> token request carrying
    /// <c>openid</c> never yields an id_token. <see cref="Oidc10IdTokenProducer"/>'s
    /// <c>IsApplicable</c> independently requires <c>GrantType ∈ {authorization_code,
    /// refresh_token}</c>, and the source-side <c>DropIdentityScopesForNonEndUserGrant</c> already
    /// strips <c>openid</c> before the producer walk even runs — this test pins BOTH layers hold.
    /// </summary>
    [TestMethod]
    public async Task NoIdTokenIsMintedForClientCredentialsEvenWithOpenidRequestedAndOidcFeatureGranted()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterDpopClient(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue("client_secret", out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.IsTrue(doc.RootElement.TryGetProperty(WellKnownTokenTypes.AccessToken, out _),
            "An access token must still be minted (D3 leaves the access-token producer unaffected).");
        Assert.IsFalse(doc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out _),
            "client_credentials must never carry an id_token even when openid was requested on a "
            + "tenant with the OidcOpenIdConnect feature granted.");
    }


    /// <summary>
    /// Contract wave-4 D4 source layer: <c>client_credentials</c> has no authenticated End-User (the
    /// token's <c>sub</c> is the client itself), so a request carrying <c>openid</c> and every OIDC
    /// Core §5.4 identity scope has them narrowed away (RFC 6749 §3.3) before the granted scope ever
    /// reaches the token — the issued access token's <c>scope</c> claim carries none of them — and
    /// the narrowing emits <see cref="OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant"/>
    /// naming exactly the dropped values.
    /// </summary>
    [TestMethod]
    public async Task OpenidAndIdentityScopesAreDroppedFromClientCredentialsGrantedScopeWithOtelEvent()
    {
        ConcurrentBag<Activity> captured = [];
        using ActivityListener listener = new()
        {
            ShouldListenTo = static source =>
                string.Equals(source.Name, ServerActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => captured.Add(activity)
        };
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterMachineClient(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        //RegisterMachineClient's AllowedScopes (via RegisterDpopClient) is exactly the OIDC identity
        //scope set — every token requested here is an identity scope, so the narrowed grant is empty.
        string requestedScope = string.Join(' ',
            WellKnownScopes.OpenId, WellKnownScopes.Profile, WellKnownScopes.Email,
            WellKnownScopes.Address, WellKnownScopes.Phone);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = requestedScope
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        //client_credentials always writes the scope field (unlike pre_authorized_code, which omits
        //it when empty) — every identity token was narrowed away, so it comes back empty.
        Assert.AreEqual(string.Empty, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "The response scope must be empty once every requested token — all five are identity scopes — is narrowed away.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        string issuedScope = payload.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString()!;
        Assert.AreEqual(string.Empty, issuedScope,
            "The issued access token's scope claim must be empty — RFC 6749 §3.3 narrowing removed "
            + "every identity token before IssuanceContext.Scope was set.");

        //ActivityListener is process-wide (see the ActivityListener cross-contamination
        //guidance): filter captured activities to this test's tenant before asserting.
        List<ActivityEvent> dropEvents = captured
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantId) as string, segment, StringComparison.Ordinal))
            .SelectMany(a => a.Events)
            .Where(e => string.Equals(e.Name, OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant, StringComparison.Ordinal))
            .ToList();

        Assert.IsGreaterThan(0, dropEvents.Count,
            $"A '{OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant}' event tagged with tenant "
            + $"'{segment}' must be emitted.");

        string droppedScopesTagValue = dropEvents[0].Tags
            .FirstOrDefault(t => string.Equals(t.Key, OAuthEventNames.DroppedScopesTagName, StringComparison.Ordinal))
            .Value as string ?? string.Empty;
        string[] droppedTokens = droppedScopesTagValue.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.HasCount(5, droppedTokens, $"Dropped scopes tag was '{droppedScopesTagValue}'.");
        Assert.Contains(WellKnownScopes.OpenId, droppedTokens);
        Assert.Contains(WellKnownScopes.Profile, droppedTokens);
        Assert.Contains(WellKnownScopes.Email, droppedTokens);
        Assert.Contains(WellKnownScopes.Address, droppedTokens);
        Assert.Contains(WellKnownScopes.Phone, droppedTokens);
    }
}
