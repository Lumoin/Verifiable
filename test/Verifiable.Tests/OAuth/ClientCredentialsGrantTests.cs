using System.Buffers;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
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

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public async Task IssuesBearerAccessTokenOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterMachineClient(app);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        using HttpResponseMessage response = await PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        }).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;
        string accessToken = root.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, root.GetProperty("token_type").GetString());
        Assert.IsGreaterThan(0, root.GetProperty("expires_in").GetInt32(), "expires_in must reflect the token's exp-iat.");
        Assert.AreEqual(WellKnownScopes.OpenId, root.GetProperty(OAuthRequestParameterNames.Scope).GetString());

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
        using HttpResponseMessage badSecret = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = "guessed-wrong"
        }).ConfigureAwait(false);
        Assert.AreEqual(401, (int)badSecret.StatusCode);

        //A scope outside the registration's allowed set — 400 invalid_scope.
        using HttpResponseMessage badScope = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.SsfManage
        }).ConfigureAwait(false);
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
        Assert.Contains(OAuthRequestParameterValues.GrantTypeClientCredentials, discoveryBody,
            "grant_types_supported must advertise client_credentials when the grant is active.");

        //Without the seam, the grant endpoint does not exist — fail-closed: an
        //unauthenticated client-credentials grant would mint tokens for anyone.
        await using TestHostShell bare = new(TimeProvider);
        using VerifierKeyMaterial bareMaterial = bare.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials));
        await bare.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer bareHost = bare.Host("default");
        Uri bareTokenUrl = new(bareHost.HttpBaseAddress!, $"/connect/{bareMaterial.Registration.TenantId.Value}/token");

        using HttpResponseMessage unmatched = await PostFormAsync(bareHost.SharedHttpClient!, bareTokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret
        }).ConfigureAwait(false);
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
        app.Server.Integration.UseDefaultAuthorizationDetailsJsonParsing();

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        HttpClient http = host.SharedHttpClient!;

        //(a) Malformed JSON — §5 "not conforming to the respective type definition".
        using HttpResponseMessage malformed = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] = "{ not json"
        }).ConfigureAwait(false);
        string malformedBody = await malformed.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)malformed.StatusCode, malformedBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, malformedBody);

        //(b) Unknown type — §5 "contains an unknown authorization details type value".
        using HttpResponseMessage unknownType = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] =
                """[{"type":"no_such_type_for_this_server"}]"""
        }).ConfigureAwait(false);
        string unknownTypeBody = await unknownType.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)unknownType.StatusCode, unknownTypeBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, unknownTypeBody);

        //(c) Shape-valid openid_credential — §6: the grant's policy cannot allow the issuance, so
        //the request is refused, not silently dropped.
        using HttpResponseMessage shapeValid = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] =
                """[{"type":"openid_credential","credential_configuration_id":"UniversityDegree_dc_sd_jwt"}]"""
        }).ConfigureAwait(false);
        string shapeValidBody = await shapeValid.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)shapeValid.StatusCode, shapeValidBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, shapeValidBody);
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, shapeValidBody,
            "A shape-valid authorization_details request must be refused, never minted into a token.");

        //(d) No authorization_details — the grant is issued exactly as before.
        using HttpResponseMessage plain = await PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        }).ConfigureAwait(false);
        string plainBody = await plain.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)plain.StatusCode, plainBody);
        using JsonDocument plainDoc = JsonDocument.Parse(plainBody);
        Assert.IsTrue(plainDoc.RootElement.TryGetProperty(WellKnownTokenTypes.AccessToken, out _));
        Assert.IsFalse(plainDoc.RootElement.TryGetProperty(OAuthRequestParameterNames.AuthorizationDetails, out _),
            "A client_credentials response carries no authorization_details.");
    }


    /// <summary>
    /// Registers a confidential machine client and wires a client_secret_post
    /// validator. The registration carries OAuthAuthorizationCode alongside
    /// OAuthClientCredentials because the shipped RFC 9068 access-token producer
    /// is gated on it; a client-credentials-only deployment supplies its own
    /// producer set.
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
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        //client_secret_post (RFC 6749 §2.3.1): the application owns the secret
        //store and the comparison; this test glue checks the form field.
        app.Server.Integration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue("client_secret", out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        return material;
    }


    private async Task<HttpResponseMessage> PostFormAsync(
        HttpClient http, Uri url, Dictionary<string, string> fields)
    {
        using FormUrlEncodedContent content = new(fields);

        return await http.PostAsync(url, content, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
