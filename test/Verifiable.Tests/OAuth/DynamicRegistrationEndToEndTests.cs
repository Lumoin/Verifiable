using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.WebFinger;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end test exercising dynamic client registration into an AuthCode
/// flow. The test gate for phase 4: when it passes, every type phases 1–3
/// introduced has been exercised in one continuous flow.
/// </summary>
[TestClass]
internal sealed class DynamicRegistrationEndToEndTests
{
    /// <summary>The test-owned cancellation and execution context.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>The deterministic clock used by the fixture.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>The registered callback URI used by the client.</summary>
    private static Uri DefaultRedirectUri { get; } = new("https://client.example.com/callback");


    /// <summary>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 section 3.2.1</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "Registration creation, conditional replacement and deletion commit through the required registration store before optional observers run."
    /// </summary>
    [TestMethod]
    public async Task RegisterAsyncIssuesClientIdAndDrivesAuthCodeFlow()
    {
        await using TestHostShell host = new(TimeProvider);

        OAuthClient client = host.CreateOAuthClientWithoutRegistration();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        ClientMetadata metadata = new()
        {
            ClientName = "phase-4-test-client",
            RedirectUris = [DefaultRedirectUri],
            TokenEndpointAuthMethod = ClientAuthenticationMethod.None,
            Scope = "openid"
        };

        RegisterClientOptions registerOptions = new()
        {
            RegistrationEndpoint = host.GlobalRegistrationEndpoint,
            AuthorizationServerIssuer = host.IssuerUri,
            Metadata = metadata,
            AuthenticationMethod = ClientAuthenticationMethod.None,
            SigningKeyMaterial = signingKey,
            Profile = PolicyProfile.Haip10
        };

        DynamicRegistrationResult result = await client.DynamicRegistration
            .RegisterAsync(registerOptions, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(result.Registration.ClientId.Value,
            "AS-issued client_id must be non-null.");
        Assert.IsNotNull(result.Response.AccessToken,
            "AS must issue a registration_access_token alongside the client_id.");
        Assert.AreEqual(host.IssuerUri, result.Registration.AuthorizationServerIssuer,
            "Registration AS issuer must equal the host's issuer URI.");

        //Drive an AuthCode flow against the dynamically registered client.
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            result.Registration,
            DefaultRedirectUri,
            OAuthFormEncodedFieldsFixtures.OpenIdScope,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR against dynamically registered client must succeed. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");
        Assert.IsNotNull(parResult.RedirectUri);
        Assert.Contains("request_uri", parResult.RedirectUri.ToString(), StringComparison.Ordinal,
            "Authorize redirect URI must carry the PAR-issued request_uri.");
    }


    /// <summary>
    /// Proves <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 section 2.1</see>.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "Management requests for absent clients or with invalid registration access tokens return HTTP 401."
    /// </summary>
    [TestMethod]
    public async Task RegistrationLifecycleRegistersReadsUpdatesAndDeregisters()
    {
        await using TestHostShell host = new(TimeProvider);

        OAuthClient client = host.CreateOAuthClientWithoutRegistration();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        ClientMetadata initialMetadata = new()
        {
            ClientName = "phase-5-lifecycle-client",
            RedirectUris = [DefaultRedirectUri],
            TokenEndpointAuthMethod = ClientAuthenticationMethod.None,
            Scope = WellKnownScopes.OpenId
        };

        RegisterClientOptions registerOptions = new()
        {
            RegistrationEndpoint = host.GlobalRegistrationEndpoint,
            AuthorizationServerIssuer = host.IssuerUri,
            Metadata = initialMetadata,
            AuthenticationMethod = ClientAuthenticationMethod.None,
            SigningKeyMaterial = signingKey,
            Profile = PolicyProfile.Haip10
        };

        //Register.
        DynamicRegistrationResult registered = await client.DynamicRegistration
            .RegisterAsync(registerOptions, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(registered.Registration.ClientId.Value);
        Assert.IsNotNull(registered.Registration.ManagementUri);
        Assert.IsNotNull(registered.Registration.AccessToken);

        //Read.
        ClientMetadata fetchedAfterRegister = await client.DynamicRegistration
            .ReadAsync(registered.Registration, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(initialMetadata.Scope, fetchedAfterRegister.Scope);
        Assert.HasCount(1, fetchedAfterRegister.RedirectUris,
            "Read must echo the single registered redirect_uri.");

        //Update.
        ClientMetadata updatedMetadata = initialMetadata with
        {
            ClientName = "phase-5-lifecycle-client-renamed",
            Scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}"
        };

        ClientMetadata appliedAfterUpdate = await client.DynamicRegistration
            .UpdateAsync(registered.Registration, updatedMetadata, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Scope is a set on the wire per RFC 6749 §3.3 — order is not significant.
        //The server stores it as ImmutableHashSet and emits via deterministic
        //alphabetic sort, so the wire order is stable but caller code should
        //still treat scope as a set rather than relying on the ordering.
        HashSet<string> expectedScopes = [WellKnownScopes.OpenId, WellKnownScopes.Profile];
        HashSet<string> appliedScopes = SplitScope(appliedAfterUpdate.Scope);
        Assert.IsTrue(appliedScopes.SetEquals(expectedScopes),
            $"Update response must echo the new scope tokens; got '{appliedAfterUpdate.Scope}'.");

        //Read again — confirms the update persisted on the AS side.
        ClientMetadata fetchedAfterUpdate = await client.DynamicRegistration
            .ReadAsync(registered.Registration, TestContext.CancellationToken)
            .ConfigureAwait(false);

        HashSet<string> fetchedScopes = SplitScope(fetchedAfterUpdate.Scope);
        Assert.IsTrue(fetchedScopes.SetEquals(expectedScopes),
            $"Second read must reflect the updated scope tokens; got '{fetchedAfterUpdate.Scope}'.");

        //Deregister.
        await client.DynamicRegistration
            .DeregisterAsync(registered.Registration, TestContext.CancellationToken)
            .ConfigureAwait(false);

        //The deleted registration must refuse subsequent reads.
        InvalidOperationException postDeleteRead = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await client.DynamicRegistration
                .ReadAsync(registered.Registration, TestContext.CancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains("RFC 7592 read failed with status 401", postDeleteRead.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire with no <c>Authorization</c> field is answered
    /// 401 with an empty body and the one challenge <c>Bearer realm="https://registration.issuer.test/"</c>,
    /// which carries no error code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or
    /// attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code
    /// or other error information."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>: "The server
    /// generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one
    /// challenge applicable to the target resource."
    /// </summary>
    [TestMethod]
    public async Task AClientConfigurationRequestWithoutATokenIsChallenged()
    {
        await using TestHostShell host = new(TimeProvider);
        (_, _, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationFieldAsync(
            host, HttpMethod.Get, managementUri, authorization: null, json: null, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.AreEqual(string.Empty, body, "No error code or other error information.");
        Assert.AreEqual("Bearer realm=\"https://registration.issuer.test/\"", Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)));
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire whose <c>Authorization</c> field carries no Bearer
    /// token, an empty value, a value of white space or a credential of the <c>Basic</c> scheme, is answered 401
    /// with an empty body and the one challenge <c>Bearer realm="https://registration.issuer.test/"</c>, which
    /// carries no error code: the request lacks the authentication information the endpoint reads.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 Section 2</see>: "The client MUST use
    /// its registration access token in all calls to this endpoint as an OAuth 2.0 Bearer Token [RFC6750]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or
    /// attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code
    /// or other error information."
    /// </summary>
    /// <param name="authorization">The value of the request's <c>Authorization</c> field.</param>
    [TestMethod]
    [DataRow("", DisplayName = "an empty Authorization value")]
    [DataRow(" ", DisplayName = "an Authorization value of white space")]
    [DataRow("Basic dXNlcjpwYXNz", DisplayName = "an Authorization value of the Basic scheme")]
    public async Task AClientConfigurationRequestWhoseAuthorizationFieldCarriesNoBearerTokenIsChallenged(string authorization)
    {
        await using TestHostShell host = new(TimeProvider);
        (_, _, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationFieldAsync(
            host, HttpMethod.Get, managementUri, authorization, json: null, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.AreEqual(string.Empty, body, "No error code or other error information.");
        Assert.AreEqual("Bearer realm=\"https://registration.issuer.test/\"", Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)));
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire with a Bearer token the registration access token
    /// seam refuses is answered 401 with the body's error <c>invalid_token</c> and the one challenge
    /// <c>Bearer realm="https://registration.issuer.test/", error="invalid_token"</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "If the
    /// registration access token used to make this request is not valid, the server MUST respond with an error as
    /// described in the OAuth Bearer Token Usage specification [RFC6750]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "If the protected
    /// resource request included an access token and failed authentication, the resource server SHOULD include the
    /// "error" attribute to provide the client with the reason why the access request was declined."
    /// </summary>
    [TestMethod]
    public async Task AClientConfigurationRequestWhoseTokenIsRefusedIsAnInvalidToken()
    {
        await using TestHostShell host = new(TimeProvider);
        (_, _, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(
            host, HttpMethod.Get, managementUri, "invalid-bearer", json: null, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.AreEqual(
            "Bearer realm=\"https://registration.issuer.test/\", error=\"invalid_token\"", Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)));
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", error.RootElement.GetProperty("error").GetString(), body);
    }


    /// <summary>
    /// A DELETE of the client configuration URI sent over the wire with the client's own registration access token,
    /// whose client another party deletes after the request is authenticated and before its conditional deletion
    /// commits, is answered 401 with the body's error <c>invalid_token</c> and the one challenge
    /// <c>Bearer realm="https://registration.issuer.test/", error="invalid_token"</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 Section 2.3</see>: "If the client
    /// does not exist on this server, the server MUST respond with HTTP 401 Unauthorized and the registration access
    /// token used to make this request SHOULD be immediately revoked, if possible."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>: "The server
    /// generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one
    /// challenge applicable to the target resource."
    /// </summary>
    [TestMethod]
    public async Task ADeletionWhoseClientIsGoneWhileItRunsIsAnInvalidToken()
    {
        await using TestHostShell host = new(TimeProvider);
        (_, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        HostedAuthorizationServer served = host.Host("default");
        served.BeforeRegistrationDeleteAsync = (registration, cancellationToken) =>
        {
            //Another party removes the client between this request's authentication and its deletion.
            _ = served.Registrations.TryRemove(registration.TenantId.Value, out _);
            _ = served.Registrations.TryRemove(registration.ClientId, out _);

            return ValueTask.CompletedTask;
        };

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(
            host, HttpMethod.Delete, managementUri, accessToken, json: null, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.AreEqual(
            "Bearer realm=\"https://registration.issuer.test/\", error=\"invalid_token\"", Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)));
        using JsonDocument error = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", error.RootElement.GetProperty("error").GetString(), body);
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire with the client's own registration access token is
    /// answered 200 and carries no <c>WWW-Authenticate</c> field: the challenge belongs to a refusal only.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "Upon successful
    /// read of the information for a currently active client, the authorization server responds with an HTTP 200 OK
    /// with content type of "application/json" and a payload as described in Section 3."
    /// </summary>
    [TestMethod]
    public async Task AClientConfigurationReadWithItsTokenCarriesNoChallenge()
    {
        await using TestHostShell host = new(TimeProvider);
        (_, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(
            host, HttpMethod.Get, managementUri, accessToken, json: null, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsEmpty(RawAuthCodeWirePushers.ChallengesOf(response), "An accepted request carries no challenge.");
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire with the client's own, valid registration access
    /// token presented under the <c>DPoP</c> scheme is answered 401 with an empty body and the one challenge
    /// <c>Bearer realm="https://registration.issuer.test/"</c>, which carries no error code, and no client metadata
    /// is returned: the endpoint reads a Bearer token only, so the request lacks the authentication information the
    /// endpoint reads.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 Section 2</see>: "The client MUST use
    /// its registration access token in all calls to this endpoint as an OAuth 2.0 Bearer Token [RFC6750]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request
    /// lacks any authentication information (e.g., the client was unaware that authentication is necessary or
    /// attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code
    /// or other error information."
    /// </summary>
    [TestMethod]
    public async Task AClientConfigurationRequestPresentingItsTokenUnderTheDPoPSchemeIsChallengedWithoutAnErrorCode()
    {
        await using TestHostShell host = new(TimeProvider);
        (_, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationFieldAsync(
            host, HttpMethod.Get, managementUri, $"DPoP {accessToken}", json: null, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.AreEqual(string.Empty, body, "No error code and no client metadata.");
        Assert.AreEqual("Bearer realm=\"https://registration.issuer.test/\"", Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>:
    /// "invalid_request The request is missing a required parameter, includes an unsupported parameter or
    /// parameter value, repeats the same parameter, uses more than one method for including an access
    /// token, or is otherwise malformed.  The resource server SHOULD respond with the HTTP 400 (Bad
    /// Request) status code." A GET of the client configuration URI sent over a raw TLS connection with two
    /// <c>Authorization: Bearer</c> field lines carrying the client's own registration access token
    /// (<c>Authorization = credentials</c> is no list,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>) is refused
    /// with 400 <c>invalid_request</c> and the one challenge
    /// <c>Bearer realm="https://registration.issuer.test/", error="invalid_request"</c>: the endpoint reads a
    /// Bearer token only (<see href="https://www.rfc-editor.org/rfc/rfc7592#section-2">RFC 7592 Section 2</see>), so
    /// its challenge is the <c>Bearer</c> one.
    /// </summary>
    [TestMethod]
    public async Task AClientConfigurationReadWithTwoAuthorizationLinesIsAnInvalidRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        (_, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, managementUri,
            [
                new(WellKnownHttpHeaderNames.Authorization, $"Bearer {accessToken}"),
                new(WellKnownHttpHeaderNames.Authorization, $"Bearer {accessToken}")
            ],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual("Bearer realm=\"https://registration.issuer.test/\", error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        using JsonDocument error = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", error.RootElement.GetProperty("error").GetString(), response.Body);
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire, served under a registration the application's
    /// materialization seam replaces with a record that is not an OAuth client registration, is answered 500 with the
    /// body's error <c>server_error</c> and no challenge, whether or not the request presents the client's own
    /// registration access token, and the endpoint itself gives that answer, so no fault reaches the host: the
    /// endpoint cannot serve the request, and the cause is the server's wiring, not the caller.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that
    /// prevented it from fulfilling the request."
    /// </summary>
    /// <param name="isTokenPresented">Whether the request presents the client's own registration access token.</param>
    [TestMethod]
    [DataRow(false, DisplayName = "no Authorization field")]
    [DataRow(true, DisplayName = "the client's own registration access token")]
    public async Task AClientConfigurationRequestServedUnderARegistrationTheEndpointCannotUseIsAServerError(bool isTokenPresented)
    {
        await using TestHostShell host = new(TimeProvider);
        (_, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.MaterializeRegistrationAsync = static (registration, _, _) => ValueTask.FromResult(new RegistrationMaterialization
            {
                Registration = new WebFingerHttpApplication.PlainRegistration
                {
                    ClientId = registration.ClientId,
                    TenantId = registration.TenantId,
                    AllowedCapabilities = registration.AllowedCapabilities
                }
            });
        }).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationFieldAsync(
            host, HttpMethod.Get, managementUri, isTokenPresented ? $"Bearer {accessToken}" : null, json: null,
            TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Exception[] faults = host.Host("default").ConsumeHttpFaults();

        Assert.AreEqual(500, (int)response.StatusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", body);
        Assert.IsEmpty(RawAuthCodeWirePushers.ChallengesOf(response), "A fault of the server carries no challenge.");
        Assert.IsEmpty(faults, "The endpoint answers the registration it cannot use itself.");
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire with a Bearer token the registration access token
    /// seam refuses, served where no issuer resolves (no application issuer resolver, a dynamically registered client
    /// without an issuer and no issuer on the request's context), is answered 500 with the body's error
    /// <c>server_error</c> and no challenge: the challenge's realm is the issuer, and the default issuer resolver
    /// raises <see cref="InvalidOperationException"/> when nothing names one, which the host's HTTP application
    /// answers as a fault of the server. This records the answer of that composition; whether such a refusal
    /// answers 401 with a realm of its own is open.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that
    /// prevented it from fulfilling the request."
    /// </summary>
    [TestMethod]
    public async Task AClientConfigurationRefusalServedWhereNoIssuerResolvesIsAServerFault()
    {
        await using TestHostShell host = new(TimeProvider);
        (_, _, Uri managementUri) = await RegisterOverTheListenerAsync(host, isIssuerNamed: false).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(
            host, HttpMethod.Get, managementUri, "invalid-bearer", json: null, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Exception[] faults = host.Host("default").ConsumeHttpFaults();

        Assert.AreEqual(500, (int)response.StatusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", body);
        Assert.IsEmpty(RawAuthCodeWirePushers.ChallengesOf(response), "A fault of the server carries no challenge.");
        _ = Assert.IsInstanceOfType<InvalidOperationException>(Assert.ContainsSingle(faults));
    }


    /// <summary>
    /// Starts the host's listener, wires the application's issuer resolver to answer
    /// <see cref="RawAuthCodeWirePushers.ManagedClientIssuer"/> (<see cref="TestHostShell.NameIssuerAsync"/>) when
    /// <paramref name="isIssuerNamed"/> holds, and registers a managed client over the listener through
    /// <see cref="RawAuthCodeWirePushers.RegisterManagedClientAsync"/>.
    /// </summary>
    /// <param name="host">The serving fixture.</param>
    /// <param name="isIssuerNamed">Whether the application's issuer resolver names the issuer.</param>
    /// <returns>The issued client identifier, the registration access token and the client configuration URI.</returns>
    private async Task<(string ClientId, string AccessToken, Uri ManagementUri)> RegisterOverTheListenerAsync(
        TestHostShell host, bool isIssuerNamed = true)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        if(isIssuerNamed)
        {
            await TestHostShell.NameIssuerAsync(host.Server, RawAuthCodeWirePushers.ManagedClientIssuer).ConfigureAwait(false);
        }

        return await RawAuthCodeWirePushers.RegisterManagedClientAsync(host, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>The unordered scope set used to compare RFC 6749 section 3.3 responses.</summary>
    private static HashSet<string> SplitScope(string? scope) =>
        [.. (scope ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries)];
}
