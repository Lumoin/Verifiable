using Microsoft.Extensions.Time.Testing;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
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
    /// commits, is answered as a deletion that lost its race: 400 with the body
    /// <c>{"error":"invalid_client_metadata","error_description":"The registration changed during this deletion."}</c>
    /// and no challenge, with the application's registration access token seam asked once. The client's DELETE sent
    /// again finds no client and is answered 401 with the body's error <c>invalid_token</c> and no
    /// <c>WWW-Authenticate</c> field, as a management request whose client does not exist when it arrives is answered.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "A lost race is answered HTTP 400 `invalid_client_metadata` with the description "The registration changed during this deletion." and no event, and the handler loads nothing again; a deletion the client sends again is authenticated against the record it finds, and an absent or replaced identity receives HTTP 401."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 Section 2.3</see>: "If the client
    /// does not exist on this server, the server MUST respond with HTTP 401 Unauthorized and the registration access
    /// token used to make this request SHOULD be immediately revoked, if possible."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ADeletionWhoseClientIsGoneWhileItRunsLosesItsRaceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        (string clientId, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        StrongBox<int> checks = await CountTheTokenChecksAsync(host).ConfigureAwait(false);
        HostedAuthorizationServer served = host.Host("default");
        served.BeforeRegistrationDeleteAsync = (registration, cancellationToken) =>
        {
            //Another party removes the client between this request's authentication and its deletion.
            _ = served.Registrations.TryRemove(registration.TenantId.Value, out _);
            _ = served.Registrations.TryRemove(registration.ClientId, out _);

            return ValueTask.CompletedTask;
        };

        string deletion = await SendToTheClientConfigurationAsync(
            host, HttpMethod.Delete, managementUri, clientId, accessToken, json: null).ConfigureAwait(false);
        int checksOfTheDeletion = Volatile.Read(ref checks.Value);
        string sentAgain = await SendToTheClientConfigurationAsync(
            host, HttpMethod.Delete, managementUri, clientId, accessToken, json: null).ConfigureAwait(false);

        Assert.AreEqual(
            "400\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + /*lang=json,strict*/ "{\"error\":\"invalid_client_metadata\",\"error_description\":\"The registration changed during this deletion.\"}",
            deletion);
        Assert.AreEqual(1, checksOfTheDeletion, "The deletion asks the registration access token seam once.");
        Assert.AreEqual(
            "401\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + /*lang=json,strict*/ "{\"error\":\"invalid_token\",\"error_description\":\"Registration access token is invalid.\"}",
            sentAgain);
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
    /// A PUT of the client configuration URI sent over the wire with the client's own registration access token and
    /// its own metadata, served under an application's materialization that answers the registration with a member
    /// changed, replaces the metadata of the registration as stored and nothing else: the PUT is answered byte for
    /// byte as the same PUT with no materialization wired, the stored registration keeps its one capability
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/>, no <see cref="ClientRecord.LogoUri"/>
    /// and the revision the update gives it, and a later token exchange request with no materialization wired, sent to
    /// a server that serves the token exchange grant to a registration holding
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/>, is answered byte for byte as at a registration
    /// that never held that capability, <c>404</c> with an empty body. The materialization adds the capability
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/>, or gives <see cref="ClientRecord.LogoUri"/>, a
    /// member the update does not set and the library's client ID metadata materialization fills from a fetched
    /// document, a value.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 Section 2.2</see>: "Valid values of
    /// client metadata fields in this request MUST replace, not augment, the values previously associated with this
    /// client."
    /// <see href="../../../documents/AuthorizationServerDesign.md#8-settled-architectural-decisions-promote-when-ready">Section 8</see>:
    /// "The read and the update are built from the registration as stored, loaded again through
    /// `LoadRegistrationAsync`, not from the record an application's materialization answered for the request, so
    /// nothing a materialization changes is answered as registered or written to the store."
    /// </summary>
    /// <param name="member">The member the application's materialization changes.</param>
    [TestMethod]
    [DataRow("capability", DisplayName = "a capability added")]
    [DataRow("logoUri", DisplayName = "a member the update does not set")]
    public async Task AnUpdateUnderAMaterializationReplacesTheMetadataOfTheRegistrationAsStoredAsync(string member)
    {
        (_, string unmaterializedUpdate, string neverHeld, _, _) = await ManageUnderAMaterializationAsync(materialization: null).ConfigureAwait(false);
        (_, string update, string later, ClientRecord stored, _) = await ManageUnderAMaterializationAsync(MaterializationChanging(member)).ConfigureAwait(false);

        Assert.AreEqual(unmaterializedUpdate, update, "The PUT is answered as the same PUT with no materialization.");
        Assert.AreEqual(neverHeld, later, "The later request is answered as at a registration that never held the capability.");
        Assert.AreEqual("404\nContent-Length: 0\nServer: Kestrel\n\n", later);
        Assert.IsTrue(stored.AllowedCapabilities.SetEquals([WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration]),
            $"The stored registration keeps its capabilities; it holds {string.Join(", ", stored.AllowedCapabilities.Select(capability => capability.Urn))}.");
        Assert.IsNull(stored.LogoUri, "The stored registration keeps the value of a member the update does not set.");
        Assert.AreEqual(2L, stored.Revision);
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire with the client's own registration access token,
    /// served under an application's materialization that answers the registration with another client name, is
    /// answered byte for byte as the same GET with no materialization wired, carrying the registered
    /// <c>client_name</c> <c>initial-client</c>: the read answers the registration as stored.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "To read the
    /// current configuration of the client on the authorization server, the client makes an HTTP GET request to the
    /// client configuration endpoint, authenticating with its registration access token."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-3">RFC 7592 Section 3</see>: "Additionally, the
    /// authorization server MUST return all registered metadata about this client, including any fields provisioned
    /// by the authorization server itself."
    /// </summary>
    [TestMethod]
    public async Task AReadUnderAMaterializationAnswersTheRegistrationAsStoredAsync()
    {
        (string unmaterializedRead, _, _, _, _) = await ManageUnderAMaterializationAsync(materialization: null).ConfigureAwait(false);
        (string read, _, _, _, _) = await ManageUnderAMaterializationAsync(MaterializationChanging("clientName")).ConfigureAwait(false);

        Assert.AreEqual(unmaterializedRead, read, "The read is answered as the same read with no materialization.");
        Assert.Contains("\"client_name\":\"initial-client\"", read, StringComparison.Ordinal);
    }


    /// <summary>
    /// A PUT of the client configuration URI sent over the wire with the client's own registration access token and
    /// its own metadata, served under an application whose registration access token seam, after answering that the
    /// token is valid, replaces the client's registration access token and commits another revision of the stored
    /// registration, is answered as an update whose registration changed while it ran: 400 with the body
    /// <c>{"error":"invalid_client_metadata","error_description":"The registration changed during this update."}</c>.
    /// The stored registration keeps the other party's revision and client name, and the metadata the PUT carried is
    /// not written: the update replaces the revision it loaded, whose tenant and client identifier the token was
    /// checked for, or none.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 Section 2.2</see>: "This request is
    /// authenticated by the registration access token issued to the client."
    /// <see href="../../../documents/AuthorizationServerDesign.md#8-settled-architectural-decisions-promote-when-ready">Section 8</see>:
    /// "Record revisions and conditional replacement provide one winner for requests sharing a loaded revision, with
    /// HTTP 400 `invalid_client_metadata` for stale updates."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnUpdateWhoseTokenIsReplacedAfterItsCheckWritesNothingAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        (string clientId, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        await ReplaceTheTokenAroundItsCheckAsync(host, isAfterTheAnswer: true).ConfigureAwait(false);

        string update = await SendToTheClientConfigurationAsync(host, HttpMethod.Put, managementUri, clientId, accessToken,
            UpdatedMetadataOf(clientId)).ConfigureAwait(false);
        ClientRecord stored = host.Host("default").Registrations[clientId];

        Assert.AreEqual(
            "400\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + /*lang=json,strict*/ "{\"error\":\"invalid_client_metadata\",\"error_description\":\"The registration changed during this update.\"}",
            update);
        Assert.AreEqual(2L, stored.Revision, "The stored registration keeps the other party's revision.");
        Assert.AreEqual(AnotherPartysClientName, stored.ClientName, "The metadata the update carried is not written.");
    }


    /// <summary>
    /// A GET of the client configuration URI sent over the wire with the client's own registration access token, served
    /// under an application whose registration access token seam, after answering that the token is valid, replaces the
    /// client's registration access token and commits another revision of the stored registration with another client
    /// name, is answered byte for byte as the same GET before that seam was wired, carrying the registered
    /// <c>client_name</c> <c>initial-client</c>: the read answers the revision it loaded.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "To read the
    /// current configuration of the client on the authorization server, the client makes an HTTP GET request to the
    /// client configuration endpoint, authenticating with its registration access token."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AReadWhoseTokenIsReplacedAfterItsCheckAnswersTheRevisionItCheckedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        (string clientId, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        string beforeTheReplacement = await SendToTheClientConfigurationAsync(
            host, HttpMethod.Get, managementUri, clientId, accessToken, json: null).ConfigureAwait(false);
        await ReplaceTheTokenAroundItsCheckAsync(host, isAfterTheAnswer: true).ConfigureAwait(false);

        string read = await SendToTheClientConfigurationAsync(
            host, HttpMethod.Get, managementUri, clientId, accessToken, json: null).ConfigureAwait(false);

        Assert.AreEqual(beforeTheReplacement, read, "The read answers the revision it loaded.");
        Assert.Contains("\"client_name\":\"initial-client\"", read, StringComparison.Ordinal);
    }


    /// <summary>
    /// A DELETE of the client configuration URI sent over the wire with the client's own registration access token,
    /// whose conditional deletion fails because another party replaces the client's registration access token and
    /// commits another revision of the stored registration after the token check and before the deletion commits, is
    /// answered as a deletion that lost its race: 400 with the body
    /// <c>{"error":"invalid_client_metadata","error_description":"The registration changed during this deletion."}</c>,
    /// with the application's registration access token seam asked once and the stored registration kept at the other
    /// party's revision. The client's DELETE sent again with the registration access token valid for the stored record
    /// is answered 204 and removes the registration.
    /// <see href="../../../documents/AuthorizationServerDesign.md#41-live-configuration">Section 4.1</see>:
    /// "A lost race is answered HTTP 400 `invalid_client_metadata` with the description "The registration changed during this deletion." and no event, and the handler loads nothing again; a deletion the client sends again is authenticated against the record it finds, and an absent or replaced identity receives HTTP 401."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 Section 2.3</see>: "If a client has
    /// been successfully deprovisioned, the authorization server MUST respond with an HTTP 204 No Content message."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ADeletionWhoseTokenIsReplacedBeforeItsDeletionCommitsLosesItsRaceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        (string clientId, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        StrongBox<int> checks = await CountTheTokenChecksAsync(host).ConfigureAwait(false);
        HostedAuthorizationServer served = host.Host("default");
        int replacements = 0;
        served.BeforeRegistrationDeleteAsync = async (registration, cancellationToken) =>
        {
            //Another party replaces the token and commits a revision before this request's deletion commits.
            if(Interlocked.Exchange(ref replacements, 1) == 0)
            {
                await ReplaceTheTokenAsync(served, registration.ClientId, cancellationToken).ConfigureAwait(false);
            }
        };

        string deletion = await SendToTheClientConfigurationAsync(
            host, HttpMethod.Delete, managementUri, clientId, accessToken, json: null).ConfigureAwait(false);
        int checksOfTheDeletion = Volatile.Read(ref checks.Value);
        ClientRecord kept = served.Registrations[clientId];
        string sentAgain = await SendToTheClientConfigurationAsync(
            host, HttpMethod.Delete, managementUri, clientId, ReplacedRegistrationAccessToken, json: null).ConfigureAwait(false);

        Assert.AreEqual(
            "400\nContent-Type: application/json\nServer: Kestrel\nTransfer-Encoding: chunked\n\n"
            + /*lang=json,strict*/ "{\"error\":\"invalid_client_metadata\",\"error_description\":\"The registration changed during this deletion.\"}",
            deletion);
        Assert.AreEqual(1, checksOfTheDeletion, "The deletion asks the registration access token seam once.");
        Assert.AreEqual(2L, kept.Revision, "The stored registration keeps the other party's revision.");
        Assert.AreEqual(AnotherPartysClientName, kept.ClientName, "The stored registration is the other party's.");
        Assert.AreEqual("204\nServer: Kestrel\n\n", sentAgain);
        Assert.IsFalse(served.Registrations.ContainsKey(clientId), "The deletion sent again removes the registration.");
    }


    /// <summary>
    /// A request to the client configuration URI sent over the wire with the client's own registration access token,
    /// served under an application whose registration access token seam, before it answers, replaces the client's
    /// registration access token and commits another revision of the stored registration, is answered byte for byte as
    /// the same request presenting a registration access token the seam refuses, at read, update and delete alike.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>, in the same words
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">Section 2.2</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">Section 2.3</see>: "If the registration access
    /// token used to make this request is not valid, the server MUST respond with an error as described in the OAuth
    /// Bearer Token Usage specification [RFC6750]."
    /// </summary>
    /// <param name="method">The RFC 7592 management verb.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("GET", DisplayName = "the read")]
    [DataRow("PUT", DisplayName = "the update")]
    [DataRow("DELETE", DisplayName = "the deletion")]
    public async Task ARequestWhoseTokenIsReplacedBeforeItsCheckIsAnInvalidTokenAsync(string method)
    {
        await using TestHostShell host = new(TimeProvider);
        (string clientId, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        HttpMethod verb = new(method);
        string refused = await SendARefusedTokenAsync(host, verb, managementUri, clientId).ConfigureAwait(false);
        await ReplaceTheTokenAroundItsCheckAsync(host, isAfterTheAnswer: false).ConfigureAwait(false);

        string answer = await SendToTheClientConfigurationAsync(
            host, verb, managementUri, clientId, accessToken, MetadataFor(verb, clientId)).ConfigureAwait(false);

        Assert.AreEqual(refused, answer);
    }


    /// <summary>
    /// A GET or a PUT of the client configuration URI sent over the wire with the client's own registration access
    /// token, whose registration the dispatcher loads and which the application's load seam answers, when the operation
    /// loads it, as gone or as a record of another client identifier, is answered byte for byte as the same request
    /// presenting a registration access token the application's seam refuses: 401 with the body's error
    /// <c>invalid_token</c> and the challenge <c>Bearer realm="https://registration.issuer.test/", error="invalid_token"</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 Section 2.1</see>: "If the client does
    /// not exist on this server, the server MUST respond with HTTP 401 Unauthorized and the registration access token
    /// used to make this request SHOULD be immediately revoked."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 Section 2.2</see>: "If the client does
    /// not exist on this server, the server MUST respond with HTTP 401 Unauthorized, and the registration access token
    /// used to make this request SHOULD be immediately revoked."
    /// </summary>
    /// <param name="method">The RFC 7592 management verb.</param>
    /// <param name="isAnotherClient">Whether the load answers a record of another client identifier, else none.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("GET", false, DisplayName = "the read of a client that is gone")]
    [DataRow("GET", true, DisplayName = "the read of a record naming another client")]
    [DataRow("PUT", false, DisplayName = "the update of a client that is gone")]
    [DataRow("PUT", true, DisplayName = "the update of a record naming another client")]
    public async Task AManagementRequestWhoseClientIsNotStoredWhenItIsLoadedIsAnInvalidTokenAsync(string method, bool isAnotherClient)
    {
        await using TestHostShell host = new(TimeProvider);
        (string clientId, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        HttpMethod verb = new(method);
        string refused = await SendARefusedTokenAsync(host, verb, managementUri, clientId).ConfigureAwait(false);
        int loads = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            LoadRegistrationDelegate load = candidateIntegration.LoadRegistrationAsync!;
            candidateIntegration.LoadRegistrationAsync = async (tenantId, context, cancellationToken) =>
            {
                IRegistrationRecord? loaded = await load(tenantId, context, cancellationToken).ConfigureAwait(false);

                //The dispatcher's load answers the registration; a later load answers it gone or another client's.
                return (Interlocked.Increment(ref loads), isAnotherClient) switch
                {
                    (1, _) => loaded,
                    (_, true) => ((ClientRecord)loaded!) with { ClientId = "another-client" },
                    (_, false) => null
                };
            };
        }).ConfigureAwait(false);

        string answer = await SendToTheClientConfigurationAsync(
            host, verb, managementUri, clientId, accessToken, MetadataFor(verb, clientId)).ConfigureAwait(false);

        Assert.AreEqual(refused, answer);
        Assert.StartsWith("401\n", answer, StringComparison.Ordinal);
        Assert.Contains("WWW-Authenticate: Bearer realm=\"https://registration.issuer.test/\", error=\"invalid_token\"\n", answer, StringComparison.Ordinal);
    }


    /// <summary>
    /// A PUT of the client configuration URI sent over the wire with the client's own registration access token and
    /// its own metadata, served under an application's materialization that adds
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> to the registration, is announced to the server's
    /// registration observers by one <see cref="ClientUpdated"/> whose earlier registration is the registration as
    /// stored: its revision one, its client name <c>initial-client</c> and its one capability
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration"/>, not the record the materialization
    /// answered.
    /// <see href="../../../documents/AuthorizationServerDesign.md#8-settled-architectural-decisions-promote-when-ready">Section 8</see>:
    /// "The update sets the RFC 7591 metadata members it sets and no other member of the stored record, its conditional
    /// replacement is against the stored revision, and the update notification receives the stored record as the
    /// earlier one."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnUpdateUnderAMaterializationAnnouncesTheRegistrationAsStoredAsTheEarlierOneAsync()
    {
        (_, _, _, _, ClientRegistrationProjection earlier) = await ManageUnderAMaterializationAsync(
            MaterializationChanging("capability")).ConfigureAwait(false);

        Assert.AreEqual(1L, earlier.Revision);
        Assert.AreEqual("initial-client", earlier.ClientName);
        Assert.IsTrue(earlier.Capabilities.SetEquals([WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration]),
            $"The earlier registration holds {string.Join(", ", earlier.Capabilities.Select(capability => capability.Urn))}.");
    }


    /// <summary>The client name the other party's revision of the stored registration carries.</summary>
    private static string AnotherPartysClientName { get; } = "another-party-client";


    /// <summary>The registration access token the other party replaces the client's own with.</summary>
    private static string ReplacedRegistrationAccessToken { get; } = "replaced-registration-access-token";


    /// <summary>
    /// The complete metadata a client's PUT carries: its issued <paramref name="clientId"/>, the client name
    /// <c>updated-client</c>, and every other member as the managed client registers it.
    /// </summary>
    /// <param name="clientId">The issued client identifier.</param>
    /// <returns>The JSON body of the PUT.</returns>
    private static string UpdatedMetadataOf(string clientId) =>
        $$"""{"client_id":"{{clientId}}","client_name":"updated-client","client_uri":"https://client.example.test/","redirect_uris":["https://client.example.test/callback"],"scope":"initial-scope"}""";


    /// <summary>The body a request of <paramref name="method"/> carries: the PUT's metadata, else none.</summary>
    /// <param name="method">The RFC 7592 management verb.</param>
    /// <param name="clientId">The issued client identifier.</param>
    /// <returns>The JSON body of a PUT, or <see langword="null"/>.</returns>
    private static string? MetadataFor(HttpMethod method, string clientId) =>
        method == HttpMethod.Put ? UpdatedMetadataOf(clientId) : null;


    /// <summary>
    /// Sends a request of <paramref name="method"/> to the client configuration URI with a Bearer token the application's
    /// registration access token seam refuses, through <see cref="SendToTheClientConfigurationAsync"/>, carrying the
    /// body <see cref="MetadataFor"/> gives it.
    /// </summary>
    /// <param name="host">The serving fixture.</param>
    /// <param name="method">The RFC 7592 management verb.</param>
    /// <param name="managementUri">The client configuration URI.</param>
    /// <param name="clientId">The issued client identifier.</param>
    /// <returns>The answer as <see cref="SendToTheClientConfigurationAsync"/> projects it.</returns>
    private Task<string> SendARefusedTokenAsync(TestHostShell host, HttpMethod method, Uri managementUri, string clientId) =>
        SendToTheClientConfigurationAsync(host, method, managementUri, clientId, "invalid-bearer", MetadataFor(method, clientId));


    /// <summary>
    /// Wraps the application's registration access token seam so that, the first time it is asked, another party
    /// replaces the client's registration access token and commits another revision of the stored registration
    /// (<see cref="ReplaceTheTokenAsync"/>): before the seam's own answer when <paramref name="isAfterTheAnswer"/> is
    /// <see langword="false"/>, and after the seam answers that the token is valid when it is <see langword="true"/>.
    /// </summary>
    /// <param name="host">The serving fixture.</param>
    /// <param name="isAfterTheAnswer">Whether the replacement follows the seam's answer of valid, else precedes it.</param>
    /// <returns>A task that completes when the server serves under the wrapped seam.</returns>
    private static Task ReplaceTheTokenAroundItsCheckAsync(TestHostShell host, bool isAfterTheAnswer)
    {
        HostedAuthorizationServer served = host.Host("default");
        int replacements = 0;

        return TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ValidateRegistrationAccessTokenDelegate validate = candidateIntegration.ValidateRegistrationAccessTokenAsync!;
            candidateIntegration.ValidateRegistrationAccessTokenAsync = async (tenantId, clientId, presented, context, cancellationToken) =>
            {
                if(!isAfterTheAnswer && Interlocked.Exchange(ref replacements, 1) == 0)
                {
                    await ReplaceTheTokenAsync(served, clientId, cancellationToken).ConfigureAwait(false);
                }

                bool isValid = await validate(tenantId, clientId, presented, context, cancellationToken).ConfigureAwait(false);
                if(isAfterTheAnswer && isValid && Interlocked.Exchange(ref replacements, 1) == 0)
                {
                    await ReplaceTheTokenAsync(served, clientId, cancellationToken).ConfigureAwait(false);
                }

                return isValid;
            };
        });
    }


    /// <summary>
    /// Wraps the application's registration access token seam so that each time it is asked the count the answered box
    /// holds grows by one before the seam answers, which tells a row how often a request checked its token.
    /// </summary>
    /// <param name="host">The serving fixture.</param>
    /// <returns>The box whose value counts the seam's calls, once the server serves under the wrapped seam.</returns>
    private static async Task<StrongBox<int>> CountTheTokenChecksAsync(TestHostShell host)
    {
        StrongBox<int> checks = new(0);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ValidateRegistrationAccessTokenDelegate validate = candidateIntegration.ValidateRegistrationAccessTokenAsync!;
            candidateIntegration.ValidateRegistrationAccessTokenAsync = (tenantId, clientId, presented, context, cancellationToken) =>
            {
                _ = Interlocked.Increment(ref checks.Value);

                return validate(tenantId, clientId, presented, context, cancellationToken);
            };
        }).ConfigureAwait(false);

        return checks;
    }


    /// <summary>
    /// Another party's change of the client: the client's registration access token becomes
    /// <see cref="ReplacedRegistrationAccessToken"/>, and the stored registration's next revision, carrying the client
    /// name <see cref="AnotherPartysClientName"/>, is committed through the fixture's store and announced.
    /// </summary>
    /// <param name="served">The hosted server whose store holds the client.</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="cancellationToken">Cancellation of the commit.</param>
    /// <returns>A task that completes when the revision is committed and announced.</returns>
    private static async Task ReplaceTheTokenAsync(HostedAuthorizationServer served, string clientId, CancellationToken cancellationToken)
    {
        served.RegistrationAccessTokens[clientId] = ReplacedRegistrationAccessToken;
        ClientRecord stored = served.Registrations[clientId];
        _ = await served.UpdateClientAsync(stored, stored with { ClientName = AnotherPartysClientName }, [], cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A materialization that answers the client registration it is handed with <paramref name="member"/> changed and
    /// every other member kept: <c>capability</c> adds <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/>,
    /// <c>logoUri</c> gives <see cref="ClientRecord.LogoUri"/> a value and <c>clientName</c> gives
    /// <see cref="ClientRecord.ClientName"/> another value.
    /// </summary>
    /// <param name="member">The member the materialization changes.</param>
    /// <returns>The materialization seam.</returns>
    private static MaterializeRegistrationDelegate MaterializationChanging(string member) => member switch
    {
        "capability" => CapabilityBounds.MaterializationAdding(WellKnownCapabilityIdentifiers.OAuthTokenExchange),
        "logoUri" => static (registration, _, _) => ValueTask.FromResult(new RegistrationMaterialization
        {
            Registration = ((ClientRecord)registration) with { LogoUri = new Uri("https://client.example.test/materialized-logo.png") }
        }),
        "clientName" => static (registration, _, _) => ValueTask.FromResult(new RegistrationMaterialization
        {
            Registration = ((ClientRecord)registration) with { ClientName = "materialized-client" }
        }),
        _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unknown member.")
    };


    /// <summary>
    /// Registers a managed client over the listener of a fresh host through <see cref="RegisterOverTheListenerAsync"/>,
    /// wires the server to serve the token exchange grant (<see cref="ServeTheTokenExchangeGrantAsync"/>), subscribes a
    /// <see cref="CollectingObserver{T}"/> to the server's registration notifications, installs
    /// <paramref name="materialization"/> as the application's materialization seam when given, sends the client's GET
    /// and then its PUT of its own metadata (the client name <c>updated-client</c>, every other member as registered)
    /// to its client configuration URI with its registration access token, removes the materialization, and posts a
    /// token exchange request carrying only its <c>grant_type</c> to the token endpoint of the client's tenant.
    /// </summary>
    /// <param name="materialization">The application's materialization seam, or <see langword="null"/> for none.</param>
    /// <returns>
    /// The answers to the GET, the PUT and the token request as <see cref="OAuthTestTransport.ProjectWireAnswer"/>
    /// projects them, the registration the store holds after the PUT, and the earlier registration the one update
    /// notification carries.
    /// </returns>
    private async Task<(string Read, string Update, string Later, ClientRecord Stored, ClientRegistrationProjection Earlier)> ManageUnderAMaterializationAsync(
        MaterializeRegistrationDelegate? materialization)
    {
        await using TestHostShell host = new(TimeProvider);
        (string clientId, string accessToken, Uri managementUri) = await RegisterOverTheListenerAsync(host).ConfigureAwait(false);
        await ServeTheTokenExchangeGrantAsync(host).ConfigureAwait(false);
        List<ClientRegistrationEvent> notifications = [];
        using IDisposable subscription = host.Server.Events.Subscribe(new CollectingObserver<ClientRegistrationEvent>(notifications));
        if(materialization is not null)
        {
            await TestHostShell.AlterAsync(host.Server,
                candidateIntegration => candidateIntegration.MaterializeRegistrationAsync = materialization).ConfigureAwait(false);
        }

        string read = await SendToTheClientConfigurationAsync(host, HttpMethod.Get, managementUri, clientId, accessToken, json: null).ConfigureAwait(false);
        string update = await SendToTheClientConfigurationAsync(host, HttpMethod.Put, managementUri, clientId, accessToken,
            UpdatedMetadataOf(clientId)).ConfigureAwait(false);
        if(materialization is not null)
        {
            await TestHostShell.AlterAsync(host.Server,
                candidateIntegration => candidateIntegration.MaterializeRegistrationAsync = null).ConfigureAwait(false);
        }

        HostedAuthorizationServer served = host.Host("default");
        ClientRecord stored = served.Registrations[clientId];
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            served.SharedHttpClient!,
            new Uri(served.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.TokenExchangeToken, stored.TenantId.Value)),
            new Dictionary<string, string> { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange },
            TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        ClientUpdated updated = Assert.ContainsSingle(notifications.OfType<ClientUpdated>());

        return (read, update, OAuthTestTransport.ProjectWireAnswer(response, body), stored, updated.Previous);
    }


    /// <summary>
    /// Wires the three seams the token endpoint needs to serve the token exchange grant, as a deployment that serves
    /// it does: the client authentication seam, the subject token validation seam and the impersonation decision, each
    /// accepting. A registration that holds <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/> is then
    /// served that grant.
    /// </summary>
    /// <param name="host">The serving fixture.</param>
    /// <returns>A task that completes when the server serves under the wiring.</returns>
    private static Task ServeTheTokenExchangeGrantAsync(TestHostShell host) =>
        TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.ValidateTokenExchangeTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(new ValidatedSecurityToken { Subject = "https://subject.example.com" });
            candidateIntegration.AuthorizeTokenExchangeAsync = static (subject, _, _, _, _, _) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(new TokenExchangeAuthorization
                {
                    Subject = subject.Subject,
                    Scope = "read",
                    IssuedTokenType = TokenType.AccessToken
                });
        });


    /// <summary>
    /// Sends one registration management operation over the pinned listener with the client's registration access
    /// token through <see cref="RawAuthCodeWirePushers.SendPinnedRegistrationAsync"/> and projects its answer with the
    /// two values each host generates afresh replaced: the issued <paramref name="clientId"/> by <c>{client_id}</c> and
    /// the listener's scheme, host and port by <c>{listener}</c>. Each is asserted well-formed first: the identifier
    /// thirty-two lowercase hexadecimal digits, the listener an HTTPS loopback authority.
    /// </summary>
    /// <param name="host">The serving fixture.</param>
    /// <param name="method">The RFC 7592 management verb.</param>
    /// <param name="managementUri">The client configuration URI.</param>
    /// <param name="clientId">The issued client identifier.</param>
    /// <param name="accessToken">The registration access token.</param>
    /// <param name="json">The complete metadata replacement for PUT, or <see langword="null"/>.</param>
    /// <returns>The answer as <see cref="OAuthTestTransport.ProjectWireAnswer"/> projects it, the two values replaced.</returns>
    private async Task<string> SendToTheClientConfigurationAsync(
        TestHostShell host, HttpMethod method, Uri managementUri, string clientId, string accessToken, string? json)
    {
        Assert.AreEqual(32, clientId.Length, clientId);
        Assert.IsTrue(clientId.All(char.IsAsciiHexDigitLower), clientId);
        Assert.AreEqual(Uri.UriSchemeHttps, managementUri.Scheme);
        Assert.IsTrue(managementUri.IsLoopback, managementUri.AbsoluteUri);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedRegistrationAsync(
            host, method, managementUri, accessToken, json, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return OAuthTestTransport.ProjectWireAnswer(response, body)
            .Replace(clientId, "{client_id}", StringComparison.Ordinal)
            .Replace(managementUri.GetLeftPart(UriPartial.Authority), "{listener}", StringComparison.Ordinal);
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
