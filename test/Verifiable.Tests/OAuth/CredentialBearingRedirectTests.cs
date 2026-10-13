using Microsoft.Extensions.Time.Testing;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests that every client flow sending a credential through <see cref="OAuthClientInfrastructure"/>'s
/// transports refuses an endpoint's redirect answer and sends nothing further: the transports are single
/// hop (<see cref="SendFormPostDelegate"/>), so a 3xx reaches the flow as received, and the flow answers it
/// with a typed <see cref="OAuthRedirectRefused"/>, records an
/// <see cref="OAuthEventNames.CredentialBearingRedirectRefused"/> event and never sends its credential
/// again. <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4.8">RFC 9110 §15.4.8</see>: the 307
/// status "indicates that the target resource resides temporarily under a different URI and the user agent
/// MUST NOT change the request method if it performs an automatic redirection to that URI", so following
/// it re-sends the credential to whatever origin the <c>Location</c> field names.
/// </summary>
[TestClass]
internal sealed class CredentialBearingRedirectTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private FillEntropyDelegate ClientEntropy { get; } = TestEntropy.NewCounterStream();

    /// <summary>The authorization server's issuer identifier.</summary>
    private static Uri Issuer { get; } = new("https://as.example.com");

    /// <summary>The pushed authorization request endpoint the metadata names.</summary>
    private static Uri ParEndpoint { get; } = new("https://as.example.com/par");

    /// <summary>The token endpoint the metadata names.</summary>
    private static Uri TokenEndpoint { get; } = new("https://as.example.com/token");

    /// <summary>The revocation endpoint the metadata names.</summary>
    private static Uri RevocationEndpoint { get; } = new("https://as.example.com/revoke");

    /// <summary>The RFC 7591 registration endpoint.</summary>
    private static Uri RegistrationEndpoint { get; } = new("https://as.example.com/register");

    /// <summary>The RFC 7592 client configuration endpoint of the registered client.</summary>
    private static Uri ManagementUri { get; } = new("https://as.example.com/register/client-1");

    /// <summary>The client's redirect URI.</summary>
    private static Uri ClientRedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>The origin every redirect answer names: another origin than the endpoint's.</summary>
    private const string ElsewhereLocation = "https://elsewhere.example.net/collect";

    /// <summary>The 307 (Temporary Redirect) status, RFC 9110 §15.4.8.</summary>
    private const int TemporaryRedirect = 307;

    /// <summary>The 308 (Permanent Redirect) status, RFC 9110 §15.4.9.</summary>
    private const int PermanentRedirect = 308;

    /// <summary>The registration access token the RFC 7592 rows present.</summary>
    private const string RegistrationAccessTokenValue = "registration-access-token-value";

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// <see cref="HttpResponseData.IsRedirection"/> is the 3xx class and nothing beside it.
    /// </summary>
    /// <param name="statusCode">The status code.</param>
    /// <param name="isRedirection">Whether it is of the 3xx class.</param>
    [TestMethod]
    [DataRow(299, false)]
    [DataRow(300, true)]
    [DataRow(304, true)]
    [DataRow(399, true)]
    [DataRow(400, false)]
    public void RedirectionIsTheThreeHundredClass(int statusCode, bool isRedirection)
    {
        Assert.AreEqual(isRedirection, new HttpResponseData { StatusCode = statusCode }.IsRedirection);
    }


    /// <summary>
    /// A pushed authorization request answered with any redirect status is refused: the flow answers
    /// <see cref="AuthCodeFlowEndpointOutcome.InternalError"/> carrying the typed refusal, stores no flow
    /// state, and the request was sent once, to the pushed authorization request endpoint.
    /// </summary>
    /// <param name="statusCode">The redirect status the endpoint answers with.</param>
    [TestMethod]
    [DataRow(301)]
    [DataRow(302)]
    [DataRow(303)]
    [DataRow(TemporaryRedirect)]
    [DataRow(PermanentRedirect)]
    public async Task APushedRequestAnsweredWithARedirectIsRefusedAndNothingFollows(int statusCode)
    {
        RedirectingTransport transport = new(statusCode);
        List<FlowState> savedStates = [];
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport, savedStates: savedStates);
        using Activity activity = StartRowActivity();

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), ClientRedirectUri, infrastructure, PublicClientRegistration(), [], resource: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertEndpointResultRefusal(result, transport, ParEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.CodeChallenge), "The pushed request carried the PKCE challenge.");
        Assert.IsEmpty(savedStates, "A refused pushed request stores no flow state.");
    }


    /// <summary>
    /// A pushed signed request object (RFC 9101) answered with a redirect is refused: the signed object was
    /// sent once, to the pushed authorization request endpoint, and the flow stores no flow state.
    /// </summary>
    [TestMethod]
    public async Task APushedSignedRequestAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        List<FlowState> savedStates = [];
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport, savedStates: savedStates);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory signingKey = keyMaterial.PrivateKey;
        using Activity activity = StartRowActivity();

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleJarParAsync(
            new AuthCodeStartJarParOptions
            {
                Scope = "openid",
                SigningKey = signingKey,
                SigningKeyId = "client-key-1",
                RedirectUri = ClientRedirectUri,
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer,
                MemoryPool = BaseMemoryPool.Shared
            },
            infrastructure, PublicClientRegistration(), [], TestContext.CancellationToken).ConfigureAwait(false);

        AssertEndpointResultRefusal(result, transport, ParEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.Request), "The pushed request carried the signed request object.");
        Assert.IsEmpty(savedStates, "A refused pushed request stores no flow state.");
    }


    /// <summary>
    /// A code redemption answered with a redirect is refused: the authorization code and its PKCE
    /// verifier were sent once, to the token endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task ACodeRedemptionAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(PermanentRedirect);
        DateTimeOffset now = TimeProvider.GetUtcNow();
        AuthorizationCodeReceivedState codeState = new()
        {
            FlowId = "flow-redirected",
            ExpectedIssuer = Issuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.AddMinutes(5),
            Kind = FlowKind.AuthCodeClient,
            Code = "authorization-code-value",
            State = "state-value",
            IssuerId = Issuer.OriginalString,
            Pkce = new PkceParameters("code-verifier-value-with-enough-length-0123456789", "code-challenge-value", PkceMethod.S256),
            RedirectUri = ClientRedirectUri
        };

        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport, storedState: codeState);
        using Activity activity = StartRowActivity();

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = codeState.FlowId },
            infrastructure, PublicClientRegistration(), [], clientAssertionOptions: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertEndpointResultRefusal(result, transport, TokenEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.Code), "The redemption carried the authorization code.");
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.CodeVerifier), "The redemption carried the PKCE verifier.");
    }


    /// <summary>
    /// A refresh answered with a redirect is refused: the refresh token was sent once, to the token
    /// endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task ARefreshAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        ClientRegistration registration = PublicClientRegistration();
        using Activity activity = StartRowActivity();

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.RefreshAsync(
            new RefreshTokenRequest { ClientId = registration.ClientId.Value, RefreshToken = "refresh-token-value" },
            infrastructure, registration, [], TestContext.CancellationToken).ConfigureAwait(false);

        AssertEndpointResultRefusal(result, transport, TokenEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.RefreshToken), "The refresh carried the refresh token.");
    }


    /// <summary>
    /// A revocation answered with a redirect is refused rather than answered <c>Ok</c>: the token to revoke
    /// was sent once, to the revocation endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task ARevocationAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        using Activity activity = StartRowActivity();

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleRevocationAsync(
            new Dictionary<string, string> { [OAuthRequestParameterNames.Token] = "token-to-revoke" },
            infrastructure, PublicClientRegistration(), [], TestContext.CancellationToken).ConfigureAwait(false);

        AssertEndpointResultRefusal(result, transport, RevocationEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.Token), "The revocation carried the token to revoke.");
    }


    /// <summary>
    /// A <c>client_credentials</c> token request authenticated with <c>client_secret_post</c> and answered
    /// with a redirect is refused: the client secret was sent once, to the token endpoint, and nothing
    /// followed.
    /// </summary>
    [TestMethod]
    public async Task AClientCredentialsRequestAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);

        //client_secret_post reads the shared secret from the private half of the key material; the public
        //half is never read, but the pair requires one.
        byte[] secretBytes = System.Text.Encoding.UTF8.GetBytes("client-secret-value");
        System.Buffers.IMemoryOwner<byte> secretOwner = BaseMemoryPool.Shared.Rent(secretBytes.Length);
        secretBytes.CopyTo(secretOwner.Memory.Span);
        using PrivateKeyMemory secret = new(secretOwner, Tag.Empty);
        using PublicKeyMemory unusedPublicHalf = new(BaseMemoryPool.Shared.Rent(1), Tag.Empty);

        ClientRegistration registration = PublicClientRegistration() with
        {
            AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
            AuthenticationKeyMaterial = new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(unusedPublicHalf, secret)
        };

        OAuthClient client = new(infrastructure);
        using Activity activity = StartRowActivity();

        AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
            registration, scope: null, resource: null, [], clientAssertionOptions: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssertEndpointResultRefusal(result, transport, TokenEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.ClientSecret), "The request carried the client secret.");
    }


    /// <summary>
    /// An ID-JAG mint (a token exchange) answered with a redirect is refused with the typed
    /// <see cref="OAuthRedirectRefused"/>: the subject token and the signed client assertion were sent
    /// once, to the token endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task AnIdJagMintAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory signingKey = keyMaterial.PrivateKey;
        using Activity activity = StartRowActivity();

        Result<TokenResponse, OAuthParseError> result = await IdJagFlowHandlers.MintAsync(
            new IdJagMintOptions
            {
                Audience = "https://resource-as.example.com/",
                SubjectToken = "subject-token-opaque",
                SubjectTokenType = TokenType.IdToken,
                SigningKey = signingKey,
                SigningKeyId = "client-key-1",
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer
            },
            infrastructure, MachineClientRegistration(), [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        AssertRefusal(Assert.IsInstanceOfType<OAuthRedirectRefused>(result.Error), transport, TokenEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.SubjectToken), "The mint carried the subject token.");
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.ClientAssertion), "The mint carried the signed client assertion.");
    }


    /// <summary>
    /// An ID-JAG redemption (a JWT bearer grant) answered with a redirect is refused with the typed
    /// <see cref="OAuthRedirectRefused"/>: the grant and the signed client assertion were sent once, to the
    /// token endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task AnIdJagRedemptionAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(PermanentRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory signingKey = keyMaterial.PrivateKey;
        using Activity activity = StartRowActivity();

        Result<TokenResponse, OAuthParseError> result = await IdJagFlowHandlers.RedeemAsync(
            new IdJagRedeemOptions
            {
                Assertion = "id-jag-assertion-opaque",
                SigningKey = signingKey,
                SigningKeyId = "client-key-1",
                HeaderSerializer = HeaderSerializer,
                PayloadSerializer = PayloadSerializer
            },
            infrastructure, MachineClientRegistration(), [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        AssertRefusal(Assert.IsInstanceOfType<OAuthRedirectRefused>(result.Error), transport, TokenEndpoint, activity);
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.Assertion), "The redemption carried the grant.");
        Assert.IsTrue(transport.SentField(0, OAuthRequestParameterNames.ClientAssertion), "The redemption carried the signed client assertion.");
    }


    /// <summary>
    /// An RFC 7591 registration answered with a redirect throws the typed
    /// <see cref="OAuthRedirectRefusedException"/>: the client's metadata was posted once, to the
    /// registration endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task ARegistrationAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        using Activity activity = StartRowActivity();

        OAuthRedirectRefusedException refused = await Assert.ThrowsExactlyAsync<OAuthRedirectRefusedException>(
            async () => await DynamicRegistrationHandlers.HandleRegisterAsync(
                new RegisterClientOptions
                {
                    RegistrationEndpoint = RegistrationEndpoint,
                    AuthorizationServerIssuer = Issuer,
                    Metadata = new ClientMetadata { RedirectUris = [ClientRedirectUri] },
                    AuthenticationMethod = ClientAuthenticationMethod.None
                },
                infrastructure, [], TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        AssertRefusal(refused.Refusal, transport, RegistrationEndpoint, activity);
    }


    /// <summary>
    /// An RFC 7592 read answered with a redirect throws the typed <see cref="OAuthRedirectRefusedException"/>:
    /// the registration access token was sent once, to the client configuration endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task ARegistrationReadAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        using Activity activity = StartRowActivity();

        OAuthRedirectRefusedException refused = await Assert.ThrowsExactlyAsync<OAuthRedirectRefusedException>(
            async () => await DynamicRegistrationHandlers.HandleReadAsync(
                ManagedClientRegistration(), infrastructure, [], TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        AssertRefusal(refused.Refusal, transport, ManagementUri, activity);
        Assert.IsTrue(transport.SentBearer(0, RegistrationAccessTokenValue), "The read carried the registration access token.");
    }


    /// <summary>
    /// An RFC 7592 update answered with a redirect throws the typed <see cref="OAuthRedirectRefusedException"/>:
    /// the registration access token was sent once, to the client configuration endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task ARegistrationUpdateAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(PermanentRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        using Activity activity = StartRowActivity();

        OAuthRedirectRefusedException refused = await Assert.ThrowsExactlyAsync<OAuthRedirectRefusedException>(
            async () => await DynamicRegistrationHandlers.HandleUpdateAsync(
                ManagedClientRegistration(), new ClientMetadata { RedirectUris = [ClientRedirectUri] },
                infrastructure, [], TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        AssertRefusal(refused.Refusal, transport, ManagementUri, activity);
        Assert.IsTrue(transport.SentBearer(0, RegistrationAccessTokenValue), "The update carried the registration access token.");
    }


    /// <summary>
    /// An RFC 7592 deregistration answered with a redirect throws the typed
    /// <see cref="OAuthRedirectRefusedException"/>: the registration access token was sent once, to the
    /// client configuration endpoint, and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task ADeregistrationAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        RedirectingTransport transport = new(TemporaryRedirect);
        OAuthClientInfrastructure infrastructure = CreateInfrastructure(transport);
        using Activity activity = StartRowActivity();

        OAuthRedirectRefusedException refused = await Assert.ThrowsExactlyAsync<OAuthRedirectRefusedException>(
            async () => await DynamicRegistrationHandlers.HandleDeregisterAsync(
                ManagedClientRegistration(), infrastructure, [], TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        AssertRefusal(refused.Refusal, transport, ManagementUri, activity);
        Assert.IsTrue(transport.SentBearer(0, RegistrationAccessTokenValue), "The deregistration carried the registration access token.");
    }


    /// <summary>
    /// Asserts a flow answering in an <see cref="AuthCodeFlowEndpointResult"/> refused the redirect: an
    /// <see cref="AuthCodeFlowEndpointOutcome.InternalError"/> whose description names no location, carrying
    /// the typed refusal (see <see cref="AssertRefusal"/>).
    /// </summary>
    private static void AssertEndpointResultRefusal(
        AuthCodeFlowEndpointResult result, RedirectingTransport transport, Uri endpoint, Activity activity)
    {
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.AreEqual(OAuthErrors.ServerError, result.ErrorCode);
        Assert.DoesNotContain(ElsewhereLocation, result.ErrorDescription ?? string.Empty, StringComparison.Ordinal,
            "The location the endpoint chose rides the typed refusal and the trace event, never the description.");
        AssertRefusal(Assert.IsInstanceOfType<OAuthRedirectRefused>(result.ResponseError), transport, endpoint, activity);
    }


    /// <summary>
    /// Asserts the typed refusal names the endpoint, the status and the location the endpoint answered with,
    /// that the transport received exactly one request, to that endpoint, and that the row's activity
    /// recorded the refusal event with the same three values.
    /// </summary>
    private static void AssertRefusal(OAuthRedirectRefused refusal, RedirectingTransport transport, Uri endpoint, Activity activity)
    {
        Assert.AreEqual(endpoint, refusal.Endpoint);
        Assert.AreEqual(transport.StatusCode, refusal.StatusCode);
        Assert.AreEqual(ElsewhereLocation, refusal.Location);
        Assert.HasCount(1, transport.Endpoints, "The flow sends its credential once and nothing after the redirect.");
        Assert.AreEqual(endpoint, transport.Endpoints[0]);

        ActivityEvent refusalEvent = activity.Events.Single(
            static candidate => candidate.Name == OAuthEventNames.CredentialBearingRedirectRefused);
        Dictionary<string, object?> tags = refusalEvent.Tags.ToDictionary(static tag => tag.Key, static tag => tag.Value);
        Assert.AreEqual(endpoint.ToString(), tags[OAuthEventNames.RedirectRefusalEndpointTagName]);
        Assert.AreEqual(transport.StatusCode, tags[OAuthEventNames.RedirectRefusalStatusCodeTagName]);
        Assert.AreEqual(ElsewhereLocation, tags[OAuthEventNames.RedirectRefusalLocationTagName]);
    }


    /// <summary>
    /// Starts an activity of the row's own, so the refusal event a flow records on the current activity
    /// lands where only this row reads it.
    /// </summary>
    private static Activity StartRowActivity()
    {
        Activity activity = new(nameof(CredentialBearingRedirectTests));
        _ = activity.Start();

        return activity;
    }


    /// <summary>A public client registered at <see cref="Issuer"/>.</summary>
    private static ClientRegistration PublicClientRegistration() =>
        new()
        {
            ClientId = new ClientId("https://client.example.com"),
            AuthorizationServerIssuer = Issuer,
            RedirectUris = [ClientRedirectUri],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Rfc6749WithPkce
        };


    /// <summary>A machine client registered at <see cref="Issuer"/> that authenticates with a signed assertion.</summary>
    private static ClientRegistration MachineClientRegistration() =>
        new()
        {
            ClientId = new ClientId("https://machine.example.com"),
            AuthorizationServerIssuer = Issuer,
            AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
            Profile = PolicyProfile.Haip10
        };


    /// <summary>A dynamically registered client holding its RFC 7592 management URI and access token.</summary>
    private static ClientRegistration ManagedClientRegistration() =>
        PublicClientRegistration() with
        {
            ManagementUri = ManagementUri,
            AccessToken = new RegistrationAccessToken(RegistrationAccessTokenValue)
        };


    /// <summary>
    /// Builds a client infrastructure whose every transport is <paramref name="transport"/>, whose metadata
    /// resolution names this class's endpoints, and whose parsers are the library's own.
    /// </summary>
    private OAuthClientInfrastructure CreateInfrastructure(
        RedirectingTransport transport, FlowState? storedState = null, List<FlowState>? savedStates = null) =>
        OAuthClientInfrastructure.Create(
            sendFormPostAsync: transport.SendFormPostAsync,
            saveStateAsync: (state, _, _) =>
            {
                savedStates?.Add(state);

                return ValueTask.CompletedTask;
            },
            loadStateAsync: (_, _, _) => ValueTask.FromResult(storedState),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new InvalidOperationException("A registration answer the flow refused must never reach the parser."),
            resolveAuthorizationServerMetadataAsync: (_, _, _) =>
                ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                {
                    MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(Issuer.OriginalString),
                    Metadata = new AuthorizationServerMetadata
                    {
                        Issuer = Issuer,
                        AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
                        TokenEndpoint = TokenEndpoint,
                        PushedAuthorizationRequestEndpoint = ParEndpoint,
                        RevocationEndpoint = RevocationEndpoint
                    }
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: ClientEntropy,
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, ClientEntropy, BaseMemoryPool.Shared),
            sendJsonPostAsync: transport.SendJsonPostAsync,
            sendJsonGetAsync: transport.SendJsonGetAsync,
            sendJsonPutAsync: transport.SendJsonPutAsync,
            sendJsonDeleteAsync: transport.SendJsonDeleteAsync,
            parseClientMetadataAsync: (body, ct) =>
                throw new InvalidOperationException("A client metadata answer the flow refused must never reach the parser."));


    /// <summary>
    /// A single-hop transport that answers every request with one redirect to another origin and records
    /// each request it receives, so a row can tell that a flow sent its credential once and nothing after.
    /// </summary>
    private sealed class RedirectingTransport
    {
        /// <summary>Creates the transport answering every request with <paramref name="statusCode"/>.</summary>
        /// <param name="statusCode">The 3xx status every answer carries.</param>
        public RedirectingTransport(int statusCode)
        {
            StatusCode = statusCode;
        }


        /// <summary>The 3xx status every answer carries.</summary>
        public int StatusCode { get; }

        /// <summary>The endpoint of each request received, in order.</summary>
        public List<Uri> Endpoints { get; } = [];

        /// <summary>The form fields of each request received, in order; empty for a request that carried none.</summary>
        public List<KeyValuePair<string, string>[]> Fields { get; } = [];

        /// <summary>The headers of each request received, in order.</summary>
        public List<OutgoingHeaders> Headers { get; } = [];

        /// <summary>The form post transport.</summary>
        public SendFormPostDelegate SendFormPostAsync => (endpoint, formFields, headers, _, _) => Answer(endpoint, [.. formFields], headers);

        /// <summary>The JSON post transport.</summary>
        public SendJsonPostDelegate SendJsonPostAsync => (endpoint, _, headers, _, _) => Answer(endpoint, [], headers);

        /// <summary>The JSON get transport.</summary>
        public SendJsonGetDelegate SendJsonGetAsync => (endpoint, headers, _, _) => Answer(endpoint, [], headers);

        /// <summary>The JSON put transport.</summary>
        public SendJsonPutDelegate SendJsonPutAsync => (endpoint, _, headers, _, _) => Answer(endpoint, [], headers);

        /// <summary>The JSON delete transport.</summary>
        public SendJsonDeleteDelegate SendJsonDeleteAsync => (endpoint, headers, _, _) => Answer(endpoint, [], headers);


        /// <summary>Whether the request at <paramref name="index"/> carried the form field <paramref name="name"/>.</summary>
        public bool SentField(int index, string name) =>
            Fields[index].Any(field => string.Equals(field.Key, name, StringComparison.Ordinal) && field.Value.Length > 0);


        /// <summary>Whether the request at <paramref name="index"/> carried <paramref name="token"/> as its Bearer authorization.</summary>
        public bool SentBearer(int index, string token) =>
            Headers[index].Values.TryGetValue(WellKnownHttpHeaderNames.Authorization, out string? authorization)
            && string.Equals(authorization, $"{WellKnownAuthenticationSchemes.Bearer} {token}", StringComparison.Ordinal);


        /// <summary>Records one request and answers it with the redirect.</summary>
        private ValueTask<HttpResponseData> Answer(Uri endpoint, KeyValuePair<string, string>[] formFields, OutgoingHeaders headers)
        {
            Endpoints.Add(endpoint);
            Fields.Add(formFields);
            Headers.Add(headers);

            return ValueTask.FromResult(new HttpResponseData
            {
                StatusCode = StatusCode,
                Body = string.Empty,
                Headers = new ResponseHeaders { Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.Location, ElsewhereLocation)) }
            });
        }
    }
}
