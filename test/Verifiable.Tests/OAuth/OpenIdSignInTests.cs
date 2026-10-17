using Microsoft.Extensions.Time.Testing;
using System.Text;
using System.Web;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The relying party's OpenID Connect sign-in of the authorization code flow through the library: the start mints a
/// <c>nonce</c> beside its <c>state</c> and PKCE pair and holds it with the flow
/// (<see cref="AuthCodeClient.StartOpenIdAsync"/>), the callback carries it forward, and the code exchange verifies the ID
/// Token it answers - its signature under the provider's key, its audience and the nonce sent
/// (<see cref="AuthCodeClient.ExchangeOpenIdTokenAsync"/>). Each negative passes only where its binding holds.
/// </summary>
[TestClass]
internal sealed class OpenIdSignInTests
{
    /// <summary>The OpenID Provider's issuer.</summary>
    private const string ProviderIssuer = "https://op.example.com";

    /// <summary>The relying party's client identifier at the provider.</summary>
    private const string RelyingPartyClientId = "relying-party-client";

    /// <summary>The key identifier the provider publishes its signing key under.</summary>
    private const string ProviderKeyId = "op-key-1";

    /// <summary>The relying party's callback.</summary>
    private static Uri Callback { get; } = new("https://rp.example.com/callback");

    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fixed clock.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);


    /// <summary>
    /// The roundtrip: the start sends a nonce and holds it, the provider's ID Token carries it, and the exchange verifies the ID
    /// Token and answers its claims, the nonce read back equal to the one the redirect carried.
    /// </summary>
    [TestMethod]
    public async Task TheSignInSendsANonceAndTheVerifiedIdTokenCarriesIt()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var provider = new StandInProvider(this, privateKey);
        var client = new OAuthClient(provider.Infrastructure).AuthCode;

        var started = await client.StartOpenIdAsync(
            Registration(), Callback, Scope(), [], resource: null, TimeSpan.FromMinutes(10), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, started.Outcome);
        var query = HttpUtility.ParseQueryString(started.RedirectUri!.Query);
        var nonce = query[OAuthRequestParameterNames.Nonce];
        var state = query[OAuthRequestParameterNames.State]!;
        Assert.IsFalse(string.IsNullOrEmpty(nonce), "The OpenID Connect start sends a nonce.");
        Assert.AreEqual(nonce, Assert.IsInstanceOfType<ParCompletedState>(provider.States[state]).Nonce);

        provider.IdTokenNonce = nonce;
        var signedIn = await CallbackAndExchangeAsync(client, provider, state, publicKey, WellKnownJwaValues.Es256).ConfigureAwait(false);

        Assert.IsTrue(signedIn.IsSignedIn, $"The sign-in holds; refused by {signedIn.Refusal} {signedIn.IdTokenFailure}.");
        Assert.AreEqual(nonce, signedIn.Claims!.Nonce);
        Assert.AreEqual("person-at-op", signedIn.Claims.Subject);
        Assert.AreEqual("refresh-token-issued-beside", signedIn.RefreshToken);
    }


    /// <summary>An ID Token carrying another nonce than the one sent is refused by the nonce check.</summary>
    [TestMethod]
    public async Task AnIdTokenOfAnotherNonceIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var provider = new StandInProvider(this, privateKey);
        var client = new OAuthClient(provider.Infrastructure).AuthCode;

        var started = await client.StartOpenIdAsync(
            Registration(), Callback, Scope(), [], resource: null, TimeSpan.FromMinutes(10), TestContext.CancellationToken).ConfigureAwait(false);
        var state = HttpUtility.ParseQueryString(started.RedirectUri!.Query)[OAuthRequestParameterNames.State]!;

        provider.IdTokenNonce = "another-sign-ins-nonce";
        var signedIn = await CallbackAndExchangeAsync(client, provider, state, publicKey, WellKnownJwaValues.Es256).ConfigureAwait(false);

        Assert.AreEqual(OpenIdSignInRefusal.IdTokenRefused, signedIn.Refusal);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.NonceMismatch, signedIn.IdTokenFailure);
        Assert.IsNull(signedIn.IdToken);
    }


    /// <summary>An ID Token audienced at another client is refused by the audience check.</summary>
    [TestMethod]
    public async Task AnIdTokenAudiencedAtAnotherClientIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var provider = new StandInProvider(this, privateKey);
        var client = new OAuthClient(provider.Infrastructure).AuthCode;

        var started = await client.StartOpenIdAsync(
            Registration(), Callback, Scope(), [], resource: null, TimeSpan.FromMinutes(10), TestContext.CancellationToken).ConfigureAwait(false);
        var query = HttpUtility.ParseQueryString(started.RedirectUri!.Query);

        provider.IdTokenNonce = query[OAuthRequestParameterNames.Nonce];
        provider.IdTokenAudience = "another-client";
        var signedIn = await CallbackAndExchangeAsync(client, provider, query[OAuthRequestParameterNames.State]!, publicKey, WellKnownJwaValues.Es256).ConfigureAwait(false);

        Assert.AreEqual(OpenIdSignInRefusal.IdTokenRefused, signedIn.Refusal);
        Assert.IsNotNull(signedIn.IdTokenFailure);
    }


    /// <summary>An ID Token whose key the provider does not publish is refused before the validator runs.</summary>
    [TestMethod]
    public async Task AnIdTokenWhoseKeyIsNotPublishedIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var provider = new StandInProvider(this, privateKey) { IdTokenKeyId = "unpublished-key" };
        var client = new OAuthClient(provider.Infrastructure).AuthCode;

        var started = await client.StartOpenIdAsync(
            Registration(), Callback, Scope(), [], resource: null, TimeSpan.FromMinutes(10), TestContext.CancellationToken).ConfigureAwait(false);
        var query = HttpUtility.ParseQueryString(started.RedirectUri!.Query);

        provider.IdTokenNonce = query[OAuthRequestParameterNames.Nonce];
        var signedIn = await CallbackAndExchangeAsync(client, provider, query[OAuthRequestParameterNames.State]!, publicKey, WellKnownJwaValues.Es256).ConfigureAwait(false);

        Assert.AreEqual(OpenIdSignInRefusal.KeyUnresolved, signedIn.Refusal);
    }


    /// <summary>
    /// OpenID Connect Core 1.0 §3.1.3.7 item 7: an ID Token correctly signed under a key the provider publishes, but under another
    /// algorithm than the one the relying party registered - ES256 where it registered the default RS256 - is refused by the
    /// algorithm check, and the provider's key is never asked for; the same token is verified where ES256 is the one registered.
    /// </summary>
    [TestMethod]
    public async Task AnIdTokenUnderAnotherPublishedAlgorithmThanTheRegisteredOneIsRefused()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var provider = new StandInProvider(this, privateKey);
        var client = new OAuthClient(provider.Infrastructure).AuthCode;

        var started = await client.StartOpenIdAsync(
            Registration(), Callback, Scope(), [], resource: null, TimeSpan.FromMinutes(10), TestContext.CancellationToken).ConfigureAwait(false);
        var query = HttpUtility.ParseQueryString(started.RedirectUri!.Query);

        provider.IdTokenNonce = query[OAuthRequestParameterNames.Nonce];
        var signedIn = await CallbackAndExchangeAsync(client, provider, query[OAuthRequestParameterNames.State]!, publicKey, WellKnownJwaValues.Rs256).ConfigureAwait(false);

        Assert.AreEqual(OpenIdSignInRefusal.AlgorithmNotRegistered, signedIn.Refusal, "The token signed under an algorithm other than the registered one is refused.");
        Assert.IsNull(signedIn.IdToken, "No token is answered as verified.");
        Assert.AreEqual(0, provider.KeyRequests, "No key of another algorithm than the registered one is asked for.");

        var again = await client.StartOpenIdAsync(
            Registration(), Callback, Scope(), [], resource: null, TimeSpan.FromMinutes(10), TestContext.CancellationToken).ConfigureAwait(false);
        var againQuery = HttpUtility.ParseQueryString(again.RedirectUri!.Query);

        provider.IdTokenNonce = againQuery[OAuthRequestParameterNames.Nonce];
        var registered = await CallbackAndExchangeAsync(client, provider, againQuery[OAuthRequestParameterNames.State]!, publicKey, WellKnownJwaValues.Es256).ConfigureAwait(false);

        Assert.IsTrue(registered.IsSignedIn, $"The same provider's token verifies under the algorithm registered; refused by {registered.Refusal} {registered.IdTokenFailure}.");
    }


    /// <summary>A flow whose request sent no nonce - a plain start - is never exchanged as an OpenID Connect sign-in.</summary>
    [TestMethod]
    public async Task APlainFlowIsNeverExchangedAsASignIn()
    {
        var keys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keys.PublicKey;
        using var privateKey = keys.PrivateKey;
        var provider = new StandInProvider(this, privateKey);
        var client = new OAuthClient(provider.Infrastructure).AuthCode;

        var started = await client.StartAsync(
            Registration(), Callback, Scope(), [], resource: null, TimeSpan.FromMinutes(10), TestContext.CancellationToken).ConfigureAwait(false);
        var query = HttpUtility.ParseQueryString(started.RedirectUri!.Query);
        Assert.IsNull(query[OAuthRequestParameterNames.Nonce], "A plain start sends no nonce.");

        var signedIn = await CallbackAndExchangeAsync(client, provider, query[OAuthRequestParameterNames.State]!, publicKey, WellKnownJwaValues.Es256).ConfigureAwait(false);

        Assert.AreEqual(OpenIdSignInRefusal.NonceNotHeld, signedIn.Refusal);
        Assert.AreEqual(0, provider.TokenRequests, "No code is exchanged for a flow holding no nonce.");
    }


    /// <summary>Answers the callback with a code for the state, then exchanges it as an OpenID Connect sign-in.</summary>
    /// <param name="client">The client.</param>
    /// <param name="provider">The stand-in provider.</param>
    /// <param name="state">The state the start sent.</param>
    /// <param name="publicKey">The provider's published key.</param>
    /// <param name="registeredAlgorithm">The algorithm the relying party registered for its ID Tokens.</param>
    /// <returns>What the sign-in came to.</returns>
    private async Task<OpenIdSignInResult> CallbackAndExchangeAsync(AuthCodeClient client, StandInProvider provider, string state, PublicKeyMemory publicKey, string registeredAlgorithm)
    {
        var callback = await client.HandleCallbackAsync(
            Registration(),
            new OAuthFormEncodedFields(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.Code] = "authorization-code-of-the-sign-in",
                [OAuthRequestParameterNames.State] = state,
                [OAuthRequestParameterNames.Iss] = ProviderIssuer
            }),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callback.Outcome, callback.ErrorDescription);

        return await client.ExchangeOpenIdTokenAsync(
            Registration(),
            state,
            [],
            clientAssertionOptions: null,
            new OpenIdTokenVerification
            {
                ResolveKey = (keyId, algorithm, cancellationToken) =>
                {
                    provider.KeyRequests++;

                    return ValueTask.FromResult(
                        string.Equals(keyId, ProviderKeyId, StringComparison.Ordinal) && WellKnownJwaValues.IsEs256(algorithm)
                            ? IdJagGrantHoldingTests.CopyOf(publicKey)
                            : null);
                },
                Parser = JwsAccessTokenTestSupport.Parser,
                Base64UrlDecoder = TestSetup.Base64UrlDecoder,
                ClockSkew = TimeSpan.FromSeconds(60),
                RegisteredAlgorithm = registeredAlgorithm
            },
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>The relying party's registration at the provider: a public client under RFC 6749 with PKCE.</summary>
    /// <returns>The registration.</returns>
    private static ClientRegistration Registration() => new()
    {
        ClientId = new ClientId(RelyingPartyClientId),
        AuthorizationServerIssuer = new Uri(ProviderIssuer),
        AuthenticationMethod = ClientAuthenticationMethod.None,
        Profile = PolicyProfile.Rfc6749WithPkce
    };


    /// <summary>The sign-in's scope: <c>openid</c>.</summary>
    /// <returns>The fields.</returns>
    private static OAuthFormEncodedFields Scope() =>
        new(new Dictionary<string, string>(StringComparer.Ordinal) { [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId });


    /// <summary>
    /// A stand-in OpenID Provider: its metadata, the flow states the client holds, and a token endpoint answering every code
    /// exchange with an ID Token signed under the provider's key, carrying the nonce, audience and key identifier the row sets.
    /// </summary>
    private sealed class StandInProvider
    {
        /// <summary>Composes the provider over the row's clock and the provider's signing key.</summary>
        /// <param name="row">The row.</param>
        /// <param name="signingKey">The provider's signing key.</param>
        public StandInProvider(OpenIdSignInTests row, PrivateKeyMemory signingKey)
        {
            Row = row;
            SigningKey = signingKey;
            var entropy = TestEntropy.NewCounterStream();
            var issuer = new Uri(ProviderIssuer);

            Infrastructure = OAuthClientInfrastructure.Create(
                sendFormPostAsync: AnswerTokenRequestAsync,
                saveStateAsync: (state, context, cancellationToken) =>
                {
                    States[state.FlowId] = state;

                    return ValueTask.CompletedTask;
                },
                loadStateAsync: (flowId, context, cancellationToken) => ValueTask.FromResult(States.GetValueOrDefault(flowId)),
                loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
                parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
                parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
                parseRegistrationResponseAsync: (body, cancellationToken) =>
                    throw new NotSupportedException("The sign-in reads no registration response."),
                resolveAuthorizationServerMetadataAsync: (requested, context, cancellationToken) =>
                    ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                    {
                        MetadataLocation = WellKnownPaths.OpenIdConfiguration.ComputeUri(issuer.OriginalString),
                        Metadata = new AuthorizationServerMetadata
                        {
                            Issuer = issuer,
                            AuthorizationEndpoint = new Uri("https://op.example.com/authorize"),
                            TokenEndpoint = new Uri("https://op.example.com/token")
                        }
                    }),
                resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
                base64UrlEncoder: TestSetup.Base64UrlEncoder,
                memoryPool: BaseMemoryPool.Shared,
                timeProvider: row.TimeProvider,
                fillEntropy: entropy,
                generateIdentifierAsync: DefaultIdentifierGenerator.For(row.TimeProvider, entropy, BaseMemoryPool.Shared));
        }

        /// <summary>The row, for its clock and cancellation.</summary>
        private OpenIdSignInTests Row { get; }

        /// <summary>The provider's signing key.</summary>
        private PrivateKeyMemory SigningKey { get; }

        /// <summary>The client's infrastructure toward this provider.</summary>
        public OAuthClientInfrastructure Infrastructure { get; }

        /// <summary>The flow states the client holds, by flow identifier.</summary>
        public Dictionary<string, FlowState> States { get; } = new(StringComparer.Ordinal);

        /// <summary>How many token requests reached the token endpoint.</summary>
        public int TokenRequests { get; private set; }

        /// <summary>How many times the client asked for the provider's published key.</summary>
        public int KeyRequests { get; set; }

        /// <summary>The nonce the ID Token carries, or <see langword="null"/> for none.</summary>
        public string? IdTokenNonce { get; set; }

        /// <summary>The audience the ID Token carries.</summary>
        public string IdTokenAudience { get; set; } = RelyingPartyClientId;

        /// <summary>The key identifier the ID Token's header names.</summary>
        public string IdTokenKeyId { get; init; } = ProviderKeyId;


        /// <summary>Answers a code exchange with an access token, a refresh token and an ID Token signed under the provider's key.</summary>
        /// <param name="endpoint">The endpoint.</param>
        /// <param name="fields">The form.</param>
        /// <param name="headers">The headers.</param>
        /// <param name="context">The context.</param>
        /// <param name="cancellationToken">Cancels the answer.</param>
        /// <returns>The answer.</returns>
        private async ValueTask<HttpResponseData> AnswerTokenRequestAsync(
            Uri endpoint, IReadOnlyCollection<KeyValuePair<string, string>> fields, OutgoingHeaders headers, ExchangeContext context, CancellationToken cancellationToken)
        {
            TokenRequests++;
            var now = Row.TimeProvider.GetUtcNow().ToUnixTimeSeconds();
            var claims = new Dictionary<string, object>
            {
                [WellKnownJwtClaimNames.Iss] = ProviderIssuer,
                [WellKnownJwtClaimNames.Sub] = "person-at-op",
                [WellKnownJwtClaimNames.Aud] = IdTokenAudience,
                [WellKnownJwtClaimNames.Iat] = now,
                [WellKnownJwtClaimNames.Exp] = now + 600
            };

            if(IdTokenNonce is { } nonce)
            {
                claims[WellKnownJwtClaimNames.Nonce] = nonce;
            }

            using var message = await Jws.SignAsync(
                new Dictionary<string, object>
                {
                    [WellKnownJoseHeaderNames.Alg] = WellKnownJwaValues.Es256,
                    [WellKnownJwkMemberNames.Kid] = IdTokenKeyId,
                    [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
                },
                claims,
                JwtWireFixtures.EncodeJwtPart,
                TestSetup.Base64UrlEncoder,
                SigningKey,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async,
                BaseMemoryPool.Shared,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            var idToken = JwsSerialization.SerializeCompact(message, TestSetup.Base64UrlEncoder);
            var body = new StringBuilder()
                .Append("{\"access_token\":\"access-token-of-the-sign-in-0123456789\",\"token_type\":\"Bearer\",\"expires_in\":300,")
                .Append("\"refresh_token\":\"refresh-token-issued-beside\",\"id_token\":\"").Append(idToken).Append("\"}")
                .ToString();

            return new HttpResponseData { StatusCode = 200, Body = body };
        }
    }
}
