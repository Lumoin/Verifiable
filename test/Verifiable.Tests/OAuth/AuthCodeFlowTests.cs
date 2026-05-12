using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Linq;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


[TestClass]
internal sealed class AuthCodeFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static readonly Uri DefaultRedirectUri = new("https://client.example.com/callback");


    [TestMethod]
    public async Task HandleParAsyncReturnsRedirectOnSuccess()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:abc", 60));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string> { [OAuthRequestParameters.Scope] = "openid" },
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome);
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains("request_uri", result.RedirectUri.ToString(), StringComparison.Ordinal);
        Assert.HasCount(1, store, "PAR success must persist exactly one flow state.");
        Assert.IsInstanceOfType<ParCompletedState>(TestDictionaryHelpers.GetFirstValue(store));
    }


    [TestMethod]
    public async Task HandleParAsyncReturnsInternalErrorWhenHttpFails()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store: [],
            httpException: new InvalidOperationException("Network unreachable."));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome);
        Assert.AreEqual("server_error", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleParAsyncReturnsBadRequestWhenServerReturnsProtocolError()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store: new Dictionary<string, OAuthFlowState>(),
            parResponse: /*lang=json,strict*/ "{\"error\":\"invalid_client\"}");

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_client", result.ErrorCode,
            "A well-formed OAuth error response must surface the server error code directly.");
    }


    [TestMethod]
    public async Task HandleParAsyncReturnsInternalErrorWhenResponseIsMalformed()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store: new Dictionary<string, OAuthFlowState>(),
            parResponse: "<html>502 Bad Gateway</html>");

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome);
        Assert.AreEqual("server_error", result.ErrorCode,
            "An HTML error page or unparseable body must map to server_error.");
    }


    [TestMethod]
    public async Task HandleCallbackAsyncReturnsBadRequestWhenMissingParameters()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(new Dictionary<string, OAuthFlowState>());

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string> { [OAuthRequestParameters.Code] = "abc" },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleCallbackAsyncReturnsBadRequestWhenFlowNotFound()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(new Dictionary<string, OAuthFlowState>());

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "auth-code-xyz",
                [OAuthRequestParameters.State] = "unknown-flow-id",
                [OAuthRequestParameters.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleCallbackAsyncReturnsBadRequestOnIssuerMismatch()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:x", 60));
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "code-abc",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = "https://attacker.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleCallbackAsyncPersistsCodeStateOnSuccess()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:y", 60));
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "code-xyz",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
        Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(store[flowId],
            "Callback success must replace ParCompleted with AuthorizationCodeReceived in the store.");
    }


    [TestMethod]
    public async Task HandleTokenAsyncReturnsBadRequestWhenFlowIdMissing()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(new Dictionary<string, OAuthFlowState>());

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string>(),
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleTokenAsyncReturnsBadRequestWhenNoCodePending()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:z", 60));
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "Token exchange with ParCompleted state (no code yet) must be rejected.");
    }


    [TestMethod]
    public async Task HandleTokenAsyncReturnsOkWithTokensOnFullHappyPath()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:happy", 60),
            tokenResponse: BuildTokenJson("at.abc", "Bearer", 3600, "rt.xyz"));

        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);
        string flowId = GetSingleFlowId(store);

        await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "code-happy",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
        Assert.IsNotNull(result.Body);
        Assert.AreEqual("at.abc", result.Body["access_token"]);
        Assert.AreEqual("Bearer", result.Body["token_type"]);
        Assert.IsInstanceOfType<TokenReceivedState>(store[flowId],
            "Token exchange success must persist TokenReceived in the store.");
    }


    [TestMethod]
    public async Task HandleRevocationAsyncReturnsBadRequestWhenEndpointMissing()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            new Dictionary<string, OAuthFlowState>(),
            useDefaultRevocationEndpoint: false);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleRevocationAsync(
            new Dictionary<string, string> { ["token"] = "some-token" },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("unsupported_token_type", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleRevocationAsyncReturnsOkWhenEndpointPresent()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            new Dictionary<string, OAuthFlowState>());

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleRevocationAsync(
            new Dictionary<string, string> { ["token"] = "some-token" },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
    }


    [TestMethod]
    public async Task RefreshAsyncReturnsOkWithNewTokens()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            new Dictionary<string, OAuthFlowState>(),
            tokenResponse: BuildTokenJson("at.new", "Bearer", 3600, "rt.new"));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.RefreshAsync(
            new RefreshTokenRequest
            {
                ClientId = "test-client",
                RefreshToken = "rt.old"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
        Assert.IsNotNull(result.Body);
        Assert.AreEqual("at.new", result.Body["access_token"]);
        Assert.AreEqual("rt.new", result.Body["refresh_token"]);
    }


    [TestMethod]
    public async Task PkceVerifierIsBase64UrlEncodedWithCorrectLength()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:pkce1", 60));

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompletedState state = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store));

        Assert.AreEqual(43, state.Pkce.EncodedVerifier.Length,
            "PKCE verifier must be exactly 43 Base64url characters for 32 bytes.");
        Assert.AreEqual(43, state.Pkce.EncodedChallenge.Length,
            "PKCE S256 challenge must be exactly 43 Base64url characters.");
        Assert.IsLessThan(0, state.Pkce.EncodedVerifier.AsSpan().IndexOf('+'),
            "Verifier must not contain + character.");
        Assert.IsLessThan(0, state.Pkce.EncodedVerifier.AsSpan().IndexOf('/'),
            "Verifier must not contain / character.");
        Assert.IsLessThan(0, state.Pkce.EncodedVerifier.AsSpan().IndexOf('='),
            "Verifier must not contain padding.");
        Assert.IsLessThan(0, state.Pkce.EncodedChallenge.AsSpan().IndexOf('+'));
        Assert.IsLessThan(0, state.Pkce.EncodedChallenge.AsSpan().IndexOf('/'));
        Assert.IsLessThan(0, state.Pkce.EncodedChallenge.AsSpan().IndexOf('='));
    }


    [TestMethod]
    public async Task EachParRequestProducesUniqueVerifierAndChallenge()
    {
        var store1 = new Dictionary<string, OAuthFlowState>();
        var store2 = new Dictionary<string, OAuthFlowState>();

        (OAuthClientInfrastructure infrastructure1, ClientRegistration registration1) = CreateInfrastructureAndRegistration(store1,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:u1", 60));
        (OAuthClientInfrastructure infrastructure2, ClientRegistration registration2) = CreateInfrastructureAndRegistration(store2,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:u2", 60));

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, infrastructure1, registration1,
            TestContext.CancellationToken).ConfigureAwait(false);
        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, infrastructure2, registration2,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompletedState state1 = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store1));
        ParCompletedState state2 = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store2));

        Assert.AreNotEqual(state1.Pkce.EncodedVerifier, state2.Pkce.EncodedVerifier,
            "Each PAR request must produce a unique PKCE verifier.");
        Assert.AreNotEqual(state1.Pkce.EncodedChallenge, state2.Pkce.EncodedChallenge,
            "Different verifiers must produce different challenges.");
    }


    [TestMethod]
    public async Task ParResponsePopulatesExpiresAtFromExpiresIn()
    {
        const int expiresIn = 90;
        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:exp", expiresIn));

        DateTimeOffset before = TimeProvider.GetUtcNow();

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompletedState state = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store));

        Assert.AreEqual(expiresIn, state.Par.ExpiresIn,
            "PAR expires_in must be stored from the response.");
        Assert.IsGreaterThan(before, state.ExpiresAt,
            "ExpiresAt must be in the future relative to the PAR request.");
        Assert.AreEqual(before.AddSeconds(expiresIn), state.ExpiresAt,
            "ExpiresAt must be exactly now + expires_in seconds.");
    }


    [TestMethod]
    public async Task EntropyEventsAreEmittedDuringPkceGeneration()
    {
        var observer = new TestObserver<CryptoEvent>();
        using IDisposable subscription = CryptographicKeyEvents.Events.Subscribe(observer);

        var store = new Dictionary<string, OAuthFlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:obs", 60));

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        System.Collections.Generic.List<EntropyConsumedEvent> entropyEvents =
            observer.Received.OfType<EntropyConsumedEvent>().ToList();

        Assert.IsGreaterThanOrEqualTo(1, entropyEvents.Count,
            "At least one EntropyConsumedEvent must be emitted during PKCE generation.");
        Assert.AreEqual(32, entropyEvents[0].ByteCount,
            "PKCE verifier must consume exactly 32 bytes of entropy.");
    }


    private (OAuthClientInfrastructure Infrastructure, ClientRegistration Registration) CreateInfrastructureAndRegistration(
        Dictionary<string, OAuthFlowState> store,
        string? parResponse = null,
        string? tokenResponse = null,
        Exception? httpException = null,
        Uri? revocationEndpoint = null,
        bool useDefaultRevocationEndpoint = true)
    {
        Uri? resolvedRevocationEndpoint = revocationEndpoint
            ?? (useDefaultRevocationEndpoint ? new Uri("https://as.example.com/revoke") : null);

        Uri issuerUri = new("https://as.example.com");

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUri,
            PushedAuthorizationRequestEndpoint = new Uri("https://as.example.com/par"),
            AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
            TokenEndpoint = new Uri("https://as.example.com/token"),
            RevocationEndpoint = resolvedRevocationEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: async (endpoint, _, __) =>
            {
                if(httpException is not null)
                {
                    throw httpException;
                }
                bool isTokenEndpoint = endpoint.AbsolutePath.EndsWith("/token", StringComparison.Ordinal)
                                    || endpoint.AbsolutePath.EndsWith("/revoke", StringComparison.Ordinal);
                string body = isTokenEndpoint
                    ? tokenResponse ?? string.Empty
                    : parResponse ?? string.Empty;
                return new HttpResponseData { Body = body, StatusCode = 200 };
            },
            saveStateAsync: (state, _) =>
            {
                store[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _) =>
                ValueTask.FromResult(store.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _) =>
            {
                OAuthFlowState? found = null;
                foreach(OAuthFlowState s in store.Values)
                {
                    if(s is ParCompletedState pc
                        && string.Equals(pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        found = s;
                        break;
                    }
                }
                return ValueTask.FromResult(found);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("AuthCodeFlowTests does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: (registration, timeProvider) =>
                new ClaimIssuer<ValidationContext>(
                    "test-callback-validator",
                    ValidationProfiles.CallbackHaip10Rules(),
                    timeProvider),
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: TimeProvider);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId("test-client"),
            AuthorizationServerIssuer = issuerUri,
            RedirectUris = [DefaultRedirectUri],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Haip10
        };

        return (infrastructure, registration);
    }

    private static string BuildParJson(string requestUri, int expiresIn) =>
        /*lang=json,strict*/ $"{{\"request_uri\":\"{requestUri}\",\"expires_in\":{expiresIn}}}";

    private static string BuildTokenJson(string accessToken, string tokenType, int expiresIn, string? refreshToken) =>
        refreshToken is null
            ? /*lang=json,strict*/ $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"{tokenType}\",\"expires_in\":{expiresIn}}}"
            : /*lang=json,strict*/ $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"{tokenType}\",\"expires_in\":{expiresIn},\"refresh_token\":\"{refreshToken}\"}}";

    private static string GetSingleFlowId(Dictionary<string, OAuthFlowState> store)
    {
        Assert.IsNotEmpty(store, "Store must contain at least one flow state.");
        return TestDictionaryHelpers.GetFirstKey(store);
    }
}

internal static class TestDictionaryHelpers
{
    public static TValue GetFirstValue<TKey, TValue>(Dictionary<TKey, TValue> dict)
        where TKey : notnull
    {
        foreach(TValue value in dict.Values)
        {
            return value;
        }

        throw new InvalidOperationException("Dictionary is empty.");
    }

    public static TKey GetFirstKey<TKey, TValue>(Dictionary<TKey, TValue> dict)
        where TKey : notnull
    {
        foreach(TKey key in dict.Keys)
        {
            return key;
        }

        throw new InvalidOperationException("Dictionary is empty.");
    }
}
