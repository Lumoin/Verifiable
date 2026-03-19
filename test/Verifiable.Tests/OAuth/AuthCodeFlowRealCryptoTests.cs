using Microsoft.Extensions.Time.Testing;
using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end Authorization Code flow tests using real PKCE generation and
/// real JSON parsing via <see cref="AuthorizationServerMetadataParsers"/>.
/// </summary>
[TestClass]
internal sealed class AuthCodeFlowRealCryptoTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    [TestMethod]
    public async Task RealPkceGenerationProducesValidBase64UrlEncodedPair()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:real1", 60));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome);
        Assert.HasCount(1, store, "PAR must persist exactly one flow state.");

        ParCompleted parState = Assert.IsInstanceOfType<ParCompleted>(
            GetFirstValue(store));

        //Verifier: 43 Base64url chars for 32 random bytes.
        Assert.AreEqual(43, parState.Pkce.EncodedVerifier.Length,
            "PKCE verifier must be exactly 43 Base64url characters for 32 bytes.");

        //Challenge: always 43 chars for SHA-256 output Base64url-encoded.
        Assert.AreEqual(43, parState.Pkce.EncodedChallenge.Length,
            "PKCE S256 challenge must be exactly 43 Base64url characters.");

        //Both must be valid Base64url — no padding, no +//.
        Assert.IsLessThan(0, parState.Pkce.EncodedVerifier.AsSpan().IndexOf('+'), "Verifier must use Base64url encoding without + character.");
        Assert.IsLessThan(0, parState.Pkce.EncodedVerifier.AsSpan().IndexOf('/'), "Verifier must use Base64url encoding without / character.");
        Assert.IsLessThan(0, parState.Pkce.EncodedVerifier.AsSpan().IndexOf('='), "Verifier must not contain padding.");
        Assert.IsLessThan(0, parState.Pkce.EncodedChallenge.AsSpan().IndexOf('+'));
        Assert.IsLessThan(0, parState.Pkce.EncodedChallenge.AsSpan().IndexOf('/'));
        Assert.IsLessThan(0, parState.Pkce.EncodedChallenge.AsSpan().IndexOf('='));
    }


    [TestMethod]
    public async Task TwoParRequestsProduceDifferentVerifiers()
    {
        var store1 = new Dictionary<string, OAuthFlowState>();
        var store2 = new Dictionary<string, OAuthFlowState>();

        AuthCodeFlowOptions options1 = CreateOptions(store1,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:a", 60));
        AuthCodeFlowOptions options2 = CreateOptions(store2,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:b", 60));

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            options1,
            TestContext.CancellationToken).ConfigureAwait(false);

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            options2,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompleted state1 = Assert.IsInstanceOfType<ParCompleted>(
            GetFirstValue(store1));
        ParCompleted state2 = Assert.IsInstanceOfType<ParCompleted>(
            GetFirstValue(store2));

        Assert.AreNotEqual(state1.Pkce.EncodedVerifier, state2.Pkce.EncodedVerifier,
            "Each PAR request must produce a unique PKCE verifier.");
        Assert.AreNotEqual(state1.Pkce.EncodedChallenge, state2.Pkce.EncodedChallenge,
            "Different verifiers must produce different challenges.");
    }


    [TestMethod]
    public async Task ParsedParResponsePopulatesFlowStateCorrectly()
    {
        const string requestUri = "urn:ietf:params:oauth:request_uri:test123";
        const int expiresIn = 90;

        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store,
            parResponse: BuildParJson(requestUri, expiresIn));

        DateTimeOffset before = TimeProvider.GetUtcNow();

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompleted state = Assert.IsInstanceOfType<ParCompleted>(
            GetFirstValue(store));

        Assert.AreEqual(requestUri, state.Par.RequestUri.ToString(),
            "PAR request_uri must be stored exactly as returned by the endpoint.");
        Assert.AreEqual(expiresIn, state.Par.ExpiresIn,
            "PAR expires_in must be stored from the response.");
        Assert.IsGreaterThan(before, state.ExpiresAt, "ExpiresAt must be in the future relative to the PAR request.");
        Assert.AreEqual(before.AddSeconds(expiresIn), state.ExpiresAt,
            "ExpiresAt must be exactly now + expires_in seconds.");
    }


    [TestMethod]
    public async Task MetadataParserExtractsAllEndpointsFromWellKnownDocument()
    {
        const string issuer = "https://as.example.com";
        string metadataJson = BuildMetadataJson(
            issuer: issuer,
            authorizationEndpoint: "https://as.example.com/authorize",
            tokenEndpoint: "https://as.example.com/token",
            parEndpoint: "https://as.example.com/par",
            revocationEndpoint: "https://as.example.com/revoke",
            jwksUri: "https://as.example.com/.well-known/jwks.json");

        bool parsed = TryParseMetadataJson(metadataJson, out AuthorizationServerEndpoints? endpoints);

        Assert.IsTrue(parsed, "Valid metadata document must parse successfully.");
        Assert.IsNotNull(endpoints);
        Assert.AreEqual(issuer, endpoints.Issuer);
        Assert.AreEqual("https://as.example.com/authorize", endpoints.AuthorizationEndpoint.ToString());
        Assert.AreEqual("https://as.example.com/token", endpoints.TokenEndpoint.ToString());
        Assert.AreEqual("https://as.example.com/par", endpoints.PushedAuthorizationRequestEndpoint.ToString());
        Assert.AreEqual("https://as.example.com/revoke", endpoints.RevocationEndpoint!.ToString());
        Assert.AreEqual("https://as.example.com/.well-known/jwks.json", endpoints.JwksUri!.ToString());
    }


    [TestMethod]
    public void MetadataParserReturnsFalseWhenIssuerMissing()
    {
        string json = /*lang=json,strict*/ """
            {
                "authorization_endpoint": "https://as.example.com/authorize",
                "token_endpoint": "https://as.example.com/token",
                "pushed_authorization_request_endpoint": "https://as.example.com/par"
            }
            """;

        bool parsed = TryParseMetadataJson(json, out AuthorizationServerEndpoints? endpoints);

        Assert.IsFalse(parsed, "Metadata without issuer must not parse successfully.");
        Assert.IsNull(endpoints);
    }


    [TestMethod]
    public void MetadataParserReturnsFalseWhenParEndpointMissing()
    {
        string json = /*lang=json,strict*/ """
            {
                "issuer": "https://as.example.com",
                "authorization_endpoint": "https://as.example.com/authorize",
                "token_endpoint": "https://as.example.com/token"
            }
            """;

        bool parsed = TryParseMetadataJson(json, out AuthorizationServerEndpoints? endpoints);

        Assert.IsFalse(parsed,
            "Metadata without pushed_authorization_request_endpoint must not parse successfully.");
        Assert.IsNull(endpoints);
    }


    [TestMethod]
    public async Task FullHappyPathWithRealPkceAndRealParsers()
    {
        const string issuer = "https://as.example.com";
        var store = new Dictionary<string, OAuthFlowState>();
        string accessToken = "eyJhbGciOiJFUzI1NiJ9.real.token";
        string tokenJson = BuildTokenJson(accessToken, "Bearer", 3600, null);

        AuthCodeFlowOptions options = CreateOptions(store,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:full", 60),
            tokenResponse: tokenJson);

        //Step 1 — PAR.
        AuthCodeFlowEndpointResult parResult = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome);
        string flowId = GetFirstKey(store);
        //Step 2 — callback with issuer present (HAIP 1.0).
        AuthCodeFlowEndpointResult callbackResult = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "auth-code-xyz",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = issuer
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome);

        //Step 3 — token exchange.
        AuthCodeFlowEndpointResult tokenResult = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string>
            {
                [AuthCodeFlowRoutes.FlowIdField] = flowId
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome);
        Assert.IsNotNull(tokenResult.Body);
        Assert.AreEqual(accessToken, tokenResult.Body[OAuthRequestParameters.AccessToken].ToString());

        Assert.IsInstanceOfType<TokenReceived>(store[flowId],
            "Flow must reach TokenReceived state after successful token exchange.");
    }


    [TestMethod]
    public async Task EntropyEventsAreEmittedDuringPkceGeneration()
    {
        var observer = new TestObserver<CryptoEvent>();
        using IDisposable subscription = CryptoObservable.Events.Subscribe(observer);

        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:obs", 60));

        await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        List<EntropyConsumedEvent> entropyEvents = observer.Received
            .OfType<EntropyConsumedEvent>()
            .ToList();

        Assert.IsGreaterThanOrEqualTo(1, entropyEvents.Count,
            "At least one EntropyConsumedEvent must be emitted during PKCE generation.");

        EntropyConsumedEvent nonceEvent = entropyEvents[0];
        Assert.AreEqual(32, nonceEvent.ByteCount,
            "PKCE verifier must consume exactly 32 bytes of entropy.");
    }


    private AuthCodeFlowOptions CreateOptions(
        Dictionary<string, OAuthFlowState> store,
        string? parResponse = null,
        string? tokenResponse = null)
    {
        return AuthCodeFlowOptions.Create(
            clientId: "test-client",
            endpoints: new AuthorizationServerEndpoints
            {
                Issuer = "https://as.example.com",
                PushedAuthorizationRequestEndpoint = new Uri("https://as.example.com/par"),
                AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
                TokenEndpoint = new Uri("https://as.example.com/token"),
                RevocationEndpoint = new Uri("https://as.example.com/revoke")
            },
            redirectUri: new Uri("https://client.example.com/callback"),
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
                    if(s is ParCompleted pc && string.Equals(pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        found = s;
                        break;
                    }
                }
                return ValueTask.FromResult(found);
            },
            sendFormPostAsync: async (endpoint, _, __) =>
            {
                bool isTokenEndpoint = endpoint.AbsolutePath.EndsWith("/token", StringComparison.Ordinal)
                                    || endpoint.AbsolutePath.EndsWith("/revoke", StringComparison.Ordinal);
                string body = isTokenEndpoint
                    ? tokenResponse ?? string.Empty
                    : parResponse ?? string.Empty;
                return new HttpResponseData { Body = body, StatusCode = 200 };
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            validateCallback: OAuthCallbackValidators.Haip10,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: TimeProvider);
    }

    private static string BuildParJson(string requestUri, int expiresIn) =>
        "{\"request_uri\":\"" + requestUri + "\",\"expires_in\":"
            + expiresIn.ToString(System.Globalization.CultureInfo.InvariantCulture) + "}";

    private static string BuildTokenJson(
        string accessToken,
        string tokenType,
        int expiresIn,
        string? refreshToken)
    {
        string ei = expiresIn.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if(refreshToken is null)
        {
            return "{\"access_token\":\"" + accessToken
                + "\",\"token_type\":\"" + tokenType
                + "\",\"expires_in\":" + ei + "}";
        }

        return "{\"access_token\":\"" + accessToken
            + "\",\"token_type\":\"" + tokenType
            + "\",\"expires_in\":" + ei
            + ",\"refresh_token\":\"" + refreshToken + "\"}";
    }

    private static string BuildMetadataJson(
        string issuer,
        string authorizationEndpoint,
        string tokenEndpoint,
        string parEndpoint,
        string? revocationEndpoint = null,
        string? jwksUri = null)
    {
        string result = "{\"issuer\":\"" + issuer + "\""
            + ",\"authorization_endpoint\":\"" + authorizationEndpoint + "\""
            + ",\"token_endpoint\":\"" + tokenEndpoint + "\""
            + ",\"pushed_authorization_request_endpoint\":\"" + parEndpoint + "\"";

        if(revocationEndpoint is not null)
        {
            result += ",\"revocation_endpoint\":\"" + revocationEndpoint + "\"";
        }

        if(jwksUri is not null)
        {
            result += ",\"jwks_uri\":\"" + jwksUri + "\"";
        }

        return result + "}";
    }

    private static TValue GetFirstValue<TKey, TValue>(Dictionary<TKey, TValue> dict)
        where TKey : notnull
    {
        foreach(TValue value in dict.Values)
        {
            return value;
        }

        throw new InvalidOperationException("Dictionary is empty.");
    }

    private static TKey GetFirstKey<TKey, TValue>(Dictionary<TKey, TValue> dict)
        where TKey : notnull
    {
        foreach(TKey key in dict.Keys)
        {
            return key;
        }

        throw new InvalidOperationException("Dictionary is empty.");
    }

    //Minimal metadata document parser for tests — reads the six known fields
    //from a flat JSON object using the same span-scan approach as OAuthResponseParsers.
    //Verifiable.Json provides the production implementation.
    private static bool TryParseMetadataJson(
        string json,
        out AuthorizationServerEndpoints? endpoints)
    {
        endpoints = null;
        ReadOnlySpan<char> span = json.AsSpan();

        if(!OAuthResponseParsers.TryGetStringField(span, "issuer", out ReadOnlySpan<char> issuerSpan)
            || issuerSpan.IsEmpty)
        {
            return false;
        }

        if(!OAuthResponseParsers.TryGetStringField(span, "authorization_endpoint", out ReadOnlySpan<char> authSpan)
            || !Uri.TryCreate(authSpan.ToString(), UriKind.Absolute, out Uri? authUri))
        {
            return false;
        }

        if(!OAuthResponseParsers.TryGetStringField(span, "token_endpoint", out ReadOnlySpan<char> tokenSpan)
            || !Uri.TryCreate(tokenSpan.ToString(), UriKind.Absolute, out Uri? tokenUri))
        {
            return false;
        }

        if(!OAuthResponseParsers.TryGetStringField(span, "pushed_authorization_request_endpoint", out ReadOnlySpan<char> parSpan)
            || !Uri.TryCreate(parSpan.ToString(), UriKind.Absolute, out Uri? parUri))
        {
            return false;
        }

        Uri? revocationUri = null;
        if(OAuthResponseParsers.TryGetStringField(span, "revocation_endpoint", out ReadOnlySpan<char> revSpan))
        {
            Uri.TryCreate(revSpan.ToString(), UriKind.Absolute, out revocationUri);
        }

        Uri? jwksUri = null;
        if(OAuthResponseParsers.TryGetStringField(span, "jwks_uri", out ReadOnlySpan<char> jwksSpan))
        {
            Uri.TryCreate(jwksSpan.ToString(), UriKind.Absolute, out jwksUri);
        }

        endpoints = new AuthorizationServerEndpoints
        {
            Issuer = issuerSpan.ToString(),
            AuthorizationEndpoint = authUri,
            TokenEndpoint = tokenUri,
            PushedAuthorizationRequestEndpoint = parUri,
            RevocationEndpoint = revocationUri,
            JwksUri = jwksUri
        };

        return true;
    }
}