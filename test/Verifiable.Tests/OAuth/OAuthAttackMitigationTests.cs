using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// Verifies that <see cref="AuthCodeFlow"/> resists the attacks catalogued in
/// <see href="https://www.rfc-editor.org/rfc/rfc9700">RFC 9700 — OAuth 2.0 Security
/// Best Current Practice</see>.
/// </summary>
/// <remarks>
/// <para>
/// Test names encode the RFC 9700 section that defines the attack, enabling direct
/// traceability from a failing test to the normative requirement violated. Each test
/// documents the attacker capability assumed (drawn from RFC 9700 §3, the updated
/// OAuth 2.0 attacker model) and the mitigation being verified.
/// </para>
/// <para>
/// Two security profiles are exercised:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <c>Haip10</c> — requires the <c>iss</c> parameter per HAIP 1.0 / FAPI 2.0
///       and <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>Rfc6749WithPkce</c> — plain RFC 6749 with PKCE; <c>iss</c> is not required.
///     </description>
///   </item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class OAuthAttackMitigationTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    //RFC 9700 §4.4 — Mix-Up Attack
    //
    //Attacker capability: A network attacker (A2 in RFC 9700 §3) that can inject a
    //different issuer identifier into the authorization response, or can redirect the
    //client to a malicious authorization server that returns a valid-looking code.
    //
    //Mitigation: the client must compare the iss value in the callback against the
    //issuer it sent the PAR request to. Exact string comparison is required per
    //RFC 8414 §3.3 and RFC 9700 §4.4.2.1.

    [TestMethod]
    public async Task Rfc9700Section4Point4MixUpAttackCallbackWithWrongIssuerIsRejected()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store, OAuthCallbackValidators.Haip10);
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);
        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "auth-code",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = "https://attacker.example.com"
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        AssertClaimFailed(result.ValidationClaims, OAuthCallbackClaimIds.IssuerMatchesExpected,
            "Issuer mismatch must produce a failed IssuerMatchesExpected claim.");
    }


    [TestMethod]
    public async Task Rfc9700Section4Point4MixUpAttackCallbackWithMissingIssuerIsRejectedUnderHaip10()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store, OAuthCallbackValidators.Haip10);
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);
        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "auth-code",
                [OAuthRequestParameters.State] = flowId
                //iss deliberately absent — HAIP 1.0 requires it.
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        AssertClaimFailed(result.ValidationClaims, OAuthCallbackClaimIds.CallbackIssPresent,
            "Absent iss must produce a failed CallbackIssPresent claim under HAIP 1.0.");
    }


    [TestMethod]
    public async Task Rfc9700Section4Point4MixUpAttackCallbackWithMissingIssuerSucceedsUnderRfc6749()
    {
        //Plain RFC 6749 with PKCE does not require iss. The callback is valid without it.
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store, OAuthCallbackValidators.Rfc6749WithPkce);
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);
        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "auth-code",
                [OAuthRequestParameters.State] = flowId
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome,
            "Plain RFC 6749 profile must not require iss.");
    }


    [TestMethod]
    public async Task Rfc9700Section4Point4MixUpAttackCallbackWithCorrectIssuerSucceeds()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store, OAuthCallbackValidators.Haip10);
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);
        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "auth-code",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = "https://as.example.com"
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
        AssertAllClaimsSucceeded(result.ValidationClaims);
    }


    //RFC 9700 §4.7 — Cross-Site Request Forgery (CSRF)
    //
    //Attacker capability: A web attacker (A1 in RFC 9700 §3) that can cause the
    //victim's browser to issue a request to the client's redirect URI carrying a
    //code obtained by the attacker from a different OAuth session.
    //
    //Mitigation: the state parameter binds the authorization response to the
    //originating session. An unknown or replayed state value must be rejected.

    [TestMethod]
    public async Task Rfc9700Section4Point7CsrfCallbackWithUnknownStateIsRejected()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store, OAuthCallbackValidators.Haip10);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "attacker-code",
                [OAuthRequestParameters.State] = "no-such-flow-id",
                [OAuthRequestParameters.Iss] = "https://as.example.com"
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "Callback with unknown state must be rejected.");
    }


    [TestMethod]
    public async Task Rfc9700Section4Point7CsrfCallbackWithMissingStateIsRejected()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(store, OAuthCallbackValidators.Haip10);
        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "auth-code",
                [OAuthRequestParameters.Iss] = "https://as.example.com"
                //state deliberately absent.
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "Callback without state must be rejected.");
    }


    //RFC 9700 §4.5 — Authorization Code Injection
    //
    //Attacker capability: A network attacker (A2) that has obtained a valid
    //authorization code (e.g., by intercepting a redirect) and attempts to inject
    //it into a different victim session.
    //
    //Mitigation: PKCE binds the code to the session that initiated the flow. The
    //token endpoint will reject a code whose code_challenge does not match the
    //code_verifier presented. The client side ensures code_challenge is always
    //sent in the PAR body and code_verifier is always sent in the token request.

    [TestMethod]
    public async Task Rfc9700Section4Point5AuthCodeInjectionParBodyAlwaysContainsCodeChallenge()
    {
        //Verify that every PAR request body produced by the flow includes code_challenge.
        //Its absence would allow a PKCE downgrade attack per RFC 9700 §4.8.
        var capturedFields = new Dictionary<string, string>();
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(
            store,
            OAuthCallbackValidators.Haip10,
            captureFormFields: capturedFields);

        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsTrue(
            capturedFields.ContainsKey(OAuthRequestParameters.CodeChallenge),
            "PAR request body must always contain code_challenge.");
        Assert.AreEqual(
            OAuthRequestParameters.CodeChallengeMethodS256,
            capturedFields[OAuthRequestParameters.CodeChallengeMethod],
            "code_challenge_method must be S256.");
    }


    [TestMethod]
    public async Task Rfc9700Section4Point5AuthCodeInjectionTokenRequestAlwaysContainsCodeVerifier()
    {
        //Verify that every token request produced by the flow includes code_verifier.
        var parCaptured = new Dictionary<string, string>();
        var tokenCaptured = new Dictionary<string, string>();
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(
            store,
            OAuthCallbackValidators.Haip10,
            captureFormFields: parCaptured,
            captureTokenFields: tokenCaptured,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:test", 60),
            tokenResponse: BuildTokenJson("at.123", "Bearer", 3600, null));

        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string flowId = GetSingleFlowId(store);
        await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "code-abc",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = "https://as.example.com"
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            tokenCaptured.ContainsKey(OAuthRequestParameters.CodeVerifier),
            "Token request must always contain code_verifier.");
    }


    //RFC 9700 §4.8 — PKCE Downgrade Attack
    //
    //Attacker capability: A network attacker that can strip the code_challenge
    //parameter from the authorization request, causing an authorization server that
    //treats PKCE as optional to issue a code without binding it to a verifier.
    //
    //Mitigation: the client must always send code_challenge (enforced above in §4.5
    //tests). The flow state carries PkceParameters so that the token request always
    //includes code_verifier regardless of whether the AS enforced PKCE.

    [TestMethod]
    public async Task Rfc9700Section4Point8PkceDowngradeCodeChallengeMethodIsAlwaysS256()
    {
        var capturedFields = new Dictionary<string, string>();
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(
            store,
            OAuthCallbackValidators.Haip10,
            captureFormFields: capturedFields);

        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(
            OAuthRequestParameters.CodeChallengeMethodS256,
            capturedFields[OAuthRequestParameters.CodeChallengeMethod],
            "The plain method must never be used; only S256 is permitted per RFC 9700 §2.1.1.");
    }


    //RFC 9700 §4.9 — Token Replay (expired flow state)
    //
    //Mitigation: flows have a bounded lifetime. An attempt to complete a flow after
    //the expiry window must be rejected to prevent replay of stale authorization codes.

    [TestMethod]
    public async Task Rfc9700Section4Point9TokenReplayExpiredFlowStateIsRejected()
    {
        var store = new Dictionary<string, OAuthFlowState>();
        AuthCodeFlowOptions options = CreateOptions(
            store,
            OAuthCallbackValidators.Haip10,
            parResponse: BuildParJson("urn:ietf:params:oauth:request_uri:expired", 1));

        await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), options, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string flowId = GetSingleFlowId(store);

        //Advance time past the PAR expires_in of 1 second.
        TimeProvider.Advance(TimeSpan.FromSeconds(10));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameters.Code] = "stale-code",
                [OAuthRequestParameters.State] = flowId,
                [OAuthRequestParameters.Iss] = "https://as.example.com"
            },
            options,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "Callback on an expired flow state must be rejected.");
        AssertClaimFailed(result.ValidationClaims, OAuthCallbackClaimIds.FlowStateNotExpired,
            "Expired flow must produce a failed FlowStateNotExpired claim.");
    }


    private AuthCodeFlowOptions CreateOptions(
        Dictionary<string, OAuthFlowState> store,
        ValidateCallbackDelegate validateCallback,
        string? parResponse = null,
        string? tokenResponse = null,
        Dictionary<string, string>? captureFormFields = null,
        Dictionary<string, string>? captureTokenFields = null,
        Uri? revocationEndpoint = null,
        bool useDefaultRevocationEndpoint = true)
    {
        Uri? resolvedRevocationEndpoint = revocationEndpoint
            ?? (useDefaultRevocationEndpoint ? new Uri("https://as.example.com/revoke") : null);

        return AuthCodeFlowOptions.Create(
            clientId: "test-client",
            endpoints: new AuthorizationServerEndpoints
            {
                Issuer = "https://as.example.com",
                PushedAuthorizationRequestEndpoint = new Uri("https://as.example.com/par"),
                AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
                TokenEndpoint = new Uri("https://as.example.com/token"),
                RevocationEndpoint = resolvedRevocationEndpoint
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
                    if(s is ParCompleted pc
                        && string.Equals(pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        found = s;
                        break;
                    }
                }
                return ValueTask.FromResult(found);
            },
            sendFormPostAsync: async (endpoint, fields, _) =>
            {
                bool isTokenEndpoint = endpoint.AbsolutePath.EndsWith("/token", StringComparison.Ordinal)
                                    || endpoint.AbsolutePath.EndsWith("/revoke", StringComparison.Ordinal);
                if(isTokenEndpoint && captureTokenFields is not null)
                {
                    foreach(KeyValuePair<string, string> kv in fields)
                    {
                        captureTokenFields[kv.Key] = kv.Value;
                    }
                }
                else if(!isTokenEndpoint && captureFormFields is not null)
                {
                    foreach(KeyValuePair<string, string> kv in fields)
                    {
                        captureFormFields[kv.Key] = kv.Value;
                    }
                }
                string body = isTokenEndpoint
                    ? tokenResponse ?? string.Empty
                    : parResponse ?? BuildParJson("urn:ietf:params:oauth:request_uri:default", 60);
                return new HttpResponseData { Body = body, StatusCode = 200 };
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            validateCallback: validateCallback,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: TimeProvider);
    }

    private static string BuildParJson(string requestUri, int expiresIn) =>
        /*lang=json,strict*/ $"{{\"request_uri\":\"{requestUri}\",\"expires_in\":{expiresIn}}}";

    private static string BuildTokenJson(
        string accessToken,
        string tokenType,
        int expiresIn,
        string? refreshToken) =>
        refreshToken is null
            ? /*lang=json,strict*/ $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"{tokenType}\",\"expires_in\":{expiresIn}}}"
            : /*lang=json,strict*/ $"{{\"access_token\":\"{accessToken}\",\"token_type\":\"{tokenType}\",\"expires_in\":{expiresIn},\"refresh_token\":\"{refreshToken}\"}}";

    private static string GetSingleFlowId(Dictionary<string, OAuthFlowState> store)
    {
        Assert.IsNotEmpty(store, "Store must contain at least one flow state.");
        foreach(string key in store.Keys)
        {
            return key;
        }

        throw new InvalidOperationException("Store is empty.");
    }

    private static void AssertClaimFailed(
        System.Collections.Generic.IReadOnlyList<Claim> claims,
        ClaimId expectedId,
        string message)
    {
        Claim? found = null;
        foreach(Claim c in claims)
        {
            if(c.Id.Code == expectedId.Code)
            {
                found = c;
                break;
            }
        }
        Assert.IsNotNull(found, $"Expected claim {expectedId} to be present. {message}");
        Assert.AreEqual(ClaimOutcome.Failure, found.Outcome, message);
    }

    private static void AssertAllClaimsSucceeded(
        IReadOnlyList<Claim> claims)
    {
        foreach(Claim c in claims)
        {
            Assert.AreEqual(ClaimOutcome.Success, c.Outcome,
                $"Expected all validation claims to succeed but claim {c.Id} has outcome {c.Outcome}.");
        }
    }
}