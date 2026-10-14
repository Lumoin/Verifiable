using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The phase 6 gate test. Exercises the full DPoP-bound AuthCode flow end to
/// end against a real <see cref="AuthorizationServerIntegration"/> dispatch chain:
/// PAR → Authorize → Token, with the AS challenging the first token request
/// for a fresh nonce and the client retrying exactly once with the nonce
/// echoed. Then plays the RS-side proof validation for a resource call,
/// confirming that the recorded <c>cnf.jkt</c> binding matches the proving
/// key's thumbprint.
/// </summary>
[TestClass]
internal sealed class DpopEndToEndTests
{
    public TestContext TestContext { get; set; } = null!;

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch.AddDays(-18);
    private const string ClientId = "https://client.example.com";
    private const string TestSubject = "subject-1";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 §6.1</see>: "The value of
    /// the jkt member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256
    /// Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK format) to which the access
    /// token is bound." A client
    /// driving PAR, authorize and the token request with a DPoP proof, answering the token endpoint's one
    /// nonce challenge, receives a DPoP-bound access token whose <c>cnf.jkt</c> is its key's thumbprint,
    /// and a proof it then builds for a resource call validates with that same thumbprint.
    /// </summary>
    [TestMethod]
    public async Task TokenIssuanceAndResourceCallValidateUnderDpopProtocol()
    {
        //Proof-point migration to the HTTP-backed factory. Bytes
        //flow through Kestrel ↔ HttpClient over a real socket; the test's
        //wire-level assertions (token_type from response body, cnf.jkt from
        //the JWT) now run against bytes that actually traversed HTTP framing.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration,
            RedirectUri.OriginalString,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Step 1 — PAR. No DPoP at this endpoint per HAIP, just the PKCE-bearing
        //pushed authorization request that returns the request_uri handle.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration,
            RedirectUri,
            OAuthFormEncodedFieldsFixtures.OpenIdScope,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"Expected PAR to yield a redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");
        Assert.IsNotNull(parResult.RedirectUri);

        //The client-side `state` was generated inside StartParAsync and stored
        //as the ParCompletedState's FlowId. Read it back via the exposed flow
        //store rather than threading state through the test's manual Authorize
        //dispatch.
        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        //Step 2 — Authorize. The user-agent would normally GET the redirect URL
        //against the AS. Replicate that in-process by dispatching a GET to
        //authorize with the request_uri lifted from the PAR response and a
        //pre-authenticated subject identifier on the context.
        string requestUri = parCompleted.Par.RequestUri.ToString();
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };

        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(TestSubject);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get,
            authorizeFields,
            authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode,
            $"Expected redirect from authorize. Body: {authorizeResponse.Body}");
        Assert.IsNotNull(authorizeResponse.Location);

        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location);
        Assert.IsNotNull(iss, "HAIP-aligned policy must emit iss on redirect.");

        //Step 3 — Callback. Client-side: validates iss, persists the
        //AuthorizationCodeReceivedState ready for token exchange.
        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId,
            [OAuthRequestParameterNames.Iss] = iss
        };

        AuthCodeFlowEndpointResult callbackResult = await fixture.Client.AuthCode.HandleCallbackAsync(
            fixture.Registration,
            new OAuthFormEncodedFields(callbackFields),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        //Step 4 — Token. Client has no cached nonce yet; the AS challenges
        //with HTTP 400 + use_dpop_nonce + DPoP-Nonce response header. The
        //AuthCode handler reads the header, stores the nonce, and retries
        //exactly once with a nonce-bearing proof. Result must be Ok with an
        //access token.
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration,
            flowId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Expected token issuance success. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        Assert.IsNotNull(tokenResult.Body);
        Assert.IsTrue(tokenResult.Body.TryGetValue(OAuthRequestParameterNames.AccessToken, out object? accessTokenObj));
        string accessToken = (string)accessTokenObj;
        Assert.IsFalse(string.IsNullOrEmpty(accessToken));

        //Wire-level assertion: the response body's token_type field carries
        //"DPoP" (RFC 9449 §5), not "Bearer", because DPoP enforcement bound
        //the token. Reading from the parsed Body dictionary is equivalent to
        //reading the wire because OAuthResponseParsers passes the JSON
        //field through unchanged.
        Assert.IsTrue(tokenResult.Body.TryGetValue(OAuthRequestParameterNames.TokenType, out object? tokenTypeObj));
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)tokenTypeObj,
            "DPoP-bound issuance must emit token_type=DPoP per RFC 9449 §5.");

        //Wire-level assertion: the access-token JWT itself carries cnf.jkt
        //(RFC 9449 §6.1) equal to the DPoP key's thumbprint. Read the JWT
        //payload directly — no host-side accessor shortcut.
        string expectedThumbprint = fixture.DpopKey.GetThumbprint(
            TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
        string wireJkt = JwtPayloadReader.ReadCnfJkt(accessToken)
            ?? throw new AssertFailedException("Access-token JWT must carry cnf.jkt under DPoP issuance.");
        Assert.AreEqual(expectedThumbprint, wireJkt,
            "JWT cnf.jkt must equal the DPoP key's RFC 7638 thumbprint.");

        //Audit follow-up — RFC 9068 §2 / RFC 8414 §3: the access token's iss
        //claim preserves the full issuer URL including any path component.
        //On the real-wire host, the issuer URI is aligned to the https
        //base address (carrying the tenant segment as the path component);
        //read the live value from the client-side registration that the
        //factory wired with the aligned URI.
        string wireIss = JwtPayloadReader.ReadIssuer(accessToken)
            ?? throw new AssertFailedException("Access-token JWT must carry iss claim.");
        Assert.AreEqual(fixture.Registration.AuthorizationServerIssuer.OriginalString, wireIss,
            "Access-token iss claim must preserve the full issuer URL per RFC 8414 §3.");

        //Step 5 — RS-side validation. The application playing the RS role
        //constructs a fresh proof for a resource call carrying the ath claim
        //bound to the access token and validates it. The validator's
        //JwkThumbprint must match the binding the AS recorded.
        const string resourceUrl = "https://rs.example.com/api/profile";
        string resourceProof = await ResourceDpopProofs.BuildAsync(
            fixture.DpopKey, WellKnownHttpMethods.Get, resourceUrl, accessToken, nonce: null, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofValidationResult rsResult = await DpopProofValidator.ValidateAsync(
            new DpopProofValidationRequest
            {
                Proof = resourceProof,
                HttpMethod = WellKnownHttpMethods.Get,
                HttpUrl = resourceUrl,
                AccessToken = accessToken,
                NonceRequired = false
            },
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            DpopTestSupport.Parser,
            TestHostShell.Base64UrlEncoder,
            TestHostShell.Base64UrlDecoder,
            TimeProvider,
            TestHostShell.MemoryPool,
            iatSkew: WellKnownDpopValues.DefaultIatSkew,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(rsResult.IsSuccess,
            $"RS-side proof must validate. FailureReason={rsResult.FailureReason}");
        Assert.AreEqual(expectedThumbprint, rsResult.JwkThumbprint,
            "RS-validated thumbprint must equal the binding the AS recorded.");
    }


    [TestMethod]
    public async Task BearerTokenIssuanceOmitsConfirmationAndUsesBearerWireType()
    {
        //Negative coverage: when DPoP enforcement does not run (policy does
        //not require, no proof presented), the wire response carries
        //token_type=Bearer and the access-token JWT has no cnf claim. Same
        //wire-level reading discipline as the positive gate test — no host
        //accessor in the assertion path, except for one verification that
        //the diagnostic accessor agrees (returns null).
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            host.CreateInProcessOAuthClientAndRegistration(
                material.Registration,
                RedirectUri.OriginalString,
                material.Registration.IssuerUri!.ToString(),
                profile: PolicyProfile.Rfc6749WithPkce);

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration,
            RedirectUri,
            OAuthFormEncodedFields.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect. ErrorCode={parResult.ErrorCode}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)clientFlowStore[flowId];
        string requestUri = parCompleted.Par.RequestUri.ToString();

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(TestSubject);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get,
            authorizeFields,
            authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode);
        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location!);
        //Rfc6749WithPkce sets EmitIssOnRedirect=false; iss may be null.
        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId
        };
        if(iss is not null)
        {
            callbackFields[OAuthRequestParameterNames.Iss] = iss;
        }

        AuthCodeFlowEndpointResult callbackResult = await client.AuthCode.HandleCallbackAsync(
            registration,
            new OAuthFormEncodedFields(callbackFields),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed under Rfc6749WithPkce. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token issuance must succeed. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        Assert.IsNotNull(tokenResult.Body);

        //Wire-level: token_type is Bearer per RFC 6750 §2.1.
        Assert.IsTrue(tokenResult.Body!.TryGetValue(OAuthRequestParameterNames.TokenType, out object? typeObj));
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, (string)typeObj!,
            "Non-DPoP issuance must emit token_type=Bearer per RFC 6750 §2.1.");

        //Wire-level: JWT carries no cnf claim.
        string accessToken = (string)tokenResult.Body[OAuthRequestParameterNames.AccessToken]!;
        Assert.IsFalse(JwtPayloadReader.HasCnfClaim(accessToken),
            "Non-DPoP access token must not carry cnf claim.");

        //Diagnostic-accessor agreement: GetConfirmationForAccessToken returns null.
        Assert.IsNull(host.GetConfirmationForAccessToken(accessToken),
            "Diagnostic accessor must agree with the wire — no binding recorded.");
    }


    /// <summary>
    /// RFC 9449 §11.1 over the full DPoP-bound AuthCode wire: a store that records the DPoP proof
    /// <c>jti</c> but never resolves what it saved under <c>FlowKind.JtiReplay</c> cannot maintain the
    /// used-<c>jti</c> set, so <see cref="JtiReplayGuard"/> answers
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> and the token endpoint refuses the exchange with
    /// <c>server_error</c> — the silent no-op the half-wiring would otherwise produce is caught rather
    /// than admitted.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449, Section 11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task DpopTokenEndpointFailsClosedWhenStoreCannotProveItself()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration,
            RedirectUri.OriginalString,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration,
            RedirectUri,
            OAuthFormEncodedFieldsFixtures.OpenIdScope,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome, parResult.ErrorDescription);

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(TestSubject);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get,
            authorizeFields,
            authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location!);
        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId,
            [OAuthRequestParameterNames.Iss] = iss!
        };
        AuthCodeFlowEndpointResult callbackResult = await fixture.Client.AuthCode.HandleCallbackAsync(
            fixture.Registration,
            new OAuthFormEncodedFields(callbackFields),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome, callbackResult.ErrorDescription);

        await HalfWireJtiReplayStoreAsync(host.Server).ConfigureAwait(false);

        //The token endpoint's DPoP proof carries a jti; the half-wired store saves it but cannot resolve
        //it, so the guard cannot prove the replay defense ran and the exchange fails closed.
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration,
            flowId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome, "The half-wired store must refuse the exchange.");
        Assert.AreEqual(OAuthErrors.ServerError, tokenResult.ErrorCode,
            $"RFC 9449 §11.1: a store that cannot prove it recorded the DPoP jti fails the exchange closed. Description: {tokenResult.ErrorDescription}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "Use of the
    /// dpop_jkt authorization request parameter is OPTIONAL." The client takes the option not: the DPoP-wired
    /// client pushes its authorization request over the wire with a body that carries no <c>dpop_jkt</c> field
    /// and a request that carries no <c>DPoP</c> field (the other way
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">Section 10.1</see> names to communicate
    /// the DPoP public key at the pushed request), the server answers with its <c>request_uri</c>, and the
    /// authorization request URL the client is redirected to carries no <c>dpop_jkt</c> parameter.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientPushesItsAuthorizationRequestWithoutDpopJktAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        List<(Uri Endpoint, IReadOnlyCollection<KeyValuePair<string, string>> Fields, OutgoingHeaders Headers)> posts = [];
        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration,
            RedirectUri.OriginalString,
            (endpoint, fields, headers) => posts.Add((endpoint, [.. fields], headers)),
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration,
            RedirectUri,
            OAuthFormEncodedFieldsFixtures.OpenIdScope,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome, parResult.ErrorDescription);
        (Uri endpoint, IReadOnlyCollection<KeyValuePair<string, string>> fields, OutgoingHeaders headers) = Assert.ContainsSingle(posts);
        Assert.EndsWith(
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, material.Registration.TenantId.Value),
            endpoint.AbsolutePath, "The one form post is the pushed authorization request.");
        Assert.DoesNotContain(static field => string.Equals(field.Key, "dpop_jkt", StringComparison.Ordinal), fields,
            "The pushed authorization request body carries no dpop_jkt.");
        Assert.IsFalse(headers.Values.ContainsKey(WellKnownHttpHeaderNames.DPoP), "The pushed authorization request carries no DPoP field.");
        Assert.DoesNotContain("dpop_jkt", parResult.RedirectUri!.ToString(), "The authorization request URL carries no dpop_jkt.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "The value of the
    /// dpop_jkt authorization request parameter is the JWK Thumbprint [RFC7638] of the proof-of-possession public key
    /// using the SHA-256 hash function", and "the dpop_jkt authorization request parameter MAY also be used in
    /// combination with Proof Key for Code Exchange (PKCE)";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">Section 10.1</see>: "dpop_jkt MUST be included
    /// alongside other authorization request parameters in the POST body of the PAR request." A pushed request carrying
    /// an S256 code challenge and the thumbprint of a DPoP key in its body is answered 201, and its code redeemed under a
    /// proof by that DPoP key issues a DPoP access token whose <c>cnf.jkt</c> is the thumbprint sent.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PushedDpopJktBindsTheCodeToThatKeyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, boundThumbprint));
        (int parStatusCode, string parBody, Uri? location, int authorizeStatusCode) = await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
            host, segment, ClientId, TestSubject, fields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);
        Assert.Contains("\"request_uri\":", parBody, StringComparison.Ordinal, parBody);
        string code = DpopCodeBindingWire.ReadCode(authorizeStatusCode, location);

        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);

        DpopCodeBindingWire.AssertIssued(statusCode, body, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "When a token request
    /// is received, the authorization server computes the JWK Thumbprint of the proof-of-possession public key in the
    /// DPoP proof and verifies that it matches the dpop_jkt parameter value in the authorization request. If they do not
    /// match, it MUST reject the request." A code pushed with <c>dpop_jkt</c> and redeemed with no <c>DPoP</c> field,
    /// under a profile that does not itself require DPoP, is refused 400 <c>invalid_grant</c>; the code stays unspent,
    /// and its redemption under a proof by the bound DPoP key then issues a DPoP access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CodeBoundByPushedDpopJktRefusesARedemptionWithoutAProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, boundThumbprint).ConfigureAwait(false);

        (int noProofStatusCode, string noProofBody) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(noProofStatusCode, noProofBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: the authorization
    /// server "verifies that it matches the dpop_jkt parameter value in the authorization request. If they do not match,
    /// it MUST reject the request." A code pushed with the thumbprint of one DPoP key and redeemed under a valid proof,
    /// carrying the supplied nonce, by another DPoP key is refused 400 <c>invalid_grant</c>; the code stays unspent and
    /// its redemption under the bound DPoP key issues a DPoP access token bound to that DPoP key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CodeBoundByPushedDpopJktRefusesARedemptionUnderAnotherKeyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, boundThumbprint).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        (int otherStatusCode, string otherBody) = await RedeemAsync(host, segment, code, pkce, other.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(otherStatusCode, otherBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "the DPoP header
    /// can be added to the PAR request. In this case, the authorization server MUST check the provided DPoP proof JWT as
    /// defined in Section 4.3. It MUST further behave as if the contained public key's thumbprint was provided using
    /// dpop_jkt, i.e., reject the subsequent token request unless a DPoP proof for the same key is provided." A pushed
    /// request carrying a valid proof by one DPoP key and no <c>dpop_jkt</c> is answered 201; its code is refused 400
    /// <c>invalid_grant</c> under a proof by another DPoP key and with no proof, and redeemed under a proof by the DPoP
    /// key of the pushed request.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ProofAtThePushedRequestBindsTheCodeToItsKeyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        string pushedProof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, bound.Key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(
            host, segment, BuildAuthorizationRequestFields(pkce), pushedProof, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);
        string code = await AuthorizePushedAsync(host, segment, pushed.Body, []).ConfigureAwait(false);

        (int otherStatusCode, string otherBody) = await RedeemAsync(host, segment, code, pkce, other.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(otherStatusCode, otherBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int noProofStatusCode, string noProofBody) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(noProofStatusCode, noProofBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "the authorization
    /// server MUST check the provided DPoP proof JWT as defined in Section 4.3", whose checks
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>) hold the proof's <c>typ</c>
    /// to <c>dpop+jwt</c>, its <c>alg</c> to a registered asymmetric digital signature algorithm, its <c>jwk</c> to a
    /// public key ("The jwk JOSE Header Parameter does not contain a private key."), its <c>htm</c> and <c>htu</c> to
    /// the request, its signature, its creation time to an acceptable window, its <c>jti</c> against replay
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see>) and its nonce when the
    /// server supplies one (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>: "the
    /// authorization server responds to requests that do not include a nonce with an HTTP 400 (Bad Request) error
    /// response per Section 5.2 of [RFC6749] using use_dpop_nonce as the error code value. The authorization server
    /// includes a DPoP-Nonce HTTP header in the response supplying a nonce value");
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">Section 5</see>: "If the DPoP proof is invalid,
    /// the authorization server issues an error response per Section 5.2 of [RFC6749] with invalid_dpop_proof as the
    /// value of the error parameter."; and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126 Section 2.3</see>: "Error codes defined
    /// by the OAuth extension can also be used when such an extension is involved in the initial processing of the
    /// authorization request that was pushed." Each presentation of a proof that fails a check at the pushed request
    /// is refused there with the token endpoint's answer for it.
    /// </summary>
    /// <param name="presentation">The proof the pushed request carries.</param>
    /// <param name="expectedError">The <c>error</c> answered.</param>
    /// <param name="expectedDescription">The <c>error_description</c> answered.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("htu-of-the-token-endpoint", "invalid_dpop_proof", "DPoP proof validation failed: HtuMismatch.", DisplayName = "htu of the token endpoint")]
    [DataRow("htm-get", "invalid_dpop_proof", "DPoP proof validation failed: HtmMismatch.", DisplayName = "htm GET")]
    [DataRow("signature-over-other-bytes", "invalid_dpop_proof", "DPoP proof validation failed: SignatureFailed.", DisplayName = "a signature over other bytes")]
    [DataRow("no-nonce", "use_dpop_nonce", "DPoP nonce required.", DisplayName = "no nonce")]
    [DataRow("presented-twice", "invalid_dpop_proof", "DPoP proof jti has been seen previously.", DisplayName = "the same proof presented twice")]
    [DataRow("typ-jwt", "invalid_dpop_proof", "DPoP proof validation failed: InvalidTyp.", DisplayName = "typ JWT")]
    [DataRow("alg-hs256", "invalid_dpop_proof", "DPoP proof validation failed: InvalidAlg.", DisplayName = "alg HS256 over an ES256 signature")]
    [DataRow("jwk-with-private-member", "invalid_dpop_proof", "DPoP proof validation failed: JwkContainsPrivateKey.", DisplayName = "a jwk carrying the private member d")]
    [DataRow("iat-outside-the-window", "invalid_dpop_proof", "DPoP proof validation failed: IatOutOfWindow.", DisplayName = "an iat ten minutes old")]
    public async Task ProofAtThePushedRequestIsCheckedAsAtTheTokenEndpointAsync(
        string presentation, string expectedError, string expectedDescription)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, now, TestContext.CancellationToken).ConfigureAwait(false);
        string pushedRequestUri = RawAuthCodeWirePushers.ResolveParEndpointUri(host, segment).OriginalString;

        string proof = presentation switch
        {
            "htu-of-the-token-endpoint" => await DpopCodeBindingWire.BuildTokenProofAsync(
                host, segment, key.Key, nonce, now, TestContext.CancellationToken).ConfigureAwait(false),
            "htm-get" => await ResourceDpopProofs.BuildAsync(
                key.Key, WellKnownHttpMethods.Get, pushedRequestUri, accessToken: null, nonce, now,
                TestContext.CancellationToken).ConfigureAwait(false),
            "signature-over-other-bytes" => await BuildProofSignedOverOtherBytesAsync(
                host, segment, key.Key, nonce, now).ConfigureAwait(false),
            "no-nonce" => await DpopCodeBindingWire.BuildPushedRequestProofAsync(
                host, segment, key.Key, nonce: null, now, TestContext.CancellationToken).ConfigureAwait(false),
            "presented-twice" => await DpopCodeBindingWire.BuildPushedRequestProofAsync(
                host, segment, key.Key, nonce, now, TestContext.CancellationToken).ConfigureAwait(false),
            "typ-jwt" => await ResourceDpopProofs.BuildAsync(
                key.Key, WellKnownHttpMethods.Post, pushedRequestUri, accessToken: null, nonce, now,
                TestContext.CancellationToken, alterHeader: static header => header["typ"] = "JWT").ConfigureAwait(false),
            "alg-hs256" => await ResourceDpopProofs.BuildAsync(
                key.Key, WellKnownHttpMethods.Post, pushedRequestUri, accessToken: null, nonce, now,
                TestContext.CancellationToken, alterHeader: static header => header["alg"] = "HS256").ConfigureAwait(false),
            "jwk-with-private-member" => await ResourceDpopProofs.BuildAsync(
                key.Key, WellKnownHttpMethods.Post, pushedRequestUri, accessToken: null, nonce, now,
                TestContext.CancellationToken, alterHeader: static header => header["jwk"] =
                    new Dictionary<string, object>((Dictionary<string, object>)header["jwk"], StringComparer.Ordinal)
                    {
                        ["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    }).ConfigureAwait(false),
            "iat-outside-the-window" => await DpopCodeBindingWire.BuildPushedRequestProofAsync(
                host, segment, key.Key, nonce, now.AddMinutes(-10), TestContext.CancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(presentation), presentation, "No such presentation.")
        };

        if(presentation == "presented-twice")
        {
            HttpResponseData first = await DpopCodeBindingWire.PushAsync(
                host, segment, BuildAuthorizationRequestFields(pkce), proof, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(201, first.StatusCode, first.Body);
        }

        HttpResponseData response = await DpopCodeBindingWire.PushAsync(
            host, segment, BuildAuthorizationRequestFields(pkce), proof, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, expectedError, expectedDescription);
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
        if(presentation == "no-nonce")
        {
            Assert.HasCount(1, response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce),
                "The nonce challenge carries exactly one DPoP-Nonce field.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "The htu claim
    /// matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment
    /// parts.", and <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see>: "If an
    /// adversary is able to get hold of a DPoP proof JWT, the adversary could replay that token at the same endpoint
    /// (the HTTP endpoint and method are enforced via the respective claims in the JWTs)." The very proof a pushed
    /// request carried, presented again at the token endpoint with the code that request led to, is refused 400
    /// <c>invalid_dpop_proof</c> for its <c>htu</c>; the code stays unspent, and its redemption under a fresh proof by
    /// the same DPoP key issues a DPoP access token whose <c>cnf.jkt</c> is that DPoP key's thumbprint.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PushedRequestProofPresentedAtTheTokenEndpointIsRefusedForItsHtuAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        string thumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(key.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        string pushedProof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key.Key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(
            host, segment, BuildAuthorizationRequestFields(pkce), pushedProof, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);
        string code = await AuthorizePushedAsync(host, segment, pushed.Body, []).ConfigureAwait(false);

        (int replayStatusCode, string replayBody) = await RawAuthCodeWirePushers.RedeemCodeAsync(
            host, segment, ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString, pushedProof,
            TestContext.CancellationToken).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(replayStatusCode, replayBody, 400, "invalid_dpop_proof", "DPoP proof validation failed: HtuMismatch.");

        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "DPoP", thumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective
    /// DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI
    /// for which the jti value has been seen before would be declined.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">Section 4.2</see>: "The jti can be used by the
    /// server for replay detection and prevention". A token request proof by one DPoP key, carrying the supplied
    /// nonce, first presented with a code that was never issued (400 <c>invalid_grant</c>) and then presented again
    /// with a code bound to that DPoP key, is refused 400 <c>invalid_dpop_proof</c>; the bound code stays unspent, and
    /// its redemption under a fresh proof by the same DPoP key issues a DPoP access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UsedTokenEndpointProofIsRefusedAgainstAnUnspentBoundCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        string thumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(key.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, thumbprint).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        string usedProof = await DpopCodeBindingWire.BuildTokenProofAsync(
            host, segment, key.Key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        (int firstStatusCode, string firstBody) = await RawAuthCodeWirePushers.RedeemCodeAsync(
            host, segment, ClientId, "never-issued-authorization-code", pkce.EncodedVerifier, RedirectUri.OriginalString,
            usedProof, TestContext.CancellationToken).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(firstStatusCode, firstBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int replayStatusCode, string replayBody) = await RawAuthCodeWirePushers.RedeemCodeAsync(
            host, segment, ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString, usedProof,
            TestContext.CancellationToken).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(replayStatusCode, replayBody, 400, "invalid_dpop_proof", "DPoP proof jti has been seen previously.");

        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "DPoP", thumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "the authorization
    /// server MUST check the provided DPoP proof JWT as defined in Section 4.3. It MUST further behave as if the
    /// contained public key's thumbprint was provided using dpop_jkt", the thumbprint being
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">Section 6.1</see>) "the base64url encoding (as
    /// defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key". An
    /// authorization server whose DPoP proof validation answers a valid proof with no such thumbprint cannot behave
    /// so, whether it answers no value, the empty string, or the 64-character lowercase hexadecimal spelling of a
    /// SHA-256 digest: a pushed request carrying such a proof, with the supplied nonce, is answered 500
    /// <c>server_error</c> and no <c>request_uri</c> is issued.
    /// </summary>
    /// <param name="answeredJwkThumbprint">The JWK thumbprint the validation answers for the valid proof.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(null, DisplayName = "no thumbprint")]
    [DataRow("", DisplayName = "the empty string")]
    [DataRow(DpopCodeBindingWire.HexadecimalSha256Digest, DisplayName = "a hex thumbprint")]
    public async Task PushedRequestProofWhoseValidatorAnswersNoJwkThumbprintIsAServerErrorAsync(string? answeredJwkThumbprint)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        await host.AnswerValidatedDpopProofsWithJwkThumbprintAsync(answeredJwkThumbprint).ConfigureAwait(false);

        string proof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key.Key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData response = await DpopCodeBindingWire.PushAsync(
            host, segment, BuildAuthorizationRequestFields(pkce), proof, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 500, "server_error", "The DPoP proof validator answered no JWK SHA-256 Thumbprint for a valid proof.");
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "To sender-constrain the
    /// access token after checking the validity of the DPoP proof, the authorization server associates the issued
    /// access token with the public key from the DPoP proof", the association being
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">Section 6.1</see>) a <c>jkt</c> whose value
    /// "MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638])
    /// of the DPoP public key". An authorization server whose DPoP proof validation answers a valid proof with no such
    /// thumbprint cannot associate the token with it, whether it answers no value, the empty string, or the
    /// 64-character lowercase hexadecimal spelling of a SHA-256 digest: a redemption of a code bound to no DPoP key
    /// carrying such a proof, with the supplied nonce, is answered 500 <c>server_error</c> and no access token is
    /// issued.
    /// </summary>
    /// <param name="answeredJwkThumbprint">The JWK thumbprint the validation answers for the valid proof.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(null, DisplayName = "no thumbprint")]
    [DataRow("", DisplayName = "the empty string")]
    [DataRow(DpopCodeBindingWire.HexadecimalSha256Digest, DisplayName = "a hex thumbprint")]
    public async Task CodeRedemptionProofWhoseValidatorAnswersNoJwkThumbprintIsAServerErrorAsync(string? answeredJwkThumbprint)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, dpopJkt: string.Empty).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        await host.AnswerValidatedDpopProofsWithJwkThumbprintAsync(answeredJwkThumbprint).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(statusCode, body, 500, "server_error", "The DPoP proof validator answered no JWK SHA-256 Thumbprint for a valid proof.");
        Assert.DoesNotContain("\"access_token\":", body, StringComparison.Ordinal, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 Section 5</see>: "To sender-constrain the
    /// access token after checking the validity of the DPoP proof, the authorization server associates the issued access
    /// token with the public key from the DPoP proof", the proof carrying the <c>nonce</c> claim the server's challenge
    /// asked for (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">Section 8</see>). An authorization server
    /// whose DPoP proof validation answers a valid proof with no claims cannot check that nonce or record the proof's
    /// <c>jti</c>: a redemption of a code bound to no DPoP key carrying such a proof, with the supplied nonce, is answered
    /// 500 <c>server_error</c> "The DPoP proof validator answered no claims for a valid proof." and no access token is
    /// issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CodeRedemptionProofWhoseValidatorAnswersNoClaimsIsAServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, dpopJkt: string.Empty).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        await host.AnswerValidatedDpopProofsWithoutClaimsAsync().ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);

        DpopCodeBindingWire.AssertCarriesJsonErrorBody(body);
        DpopCodeBindingWire.AssertError(statusCode, body, 500, "server_error", "The DPoP proof validator answered no claims for a valid proof.");
        Assert.DoesNotContain("\"access_token\":", body, StringComparison.Ordinal, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate a DPoP
    /// proof, the receiving server MUST ensure the following: 1. There is not more than one DPoP HTTP request header
    /// field." A redemption sent to the token endpoint over a raw TLS connection with two <c>DPoP</c> field lines, each a
    /// valid proof carrying the supplied nonce, is refused 400 <c>invalid_dpop_proof</c> "More than one DPoP header field
    /// was presented." before any code is looked up; the same redemption with one proof carrying no nonce is answered 400
    /// <c>use_dpop_nonce</c> "DPoP nonce required.", the field read as the one proof it is.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CodeRedemptionRefusesTwoDpopFieldsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, now, TestContext.CancellationToken).ConfigureAwait(false);
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        byte[] redemption = RawHttpsRequest.FormBody(RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, "never-issued-authorization-code", "never-issued-code-verifier-of-forty-three-or-more", RedirectUri.OriginalString));

        string firstProof = await DpopCodeBindingWire.BuildTokenProofAsync(
            host, segment, key.Key, nonce, now, TestContext.CancellationToken).ConfigureAwait(false);
        string secondProof = await DpopCodeBindingWire.BuildTokenProofAsync(
            host, segment, key.Key, nonce, now, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData twoFields = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, tokenUri,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.FormUrlEncoded),
                new(WellKnownHttpHeaderNames.DPoP, firstProof),
                new(WellKnownHttpHeaderNames.DPoP, secondProof)
            ],
            redemption, TestContext.CancellationToken).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(twoFields.StatusCode, twoFields.Body, 400, "invalid_dpop_proof", "More than one DPoP header field was presented.");

        string nonceLessProof = await DpopCodeBindingWire.BuildTokenProofAsync(
            host, segment, key.Key, nonce: null, now, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData oneField = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, tokenUri,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.FormUrlEncoded),
                new(WellKnownHttpHeaderNames.DPoP, nonceLessProof)
            ],
            redemption, TestContext.CancellationToken).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(oneField.StatusCode, oneField.Body, 400, "use_dpop_nonce", "DPoP nonce required.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate a DPoP
    /// proof, the receiving server MUST ensure the following: ... 5. The alg JOSE Header Parameter indicates a registered
    /// asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is supported by the application, and is
    /// acceptable per local policy." A host whose supported DPoP proof algorithms are <c>ES384</c> alone refuses the
    /// redemption of a code bound to no DPoP key carrying a valid ES256 proof with the supplied nonce, 400
    /// <c>invalid_dpop_proof</c> "DPoP proof validation failed: InvalidAlg."; once the host's list names <c>ES256</c> as
    /// well, the same code redeemed with a fresh ES256 proof by that DPoP key is answered 200 with <c>token_type</c>
    /// <c>DPoP</c> and the access token's <c>cnf.jkt</c> the JWK SHA-256 Thumbprint of that DPoP key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CodeRedemptionRefusesAProofOutsideTheAcceptedAlgorithmsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, dpopJkt: string.Empty).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        await host.AcceptDpopProofsUnderAsync([WellKnownJwaValues.Es384]).ConfigureAwait(false);
        (int refusedStatusCode, string refusedBody) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(refusedStatusCode, refusedBody, 400, "invalid_dpop_proof", "DPoP proof validation failed: InvalidAlg.");

        await host.AcceptDpopProofsUnderAsync([WellKnownJwaValues.Es384, WellKnownJwaValues.Es256]).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);

        DpopCodeBindingWire.AssertIssued(statusCode, body, "DPoP", key.Key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>: "To validate a DPoP
    /// proof, the receiving server MUST ensure the following: ... 5. The alg JOSE Header Parameter indicates a registered
    /// asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is supported by the application, and is
    /// acceptable per local policy." A server whose policy names no list of algorithms cannot ensure the proof's
    /// <c>alg</c> is acceptable per that policy: the redemption of a code bound to no DPoP key carrying a valid ES256
    /// proof with the supplied nonce, at a host whose signing-algorithm resolver answers no list for DPoP proofs, is
    /// answered 500 <c>server_error</c> "The signing-algorithm resolver answered no list for DPoP proofs." and no access
    /// token is issued; once the host's resolver answers the default list
    /// <see cref="WellKnownDpopValues.SupportedSigningAlgorithms"/>, the same code redeemed with a fresh ES256 proof by
    /// that DPoP key is answered 200 with <c>token_type</c> <c>DPoP</c> and the access token's <c>cnf.jkt</c> the JWK
    /// SHA-256 Thumbprint of that DPoP key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CodeRedemptionProofWhoseAlgorithmResolverAnswersNoListIsAServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, dpopJkt: string.Empty).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        await host.AnswerNoDpopProofAlgorithmListAsync().ConfigureAwait(false);
        (int refusedStatusCode, string refusedBody) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(refusedStatusCode, refusedBody, 500, "server_error", "The signing-algorithm resolver answered no list for DPoP proofs.");
        Assert.DoesNotContain("\"access_token\":", refusedBody, StringComparison.Ordinal, refusedBody);

        await host.AcceptDpopProofsUnderAsync(WellKnownDpopValues.SupportedSigningAlgorithms).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key.Key, nonce).ConfigureAwait(false);

        DpopCodeBindingWire.AssertIssued(statusCode, body, "DPoP", key.Key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 9: "The htu claim
    /// matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment
    /// parts.", with <see href="https://www.rfc-editor.org/rfc/rfc9110#section-7.1">RFC 9110 Section 7.1</see>: "Upon
    /// receipt of a client's request, a server reconstructs the target URI from the received components in accordance
    /// with their local configuration and incoming connection context." A host whose configuration names its listener's
    /// authority <c>https://as-alias.test</c>, unlike its issuer's, judges a code redemption's proof against that
    /// authority: the redemption of a code bound to no DPoP key carrying a proof with the supplied nonce whose
    /// <c>htu</c> is the token endpoint's path at the listener's authority is answered 200 with <c>token_type</c>
    /// <c>DPoP</c> and the access token's <c>cnf.jkt</c> the JWK SHA-256 Thumbprint of the proof's DPoP key, and one
    /// whose <c>htu</c> is the token endpoint at the issuer's authority is refused 400 <c>invalid_dpop_proof</c> "DPoP
    /// proof validation failed: HtuMismatch.".
    /// </summary>
    /// <param name="isHtuAtTheListenerAuthority">Whether the proof's <c>htu</c> names the listener's authority rather than the issuer's.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(true, DisplayName = "htu at the listener authority")]
    [DataRow(false, DisplayName = "htu at the issuer authority")]
    public async Task CodeRedemptionHoldsHtuToTheListenerAuthorityAsync(bool isHtuAtTheListenerAuthority)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        await host.VerifyDpopProofsWithAsync(MicrosoftCryptographicFunctionsAdapter.VerifyP256Async).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, dpopJkt: string.Empty).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        host.Host("default").TrustedListenerAuthority = ListenerAliasAuthority;
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        string htu = isHtuAtTheListenerAuthority switch
        {
            true => new Uri(ListenerAliasAuthority, tokenUri.AbsolutePath).OriginalString,
            false => tokenUri.OriginalString
        };
        string proof = await ResourceDpopProofs.BuildAsync(
            key.Key, WellKnownHttpMethods.Post, htu, accessToken: null, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken).ConfigureAwait(false);
        (int statusCode, string body) = await RawAuthCodeWirePushers.RedeemCodeAsync(
            host, segment, ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString, proof,
            TestContext.CancellationToken).ConfigureAwait(false);

        if(isHtuAtTheListenerAuthority)
        {
            DpopCodeBindingWire.AssertIssued(statusCode, body, "DPoP", key.Key.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool));

            return;
        }

        DpopCodeBindingWire.AssertError(statusCode, body, 400, "invalid_dpop_proof", "DPoP proof validation failed: HtuMismatch.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "the authorization
    /// server MUST check the provided DPoP proof JWT as defined in Section 4.3", whose first check
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>) is "1. There is not more than
    /// one DPoP HTTP request header field." A pushed authorization request sent over a raw TLS connection with two
    /// <c>DPoP</c> field lines, each a valid proof for it carrying the supplied nonce, is refused 400
    /// <c>invalid_dpop_proof</c> "More than one DPoP header field was presented." and no <c>request_uri</c> is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PushedRequestRefusesTwoDpopFieldsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, now, TestContext.CancellationToken).ConfigureAwait(false);

        string firstProof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key.Key, nonce, now, TestContext.CancellationToken).ConfigureAwait(false);
        string secondProof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key.Key, nonce, now, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, RawAuthCodeWirePushers.ResolveParEndpointUri(host, segment),
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.FormUrlEncoded),
                new(WellKnownHttpHeaderNames.DPoP, firstProof),
                new(WellKnownHttpHeaderNames.DPoP, secondProof)
            ],
            RawHttpsRequest.FormBody(BuildAuthorizationRequestFields(pkce)), TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, "invalid_dpop_proof", "More than one DPoP header field was presented.");
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "the authorization
    /// server MUST check the provided DPoP proof JWT as defined in Section 4.3", whose fifth check
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>) is "5. The alg JOSE Header
    /// Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is supported
    /// by the application, and is acceptable per local policy." A host whose supported DPoP proof algorithms are
    /// <c>ES384</c> alone refuses a pushed authorization request carrying a valid ES256 proof with the supplied nonce, 400
    /// <c>invalid_dpop_proof</c> "DPoP proof validation failed: InvalidAlg.", and no <c>request_uri</c> is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PushedRequestRefusesAProofOutsideTheAcceptedAlgorithmsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        DateTimeOffset now = TimeProvider.GetUtcNow();
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, key.Key, now, TestContext.CancellationToken).ConfigureAwait(false);
        await host.AcceptDpopProofsUnderAsync([WellKnownJwaValues.Es384]).ConfigureAwait(false);

        string proof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key.Key, nonce, now, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData response = await DpopCodeBindingWire.PushAsync(
            host, segment, BuildAuthorizationRequestFields(pkce), proof, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, "invalid_dpop_proof", "DPoP proof validation failed: InvalidAlg.");
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "If both
    /// mechanisms are used at the same time, the authorization server MUST reject the request if the JWK Thumbprint in
    /// dpop_jkt does not match the public key in the DPoP header." A pushed request whose <c>dpop_jkt</c> is the
    /// thumbprint of one DPoP key and whose valid proof, carrying the supplied nonce, is by another DPoP key is refused
    /// with the token endpoint's error format (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126
    /// Section 2.3</see>) as a malformed request,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "invalid_request ...
    /// or is otherwise malformed", and no <c>request_uri</c> is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PushedDpopJktBesideAProofUnderAnotherKeyIsAnInvalidRequestAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, other.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, boundThumbprint));
        string otherProof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, other.Key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData response = await DpopCodeBindingWire.PushAsync(
            host, segment, fields, otherProof, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, "invalid_request", "dpop_jkt does not match the DPoP proof's public key.");
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "Both mechanisms
    /// MUST be supported by an authorization server that supports PAR and DPoP." A pushed request whose
    /// <c>dpop_jkt</c> is the thumbprint of the DPoP key that also signs its valid proof is answered 201; its code is
    /// refused 400 <c>invalid_grant</c> under a proof by another DPoP key and redeemed under a proof by that DPoP key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PushedDpopJktBesideAProofUnderTheSameKeyBindsTheCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, boundThumbprint));
        string boundProof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, bound.Key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(
            host, segment, fields, boundProof, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);
        string code = await AuthorizePushedAsync(host, segment, pushed.Body, []).ConfigureAwait(false);

        (int otherStatusCode, string otherBody) = await RedeemAsync(host, segment, code, pkce, other.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(otherStatusCode, otherBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "Request and response
    /// parameters MUST NOT be included more than once." A pushed request carrying <c>dpop_jkt</c> twice, whether as two
    /// thumbprints or as two empty values, is refused with the token endpoint's error format
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126 Section 2.3</see>) as
    /// <c>invalid_request</c>, and no <c>request_uri</c> is issued.
    /// </summary>
    /// <param name="areBothEmpty">Whether the two occurrences are empty values rather than two thumbprints.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(false, DisplayName = "two thumbprints")]
    [DataRow(true, DisplayName = "two empty values")]
    public async Task RepeatedDpopJktAtThePushedRequestIsAnInvalidRequestAsync(bool areBothEmpty)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string first = areBothEmpty switch
        {
            true => string.Empty,
            false => await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false)
        };
        string second = areBothEmpty switch
        {
            true => string.Empty,
            false => await ResourceDpopProofs.ComputeJwkThumbprintAsync(other.Key, TestContext.CancellationToken).ConfigureAwait(false)
        };

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, first));
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, second));
        HttpResponseData response = await DpopCodeBindingWire.PushAsync(
            host, segment, fields, dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, "invalid_request", "dpop_jkt must not be repeated.");
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: the value of
    /// <c>dpop_jkt</c> "is the JWK Thumbprint [RFC7638] of the proof-of-possession public key using the SHA-256 hash
    /// function, which is the same value as used for the jkt confirmation method defined in Section 6.1", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">Section 6.1</see>: "The value of the jkt member
    /// MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint", 32 octets written as 43
    /// base64url characters whose last character carries no set pad bit
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>: "Base64 encoding using
    /// the URL- and filename-safe character set defined in Section 5 of RFC 4648 [RFC4648], with all trailing '='
    /// characters omitted"). A pushed request whose <c>dpop_jkt</c> has another spelling is refused as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>
    /// <c>invalid_request</c> ("includes an unsupported parameter value"), and no <c>request_uri</c> is issued.
    /// </summary>
    /// <param name="dpopJkt">The <c>dpop_jkt</c> value sent.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DisplayName = "42 characters")]
    [DataRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DisplayName = "44 characters")]
    [DataRow("+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DisplayName = "43 characters holding +")]
    [DataRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", DisplayName = "43 characters whose last character sets a pad bit")]
    [DataRow("/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DisplayName = "43 characters holding /")]
    [DataRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", DisplayName = "44 characters ending =")]
    public async Task DpopJktThatIsNoThumbprintAtThePushedRequestIsAnInvalidRequestAsync(string dpopJkt)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, dpopJkt));
        HttpResponseData response = await DpopCodeBindingWire.PushAsync(
            host, segment, fields, dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, "invalid_request", "dpop_jkt is not a JWK SHA-256 Thumbprint.");
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "Use of the dpop_jkt
    /// authorization request parameter is OPTIONAL." A pushed request carrying <c>dpop_jkt</c> once with an empty value
    /// is answered 201, and its code redeemed with no <c>DPoP</c> field issues a Bearer access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task EmptyDpopJktAtThePushedRequestIsReadAsOmittedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        string code = await PushAndAuthorizeAsync(host, segment, pkce, dpopJkt: string.Empty).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);

        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "When a token request
    /// is received, the authorization server computes the JWK Thumbprint of the proof-of-possession public key in the
    /// DPoP proof and verifies that it matches the dpop_jkt parameter value in the authorization request. If they do not
    /// match, it MUST reject the request." (the authorization request of Figure 25, sent directly). A direct
    /// authorization request carrying the thumbprint of a DPoP key is answered with a code; that code is refused 400
    /// <c>invalid_grant</c> under a proof by another DPoP key and with no proof, and redeemed under a proof by the bound
    /// DPoP key.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DirectAuthorizationDpopJktBindsTheCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, boundThumbprint));
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment, fields), TestSubject,
            TestContext.CancellationToken).ConfigureAwait(false);
        string code = DpopCodeBindingWire.ReadCode((int)authorizeResponse.StatusCode, authorizeResponse.Headers.Location);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        (int otherStatusCode, string otherBody) = await RedeemAsync(host, segment, code, pkce, other.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(otherStatusCode, otherBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int noProofStatusCode, string noProofBody) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(noProofStatusCode, noProofBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 Section 4.1.2.1</see>: "If the
    /// request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing
    /// or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically
    /// redirect the user-agent to the invalid redirection URI. If the resource owner denies the access request or if
    /// the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs
    /// the client by adding the following parameters to the query component of the redirection URI", with
    /// <c>invalid_request</c>: "The request is missing a required parameter, includes an invalid parameter value,
    /// includes a parameter more than once, or is otherwise malformed." A direct authorization request at the
    /// registered redirect URI whose <c>dpop_jkt</c> is repeated or is no thumbprint is answered by a redirect carrying
    /// <c>invalid_request</c>, the description and the request's <c>state</c>, and no code; at an unregistered redirect
    /// URI the request is refused in place.
    /// </summary>
    /// <param name="defect">The <c>dpop_jkt</c> defect: <c>repeated</c> or <c>malformed</c>.</param>
    /// <param name="isRedirectUriRegistered">Whether the request's redirect URI is the registered one.</param>
    /// <param name="expectedDescription">The <c>error_description</c> of the redirect, or of the refusal in place.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("repeated", true, "dpop_jkt must not be repeated.", DisplayName = "repeated at the registered redirect URI")]
    [DataRow("malformed", true, "dpop_jkt is not a JWK SHA-256 Thumbprint.", DisplayName = "42 characters at the registered redirect URI")]
    [DataRow("repeated", false, "redirect_uri 'https://client.example.com/unregistered' is not among the registered redirect URIs.",
        DisplayName = "repeated at an unregistered redirect URI")]
    public async Task DirectAuthorizationWithARepeatedOrMalformedDpopJktIsAnsweredInvalidRequestAsync(
        string defect, bool isRedirectUriRegistered, string expectedDescription)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        if(!isRedirectUriRegistered)
        {
            int redirectUriIndex = fields.FindIndex(static field => field.Key == OAuthRequestParameterNames.RedirectUri);
            fields[redirectUriIndex] = new(OAuthRequestParameterNames.RedirectUri, "https://client.example.com/unregistered");
        }

        IReadOnlyList<string> dpopJktValues = defect switch
        {
            "repeated" =>
            [
                await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false),
                await ResourceDpopProofs.ComputeJwkThumbprintAsync(other.Key, TestContext.CancellationToken).ConfigureAwait(false)
            ],
            "malformed" => ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            _ => throw new ArgumentOutOfRangeException(nameof(defect), defect, "No such defect.")
        };
        foreach(string value in dpopJktValues)
        {
            fields.Add(new(OAuthRequestParameterNames.DpopJkt, value));
        }

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment, fields), TestSubject,
            TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        if(!isRedirectUriRegistered)
        {
            DpopCodeBindingWire.AssertError((int)response.StatusCode, body, 400, "invalid_request", expectedDescription);
            Assert.IsNull(response.Headers.Location, "An unregistered redirect URI is never redirected to.");

            return;
        }

        Assert.AreEqual(302, (int)response.StatusCode, body);
        string location = response.Headers.Location!.ToString();
        Assert.StartsWith(RedirectUri.OriginalString, location, StringComparison.Ordinal, location);
        Assert.AreEqual("invalid_request", TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Error), location);
        Assert.AreEqual(expectedDescription, TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.ErrorDescription), location);
        Assert.AreEqual(CodeBindingState, TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.State), location);
        Assert.IsNull(TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code), location);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-4">RFC 9126 Section 4</see> applies to a pushed
    /// request: "The authorization server MUST only use the parameters in the Request Object, even if the same
    /// parameter is provided in the query parameter." A code pushed with the thumbprint of one DPoP key and completed at
    /// the authorization endpoint with a <c>dpop_jkt</c> naming another DPoP key beside the <c>request_uri</c> stays
    /// bound to the pushed thumbprint: it is refused 400 <c>invalid_grant</c> under a proof by the other DPoP key and
    /// redeemed under a proof by the pushed one.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task FrontChannelDpopJktBesideRequestUriDoesNotRebindTheCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        string otherThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(other.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, boundThumbprint));
        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(
            host, segment, fields, dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);
        string code = await AuthorizePushedAsync(
            host, segment, pushed.Body, [new(OAuthRequestParameterNames.DpopJkt, otherThumbprint)]).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        (int otherStatusCode, string otherBody) = await RedeemAsync(host, segment, code, pkce, other.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(otherStatusCode, otherBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "The authorization
    /// server MUST ignore unrecognized request parameters." An authorization server that verifies no DPoP proof
    /// recognizes neither <c>dpop_jkt</c> nor the <c>DPoP</c> field: a pushed request carrying both is answered 201,
    /// and its code redeemed with no <c>DPoP</c> field issues a Bearer access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ServerVerifyingNoDpopProofIgnoresDpopJktAndTheDpopFieldAtThePushedRequestAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: false).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey key = new();
        string thumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(key.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, thumbprint));
        string proof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key.Key, nonce: null, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(
            host, segment, fields, proof, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);
        string code = await AuthorizePushedAsync(host, segment, pushed.Body, []).ConfigureAwait(false);

        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);

        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "The authorization
    /// server MUST ignore unrecognized request parameters." An authorization server that verifies no DPoP proof
    /// recognizes no <c>dpop_jkt</c>: a direct authorization request at the registered redirect URI carrying a
    /// <c>dpop_jkt</c> of 42 characters, which is no JWK SHA-256 Thumbprint, is answered by a redirect carrying a code
    /// and no <c>error</c>, and the code redeemed with no <c>DPoP</c> field issues a Bearer access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DirectAuthorizationIgnoresDpopJktWhereTheServerVerifiesNoDpopProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: false).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment, fields), TestSubject,
            TestContext.CancellationToken).ConfigureAwait(false);
        string code = DpopCodeBindingWire.ReadCode((int)authorizeResponse.StatusCode, authorizeResponse.Headers.Location);
        string location = authorizeResponse.Headers.Location!.ToString();
        Assert.IsNull(TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Error), location);

        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 Section 2.1</see>: "The authorization
    /// server MUST process the request as follows: 1. Authenticate the client in the same way as at the token endpoint
    /// ... 3. Validate the pushed request as it would an authorization request sent to the authorization endpoint." A
    /// pushed request of a <c>client_secret_basic</c> client carrying a <c>dpop_jkt</c> that is no thumbprint and no
    /// client credentials is refused for its authentication, 401 <c>invalid_client</c> "Client authentication failed." with the
    /// one challenge <c>Basic realm="&lt;issuer&gt;"</c> naming the issuer the client is registered under, never
    /// answered for its authorization request parameters.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task PushedRequestOfAnUnauthenticatedConfidentialClientIsRefusedForItsAuthenticationFirstAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        ClientRecord registration = await host.SetTokenEndpointAuthMethodAsync(
            material, ClientAuthenticationMethod.ClientSecretBasic, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretBasic];
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(false);
        }).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        HttpResponseData response = await DpopCodeBindingWire.PushAsync(
            host, segment, fields, dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 401, "invalid_client", "Client authentication failed.");
        Assert.AreEqual($"Basic realm=\"{registration.IssuerUri!.OriginalString}\"",
            response.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate), response.Body);
    }


    /// <summary>
    /// The <c>state</c> every authorization request of the code binding rows carries, so a row asserts that an error
    /// redirect echoes it.
    /// </summary>
    private static string CodeBindingState { get; } = "state-code-binding";


    /// <summary>The listener authority a row configures on the host, unlike the issuer's loopback authority.</summary>
    private static Uri ListenerAliasAuthority { get; } = new("https://as-alias.test");


    /// <summary>
    /// The capabilities of the code binding rows' registration: the authorization code grant, pushed and direct
    /// authorization requests, and OpenID Connect for the <c>openid</c> scope the requests carry.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> CodeBindingCapabilities { get; } = ImmutableHashSet.Create(
        WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
        WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
        WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
        WellKnownCapabilityIdentifiers.OidcOpenIdConnect);


    /// <summary>
    /// Registers the code binding rows' public client under a profile that does not itself require DPoP
    /// (<see cref="PolicyProfile.Rfc6749WithPkce"/>), so a code's own binding is what a redemption is held to; wires
    /// the authorization server's DPoP verification when <paramref name="isDpopWired"/>; starts the listener; and aligns
    /// the registration's issuer to the listener's authority, the authority a proof's <c>htu</c> is judged against.
    /// </summary>
    /// <param name="host">The fixture the client is registered on.</param>
    /// <param name="isDpopWired">Whether the authorization server verifies DPoP proofs.</param>
    /// <returns>The registration's key material.</returns>
    private async Task<VerifierKeyMaterial> RegisterCodeBindingClientAsync(TestHostShell host, bool isDpopWired)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CodeBindingCapabilities).ConfigureAwait(false);
        if(isDpopWired)
        {
            _ = await host.EnableDpopAsync().ConfigureAwait(false);
        }

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        _ = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        return material;
    }


    /// <summary>
    /// The fields of an authorization request for the code binding rows, pushed or sent directly: the code response
    /// type, the client, <paramref name="pkce"/>'s S256 challenge, the registered redirect URI, the <c>openid</c>
    /// scope, <see cref="CodeBindingState"/> and a nonce.
    /// </summary>
    /// <param name="pkce">The PKCE pair whose challenge the request carries.</param>
    /// <returns>The fields, ready for a row to add its <c>dpop_jkt</c> occurrences.</returns>
    private static List<KeyValuePair<string, string>> BuildAuthorizationRequestFields(PkceParameters pkce) =>
    [
        new(OAuthRequestParameterNames.ResponseType, WellKnownResponseTypes.Code),
        new(OAuthRequestParameterNames.ClientId, ClientId),
        new(OAuthRequestParameterNames.CodeChallenge, pkce.EncodedChallenge),
        new(OAuthRequestParameterNames.CodeChallengeMethod, WellKnownCodeChallengeMethods.S256),
        new(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString),
        new(OAuthRequestParameterNames.Scope, WellKnownScopes.OpenId),
        new(OAuthRequestParameterNames.State, CodeBindingState),
        new(WellKnownJwtClaimNames.Nonce, "nonce-code-binding")
    ];


    /// <summary>
    /// Pushes an authorization request carrying <paramref name="dpopJkt"/> once and no <c>DPoP</c> field, asserts the
    /// 201, and completes it at the authorization endpoint.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="pkce">The PKCE pair whose challenge the request carries.</param>
    /// <param name="dpopJkt">The <c>dpop_jkt</c> value sent.</param>
    /// <returns>The authorization code.</returns>
    private async Task<string> PushAndAuthorizeAsync(TestHostShell host, string segment, PkceParameters pkce, string dpopJkt)
    {
        List<KeyValuePair<string, string>> fields = BuildAuthorizationRequestFields(pkce);
        fields.Add(new(OAuthRequestParameterNames.DpopJkt, dpopJkt));
        (int parStatusCode, string parBody, Uri? location, int authorizeStatusCode) = await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
            host, segment, ClientId, TestSubject, fields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);

        return DpopCodeBindingWire.ReadCode(authorizeStatusCode, location);
    }


    /// <summary>Completes a pushed request at the authorization endpoint, carrying <paramref name="extraQuery"/> beside its <c>request_uri</c>.</summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="parBody">The 201 body of the pushed request.</param>
    /// <param name="extraQuery">Further query parameters of the authorize GET.</param>
    /// <returns>The authorization code.</returns>
    private async Task<string> AuthorizePushedAsync(
        TestHostShell host, string segment, string parBody, IReadOnlyCollection<KeyValuePair<string, string>> extraQuery)
    {
        (Uri? location, int statusCode) = await RawAuthCodeWirePushers.AuthorizePushedRequestAsync(
            host, segment, ClientId, TestSubject, parBody, extraQuery, TestContext.CancellationToken).ConfigureAwait(false);

        return DpopCodeBindingWire.ReadCode(statusCode, location);
    }


    /// <summary>
    /// Redeems <paramref name="code"/> with <paramref name="pkce"/>'s verifier, carrying a fresh proof by
    /// <paramref name="key"/> with <paramref name="nonce"/>, or no <c>DPoP</c> field when <paramref name="key"/> is
    /// <see langword="null"/>.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="code">The authorization code.</param>
    /// <param name="pkce">The PKCE pair whose verifier the redemption carries.</param>
    /// <param name="key">The DPoP key that signs the proof, or <see langword="null"/> for no proof.</param>
    /// <param name="nonce">The proof's <c>nonce</c>.</param>
    /// <returns>The response's status code and body.</returns>
    private async Task<(int StatusCode, string Body)> RedeemAsync(
        TestHostShell host, string segment, string code, PkceParameters pkce, DpopKey? key, string? nonce)
    {
        string? proof = key switch
        {
            null => null,
            _ => await DpopCodeBindingWire.BuildTokenProofAsync(
                host, segment, key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false)
        };

        return await RawAuthCodeWirePushers.RedeemCodeAsync(
            host, segment, ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString, proof,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a proof for the pushed request whose signature was made over other bytes: the protected header and the
    /// signature of one valid proof joined around the payload of a second valid proof by the same DPoP key, so every
    /// claim checks out and only the signature fails.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="key">The DPoP key that signs both proofs.</param>
    /// <param name="nonce">The supplied nonce both proofs carry.</param>
    /// <param name="issuedAt">The <c>iat</c> both proofs carry.</param>
    /// <returns>The compact proof whose signature does not cover its payload.</returns>
    private async Task<string> BuildProofSignedOverOtherBytesAsync(
        TestHostShell host, string segment, DpopKey key, string nonce, DateTimeOffset issuedAt)
    {
        string signed = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key, nonce, issuedAt, TestContext.CancellationToken).ConfigureAwait(false);
        string other = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, key, nonce, issuedAt, TestContext.CancellationToken).ConfigureAwait(false);
        string[] signedSegments = signed.Split('.');
        string[] otherSegments = other.Split('.');

        return $"{signedSegments[0]}.{otherSegments[1]}.{signedSegments[2]}";
    }


    /// <summary>
    /// Rewires the host's replay store so it saves normally but never resolves anything under
    /// <c>FlowKind.JtiReplay</c>, while every other correlation kind still resolves through the host's
    /// real resolver. This is the half-wired store the guard's post-save self-check must catch.
    /// </summary>
    /// <param name="server">The hosted server whose OAuth integration resolver is wrapped.</param>
    private static async Task HalfWireJtiReplayStoreAsync(EndpointServer server)
    {
        ResolveCorrelationKeyDelegate original = server.OAuth().ResolveCorrelationKeyAsync!;
        await TestHostShell.AlterAsync(server, candidateIntegration =>
        {
            candidateIntegration.ResolveCorrelationKeyAsync = (tenantId, flowKind, externalHandle, ctx, ct) =>
                flowKind == FlowKind.JtiReplay
                    ? ValueTask.FromResult<string?>(null)
                    : original(tenantId, flowKind, externalHandle, ctx, ct);
        }).ConfigureAwait(false);
    }


    private static (string Code, string? Iss) ParseAuthorizeRedirect(string location)
    {
        //The redirect Location is `<redirectUri>?code=<hash>[&iss=<issuer>]`.
        //Uri.Query parses the query string; a relative URI keeps the test
        //independent of the redirect-uri origin.
        int queryStart = location.IndexOf('?', StringComparison.Ordinal);
        Assert.IsGreaterThan(0, queryStart, $"Authorize redirect must have a query string. Got: {location}");

        Dictionary<string, string> parsed = new(StringComparer.Ordinal);
        foreach(string pair in location[(queryStart + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq <= 0)
            {
                continue;
            }
            parsed[pair[..eq]] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }

        Assert.IsTrue(parsed.TryGetValue(OAuthRequestParameterNames.Code, out string? code),
            $"Authorize redirect must carry code. Got: {location}");

        _ = parsed.TryGetValue(OAuthRequestParameterNames.Iss, out string? iss);

        return (code, iss);
    }
}
