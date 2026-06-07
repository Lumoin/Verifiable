using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The phase 6 gate test. Exercises the full DPoP-bound AuthCode flow end to
/// end against a real <see cref="AuthorizationServer"/> dispatch chain:
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

    private static readonly DateTimeOffset NowInstant = new(2026, 5, 14, 12, 0, 0, TimeSpan.Zero);
    private const string ClientId = "https://client.example.com";
    private const string TestSubject = "subject-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task TokenIssuanceAndResourceCallValidateUnderDpopProtocol()
    {
        //Phase 9b — proof-point migration to the HTTP-backed factory. Bytes
        //flow through Kestrel ↔ HttpClient over a real socket; the test's
        //wire-level assertions (token_type from response body, cnf.jkt from
        //the JWT) now run against bytes that actually traversed HTTP framing.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri);
        host.EnableDpop();

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration,
            RedirectUri.OriginalString,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Step 1 — PAR. No DPoP at this endpoint per HAIP, just the PKCE-bearing
        //pushed authorization request that returns the request_uri handle.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration,
            RedirectUri,
            OAuthFormEncodedFields.Empty,
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
        ///authorize with the request_uri lifted from the PAR response and a
        //pre-authenticated subject identifier on the context.
        string requestUri = parCompleted.Par.RequestUri.ToString();
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };

        ExchangeContext authorizeContext = new();
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

        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location!);
        Assert.IsNotNull(iss, "HAIP-aligned policy must emit iss on redirect.");

        //Step 3 — Callback. Client-side: validates iss, persists the
        //AuthorizationCodeReceivedState ready for token exchange.
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
        Assert.IsTrue(tokenResult.Body!.TryGetValue(OAuthRequestParameterNames.AccessToken, out object? accessTokenObj));
        string accessToken = (string)accessTokenObj!;
        Assert.IsFalse(string.IsNullOrEmpty(accessToken));

        //Wire-level assertion: the response body's token_type field carries
        //"DPoP" (RFC 9449 §5), not "Bearer", because DPoP enforcement bound
        //the token. Reading from the parsed Body dictionary is equivalent to
        //reading the wire because OAuthResponseParsers passes the JSON
        //field through unchanged.
        Assert.IsTrue(tokenResult.Body.TryGetValue(OAuthRequestParameterNames.TokenType, out object? tokenTypeObj));
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)tokenTypeObj!,
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
        //Under HTTP, the issuer URI is aligned to the Kestrel base address
        //(carrying the tenant segment as the path component); read the
        //live value from the client-side registration that the factory
        //wired with the aligned URI.
        string wireIss = JwtPayloadReader.ReadIssuer(accessToken)
            ?? throw new AssertFailedException("Access-token JWT must carry iss claim.");
        Assert.AreEqual(fixture.Registration.AuthorizationServerIssuer.OriginalString, wireIss,
            "Access-token iss claim must preserve the full issuer URL per RFC 8414 §3.");

        //Step 5 — RS-side validation. The application playing the RS role
        //constructs a fresh proof for a resource call carrying the ath claim
        //bound to the access token and validates it. The validator's
        //JwkThumbprint must match the binding the AS recorded.
        const string resourceUrl = "https://rs.example.com/api/profile";
        string ath = await DpopProofValidator.ComputeAthAsync(
            accessToken,
            TestHostShell.Base64UrlEncoder,
            TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        DpopProofClaims resourceClaims = new()
        {
            Htm = WellKnownHttpMethods.Get,
            Htu = resourceUrl,
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Ath = ath
        };

        string resourceProof = await DpopProofConstruction.BuildAsync(
            resourceClaims,
            fixture.DpopKey,
            TestHostShell.Base64UrlEncoder,
            DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async,
            TestHostShell.MemoryPool,
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
            MicrosoftCryptographicFunctions.VerifyP256Async,
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, OAuthFlowState> clientFlowStore) =
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
        ExchangeContext authorizeContext = new();
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

        parsed.TryGetValue(OAuthRequestParameterNames.Iss, out string? iss);

        return (code!, iss);
    }
}
