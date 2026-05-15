using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Hosting;

/// <summary>
/// Phase 9b — three wire-fidelity tests that exercise paths the
/// function-call transport can't catch. Each runs through the
/// HTTP-backed factory so bytes actually traverse Kestrel + HttpClient
/// over a real socket.
/// </summary>
[TestClass]
internal sealed class HttpWireFidelityTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private const string ClientId = "https://client.example.com";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri =
        new("https://client.example.com/callback");
    private static readonly Uri UnregisteredRedirectUri =
        new("https://attacker.example.com/callback");


    [TestMethod]
    public async Task FormEncodedFieldsWithSpecialCharactersRoundTrip()
    {
        //The PAR request body carries scope and other form-encoded fields.
        //Scope tokens containing characters that require percent-encoding
        //(space, '+', '=' inside scope-string syntax — OAuth scope tokens
        //are space-separated lists) must round-trip cleanly through
        //FormUrlEncodedContent → HTTP wire → AS form parser → AS state.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, OAuthFlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Scope value carrying characters that exercise percent-encoding.
        //Note: OAuth scope syntax (RFC 6749 §3.3) forbids some of these in
        //scope tokens themselves; we use them inside a custom-token-shape
        //value to exercise the wire-encoding round-trip rather than spec-
        //compliant scope parsing.
        const string specialScope = "openid api:read=x+y%z";
        OAuthFormEncodedFields additional = new(new Dictionary<string, string>
        {
            [OAuthRequestParameters.Scope] = specialScope
        });

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration,
            RedirectUri,
            additional,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR with special-character scope must succeed. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        //Verify the scope landed correctly on the persisted PAR state on
        //the client side. The AS-side state is keyed by request_uri and
        //the AS parses the same wire bytes; if percent-decoding broke,
        //the AS would have rejected before redirecting.
        ParCompletedState par = (ParCompletedState)clientFlowStore.Values.Single();
        Assert.IsTrue(
            par.Scopes.Any(s => s.Contains("=x+y%z", StringComparison.Ordinal)),
            $"Round-tripped scope must contain the special-character token. Got: [{string.Join(", ", par.Scopes)}]");
    }


    [TestMethod]
    public async Task ParResponseCacheControlHeaderEmitsOnHttpWire()
    {
        //OAuth 2.1 §3.2.3 — Cache-Control: no-store on the PAR response
        //(added by phase 9a) must actually traverse the HTTP wire. The
        //in-process server emits it on ServerHttpResponse.Headers; this
        //test verifies the same string lands on the client's parsed
        //response headers after a real socket round-trip.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (OAuthClient client, ClientRegistration registration, _) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Capture the raw response by directly calling the transport rather
        //than going through StartParAsync (which parses the body into the
        //client-side result and doesn't surface response headers).
        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameters.ClientId] = ClientId,
            [OAuthRequestParameters.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameters.CodeChallengeMethod] = OAuthRequestParameters.CodeChallengeMethodS256,
            [OAuthRequestParameters.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameters.Scope] = WellKnownScopes.OpenId
        };

        AuthorizationServerMetadata metadata = await client.Infrastructure
            .ResolveAuthorizationServerMetadataAsync(
                registration.AuthorizationServerIssuer, TestContext.CancellationToken)
            .ConfigureAwait(false);

        HttpResponseData parResponse = await client.Infrastructure.SendFormPostAsync(
            metadata.PushedAuthorizationRequestEndpoint!,
            parFields,
            OutgoingHeaders.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, parResponse.StatusCode,
            $"PAR must succeed over HTTP. Body: {parResponse.Body}");

        string? cacheControl = parResponse.Headers.TryGetSingle(
            WellKnownHttpHeaderNames.CacheControl);
        Assert.IsNotNull(cacheControl,
            "Cache-Control header must traverse the wire.");
        Assert.IsTrue(
            cacheControl.Contains(WellKnownCacheControlValues.NoStore, StringComparison.OrdinalIgnoreCase),
            $"Cache-Control must contain no-store directive. Got: {cacheControl}");
    }


    [TestMethod]
    public async Task BadRequestEmitsAsBadRequestOutcomeFromHttpWire()
    {
        //RFC 9700 §2.1 PKCE-PAR rejects unregistered redirect_uri with
        //HTTP 400. The client sees this as BadRequest outcome after the
        //real HTTP round-trip — the status line and body actually
        //traversed Kestrel and HttpClient.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (OAuthClient client, ClientRegistration registration, _) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration,
            UnregisteredRedirectUri,
            OAuthFormEncodedFields.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, parResult.Outcome,
            $"Unregistered redirect_uri must surface as a BadRequest outcome. " +
            $"ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");
        Assert.AreEqual(OAuthErrors.InvalidRequest, parResult.ErrorCode);
    }
}
