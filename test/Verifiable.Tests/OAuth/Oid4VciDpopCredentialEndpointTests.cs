using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using System.Text;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9449 §7.1 sender constraint at the OID4VCI Credential Endpoint, end to end over real
/// HTTP: a DPoP-bound Access Token (minted by the auth-code + DPoP token flow, carrying
/// <c>cnf.jkt</c>) must be presented under the <c>DPoP</c> scheme with a DPoP proof bound to the
/// same key. The credential endpoint verifies the proof-of-possession the token endpoint
/// established rather than accepting the token as a plain bearer.
/// </summary>
[TestClass]
internal sealed class Oid4VciDpopCredentialEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset NowInstant = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);
    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);

    private const string ClientId = "https://wallet.client.test";
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");
    //RegisterDpopClient registers exactly this callback as the client's redirect URI.
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");
    private const string TestSubject = "subject-1";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string IssuedCredential = "eyJhbGciOiJFUzI1NiJ9.body.sig";

    private static readonly ImmutableHashSet<CapabilityIdentifier> Capabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);


    [TestMethod]
    public async Task DpopBoundTokenWithValidProofIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        string proof = await BuildCredentialProofAsync(ctx, freshKey: null).ConfigureAwait(false);
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
    }


    [TestMethod]
    public async Task DpopBoundTokenWithoutProofChallengesForNonce()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        //DPoP scheme, but no DPoP proof header.
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, dpopProof: null)
            .ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, body);
        Assert.Contains(OAuthErrors.UseDpopNonce, body);
        Assert.IsTrue(response.Headers.Contains(WellKnownHttpHeaderNames.DPoPNonce),
            "A nonce challenge must carry a fresh DPoP-Nonce header.");
    }


    [TestMethod]
    public async Task DpopBoundTokenUnderBearerSchemeIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        string proof = await BuildCredentialProofAsync(ctx, freshKey: null).ConfigureAwait(false);
        //Present the sender-constrained token under the Bearer scheme — a downgrade.
        using HttpResponseMessage response = await PostCredentialAsync(
            ctx, ctx.AccessToken, proof, scheme: WellKnownAuthenticationSchemes.Bearer).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidToken, body);
    }


    [TestMethod]
    public async Task DpopProofWithWrongKeyIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        //A structurally valid proof signed by a DIFFERENT key than the token was bound to.
        var otherKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey otherKey = new(otherKeys, WellKnownJwaValues.Es256);
        string proof = await BuildCredentialProofAsync(ctx, freshKey: otherKey).ConfigureAwait(false);

        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidDpopProof, body);
    }


    [TestMethod]
    public async Task DpopBoundTokenWithUnwiredValidationSeamFailsClosed()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        //Unwire the proof-validation seam AFTER the bound token was minted: a bound token must
        //never silently fall back to bearer, so the credential endpoint fails loud.
        host.Server.OAuth().ValidateDpopProofAsync = null;

        string proof = await BuildCredentialProofAsync(ctx, freshKey: null).ConfigureAwait(false);
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode, body);
        Assert.Contains(OAuthErrors.ServerError, body);
    }


    /// <summary>Carries the live host, fixture, and minted bound token through a credential-request variation.</summary>
    private sealed record BoundTokenContext(
        TestHostShell Host, DpopClientFixture Fixture, string AccessToken, Uri CredentialUrl, HttpClient Http);


    /// <summary>
    /// Registers a DPoP issuer, drives the full PAR → Authorize → callback → token DPoP flow to
    /// mint a <c>cnf.jkt</c>-bound Access Token, and wires the credential issuance seam.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The host's key stores own and dispose the registration's key material; the returned " +
        "VerifierKeyMaterial is a handle to those same instances, released when the host is disposed.")]
    private async Task<BoundTokenContext> AcquireAsync(TestHostShell host)
    {
        VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, Capabilities);
        host.EnableDpop();
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));

        DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;

        //Step 1 — PAR.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect. {parResult.ErrorCode} {parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        //Step 2 — Authorize (user-agent GET replicated in-process with a pre-authenticated subject).
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(TestSubject);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            new RequestFields
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
            },
            authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location!);
        Assert.IsNotNull(iss);

        //Step 3 — callback.
        AuthCodeFlowEndpointResult callbackResult = await fixture.Client.AuthCode.HandleCallbackAsync(
            fixture.Registration,
            new OAuthFormEncodedFields(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = iss!
            }),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. {callbackResult.ErrorCode} {callbackResult.ErrorDescription}");

        //Step 4 — token (DPoP nonce challenge + retry handled by the client).
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token must issue. {tokenResult.ErrorCode} {tokenResult.ErrorDescription}");
        Assert.IsTrue(tokenResult.Body!.TryGetValue(OAuthRequestParameterNames.AccessToken, out object? tokenObj));
        string accessToken = (string)tokenObj!;

        Uri credentialUrl = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciCredential, segment));

        return new BoundTokenContext(host, fixture, accessToken, credentialUrl, host.Host("default").SharedHttpClient!);
    }


    /// <summary>
    /// Builds a fresh DPoP proof for the credential POST: htm=POST, htu=the credential URL,
    /// ath bound to the access token, signed by the token's key (or <paramref name="freshKey"/>
    /// to forge a thumbprint mismatch).
    /// </summary>
    private async Task<string> BuildCredentialProofAsync(BoundTokenContext ctx, DpopKey? freshKey)
    {
        string ath = await DpopProofValidator.ComputeAthAsync(
            ctx.AccessToken, TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool, TestContext.CancellationToken)
            .ConfigureAwait(false);

        DpopProofClaims claims = new()
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = ctx.CredentialUrl.ToString(),
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Ath = ath
        };

        return await DpopProofConstruction.BuildAsync(
            claims, freshKey ?? ctx.Fixture.DpopKey, TestHostShell.Base64UrlEncoder,
            DpopTestSupport.Serializer, MicrosoftCryptographicFunctions.SignP256Async,
            TestHostShell.MemoryPool, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<HttpResponseMessage> PostCredentialAsync(
        BoundTokenContext ctx, string accessToken, string? dpopProof,
        string scheme = "DPoP")
    {
        using StringContent content = new(
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, ctx.CredentialUrl) { Content = content };
        request.Headers.TryAddWithoutValidation(
            WellKnownHttpHeaderNames.Authorization, $"{scheme} {accessToken}");
        if(dpopProof is not null)
        {
            request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, dpopProof);
        }

        return await ctx.Http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static (string Code, string? Iss) ParseAuthorizeRedirect(string location)
    {
        Uri uri = new(location);
        string query = uri.Query.TrimStart('?');
        string? code = null;
        string? iss = null;
        foreach(string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq <= 0)
            {
                continue;
            }

            string key = pair[..eq];
            string value = Uri.UnescapeDataString(pair[(eq + 1)..]);
            if(string.Equals(key, OAuthRequestParameterNames.Code, StringComparison.Ordinal)) { code = value; }
            else if(string.Equals(key, OAuthRequestParameterNames.Iss, StringComparison.Ordinal)) { iss = value; }
        }

        return (code ?? throw new AssertFailedException($"No code in redirect: {location}"), iss);
    }
}
