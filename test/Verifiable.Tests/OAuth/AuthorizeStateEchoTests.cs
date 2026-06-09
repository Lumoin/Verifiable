using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 6749 §4.1.2 / §4.1.2.1 — the authorization endpoint echoes the request's <c>state</c>
/// verbatim on BOTH the success redirect (alongside <c>code</c>) and the error redirect
/// (alongside <c>error</c>), so the client can bind the response to its pending request. The
/// value is URL-encoded; it is omitted entirely when the request carried no <c>state</c>.
/// Driven end-to-end through PAR → Authorize and asserted on the wire (the redirect Location).
/// </summary>
[TestClass]
internal sealed class AuthorizeStateEchoTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-state-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    /// <summary>A state value with characters that MUST be percent-encoded on the wire.</summary>
    private const string StateWithSpecialChars = "csrf token/value&more=raw";


    /// <summary>The success redirect carries <c>state</c> (URL-encoded) next to the code.</summary>
    [TestMethod]
    public async Task SuccessRedirectEchoesStateVerbatim()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, state: StateWithSpecialChars, maxAge: null, staleAuth: false)
            .ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains("code=", authorizeResponse.Location!, StringComparison.Ordinal);
        Assert.Contains(
            $"state={Uri.EscapeDataString(StateWithSpecialChars)}", authorizeResponse.Location!,
            StringComparison.Ordinal,
            $"The success redirect must echo state, URL-encoded. Location: {authorizeResponse.Location}");
    }


    /// <summary>
    /// The error redirect (here an <c>unmet_authentication_requirements</c> from a stale
    /// <c>max_age</c>) carries <c>state</c> so the client can correlate the step-up failure to
    /// its pending request (RFC 6749 §4.1.2.1).
    /// </summary>
    [TestMethod]
    public async Task ErrorRedirectEchoesState()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, state: StateWithSpecialChars, maxAge: "0", staleAuth: true)
            .ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", authorizeResponse.Location!,
            StringComparison.Ordinal);
        Assert.Contains(
            $"state={Uri.EscapeDataString(StateWithSpecialChars)}", authorizeResponse.Location!,
            StringComparison.Ordinal,
            $"The error redirect must echo state. Location: {authorizeResponse.Location}");
    }


    /// <summary>A request that carried no <c>state</c> yields a redirect with no <c>state</c>.</summary>
    [TestMethod]
    public async Task SuccessRedirectOmitsStateWhenRequestHadNone()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, state: null, maxAge: null, staleAuth: false).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains("code=", authorizeResponse.Location!, StringComparison.Ordinal);
        Assert.DoesNotContain("state=", authorizeResponse.Location!, StringComparison.Ordinal,
            "state must be absent from the redirect when the request carried none.");
    }


    /// <summary>
    /// Drives PAR → Authorize, pushing <paramref name="state"/> / <paramref name="maxAge"/> in the
    /// PAR request. When <paramref name="staleAuth"/> is set the authorize-time auth_time is stamped
    /// an hour in the past (to trip a max_age failure); otherwise it is stamped at the request
    /// instant. Returns the authorize endpoint response.
    /// </summary>
    private async Task<ServerHttpResponse> DriveToAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material, string? state, string? maxAge, bool staleAuth)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        if(state is not null)
        {
            parFields[OAuthRequestParameterNames.State] = state;
        }

        if(maxAge is not null)
        {
            parFields[OAuthRequestParameterNames.MaxAge] = maxAge;
        }

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        using JsonDocument parBody = JsonDocument.Parse(parResponse.Body);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        authorizeContext.SetAuthTime(staleAuth
            ? TimeProvider.GetUtcNow() - TimeSpan.FromHours(1)
            : TimeProvider.GetUtcNow());

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
