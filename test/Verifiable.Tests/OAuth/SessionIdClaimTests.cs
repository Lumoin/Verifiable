using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OIDC <c>sid</c> (Session ID) claim — end-to-end through PAR → Authorize → Token.
/// The application stamps the session identifier on the authorize-time
/// <see cref="ExchangeContext"/> (<c>SetSessionId</c>), exactly as it stamps
/// <c>SubjectId</c>/<c>AuthTime</c>; the value threads through the flow state into the
/// ID Token's <c>sid</c> claim. Firewalled: the RP reads <c>sid</c> from the issued
/// token's wire bytes. Asserts the claim is present, equals the stamped value, is
/// <em>per authentication session</em> (two logins of the same subject get distinct
/// sids), and is omitted when no session was stamped.
/// </summary>
[TestClass]
internal sealed class SessionIdClaimTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-sid-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");


    /// <summary>The stamped session identifier appears verbatim as the ID Token <c>sid</c>.</summary>
    [TestMethod]
    public async Task SidClaimEmittedFromStampedSession()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId, sessionId: "session-A").ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument payload = ParseIdTokenPayload(tokenResponse);
        Assert.IsTrue(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Sid, out JsonElement sid),
            $"ID Token must carry sid when a session was stamped. Body: {tokenResponse.Body}");
        Assert.AreEqual("session-A", sid.GetString());
    }


    /// <summary>
    /// Two logins of the SAME subject produce DISTINCT sids — proving sid is per
    /// authentication session, not per subject (the property back-channel logout needs).
    /// </summary>
    [TestMethod]
    public async Task SidIsPerSessionNotPerSubject()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse first = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId, sessionId: "session-A").ConfigureAwait(false);
        ServerHttpResponse second = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId, sessionId: "session-B").ConfigureAwait(false);

        using JsonDocument firstPayload = ParseIdTokenPayload(first);
        using JsonDocument secondPayload = ParseIdTokenPayload(second);

        string firstSid = firstPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sid).GetString()!;
        string secondSid = secondPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sid).GetString()!;

        Assert.AreEqual("session-A", firstSid);
        Assert.AreEqual("session-B", secondSid);
        Assert.AreNotEqual(firstSid, secondSid,
            "Two sessions for the same subject must carry distinct sids.");
        Assert.AreEqual(
            SubjectId, secondPayload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
            "Both sessions still resolve to the same subject.");
    }


    /// <summary>No sid is stamped → the ID Token omits the <c>sid</c> claim (backward compatible).</summary>
    [TestMethod]
    public async Task SidClaimOmittedWhenNoSessionStamped()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId, sessionId: null).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument payload = ParseIdTokenPayload(tokenResponse);
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Sid, out _),
            "sid must be omitted when the application stamped no session identifier.");
    }


    /// <summary>Parses the issued ID Token's payload from the token response body.</summary>
    private static JsonDocument ParseIdTokenPayload(ServerHttpResponse tokenResponse)
    {
        using JsonDocument body = JsonDocument.Parse(tokenResponse.Body);
        string idToken = body.RootElement.GetProperty("id_token").GetString()!;

        return JwtPayloadReader.ParsePayloadJson(idToken);
    }


    /// <summary>
    /// Drives PAR → Authorize → Token, stamping <paramref name="sessionId"/> on the
    /// authorize-time context when non-null (mirrors the application's authentication
    /// middleware), and returns the token endpoint response.
    /// </summary>
    private async Task<ServerHttpResponse> DriveCodeExchangeAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope, string? sessionId)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        if(sessionId is not null)
        {
            authorizeContext.SetSessionId(sessionId);
        }

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads a string property from a JSON response body.</summary>
    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()!;
    }


    /// <summary>Extracts the <c>code</c> query parameter from an authorize redirect Location.</summary>
    private static string ExtractCode(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(
                pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter: {location}");
    }
}
