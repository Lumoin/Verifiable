using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Real-wire proof of
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OpenID
/// Connect Core 1.0 §12.2</see>'s ID Token <c>iss</c> rule and its OAuth counterpart: a grant is
/// redeemed only under the issuer resolved when it was issued, never under whatever issuer the
/// application's <see cref="Verifiable.Server.ServerIntegration.ResolveIssuerAsync"/> seam answers
/// for a LATER presentation of the same code or refresh token. Every flow state carries
/// <see cref="Verifiable.Server.FlowState.ExpectedIssuer"/>, stamped from the issuer resolved at
/// issuance; these tests change what the seam answers BETWEEN issuance and presentation
/// (<see cref="TestHostShell.AlterAsync"/> on the same live host, the pattern
/// <see cref="DpopBoundRefreshTests"/> already uses) and assert the presentation is refused.
/// </summary>
[TestClass]
internal sealed class IssuerBindingRefreshTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://issuer-binding.client.test";

    private const string SubjectId = "subject-issuer-binding-01";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static Uri ChangedIssuer { get; } = new("https://issuer-changed.example.test");


    /// <summary>
    /// A code grant with <c>openid</c> scope is redeemed under the host's real issuer; the
    /// application's issuer resolver is then changed to answer a DIFFERENT issuer for the same
    /// client; the refresh token is presented. Expected: <c>invalid_grant</c>, no token in the
    /// response, and <see cref="AuthorizationServerIntegration.RevokeIssuedTokenAsync"/> never
    /// called (an INVALID presentation revokes nothing per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16
    /// §7.5.3</see>'s denial-of-service reasoning). With the resolver put back, the SAME refresh
    /// token still rotates normally — the refusal consumed nothing.
    /// </summary>
    [TestMethod]
    public async Task RefreshUnderChangedIssuerIsInvalidGrantAndConsumesNothingAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        bool wasRevocationSeamCalled = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (tokenIdentifier, tokenType, registration, context, ct) =>
            {
                wasRevocationSeamCalled = true;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        ResolveServerIssuerDelegate? originalResolver = host.Server.OAuth().ResolveIssuerAsync;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = (_, _, _) => ValueTask.FromResult<Uri?>(ChangedIssuer);
        }).ConfigureAwait(false);

        (int refusalStatusCode, string refusalBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, refusalStatusCode, refusalBody);
        Assert.Contains(OAuthErrors.InvalidGrant, refusalBody, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuthRequestParameterNames.AccessToken, refusalBody, StringComparison.Ordinal,
            "A refresh redeemed under a changed issuer must mint nothing.");
        Assert.IsFalse(wasRevocationSeamCalled,
            "An INVALID presentation (a changed issuer) must not revoke anything.");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = originalResolver;
        }).ConfigureAwait(false);

        (int rotatedStatusCode, string rotatedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotatedStatusCode,
            $"The refusal under the changed issuer must have consumed nothing — the same refresh token must still rotate once the resolver is restored. Body={rotatedBody}");
    }


    /// <summary>
    /// The application's issuer resolver answers a DIFFERENT issuer between the authorization
    /// response (where <see cref="Verifiable.Server.FlowState.ExpectedIssuer"/> is stamped) and the
    /// FIRST code redemption. Expected: <c>invalid_grant</c>, nothing minted; with the resolver put
    /// back, the SAME code still redeems once — the refused presentation claimed nothing.
    /// </summary>
    [TestMethod]
    public async Task CodeRedemptionUnderChangedIssuerIsInvalidGrantThenRedeemsOnceRestoredAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, string authorizeLocation) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];
        Dictionary<string, string> tokenFields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, codeState.Code, codeState.Pkce.EncodedVerifier, RedirectUri.OriginalString);

        ResolveServerIssuerDelegate? originalResolver = host.Server.OAuth().ResolveIssuerAsync;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = (_, _, _) => ValueTask.FromResult<Uri?>(ChangedIssuer);
        }).ConfigureAwait(false);

        (int refusalStatusCode, string refusalBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, refusalStatusCode, refusalBody);
        Assert.Contains(OAuthErrors.InvalidGrant, refusalBody, StringComparison.Ordinal);
        Assert.DoesNotContain(OAuthRequestParameterNames.AccessToken, refusalBody, StringComparison.Ordinal,
            "A code redeemed under a changed issuer must mint nothing.");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = originalResolver;
        }).ConfigureAwait(false);

        (int redeemedStatusCode, string redeemedBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, redeemedStatusCode,
            $"The refusal under the changed issuer must have claimed nothing — the same code must still redeem once the resolver is restored. Body={redeemedBody}");
    }


    /// <summary>
    /// A rotated-out refresh token is presented (a reuse, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC 9700 §4.14.2</see>)
    /// while the application's issuer resolver answers a DIFFERENT issuer. Expected:
    /// <c>invalid_grant</c>, the revocation seam is NEVER called (a mismatched issuer is an INVALID
    /// presentation, per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16
    /// §7.5.3</see>'s denial-of-service reasoning — revoking on an invalid presentation would let
    /// anyone holding a stale refresh token and no more deny the legitimate holder's grant), and the
    /// grant's newest refresh token still works afterwards once the resolver answers the original
    /// issuer again.
    /// </summary>
    [TestMethod]
    public async Task RotatedOutRefreshTokenReuseUnderChangedIssuerIsInvalidGrantAndConsumesNothingAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        bool wasRevocationSeamCalled = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.RevokeIssuedTokenAsync = (tokenIdentifier, tokenType, registration, context, ct) =>
            {
                wasRevocationSeamCalled = true;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string oldestRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        (int rotationStatusCode, string rotationBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, rotationStatusCode, rotationBody);
        string currentRefreshToken;
        using(JsonDocument rotationDoc = JsonDocument.Parse(rotationBody))
        {
            currentRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
        }

        ResolveServerIssuerDelegate? originalResolver = host.Server.OAuth().ResolveIssuerAsync;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = (_, _, _) => ValueTask.FromResult<Uri?>(ChangedIssuer);
        }).ConfigureAwait(false);

        (int reuseStatusCode, string reuseBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuseStatusCode, reuseBody);
        Assert.Contains(OAuthErrors.InvalidGrant, reuseBody, StringComparison.Ordinal);
        Assert.IsFalse(wasRevocationSeamCalled,
            "An INVALID presentation (a changed issuer) must not revoke anything.");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = originalResolver;
        }).ConfigureAwait(false);

        (int stillWorksStatusCode, string stillWorksBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, stillWorksStatusCode,
            $"The reuse refusal under a changed issuer must have revoked nothing — the grant's newest refresh token must still work under the original issuer. Body={stillWorksBody}");
    }
}
