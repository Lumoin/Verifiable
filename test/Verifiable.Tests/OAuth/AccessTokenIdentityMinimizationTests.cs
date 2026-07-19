using System.Collections.Immutable;
using System.Net.Http;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Wave-4 D7 real-wire capstone for the <c>openid ⇒ end-user</c> data-minimization invariant on
/// the access-token producer (contract §D4 consumer layer, <see cref="Rfc9068AccessTokenProducer"/>):
/// a full PAR → authorize → callback → token authorization-code journey requesting
/// <c>openid profile email address phone</c> must never carry end-user identity claims on the
/// issued access token, even though every identity family is populated and the co-issued id_token
/// legitimately carries them. Composed via the shared <see cref="AuthCodeFlowDriver"/>, the same
/// real-wire drive <see cref="AuthCodeParPkceRealWireFlowTests"/> and the agentic-flow capstone use.
/// </summary>
[TestClass]
internal sealed class AccessTokenIdentityMinimizationTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://minimization.client.test";

    private const string SubjectId = "subject-identity-minimization-01";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>
    /// The scope requested on every leg — every OIDC Core §5.4 standard claim family alongside
    /// <c>openid</c>, so every <see cref="OidcStandardClaimsContributor"/> rule is scope-eligible.
    /// </summary>
    private static string FullIdentityScope { get; } = string.Join(
        ' ', WellKnownScopes.OpenId, WellKnownScopes.Profile, WellKnownScopes.Email,
        WellKnownScopes.Address, WellKnownScopes.Phone);


    /// <summary>
    /// Requests the full identity scope set through a real-wire authorization_code journey, then
    /// decodes the issued access token off the wire (no signature verification — the point is what
    /// the AS emitted, per <see cref="JwtPayloadReader"/>) and asserts every OIDC identity claim is
    /// absent while the RFC 9068 subject/scope/issuer/audience/client claims are present. A positive
    /// control decodes the co-issued id_token and asserts the SAME identity data IS carried there —
    /// proving the access token's absence is data minimization, not a broken claims resolver.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenOmitsIdentityClaimsWhileIdTokenCarriesThem()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SubjectClaims[SubjectId] = new OidcClaims
        {
            Subject = SubjectId,
            Profile = new ProfileClaims
            {
                Name = "Ada Lovelace",
                FamilyName = "Lovelace",
                GivenName = "Ada"
            },
            Email = new EmailClaims
            {
                Email = "ada@example.test",
                EmailVerified = true
            },
            Address = new AddressClaims
            {
                Locality = "London",
                Country = "UK",
                PostalCode = "SW1A 2AA"
            },
            Phone = new PhoneClaims
            {
                PhoneNumber = "+44 20 7946 0958",
                PhoneNumberVerified = true
            }
        };

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            FullIdentityScope, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string idToken = (string)drive.TokenResult.Body[OAuthRequestParameterNames.IdToken];
        Assert.IsFalse(string.IsNullOrEmpty(accessToken), "The AS must mint an access token.");
        Assert.IsFalse(string.IsNullOrEmpty(idToken),
            "openid in scope on authorization_code must mint an id_token (contract D3).");

        using JsonDocument accessTokenPayload = JwtPayloadReader.ParsePayloadJson(accessToken);
        JsonElement accessTokenClaims = accessTokenPayload.RootElement;

        Assert.AreEqual(SubjectId, accessTokenClaims.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
            "sub identifies the token holder per RFC 9068 §2.2 and must remain present.");
        Assert.AreEqual(FullIdentityScope, accessTokenClaims.GetProperty(WellKnownJwtClaimNames.Scope).GetString());
        Assert.IsTrue(accessTokenClaims.TryGetProperty(WellKnownJwtClaimNames.Iss, out _),
            "iss is RFC 9068 §2.2 required.");
        Assert.IsTrue(accessTokenClaims.TryGetProperty(WellKnownJwtClaimNames.Aud, out _),
            "aud is RFC 9068 §2.2 required.");
        Assert.AreEqual(ClientId, accessTokenClaims.GetProperty(WellKnownJwtClaimNames.ClientId).GetString());

        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.Name);
        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.FamilyName);
        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.GivenName);
        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.Email);
        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.EmailVerified);
        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.Address);
        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.PhoneNumber);
        AssertClaimAbsent(accessTokenClaims, WellKnownJwtClaimNames.PhoneNumberVerified);

        using JsonDocument idTokenPayload = JwtPayloadReader.ParsePayloadJson(idToken);
        JsonElement idTokenClaims = idTokenPayload.RootElement;
        Assert.AreEqual("Ada Lovelace", idTokenClaims.GetProperty(WellKnownJwtClaimNames.Name).GetString(),
            "Positive control: the same identity data the access token must omit belongs on the id_token.");
        Assert.AreEqual("ada@example.test", idTokenClaims.GetProperty(WellKnownJwtClaimNames.Email).GetString());
    }


    private static void AssertClaimAbsent(JsonElement accessTokenClaims, string claimName)
    {
        Assert.IsFalse(accessTokenClaims.TryGetProperty(claimName, out _),
            $"Access token must not carry '{claimName}' — {nameof(AccessTokenTarget)} has no field an "
            + $"{nameof(OidcStandardClaimsContributor)} rule can populate (structural target-keying).");
    }


    /// <summary>
    /// Contract D7 data-minimization gate: a real-wire authorization_code journey that never
    /// requests <c>openid</c> must never invoke the application's
    /// <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/> — the app's OIDC-claims
    /// resolver carries end-user identity data, and a request that never asked for identity must
    /// not trigger it, independent of the fact that no producer would consume the result either way.
    /// </summary>
    [TestMethod]
    public async Task ResolveOidcClaimsResolverIsSkippedWhenOpenidNotRequested()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SubjectClaims[SubjectId] = new OidcClaims
        {
            Subject = SubjectId,
            Profile = new ProfileClaims { Name = "Ada Lovelace" }
        };

        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        int resolverInvocationCount = 0;
        ResolveOidcClaimsDelegate seededResolver = host.Server.OAuth().ResolveOidcClaimsAsync!;
        host.Server.OAuth().ResolveOidcClaimsAsync = (subject, scope, tenantId, ctx, ct) =>
        {
            resolverInvocationCount++;

            return seededResolver(subject, scope, tenantId, ctx, ct);
        };

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            WellKnownScopes.Profile, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, resolverInvocationCount,
            "The app's OIDC-claims resolver must not run when the request never carried openid.");
        Assert.IsFalse(drive.TokenResult.Body!.ContainsKey(OAuthRequestParameterNames.IdToken),
            "No id_token is minted without openid in scope (contract D3), independent of the resolver gate.");
    }


    /// <summary>
    /// Contract D7 response_type validation: this authorization server issues the Authorization
    /// Code grant only (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749
    /// §4.1.1</see>). A real-wire PAR POST whose <c>response_type</c> requests <c>id_token</c> or
    /// <c>token</c> — the OIDC Core 1.0 §3 implicit response types this server does not implement —
    /// is rejected with <c>unsupported_response_type</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>)
    /// rather than silently answered as though <c>code</c> had been requested.
    /// </summary>
    [TestMethod]
    public async Task ParRejectsUnsupportedResponseTypes()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        await host.StartHttpHostAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri parUri = new(
            hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));

        foreach(string unsupportedResponseType in new[] { WellKnownResponseTypes.IdToken, WellKnownResponseTypes.Token })
        {
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            using FormUrlEncodedContent content = new(new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
                [OAuthRequestParameterNames.ResponseType] = unsupportedResponseType
            });

            using HttpResponseMessage response = await hosted.SharedHttpClient!
                .PostAsync(parUri, content, TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, (int)response.StatusCode,
                $"response_type '{unsupportedResponseType}' must be rejected at PAR. Body: {body}");

            using JsonDocument errorBody = JsonDocument.Parse(body);
            Assert.AreEqual("unsupported_response_type",
                errorBody.RootElement.GetProperty("error").GetString(),
                $"The wire error for response_type '{unsupportedResponseType}' must be unsupported_response_type. Body: {body}");
        }
    }


    /// <summary>
    /// Contract D7 response_type validation, the direct (non-PAR) Authorize entry point
    /// (<c>AuthCodeEndpoints.BuildDirectAuthorize</c>): once <c>redirect_uri</c> has been parsed, RFC
    /// 6749 §4.1.2.1 requires an unsupported <c>response_type</c> to surface as an Authorization Error
    /// Response REDIRECT — <c>error=unsupported_response_type</c> on the registered <c>redirect_uri</c>
    /// — rather than a bare HTTP error status, complementing
    /// <see cref="ParRejectsUnsupportedResponseTypes"/>'s bare-PAR JSON-400 shape (PAR has no
    /// redirect_uri to redirect to yet).
    /// </summary>
    [TestMethod]
    public async Task DirectAuthorizeRejectsUnsupportedResponseTypesWithRedirectError()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId,
            ClientBaseUri,
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDirectAuthorization));

        await host.StartHttpHostAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        foreach(string unsupportedResponseType in new[] { WellKnownResponseTypes.IdToken, WellKnownResponseTypes.Token })
        {
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

            Uri authorizeUrl = new(
                hosted.HttpBaseAddress!,
                $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeDirectAuthorize, segment)}" +
                $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
                $"&{OAuthRequestParameterNames.CodeChallenge}={Uri.EscapeDataString(pkce.EncodedChallenge)}" +
                $"&{OAuthRequestParameterNames.CodeChallengeMethod}={WellKnownCodeChallengeMethods.S256}" +
                $"&{OAuthRequestParameterNames.RedirectUri}={Uri.EscapeDataString(RedirectUri.OriginalString)}" +
                $"&{OAuthRequestParameterNames.Scope}={Uri.EscapeDataString(WellKnownScopes.OpenId)}" +
                $"&{OAuthRequestParameterNames.ResponseType}={Uri.EscapeDataString(unsupportedResponseType)}");

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
            authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, SubjectId);

            using HttpResponseMessage response = await browserClient
                .SendAsync(authorizeRequest, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(302, (int)response.StatusCode,
                $"response_type '{unsupportedResponseType}' must be rejected as a redirect once redirect_uri "
                + "is known (RFC 6749 §4.1.2.1), not a bare status.");

            string location = response.Headers.Location!.ToString();
            Assert.StartsWith(RedirectUri.ToString(), location, StringComparison.Ordinal,
                $"The error redirect must target the registered redirect_uri. Got: {location}");
            Assert.AreEqual(
                "unsupported_response_type",
                TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Error),
                $"response_type '{unsupportedResponseType}' must redirect with error=unsupported_response_type. Got: {location}");
        }
    }
}
