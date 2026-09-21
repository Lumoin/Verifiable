using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9470 §5 step-up: the authorization endpoint enforces the request's
/// authentication-recency requirement (<c>max_age</c>, OIDC Core §3.1.2.1) and, when the
/// established authentication does not satisfy it, fails with an OAuth 2.0 Authorization
/// Error Response carrying <c>error=unmet_authentication_requirements</c> per
/// <see href="https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0.html">OIDCUAR</see>.
/// <c>max_age</c> recency is a temporal comparison the library owns, using the deployment's
/// <see cref="Verifiable.OAuth.Server.TimingPolicy.ClockSkewTolerance"/> (the same skew policy
/// the JAR and access-token <c>iat</c>/<c>exp</c> checks use). The semantic <c>acr</c>
/// satisfaction decision is the application's and is covered separately.
/// </summary>
[TestClass]
internal sealed class UnmetAuthenticationRequirementsTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so authentication-recency arithmetic is reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-unmet-1";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>
    /// Every capability the four code-issuing authorize paths need — bare PAR, direct authorize,
    /// and the JAR (RFC 9101 request-object) entry point.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> AllPathCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);


    /// <summary>
    /// <c>max_age=300</c> with an authentication 600 s old (beyond the 60 s default skew)
    /// fails: the authorize response is a redirect to the client carrying
    /// <c>error=unmet_authentication_requirements</c> and no <c>code</c>.
    /// </summary>
    [TestMethod]
    public async Task StaleAuthenticationBeyondMaxAgeFailsWithUnmetRequirement()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, maxAge: "300",
            authTime: TimeProvider.GetUtcNow() - TimeSpan.FromSeconds(600)).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", authorizeResponse.Location!,
            StringComparison.Ordinal,
            $"A stale authentication must fail with unmet_authentication_requirements. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain("code=", authorizeResponse.Location!, StringComparison.Ordinal,
            "An unmet-requirement authorize response must not return an authorization code.");
    }


    /// <summary>
    /// RFC 9207 §2: "an authorization server supporting this
    /// specification MUST indicate its identity by including the iss parameter in the
    /// response" applies to error responses too, not only the success redirect. Drives
    /// the same stale-authentication failure as
    /// <see cref="StaleAuthenticationBeyondMaxAgeFailsWithUnmetRequirement"/> under a
    /// profile that emits <c>iss</c> (<see cref="PolicyProfile.Haip10"/>, unlike that
    /// test's <see cref="PolicyProfile.Rfc6749WithPkce"/>) and asserts <c>iss</c> is
    /// present on the resulting <c>error=unmet_authentication_requirements</c> redirect.
    /// </summary>
    [TestMethod]
    public async Task ErrorRedirectCarriesIssParameter()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Haip10).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, maxAge: "300",
            authTime: TimeProvider.GetUtcNow() - TimeSpan.FromSeconds(600)).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", authorizeResponse.Location!,
            StringComparison.Ordinal);
        Assert.Contains("iss=", authorizeResponse.Location!, StringComparison.Ordinal,
            $"RFC 9207 §2 requires iss on an Authorization Error Response, not only on success. Location: {authorizeResponse.Location}");
    }


    /// <summary>
    /// <c>max_age=300</c> with an authentication 60 s old satisfies the requirement: the
    /// authorize response redirects with a <c>code</c> and no error.
    /// </summary>
    [TestMethod]
    public async Task FreshAuthenticationWithinMaxAgeSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, maxAge: "300",
            authTime: TimeProvider.GetUtcNow() - TimeSpan.FromSeconds(60)).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains("code=", authorizeResponse.Location!, StringComparison.Ordinal,
            $"A fresh authentication within max_age must yield an authorization code. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain(OAuthErrors.UnmetAuthenticationRequirements, authorizeResponse.Location!,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// <c>max_age=0</c> (≡ <c>prompt=login</c>) demands a fresh authentication: a prior
    /// authentication fails, while one stamped at the request instant succeeds.
    /// </summary>
    [TestMethod]
    public async Task MaxAgeZeroRequiresFreshAuthentication()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse staleResponse = await DriveToAuthorizeAsync(
            host, material, maxAge: "0",
            authTime: TimeProvider.GetUtcNow() - TimeSpan.FromHours(1)).ConfigureAwait(false);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", staleResponse.Location!,
            StringComparison.Ordinal,
            "max_age=0 must reject an authentication that is not fresh.");

        ServerHttpResponse freshResponse = await DriveToAuthorizeAsync(
            host, material, maxAge: "0",
            authTime: TimeProvider.GetUtcNow()).ConfigureAwait(false);
        Assert.Contains("code=", freshResponse.Location!, StringComparison.Ordinal,
            "max_age=0 must accept an authentication performed at the request instant.");
    }


    /// <summary>
    /// A 30-second-old session is within the deployment's default 60 s clock-skew tolerance but
    /// is NOT a fresh authentication. <c>max_age=0</c> (≡ <c>prompt=login</c>) must reject it:
    /// the recency check is whole-second and carries NO skew padding, because <c>auth_time</c>
    /// and <c>now</c> are produced by one authorization-server clock (no two-party divergence to
    /// absorb, unlike the JAR/access-token <c>iat</c>/<c>exp</c> checks). Without this, the full
    /// clock-skew window would silently let a stale session satisfy <c>max_age=0</c>.
    /// </summary>
    [TestMethod]
    public async Task MaxAgeZeroRejectsASessionThatIsNotFreshEvenWithinClockSkew()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, maxAge: "0",
            authTime: TimeProvider.GetUtcNow() - TimeSpan.FromSeconds(30)).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", authorizeResponse.Location!,
            StringComparison.Ordinal,
            $"max_age=0 must reject a 30s-old session; no clock-skew padding applies. Location: {authorizeResponse.Location}");
    }


    /// <summary>
    /// <c>max_age</c> with no established authentication time fails closed: the library cannot
    /// confirm the requested recency, so it returns <c>unmet_authentication_requirements</c>
    /// rather than assuming the authentication is fresh (which would let a stale session pass
    /// <c>max_age</c> whenever the application omitted <c>SetAuthTime</c>).
    /// </summary>
    [TestMethod]
    public async Task MaxAgeWithoutEstablishedAuthTimeFailsClosed()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //No authTime argument → the authorize context carries no auth_time at all.
        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, maxAge: "0", authTime: null).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", authorizeResponse.Location!,
            StringComparison.Ordinal,
            $"max_age with no established auth_time must fail closed. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain("code=", authorizeResponse.Location!, StringComparison.Ordinal);
    }


    /// <summary>
    /// A <c>max_age</c> that is not a non-negative integer is a malformed request and is
    /// rejected at the PAR endpoint with <c>invalid_request</c> (OIDC Core §3.1.2.1).
    /// </summary>
    [TestMethod]
    public async Task MalformedMaxAgeIsRejectedAtPar()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.MaxAge] = "-5"
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, parResponse.StatusCode, parResponse.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, parResponse.Body, StringComparison.Ordinal);
        Assert.Contains("max_age must be a non-negative integer.", parResponse.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// The established <c>acr</c> "loa-low" does not satisfy a request for "loa-high":
    /// the application's verdict (<c>EvaluateAcrSatisfactionAsync</c>) returns
    /// <see langword="false"/> and the authorize response fails with
    /// <c>unmet_authentication_requirements</c>.
    /// </summary>
    [TestMethod]
    public async Task AcrUnsatisfiedByApplicationVerdictFailsWithUnmetRequirement()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //The deployment owns the assurance-level semantics: "loa-high" is satisfied only
        //by an established acr equal to "loa-high"; anything else is denied as an unmet
        //authentication requirement.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (evaluation, _, _, _) =>
                    ValueTask.FromResult(
                        string.Equals(evaluation.EstablishedAcr, "loa-high", StringComparison.Ordinal)
                            ? AuthorizationRequestDecision.Permit()
                            : AuthorizationRequestDecision.Deny(
                                AuthorizationDenialReason.UnmetAuthenticationRequirements));
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, acrValues: "loa-high", establishedAcr: "loa-low").ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", authorizeResponse.Location!,
            StringComparison.Ordinal,
            $"An acr the application deems insufficient must fail. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain("code=", authorizeResponse.Location!, StringComparison.Ordinal);
    }


    /// <summary>
    /// When the application's verdict accepts the established <c>acr</c>, the authorize
    /// request succeeds and returns an authorization code.
    /// </summary>
    [TestMethod]
    public async Task AcrSatisfiedByApplicationVerdictSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (evaluation, _, _, _) =>
                    ValueTask.FromResult(
                        string.Equals(evaluation.EstablishedAcr, "loa-high", StringComparison.Ordinal)
                            ? AuthorizationRequestDecision.Permit()
                            : AuthorizationRequestDecision.Deny(
                                AuthorizationDenialReason.UnmetAuthenticationRequirements));
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, acrValues: "loa-high", establishedAcr: "loa-high").ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains("code=", authorizeResponse.Location!, StringComparison.Ordinal,
            $"An acr the application accepts must yield a code. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain(OAuthErrors.UnmetAuthenticationRequirements, authorizeResponse.Location!,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// The application receives the request's <c>acr_values</c> and the established
    /// <c>acr</c> verbatim — the library passes them through without interpreting LoA
    /// semantics.
    /// </summary>
    [TestMethod]
    public async Task ApplicationVerdictReceivesRequestedAndEstablishedAcr()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string? observedRequested = null;
        string? observedEstablished = null;
        string? observedScope = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, _, _, _) =>
                {
                    observedRequested = evaluation.RequestedAcrValues;
                    observedEstablished = evaluation.EstablishedAcr;
                    observedScope = evaluation.RequestedScope;

                    return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
                };
        }).ConfigureAwait(false);

        _ = await DriveToAuthorizeAsync(
            host, material, acrValues: "loa-substantial loa-high",
            establishedAcr: "loa-substantial").ConfigureAwait(false);

        Assert.AreEqual("loa-substantial loa-high", observedRequested,
            "The library must pass the preference-ordered acr_values through verbatim.");
        Assert.AreEqual("loa-substantial", observedEstablished,
            "The library must pass the application-established acr through verbatim.");
        Assert.AreEqual(WellKnownScopes.OpenId, observedScope,
            "The evaluator must see the scope the issued code will carry.");
    }


    /// <summary>
    /// With no <c>EvaluateAuthorizationRequestAsync</c> wired, the authorization server
    /// applies no additional decision: a request carrying <c>acr_values</c> still succeeds
    /// (the achieved acr is conveyed in the tokens and the resource server's challenge loop
    /// is the backstop).
    /// </summary>
    [TestMethod]
    public async Task AcrValuesWithoutAnEvaluatorAreNotEnforced()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, acrValues: "loa-high", establishedAcr: "loa-low").ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains("code=", authorizeResponse.Location!, StringComparison.Ordinal,
            "Without an evaluator the authorization server applies no additional decision.");
    }


    /// <summary>
    /// The same decision seam carries non-authentication denials: an application that denies
    /// the request with <see cref="AuthorizationDenialReason.AccessDenied"/> (e.g. consent
    /// refused) yields the <c>access_denied</c> OAuth error — proving the reason, not the
    /// seam, selects the error code.
    /// </summary>
    [TestMethod]
    public async Task ApplicationDenialWithAccessDeniedReasonMapsToAccessDeniedError()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) =>
                    ValueTask.FromResult(AuthorizationRequestDecision.Deny(
                        AuthorizationDenialReason.AccessDenied, "Resource owner declined consent."));
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material, establishedAcr: "loa-low").ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.AccessDenied}", authorizeResponse.Location!, StringComparison.Ordinal,
            $"An AccessDenied reason must map to the access_denied error. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain(OAuthErrors.UnmetAuthenticationRequirements, authorizeResponse.Location!,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9101 §6.3 (via RFC 9126 §4) — when the request is passed by reference
    /// (<c>request_uri</c>), the authorization server MUST only use the pushed parameters even if
    /// duplicated in the query. A broader <c>scope</c> sent on the authorize GET must be ignored;
    /// the pushed scope is authoritative (PAR integrity, RFC 9126 §1). Verified via the evaluator,
    /// which sees the scope the issued code will carry.
    /// </summary>
    [TestMethod]
    public async Task PushedScopeIsAuthoritativeAndAuthorizeGetScopeIsIgnored()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        string? observedScope = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, _, _, _) =>
                {
                    observedScope = evaluation.RequestedScope;

                    return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
                };
        }).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        using JsonDocument parBody = JsonDocument.Parse(parResponse.Body);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        //The client (or a front-channel attacker) sends a BROADER scope on the authorize GET.
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri,
            [OAuthRequestParameterNames.Scope] = "openid email profile"
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.AreEqual(WellKnownScopes.OpenId, observedScope,
            "The pushed scope must be authoritative; a scope on the authorize GET must be ignored (RFC 9101 §6.3).");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 §5.1</see>:
    /// "scope: OPTIONAL, if identical to the scope requested by the client; otherwise,
    /// REQUIRED." A bare <see cref="AuthorizationRequestDecision.Permit"/> never narrows —
    /// the redeemed token response's <c>scope</c> equals the requested scope.
    /// </summary>
    [TestMethod]
    public async Task BarePermitGrantsTheRequestedScopeUnchanged()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(AuthorizationRequestDecision.Permit());
        }).ConfigureAwait(false);

        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = WellKnownScopes.OpenId },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument tokenBody = JsonDocument.Parse(result.TokenResponse.Body);
        Assert.AreEqual(WellKnownScopes.OpenId, tokenBody.RootElement.GetProperty("scope").GetString(),
            "RFC 6749 §5.1: a bare Permit grants the requested scope unchanged.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>: "The
    /// authorization server MAY fully or partially ignore the scope requested by the client ...
    /// If the issued access token scope is different from the one requested by the client, the
    /// authorization server MUST include the 'scope' response parameter to inform the client of
    /// the actual scope granted." The seam narrows the requested scope with
    /// <see cref="AuthorizationRequestDecision.Permit(string?)"/>; the redeemed token carries the
    /// narrowed set.
    /// </summary>
    [TestMethod]
    public async Task SeamPermitsWithNarrowerScopeRedeemsToATokenCarryingTheNarrowedScope()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(
                    AuthorizationRequestDecision.Permit(WellKnownScopes.OpenId));
        }).ConfigureAwait(false);

        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions
            {
                Scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument tokenBody = JsonDocument.Parse(result.TokenResponse.Body);
        Assert.AreEqual(WellKnownScopes.OpenId, tokenBody.RootElement.GetProperty("scope").GetString(),
            "RFC 6749 §3.3: the seam narrowed the granted scope; §5.1 requires the differing scope on the response.");
    }


    /// <summary>
    /// The seam's granted scope can only narrow the request, never widen it: a value outside the
    /// requested set is a seam defect answered with <c>server_error</c>, never issued as a silent
    /// widening.
    /// </summary>
    [TestMethod]
    public async Task SeamPermittingAScopeOutsideTheRequestIsAServerErrorNotASilentWidening()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(
                    AuthorizationRequestDecision.Permit($"{WellKnownScopes.OpenId} {WellKnownScopes.Email}"));
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains($"error={OAuthErrors.ServerError}", authorizeResponse.Location!, StringComparison.Ordinal,
            $"A granted scope outside the requested scope is a seam defect, never a silent widening. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain("code=", authorizeResponse.Location!, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>: "The
    /// authorization server MAY fully or partially ignore the scope requested by the client."
    /// Granting nothing is not a narrowing this seam may express — an empty
    /// <see cref="AuthorizationRequestDecision.Permit(string?)"/> is a seam defect answered with
    /// <c>server_error</c>, the same as a grant outside the requested scope.
    /// </summary>
    [TestMethod]
    public async Task SeamPermittingAnEmptyScopeIsAServerError()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(AuthorizationRequestDecision.Permit(string.Empty));
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await DriveToAuthorizeAsync(
            host, material).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains($"error={OAuthErrors.ServerError}", authorizeResponse.Location!, StringComparison.Ordinal,
            $"An empty granted scope is a seam defect, never an empty grant. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain("code=", authorizeResponse.Location!, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>: the
    /// seam narrows the requested scope. The effective scope the library stores is canonical —
    /// the requested tokens' own order, deduplicated — regardless of the order or duplication
    /// <see cref="AuthorizationRequestDecision.Permit(string?)"/> was called with.
    /// </summary>
    [TestMethod]
    public async Task SeamGrantedScopeIsCanonicalizedToTheRequestOrderWithoutDuplicates()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(
                    AuthorizationRequestDecision.Permit(
                        $"{WellKnownScopes.Profile} {WellKnownScopes.OpenId} {WellKnownScopes.OpenId}"));
        }).ConfigureAwait(false);

        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions
            {
                Scope = $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile} {WellKnownScopes.Email}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        using JsonDocument tokenBody = JsonDocument.Parse(result.TokenResponse.Body);
        Assert.AreEqual($"{WellKnownScopes.OpenId} {WellKnownScopes.Profile}",
            tokenBody.RootElement.GetProperty("scope").GetString(),
            "The granted scope must canonicalize to the requested tokens' own order, without duplicates.");
    }


    /// <summary>
    /// <see cref="AuthorizationDenialReason.InvalidScope"/> maps to the
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>
    /// <c>invalid_scope</c> Authorization Error Response, with the request's <c>state</c> echoed.
    /// </summary>
    [TestMethod]
    public async Task DenyWithInvalidScopeReasonMapsToInvalidScopeErrorWithStateEchoed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(
                    AuthorizationRequestDecision.Deny(AuthorizationDenialReason.InvalidScope));
        }).ConfigureAwait(false);

        string requestUri = await PushAsync(host, material, state: "state-scope-1", prompt: null)
            .ConfigureAwait(false);
        ServerHttpResponse response = await CompleteAuthorizeAsync(
            host, material, requestUri, subjectId: SubjectId).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.InvalidScope}", response.Location!, StringComparison.Ordinal,
            $"AuthorizationDenialReason.InvalidScope must map to invalid_scope. Location: {response.Location}");
        Assert.Contains("state=state-scope-1", response.Location!, StringComparison.Ordinal);
    }


    /// <summary>No subject, no <c>prompt</c>: <c>login_required</c> on the PAR-completion path.</summary>
    [TestMethod]
    public async Task NoSubjectNoPromptFailsWithLoginRequiredOnPushedCompletion()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        string requestUri = await PushAsync(host, material, state: "state-1", prompt: null).ConfigureAwait(false);
        ServerHttpResponse response = await CompleteAuthorizeAsync(
            host, material, requestUri, subjectId: null).ConfigureAwait(false);

        AssertLoginRequiredRedirect(response, "state-1");
    }


    /// <summary>No subject, no <c>prompt</c>: <c>login_required</c> on the direct authorize path.</summary>
    [TestMethod]
    public async Task NoSubjectNoPromptFailsWithLoginRequiredOnDirectAuthorize()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: null, prompt: null, state: "state-2",
            redirectUri: RedirectUri).ConfigureAwait(false);

        AssertLoginRequiredRedirect(response, "state-2");
    }


    /// <summary>No subject, no <c>prompt</c>: <c>login_required</c> on a signed request by reference (JAR-PAR).</summary>
    [TestMethod]
    public async Task NoSubjectNoPromptFailsWithLoginRequiredOnJarByReference()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse pushResponse = await PushJarAsync(
            host, material, state: "state-3", nonce: "nonce-3", prompt: null).ConfigureAwait(false);
        Assert.AreEqual(201, pushResponse.StatusCode, pushResponse.Body);
        string requestUri = ExtractRequestUri(pushResponse.Body);

        ServerHttpResponse response = await CompleteAuthorizeAsync(
            host, material, requestUri, subjectId: null).ConfigureAwait(false);

        AssertLoginRequiredRedirect(response, "state-3");
    }


    /// <summary>No subject, no <c>prompt</c>: <c>login_required</c> on a signed request by value.</summary>
    [TestMethod]
    public async Task NoSubjectNoPromptFailsWithLoginRequiredOnJarByValue()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await JarByValueAuthorizeAsync(
            host, material, state: "state-4", nonce: "nonce-4", subjectId: null, prompt: null)
            .ConfigureAwait(false);

        AssertLoginRequiredRedirect(response, "state-4");
    }


    /// <summary>No subject, <c>prompt=none</c>: <c>login_required</c>.</summary>
    [TestMethod]
    public async Task NoSubjectWithPromptNoneFailsWithLoginRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: null, prompt: WellKnownPromptValues.None, state: "state-5",
            redirectUri: RedirectUri).ConfigureAwait(false);

        AssertLoginRequiredRedirect(response, "state-5");
    }


    /// <summary>
    /// OIDC Core §3.1.2.1: "If this parameter contains none with any other value, an error is
    /// returned." At the pushed endpoint directly — a bare 400, since PAR has no front channel.
    /// </summary>
    [TestMethod]
    public async Task PromptWithNoneAndOtherValueIsRejectedAtPushedEndpoint()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await PushRawAsync(
            host, material, state: "state-6",
            prompt: $"{WellKnownPromptValues.None} {WellKnownPromptValues.Login}").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// OIDC Core §3.1.2.1's none-with-any-other-value rule at the authorize endpoint, as an
    /// error redirect: <c>redirect_uri</c> is already registration-validated by this point.
    /// </summary>
    [TestMethod]
    public async Task PromptWithNoneAndOtherValueIsRejectedAtDirectAuthorize()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: SubjectId,
            prompt: $"{WellKnownPromptValues.None} {WellKnownPromptValues.Login}",
            state: "state-7", redirectUri: RedirectUri).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.InvalidRequest}", response.Location!, StringComparison.Ordinal);
        Assert.Contains("state=state-7", response.Location!, StringComparison.Ordinal);
    }


    /// <summary>Subject established, <c>prompt=login</c>, no seam wired: fails closed with <c>login_required</c>.</summary>
    [TestMethod]
    public async Task SubjectEstablishedPromptLoginWithNoSeamFailsWithLoginRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: SubjectId, prompt: WellKnownPromptValues.Login,
            state: "state-8", redirectUri: RedirectUri).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.LoginRequired}", response.Location!, StringComparison.Ordinal);
        Assert.Contains("state=state-8", response.Location!, StringComparison.Ordinal);
    }


    /// <summary>Subject established, <c>prompt=login</c>, a seam that permits: a code is issued.</summary>
    [TestMethod]
    public async Task SubjectEstablishedPromptLoginWithPermittingSeamIssuesCode()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(AuthorizationRequestDecision.Permit());
        }).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: SubjectId, prompt: WellKnownPromptValues.Login,
            state: "state-9", redirectUri: RedirectUri).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains("code=", response.Location!, StringComparison.Ordinal);
    }


    /// <summary>Subject established, <c>prompt=login</c>, a seam denying <c>LoginRequired</c>: <c>login_required</c>.</summary>
    [TestMethod]
    public async Task SubjectEstablishedPromptLoginWithDenyingSeamFailsWithLoginRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                static (_, _, _, _) => ValueTask.FromResult(
                    AuthorizationRequestDecision.Deny(AuthorizationDenialReason.LoginRequired));
        }).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: SubjectId, prompt: WellKnownPromptValues.Login,
            state: "state-10", redirectUri: RedirectUri).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.LoginRequired}", response.Location!, StringComparison.Ordinal);
    }


    /// <summary>Subject established, <c>prompt=consent</c>, no seam wired: <c>consent_required</c>.</summary>
    [TestMethod]
    public async Task SubjectEstablishedPromptConsentWithNoSeamFailsWithConsentRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: SubjectId, prompt: WellKnownPromptValues.Consent,
            state: "state-11", redirectUri: RedirectUri).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.ConsentRequired}", response.Location!, StringComparison.Ordinal);
        Assert.Contains("state=state-11", response.Location!, StringComparison.Ordinal);
    }


    /// <summary>Subject established, <c>prompt=select_account</c>, no seam wired: <c>account_selection_required</c>.</summary>
    [TestMethod]
    public async Task SubjectEstablishedPromptSelectAccountWithNoSeamFailsWithAccountSelectionRequired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: SubjectId, prompt: WellKnownPromptValues.SelectAccount,
            state: "state-12", redirectUri: RedirectUri).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.AccountSelectionRequired}", response.Location!, StringComparison.Ordinal);
        Assert.Contains("state=state-12", response.Location!, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9101 §6.3 via RFC 9126 §4: a pushed request without <c>prompt</c>, authorized with
    /// <c>prompt=login</c> on the front-channel query, ignores the front-channel value and
    /// issues a code — the pushed (absent) prompt is authoritative.
    /// </summary>
    [TestMethod]
    public async Task PromptFromFrontChannelIsIgnoredOnARequestUriRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        string requestUri = await PushAsync(host, material, state: "state-13", prompt: null).ConfigureAwait(false);
        ServerHttpResponse response = await CompleteAuthorizeAsync(
            host, material, requestUri, subjectId: SubjectId,
            frontChannelPrompt: WellKnownPromptValues.Login).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains("code=", response.Location!, StringComparison.Ordinal,
            "The pushed request carried no prompt; a front-channel prompt=login must be ignored (RFC 9101 §6.3).");
    }


    /// <summary>
    /// The error redirect never goes to an unvalidated <c>redirect_uri</c>: an unauthenticated
    /// request with an unregistered <c>redirect_uri</c> still answers the existing direct 400,
    /// never a redirect to the attacker-supplied URI.
    /// </summary>
    [TestMethod]
    public async Task UnauthenticatedRequestWithUnregisteredRedirectUriStillAnswersBadRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllPathsClientAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DirectAuthorizeAsync(
            host, material, subjectId: null, prompt: null, state: "state-14",
            redirectUri: new Uri("https://attacker.example.com/callback")).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsNull(response.Location,
            "An unregistered redirect_uri must never be redirected to, even for an unauthenticated request.");
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// Drives PAR → Authorize, pushing the requested <paramref name="maxAge"/> /
    /// <paramref name="acrValues"/> in the PAR request and stamping
    /// <paramref name="authTime"/> / <paramref name="establishedAcr"/> on the authorize-time
    /// context (mirroring the application's authentication middleware). Returns the authorize
    /// endpoint response.
    /// </summary>
    private async Task<ServerHttpResponse> DriveToAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material,
        string? maxAge = null, string? acrValues = null,
        DateTimeOffset? authTime = null, string? establishedAcr = null)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        if(maxAge is not null)
        {
            parFields[OAuthRequestParameterNames.MaxAge] = maxAge;
        }

        if(acrValues is not null)
        {
            parFields[OAuthRequestParameterNames.AcrValues] = acrValues;
        }

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        using JsonDocument parBody = JsonDocument.Parse(parResponse.Body);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);
        if(authTime is { } t)
        {
            authorizeContext.SetAuthTime(t);
        }

        if(establishedAcr is not null)
        {
            authorizeContext.SetAcr(establishedAcr);
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a client with every capability the four code-issuing authorize paths need,
    /// including a JAR signing key (<see cref="TestHostShell.RegisterClientAsync"/> configures one
    /// unconditionally, unlike <see cref="TestHostShell.RegisterDpopClientAsync"/>).
    /// </summary>
    private static async Task<VerifierKeyMaterial> RegisterAllPathsClientAsync(TestHostShell host) =>
        await host.RegisterClientAsync(ClientId, ClientBaseUri, AllPathCapabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);


    private static void AssertLoginRequiredRedirect(ServerHttpResponse response, string state)
    {
        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.LoginRequired}", response.Location!, StringComparison.Ordinal,
            $"An unestablished subject must redirect with error=login_required, never a 500. Location: {response.Location}");
        Assert.Contains($"state={state}", response.Location!, StringComparison.Ordinal);
        Assert.StartsWith(RedirectUri.ToString(), response.Location!, StringComparison.Ordinal,
            "The error redirect must go to the already-validated redirect_uri.");
    }


    private async Task<string> PushAsync(
        TestHostShell host, VerifierKeyMaterial material, string state, string? prompt)
    {
        ServerHttpResponse response = await PushRawAsync(host, material, state, prompt).ConfigureAwait(false);
        Assert.AreEqual(201, response.StatusCode, response.Body);

        return ExtractRequestUri(response.Body);
    }


    private async Task<ServerHttpResponse> PushRawAsync(
        TestHostShell host, VerifierKeyMaterial material, string state, string? prompt)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = state
        };
        if(prompt is not null)
        {
            parFields[OAuthRequestParameterNames.Prompt] = prompt;
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<ServerHttpResponse> CompleteAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material, string requestUri,
        string? subjectId, string? frontChannelPrompt = null)
    {
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        if(frontChannelPrompt is not null)
        {
            authorizeFields[OAuthRequestParameterNames.Prompt] = frontChannelPrompt;
        }

        ExchangeContext authorizeContext = [];
        if(subjectId is not null)
        {
            authorizeContext.SetSubjectId(subjectId);
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<ServerHttpResponse> DirectAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material,
        string? subjectId, string? prompt, string state, Uri redirectUri)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = state
        };
        if(prompt is not null)
        {
            fields[OAuthRequestParameterNames.Prompt] = prompt;
        }

        ExchangeContext context = [];
        if(subjectId is not null)
        {
            context.SetSubjectId(subjectId);
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            fields, context,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<ServerHttpResponse> PushJarAsync(
        TestHostShell host, VerifierKeyMaterial material, string state, string nonce, string? prompt)
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RedirectUri, state, nonce);
        if(prompt is not null)
        {
            claims[OAuthRequestParameterNames.Prompt] = prompt;
        }

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeJarPar, "POST",
            fields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<ServerHttpResponse> JarByValueAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material, string state, string nonce,
        string? subjectId, string? prompt)
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RedirectUri, state, nonce);
        if(prompt is not null)
        {
            claims[OAuthRequestParameterNames.Prompt] = prompt;
        }

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ExchangeContext context = [];
        if(subjectId is not null)
        {
            context.SetSubjectId(subjectId);
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            fields, context,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractRequestUri(string parResponseBody)
    {
        using JsonDocument document = JsonDocument.Parse(parResponseBody);

        return document.RootElement.GetProperty("request_uri").GetString()!;
    }
}
