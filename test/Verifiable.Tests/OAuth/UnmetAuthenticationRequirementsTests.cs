using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
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
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-unmet-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");


    /// <summary>
    /// <c>max_age=300</c> with an authentication 600 s old (beyond the 60 s default skew)
    /// fails: the authorize response is a redirect to the client carrying
    /// <c>error=unmet_authentication_requirements</c> and no <c>code</c>.
    /// </summary>
    [TestMethod]
    public async Task StaleAuthenticationBeyondMaxAgeFailsWithUnmetRequirement()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
    /// <c>max_age=300</c> with an authentication 60 s old satisfies the requirement: the
    /// authorize response redirects with a <c>code</c> and no error.
    /// </summary>
    [TestMethod]
    public async Task FreshAuthenticationWithinMaxAgeSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
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
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, parResponse.StatusCode, parResponse.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, parResponse.Body, StringComparison.Ordinal);
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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //The deployment owns the assurance-level semantics: "loa-high" is satisfied only
        //by an established acr equal to "loa-high"; anything else is denied as an unmet
        //authentication requirement.
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            static (evaluation, _, _, _) =>
                ValueTask.FromResult(
                    string.Equals(evaluation.EstablishedAcr, "loa-high", StringComparison.Ordinal)
                        ? AuthorizationRequestDecision.Permit
                        : AuthorizationRequestDecision.Deny(
                            AuthorizationDenialReason.UnmetAuthenticationRequirements));

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            static (evaluation, _, _, _) =>
                ValueTask.FromResult(
                    string.Equals(evaluation.EstablishedAcr, "loa-high", StringComparison.Ordinal)
                        ? AuthorizationRequestDecision.Permit
                        : AuthorizationRequestDecision.Deny(
                            AuthorizationDenialReason.UnmetAuthenticationRequirements));

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string? observedRequested = null;
        string? observedEstablished = null;
        string? observedScope = null;
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, _, _, _) =>
            {
                observedRequested = evaluation.RequestedAcrValues;
                observedEstablished = evaluation.EstablishedAcr;
                observedScope = evaluation.RequestedScope;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
            };

        await DriveToAuthorizeAsync(
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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            static (_, _, _, _) =>
                ValueTask.FromResult(AuthorizationRequestDecision.Deny(
                    AuthorizationDenialReason.AccessDenied, "Resource owner declined consent."));

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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string? observedScope = null;
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, _, _, _) =>
            {
                observedScope = evaluation.RequestedScope;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
            };

        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        using System.Text.Json.JsonDocument parBody = System.Text.Json.JsonDocument.Parse(parResponse.Body);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        //The client (or a front-channel attacker) sends a BROADER scope on the authorize GET.
        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri,
            [OAuthRequestParameterNames.Scope] = "openid email profile"
        };
        ExchangeContext authorizeContext = new();
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
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        using System.Text.Json.JsonDocument parBody = System.Text.Json.JsonDocument.Parse(parResponse.Body);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
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
}
