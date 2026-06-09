using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// PAR integrity hardening: RFC 9101 §6.3 (applied to PAR via RFC 9126 §4) requires the
/// authorization server to use ONLY the pushed parameters when the request is passed by
/// reference (<c>request_uri</c>), even if the same parameter is duplicated in the front-channel
/// authorize GET. These tests model a front-channel tampering attempt — a client (or an attacker
/// who controls the user agent) appends security-relevant parameters to the authorize GET — and
/// assert the pushed values win, so the integrity guarantee PAR exists to provide (RFC 9126 §1)
/// cannot be subverted. The companion <c>PushedScopeIsAuthoritative…</c> test covers <c>scope</c>.
/// </summary>
[TestClass]
internal sealed class ParRequestIntegrityTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so authentication-recency arithmetic is reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-par-integrity-1";
    private static readonly Uri ClientBaseUri = new("https://client.example.com");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");
    private const string AttackerRedirectUri = "https://attacker.example.com/steal";


    /// <summary>
    /// A front-channel <c>redirect_uri</c> on the authorize GET must NOT redirect the code to the
    /// attacker — the pushed redirect_uri is authoritative (open-redirect / code-exfiltration guard).
    /// </summary>
    [TestMethod]
    public async Task PushedRedirectUriIsAuthoritativeAndGetRedirectUriIsIgnored()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string requestUri = await PushAsync(host, material, pushedFields: null).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri,
            [OAuthRequestParameterNames.RedirectUri] = AttackerRedirectUri
        };
        ServerHttpResponse authorizeResponse = await AuthorizeAsync(
            host, material, authorizeFields, staleAuth: false).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.StartsWith(RedirectUri.OriginalString, authorizeResponse.Location!,
            $"The code must be delivered to the PUSHED redirect_uri, never the front-channel one. Location: {authorizeResponse.Location}");
        Assert.DoesNotContain("attacker.example.com", authorizeResponse.Location!, StringComparison.Ordinal,
            "A front-channel redirect_uri must never receive the authorization code.");
    }


    /// <summary>
    /// A front-channel <c>acr_values</c> that is WEAKER than the pushed one must not downgrade the
    /// step-up requirement: the application's evaluator sees the pushed <c>acr_values</c>.
    /// </summary>
    [TestMethod]
    public async Task PushedAcrValuesAreAuthoritativeAndGetAcrValuesAreIgnored()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string? observedAcrValues = null;
        host.Server.Integration.EvaluateAuthorizationRequestAsync =
            (evaluation, _, _, _) =>
            {
                observedAcrValues = evaluation.RequestedAcrValues;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
            };

        RequestFields pushed = new() { [OAuthRequestParameterNames.AcrValues] = "loa-high" };
        string requestUri = await PushAsync(host, material, pushed).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri,
            [OAuthRequestParameterNames.AcrValues] = "loa-low"
        };
        ServerHttpResponse authorizeResponse = await AuthorizeAsync(
            host, material, authorizeFields, staleAuth: false).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.AreEqual("loa-high", observedAcrValues,
            "The pushed acr_values must be authoritative; a weaker front-channel acr_values must be ignored.");
    }


    /// <summary>
    /// A front-channel <c>max_age</c> that is LAXER than the pushed one must not relax the recency
    /// requirement: the pushed <c>max_age=0</c> is enforced and a 30-minute-old session still fails.
    /// </summary>
    [TestMethod]
    public async Task PushedMaxAgeIsAuthoritativeAndGetMaxAgeIsIgnored()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        RequestFields pushed = new() { [OAuthRequestParameterNames.MaxAge] = "0" };
        string requestUri = await PushAsync(host, material, pushed).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri,
            //A lax front-channel max_age that, if honored, would let the 30-minute-old session pass.
            [OAuthRequestParameterNames.MaxAge] = "3600"
        };
        ServerHttpResponse authorizeResponse = await AuthorizeAsync(
            host, material, authorizeFields, staleAuth: true).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains(
            $"error={OAuthErrors.UnmetAuthenticationRequirements}", authorizeResponse.Location!,
            StringComparison.Ordinal,
            $"The pushed max_age=0 must be enforced; a laxer front-channel max_age must be ignored. Location: {authorizeResponse.Location}");
    }


    /// <summary>
    /// A front-channel parameter on a <c>request_uri</c>-referenced authorize emits the
    /// observability signal (<c>oauth.authorize.extraneous_parameters_ignored</c>) so a deployment
    /// can alert on a non-conformant client or a tampering attempt. The behavior is unchanged
    /// (the parameter is still ignored); only the trace gains an event.
    /// </summary>
    [TestMethod]
    public async Task ExtraneousFrontChannelParameterEmitsTamperingEvent()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string requestUri = await PushAsync(host, material, pushedFields: null).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri,
            [OAuthRequestParameterNames.Scope] = "openid email"
        };

        IReadOnlyList<Activity> activities = await CaptureAuthorizeActivitiesAsync(
            material.Registration.TenantId.Value,
            () => AuthorizeAsync(host, material, authorizeFields, staleAuth: false)).ConfigureAwait(false);

        List<string> eventNames = activities.SelectMany(a => a.Events).Select(e => e.Name).ToList();
        Assert.Contains(OAuthEventNames.ExtraneousAuthorizeParameters, eventNames,
            "A front-channel parameter on a request_uri-referenced authorize must emit the tampering signal.");
    }


    /// <summary>A conformant <c>request_uri</c> + <c>client_id</c> authorize emits no such event.</summary>
    [TestMethod]
    public async Task CleanReferencedAuthorizeEmitsNoTamperingEvent()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        string requestUri = await PushAsync(host, material, pushedFields: null).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };

        IReadOnlyList<Activity> activities = await CaptureAuthorizeActivitiesAsync(
            material.Registration.TenantId.Value,
            () => AuthorizeAsync(host, material, authorizeFields, staleAuth: false)).ConfigureAwait(false);

        Assert.IsNotEmpty(activities,
            "Sanity: the authorize dispatch must have produced at least one captured activity.");
        List<string> eventNames = activities.SelectMany(a => a.Events).Select(e => e.Name).ToList();
        Assert.DoesNotContain(OAuthEventNames.ExtraneousAuthorizeParameters, eventNames,
            "A conformant request_uri + client_id authorize must emit no tampering signal.");
    }


    /// <summary>
    /// Runs <paramref name="drive"/> under a process-wide <see cref="ActivityListener"/> on the
    /// OAuth source and returns the stopped activities for <paramref name="tenantId"/>. The
    /// per-tenant filter isolates this test from any running in parallel (the tenant id is a fresh
    /// GUID slice per registration) — see the ActivityListener cross-contamination guidance.
    /// </summary>
    private static async Task<IReadOnlyList<Activity>> CaptureAuthorizeActivitiesAsync(
        string tenantId, Func<Task> drive)
    {
        List<Activity> captured = [];
        using ActivityListener listener = new()
        {
            ShouldListenTo = static source => string.Equals(
                source.Name, OAuthActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = activity =>
            {
                lock(captured)
                {
                    captured.Add(activity);
                }
            }
        };
        ActivitySource.AddActivityListener(listener);

        await drive().ConfigureAwait(false);

        lock(captured)
        {
            return captured
                .Where(activity => string.Equals(
                    activity.GetTagItem(OAuthTagNames.TenantId) as string, tenantId, StringComparison.Ordinal))
                .ToList();
        }
    }


    /// <summary>Pushes an authorization request and returns its <c>request_uri</c>.</summary>
    private async Task<string> PushAsync(
        TestHostShell host, VerifierKeyMaterial material, RequestFields? pushedFields)
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
        if(pushedFields is not null)
        {
            foreach(KeyValuePair<string, string> field in pushedFields)
            {
                parFields[field.Key] = field.Value;
            }
        }

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        using JsonDocument parBody = JsonDocument.Parse(parResponse.Body);

        return parBody.RootElement.GetProperty("request_uri").GetString()!;
    }


    /// <summary>Dispatches the authorize GET with the supplied fields and returns the response.</summary>
    private async Task<ServerHttpResponse> AuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material, RequestFields authorizeFields, bool staleAuth)
    {
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        authorizeContext.SetAuthTime(staleAuth
            ? TimeProvider.GetUtcNow() - TimeSpan.FromMinutes(30)
            : TimeProvider.GetUtcNow());

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
