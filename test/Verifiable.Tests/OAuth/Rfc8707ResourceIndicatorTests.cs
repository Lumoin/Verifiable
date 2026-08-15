using Microsoft.Extensions.Time.Testing;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 8707 resource-indicator threading through the authorization_code server flow: PAR/authorize
/// shape validation across all four request paths (PAR, direct authorize, JAR-PAR, JAR-by-value),
/// the <see cref="AuthorizationDenialReason.InvalidTarget"/> app-driven denial, §2.2 token/refresh
/// subset narrowing (including the "nothing granted" and "not a subset" adversarial cases), the RFC
/// 9068 producer's precedence of the granted resource over <see cref="ClientRecord.ScopeToAudience"/>,
/// and the JAR §2.1 JSON-array resource claim form. Dispatches in-process via
/// <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>;
/// the real-wire resource-pinned array-<c>aud</c> capstone and the refresh-narrowing round live in
/// <see cref="AuthCodeParPkceRealWireFlowTests.FullJourneyThreadsResourceIndicatorToArrayAudience"/>.
/// </summary>
[TestClass]
internal sealed class Rfc8707ResourceIndicatorTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private const string SubjectId = "subject-rfc8707-01";
    private const string ResourceA = "https://cal.example.com/";
    private const string ResourceB = "https://contacts.example.com/";
    private const string UngrantedResource = "https://unrelated.example.com/";

    private static readonly Uri ClientBaseUri = new(ClientId);
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    private static ImmutableHashSet<CapabilityIdentifier> Capabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest,
            WellKnownCapabilityIdentifiers.OAuthRefreshToken);



    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>: a
    /// resource value the authorization server fails to parse is rejected with
    /// <c>invalid_target</c>.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsNonAbsoluteResourceWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(host, material, "not-a-uri").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>'s
    /// <c>invalid_target</c> ("missing, unknown, or malformed") covers ANY aggregated
    /// <c>resource</c> occurrence that is null, empty, or whitespace — not only every occurrence
    /// being blank. A repeated <c>resource</c> parameter where one occurrence is a well-formed URI
    /// and the OTHER is empty must fail the whole PAR request closed: joining the aggregate with a
    /// space before splitting would otherwise silently drop the blank occurrence
    /// (<see cref="StringSplitOptions.RemoveEmptyEntries"/>) and let the valid one alone succeed.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsEmptyResourceOccurrenceMixedWithValidOne()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        parFields.Add(OAuthRequestParameterNames.Resource, ResourceA);
        parFields.Add(OAuthRequestParameterNames.Resource, "");

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "The URI MUST
    /// NOT include a fragment component."
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsResourceWithFragmentWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(
            host, material, "https://api.example.com/orders#frag").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "Its value
    /// MUST be an absolute URI." A relative resource value — the cross-platform absolute-URI guard
    /// (<c>IsAbsoluteResourceIndicatorUri</c>) must reject it on every platform, not merely on
    /// Windows where <see cref="UriKind.Absolute"/> alone would already fail it.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsRelativeResourceWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(host, material, "/relative/path").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see> places no
    /// scheme restriction on the resource value — "Its value MUST be an absolute URI ... The URI
    /// MUST NOT include a fragment component," nothing more. A non-https/http/urn absolute URI
    /// (here <c>mailto:</c>, chosen because it has no authority component at all — the strongest
    /// case that this is genuinely scheme-agnostic, not merely "any scheme with a host") must be
    /// ACCEPTED, proving the shape gate no longer allowlists schemes.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestAcceptsNonAllowlistedSchemeAbsoluteUri()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(
            host, material, "mailto:resource-owner@example.com").ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: a query
    /// component "SHOULD NOT" appear, but the RFC itself "recognized that there are cases that make
    /// a query component a useful and necessary part of the resource parameter" — a SHOULD-NOT, not
    /// a MUST-NOT. The shape gate deliberately does not enforce it; a query-bearing resource is
    /// accepted like any other absolute URI without a fragment.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestAcceptsResourceWithQueryComponent()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(
            host, material, "https://api.example.com/orders?scope=read").ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "Its value
    /// MUST be an absolute URI." <c>AuthCodeEndpoints.IsAbsoluteResourceIndicatorUri</c>'s guard
    /// against .NET's implicit path-to-<c>file:</c>-URI coercion (documented on the method itself)
    /// closes a cross-platform gap the earlier scheme allowlist closed only incidentally: a
    /// Windows-style absolute path parses as an absolute <c>file:</c> URI too, exactly like the
    /// Unix leading-slash case <see cref="PushedAuthorizationRequestRejectsRelativeResourceWithInvalidTarget"/>
    /// covers, and must be rejected the same way.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsWindowsStylePathWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(host, material, @"C:\Windows\System32").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// The mirror of the two coercion-guard tests above: a resource value that DOES literally
    /// start with the <c>file:</c> scheme is a genuine, deliberate resource indicator
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see> places no
    /// scheme restriction) and must be ACCEPTED, proving the guard rejects the implicit coercion
    /// specifically — not the <c>file:</c> scheme itself.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestAcceptsExplicitFileSchemeResource()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(
            host, material, "file:///srv/resources/orders").ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// redirect_uri is already parsed as absolute by the time the resource shape gate runs on the
    /// direct-authorize path, so a malformed resource is reported as an Authorization Error
    /// Response redirect carrying <c>error=invalid_target</c> — the same transport the application's
    /// own <see cref="AuthorizationDenialReason.InvalidTarget"/> denial uses — rather than a bare 400.
    /// </summary>
    [TestMethod]
    public async Task DirectAuthorizeRejectsMalformedResourceWithInvalidTargetRedirect()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Resource] = "not-a-uri"
        };
        ExchangeContext context = new();
        context.SetSubjectId(SubjectId);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.InvalidTarget}", response.Location!, StringComparison.Ordinal,
            $"A malformed resource must redirect with error=invalid_target. Location: {response.Location}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1">RFC 9700 §2.1</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.3">RFC 6749 §3.1.2.3</see>:
    /// an <c>redirect_uri</c> not on the client's registered set must NEVER be redirected to, even
    /// when the request also carries a defect (here a malformed <c>resource</c>) that would
    /// otherwise answer through a redirect — an attacker-supplied <c>redirect_uri</c> paired with a
    /// deliberately malformed <c>resource</c> is exactly the shape that would leak an
    /// <c>error=invalid_target</c> redirect to an unregistered origin absent the registered-set gate
    /// this test proves runs FIRST. The direct-authorize path must fail closed with a bare 400 and
    /// no <c>Location</c> header, mirroring the PAR endpoint's own exact-match gate.
    /// </summary>
    [TestMethod]
    public async Task DirectAuthorizeRejectsUnregisteredRedirectUriWithMalformedResourceAsBadRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/callback",
            [OAuthRequestParameterNames.Resource] = "not-a-uri"
        };
        ExchangeContext context = new();
        context.SetSubjectId(SubjectId);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsNull(response.Location,
            "An unregistered redirect_uri must never be redirected to, regardless of any other request defect.");
        AssertErrorCode(response, OAuthErrors.InvalidRequest);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>: the
    /// JAR-PAR endpoint has no front channel of its own (PAR always answers directly, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126 §2.3</see>), so a
    /// malformed resource claim is reported as a bare 400 — unlike its JAR-by-value twin
    /// (<see cref="JarByValueRejectsMalformedResourceClaimWithInvalidTargetRedirect"/>), which does
    /// have a redirect_uri to answer through.
    /// </summary>
    [TestMethod]
    public async Task JarParRejectsMalformedResourceClaimWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, Capabilities);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RedirectUri, "state-jar-par-resource", "nonce-jar-par-resource");
        claims[OAuthRequestParameterNames.Resource] = "not-a-uri";
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>'s array
    /// form of the <c>resource</c> claim can carry a blank element alongside a well-formed one. A
    /// blank element has no indicator to contribute, so the JAR projection
    /// (<c>AuthCodeRequestObjectExtensions.ProjectAuthCode</c>'s <c>ReadResourceClaim</c>) must
    /// treat the whole claim as malformed rather than silently dropping the blank entry and
    /// carrying the well-formed one alone into <see cref="AuthCodeRequestObject.Resource"/> — the
    /// same distinction its query-string twin (<c>ReadResource</c>, proven by
    /// <see cref="PushedAuthorizationRequestRejectsEmptyResourceOccurrenceMixedWithValidOne"/>)
    /// already draws. Constructed directly against <see cref="JarVerified"/> — a supported public
    /// entry point — because a genuinely blank JSON array element, once it crosses the wire and is
    /// re-parsed into the verified claims dictionary, is a runtime shape
    /// (<c>List&lt;object&gt;</c>) whose own empty-string filtering already collapses the claim to
    /// the single well-formed entry before <c>ReadResourceClaim</c> ever runs; driving the same
    /// defect through a real signed JAR round-trip would exercise that filtering instead of the
    /// fix. The resulting projected <see cref="AuthCodeRequestObject.Resource"/> is checked against
    /// RFC 8707 §2's own resource-indicator shape (an absolute URI with no fragment component) —
    /// the same test <c>IsAbsoluteResourceIndicatorUri</c> applies downstream at
    /// <c>ValidateResourceIndicatorsShape</c>, whose rejection is what ultimately produces
    /// <c>invalid_target</c> on the wire: silently dropping the blank entry would leave a bare,
    /// well-formed resource indicator here; failing closed leaves a value that itself is not one.
    /// </summary>
    [TestMethod]
    public void JarResourceClaimWithMixedEmptyAndValidEntriesProjectsToAMalformedIndicator()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.State] = "state-jar-resource-mixed",
            [WellKnownJwtClaimNames.Nonce] = "nonce-jar-resource-mixed",
            [OAuthRequestParameterNames.CodeChallenge] = "challenge-jar-resource-mixed",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,

            //A genuine string[] — the runtime shape JwsAccessTokenValidator.TryReadStringList's own
            //"typed" branch reads without filtering, unlike the List<object> a real wire round-trip
            //through the JSON converter would produce.
            [OAuthRequestParameterNames.Resource] = new[] { "", ResourceA }
        };
        JarVerified verified = new(new UnverifiedJwtHeader(), claims, now, now, now.AddMinutes(5));

        AuthCodeRequestObject projected = verified.ProjectAuthCode();

        Assert.IsNotNull(projected.Resource,
            "A present resource claim must never project to null — that is 'no resource requested', "
            + "a distinct fact from 'present but malformed'.");

        bool projectsToAWellFormedResourceIndicator =
            Uri.TryCreate(projected.Resource, UriKind.Absolute, out Uri? parsedResource)
            && string.IsNullOrEmpty(parsedResource.Fragment);
        Assert.IsFalse(projectsToAWellFormedResourceIndicator,
            $"The blank array element must not be silently dropped, leaving only the well-formed "
            + $"entry as the projected resource. Projected value: '{projected.Resource}'.");
    }


    /// <summary>
    /// The JAR-by-value twin of <see cref="JarParRejectsMalformedResourceClaimWithInvalidTarget"/> —
    /// both JAR-bearing matchers share <c>VerifyAndValidateAuthCodeJarAsync</c>'s resource shape
    /// gate, but each caller applies its OWN error transport per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>:
    /// JAR-by-value has a redirect_uri to answer through (redirect), JAR-PAR does not (bare 400).
    /// </summary>
    [TestMethod]
    public async Task JarByValueRejectsMalformedResourceClaimWithInvalidTargetRedirect()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, Capabilities, PolicyProfile.Rfc6749WithPkce);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RedirectUri, "state-jar-direct-resource", "nonce-jar-direct-resource");
        claims[OAuthRequestParameterNames.Resource] = "not-a-uri";
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ExchangeContext context = new();
        context.SetSubjectId(SubjectId);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, response.StatusCode, response.Body);
        Assert.Contains($"error={OAuthErrors.InvalidTarget}", response.Location!, StringComparison.Ordinal,
            $"A malformed resource claim must redirect with error=invalid_target. Location: {response.Location}");
    }



    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>: "If the
    /// authorization server ... does not consider the resource(s) acceptable, it should reject the
    /// request." A well-formed <c>resource</c> the application does not consider acceptable is
    /// denied through the ordinary authorize-decision seam with the new
    /// <see cref="AuthorizationDenialReason.InvalidTarget"/> member, mapped to
    /// <c>invalid_target</c> — distinct from the library's own shape gate above, which never
    /// invokes the application seam at all.
    /// </summary>
    [TestMethod]
    public async Task ApplicationDenialWithInvalidTargetReasonProducesInvalidTargetError()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, _, _, _) => ValueTask.FromResult(
                evaluation.RequestedResource is { Count: > 0 }
                    ? AuthorizationRequestDecision.Deny(AuthorizationDenialReason.InvalidTarget)
                    : AuthorizationRequestDecision.Permit);

        string requestUri = await ExtractRequestUriAsync(
            await PushAsync(host, material, UngrantedResource).ConfigureAwait(false)).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains($"error={OAuthErrors.InvalidTarget}", authorizeResponse.Location!, StringComparison.Ordinal,
            $"An application denial with InvalidTarget must redirect with error=invalid_target. Location: {authorizeResponse.Location}");
    }



    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: no
    /// token-request <c>resource</c> — the full PAR-granted set applies. Named for the
    /// <c>authorization_code</c> grant this exercises (RFC 8693 Token Exchange is a distinct grant,
    /// covered separately by <c>TokenExchangeGrantTests</c>).
    /// </summary>
    [TestMethod]
    public async Task CodeRedemptionWithNoRequestResourceAppliesTheFullGrantedSetAsArrayAud()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: a
    /// token-request <c>resource</c> that is a subset of the granted set narrows the ACCESS token
    /// to that subset — the code-redemption half of Figure 3's example (the real-wire twin,
    /// <see cref="AuthCodeParPkceRealWireFlowTests.FullJourneyThreadsResourceIndicatorToArrayAudience"/>,
    /// proves the same narrowing over the real wire).
    /// </summary>
    [TestMethod]
    public async Task CodeRedemptionWithSubsetRequestResourceNarrowsAud()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, requestResource: ResourceA).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(1, aud);
        Assert.AreEqual(ResourceA, aud[0]);
    }


    /// <summary>
    /// Adversarial: <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>
    /// — a token-request resource NOT in the granted set is refused <c>invalid_target</c>.
    /// </summary>
    [TestMethod]
    public async Task CodeRedemptionWithResourceNotInGrantedSetIsRefusedInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, requestResource: UngrantedResource).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode);
        AssertErrorCode(tokenResponse, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// Adversarial, library posture (not a spec mandate):
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see> leaves
    /// the acceptable resource value(s) to the authorization server's "sole discretion" — this
    /// library exercises that discretion by refusing a token-request resource when NOTHING was
    /// granted at authorize time (an empty set to narrow from), fail-closed rather than silently
    /// ignored.
    /// </summary>
    [TestMethod]
    public async Task CodeRedemptionWithResourceButNothingGrantedIsRefusedInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, resource: null).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, requestResource: ResourceA).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode);
        AssertErrorCode(tokenResponse, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// Regression guard: with no <c>resource</c> requested anywhere, the pre-existing
    /// <see cref="ClientRecord.ScopeToAudience"/> fallback still applies unchanged — only now
    /// always as a JSON array (the producer-wide unification per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>'s
    /// general representation), never a bare string;
    /// <see cref="DecodeAudienceFromTokenResponse"/> itself pins the array shape and fails on a
    /// bare string, so this test's assertions cannot pass on the old dual-shape wire form.
    /// </summary>
    [TestMethod]
    public async Task NoResourceAnywhereFallsBackToScopeToAudienceAsArray()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, resource: null, scope: WellKnownScopes.OpenId).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(1, aud);
        Assert.AreEqual("https://rs.example.com", aud[0],
            "With no resource anywhere, RegisterDpopClient's ScopeToAudience[openid] fallback must still resolve the aud.");
    }


    /// <summary>
    /// Precedence (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>'s
    /// SHOULD to audience-restrict to the indicated resource(s)): a granted <c>resource</c> wins
    /// over <see cref="ClientRecord.ScopeToAudience"/> even when the granted scope also maps to an
    /// audience there — the resource-driven value is the one that reaches <c>aud</c>.
    /// </summary>
    [TestMethod]
    public async Task GrantedResourceTakesPrecedenceOverScopeToAudience()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, ResourceA, scope: WellKnownScopes.OpenId).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(1, aud);
        Assert.AreEqual(ResourceA, aud[0],
            "The granted resource must win over ScopeToAudience['openid'] = 'https://rs.example.com'.");
    }



    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: a
    /// refresh-request resource narrows the refreshed access token to that subset (Figure 5/6's
    /// example).
    /// </summary>
    [TestMethod]
    public async Task RefreshWithSubsetResourceNarrowsAud()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        ServerHttpResponse refreshResponse = await RefreshAsync(
            host, material, refreshToken, requestResource: ResourceB).ConfigureAwait(false);

        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(refreshResponse.Body);
        Assert.HasCount(1, aud);
        Assert.AreEqual(ResourceB, aud[0]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>'s central
    /// example: "any refresh token that is returned is bound to the full original grant" — after a
    /// narrowed refresh, the ROTATED refresh token is still bound to the FULL original grant, not
    /// the prior narrowed subset — a subsequent no-resource refresh proves it.
    /// </summary>
    [TestMethod]
    public async Task RefreshTokenStaysBoundToFullGrantAcrossANarrowedRefresh()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        ServerHttpResponse narrowedRefresh = await RefreshAsync(
            host, material, refreshToken, requestResource: ResourceA).ConfigureAwait(false);
        Assert.AreEqual(200, narrowedRefresh.StatusCode, narrowedRefresh.Body);
        string rotatedRefreshToken = ExtractStringProperty(narrowedRefresh.Body, "refresh_token");

        ServerHttpResponse fullRefreshAgain = await RefreshAsync(
            host, material, rotatedRefreshToken, requestResource: null).ConfigureAwait(false);

        Assert.AreEqual(200, fullRefreshAgain.StatusCode, fullRefreshAgain.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(fullRefreshAgain.Body);
        Assert.HasCount(2, aud,
            "The rotated refresh token must still carry the FULL original grant, not the prior narrowed subset.");
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// Adversarial: <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>
    /// — a refresh-request resource NOT in the granted set is refused <c>invalid_target</c>.
    /// </summary>
    [TestMethod]
    public async Task RefreshWithResourceNotInGrantedSetIsRefusedInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        ServerHttpResponse refreshResponse = await RefreshAsync(
            host, material, refreshToken, requestResource: UngrantedResource).ConfigureAwait(false);

        Assert.AreEqual(400, refreshResponse.StatusCode);
        AssertErrorCode(refreshResponse, OAuthErrors.InvalidTarget);
    }



    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>:
    /// "multiple values are represented as an array of strings" inside a JWT-encoded authorization
    /// request. The JAR-PAR request object here carries the resource claim as a genuine JSON array
    /// (not the space-delimited string convention every other seam uses); it must still reach the
    /// token endpoint's granted set intact.
    /// </summary>
    [TestMethod]
    public async Task JarParArrayFormResourceClaimReachesTheGrantedSet()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        UpgradeToJarSigningCapable(host, material);
        host.SeedTestSubject(subject: SubjectId);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RedirectUri, "state-jar-par-array", "nonce-jar-par-array");
        claims[OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge;
        claims[OAuthRequestParameterNames.Resource] = new[] { ResourceA, ResourceB };
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = await ExtractRequestUriAsync(parResponse).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, pkce.EncodedVerifier).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }



    /// <summary>
    /// A <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>
    /// <c>resource</c> present on the direct (non-JAR) authorize path and its JAR-by-value twin
    /// must behave identically — both carry it into the same granted set and the same array
    /// <c>aud</c>. Fixes the code_challenge/verifier pair so the two runs are byte-comparable aside
    /// from the JAR envelope.
    /// </summary>
    [TestMethod]
    public async Task ResourceOnDirectAuthorizeAndItsJarByValueTwinBehaveIdentically()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        UpgradeToJarSigningCapable(host, material);
        host.SeedTestSubject(subject: SubjectId);

        PkceParameters directPkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields directFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = directPkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Resource] = ResourceA
        };
        ExchangeContext directContext = new();
        directContext.SetSubjectId(SubjectId);
        ServerHttpResponse directAuthorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            directFields, directContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, directAuthorizeResponse.StatusCode, directAuthorizeResponse.Body);
        string directCode = ExtractCode(directAuthorizeResponse.Location!);

        ServerHttpResponse directTokenResponse = await TokenAsync(
            host, material, directCode, directPkce.EncodedVerifier).ConfigureAwait(false);
        Assert.AreEqual(200, directTokenResponse.StatusCode, directTokenResponse.Body);
        List<string> directAud = DecodeAudienceFromTokenResponse(directTokenResponse.Body);

        PkceParameters jarPkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RedirectUri, "state-jar-direct-symmetry", "nonce-jar-direct-symmetry");
        claims[OAuthRequestParameterNames.CodeChallenge] = jarPkce.EncodedChallenge;
        claims[OAuthRequestParameterNames.Resource] = ResourceA;
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        RequestFields jarFields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ExchangeContext jarContext = new();
        jarContext.SetSubjectId(SubjectId);
        ServerHttpResponse jarAuthorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            jarFields, jarContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, jarAuthorizeResponse.StatusCode, jarAuthorizeResponse.Body);
        string jarCode = ExtractCode(jarAuthorizeResponse.Location!);

        ServerHttpResponse jarTokenResponse = await TokenAsync(
            host, material, jarCode, jarPkce.EncodedVerifier).ConfigureAwait(false);
        Assert.AreEqual(200, jarTokenResponse.StatusCode, jarTokenResponse.Body);
        List<string> jarAud = DecodeAudienceFromTokenResponse(jarTokenResponse.Body);

        Assert.AreSequenceEqual(directAud.OrderBy(v => v, StringComparer.Ordinal).ToList(),
            jarAud.OrderBy(v => v, StringComparer.Ordinal).ToList(),
            "resource on the direct-authorize path and its JAR-by-value twin must produce the same granted aud.");
    }



    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "Multiple
    /// 'resource' parameters MAY be used" — the direct (non-PAR) authorize path's own
    /// <c>ReadResource</c> read aggregates every repeated occurrence, not merely the PAR path's.
    /// </summary>
    [TestMethod]
    public async Task RepeatedResourceParametersAggregateAtDirectAuthorize()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        fields.Add(OAuthRequestParameterNames.Resource, ResourceA);
        fields.Add(OAuthRequestParameterNames.Resource, ResourceB);
        ExchangeContext context = new();
        context.SetSubjectId(SubjectId);

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, pkce.EncodedVerifier).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: the
    /// token endpoint's own resource read (feeding <c>ResolveEffectiveResource</c>) aggregates
    /// repeated <c>resource</c> parameters at CODE REDEMPTION, narrowing to exactly the
    /// two-of-three subset named — not merely accepting a single-valued narrowing request.
    /// </summary>
    [TestMethod]
    public async Task RepeatedResourceParametersNarrowAtCodeRedemption()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        const string ResourceC = "https://files.example.com/";
        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB, ResourceC]).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, [ResourceA, ResourceB]).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: the
    /// refresh endpoint's own resource read aggregates repeated <c>resource</c> parameters too,
    /// narrowing the refreshed access token to exactly the two-of-three subset named.
    /// </summary>
    [TestMethod]
    public async Task RepeatedResourceParametersNarrowAtRefresh()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        const string ResourceC = "https://files.example.com/";
        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB, ResourceC]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        ServerHttpResponse refreshResponse = await RefreshAsync(
            host, material, refreshToken, [ResourceA, ResourceB]).ConfigureAwait(false);

        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(refreshResponse.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: the
    /// multi-resource wire form is the REPEATED <c>resource</c> parameter, never several URIs
    /// packed into ONE occurrence separated by spaces — a resource indicator IS one absolute URI
    /// (RFC 3986 §2 / Appendix A's ABNF forbids a raw space inside one). A single occurrence
    /// carrying an embedded space must FAIL the shape gate, not be silently recovered by splitting
    /// it into two.
    /// </summary>
    [TestMethod]
    public async Task SpaceJoinedSingleResourceValueFailsShapeGateAtPushedAuthorizationRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(
            host, material, $"{ResourceA} {ResourceB}").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>: "If the
    /// authorization server fails to parse the provided value(s) ..., it should reject the request
    /// ... with the 'invalid_target' error." A resource parameter PRESENT but empty is a parse
    /// failure, not "no resource requested" — it must not be silently treated as absent.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceValueIsMalformedAtPushedAuthorizationRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);

        ServerHttpResponse response = await PushAsync(host, material, "").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// The token-request twin of <see cref="EmptyResourceValueIsMalformedAtPushedAuthorizationRequest"/> —
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>'s
    /// <c>invalid_target</c> ("missing, unknown, or malformed") covers a present-but-empty
    /// <c>resource</c> at CODE REDEMPTION too — refused by <c>ResolveEffectiveResource</c>, not
    /// treated as "no narrowing requested".
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceValueIsMalformedAtCodeRedemption()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, requestResource: "").ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode);
        AssertErrorCode(tokenResponse, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: the resource
    /// indicator set is a SET — a client that repeats the identical indicator must not duplicate it
    /// in the issued <c>aud</c>.
    /// </summary>
    [TestMethod]
    public async Task DuplicateResourceIndicatorsAreDeduplicatedInAud()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceA]).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(1, aud, "A repeated identical resource indicator must not duplicate in aud.");
        Assert.AreEqual(ResourceA, aud[0]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: the
    /// <c>client_credentials</c> grant has no prior authorization to narrow against, so a validated
    /// token-request <c>resource</c> IS the grant itself and feeds the issued access token's
    /// <c>aud</c> directly, as the RFC 7519 §4.1.3 array shape.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsWithResourceProducesArrayAudience()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials));
        const string ClientSecret = "s3cret-for-client-credentials";
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Resource] = ResourceA
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ClientCredentialsToken, WellKnownHttpMethods.Post,
            fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(response.Body);
        Assert.HasCount(1, aud);
        Assert.AreEqual(ResourceA, aud[0]);
    }


    /// <summary>
    /// The client_credentials twin of the PAR/authorize shape gate: a malformed
    /// <c>resource</c> at the <c>client_credentials</c> grant is rejected <c>invalid_target</c>
    /// the same way, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsRejectsMalformedResourceWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials));
        const string ClientSecret = "s3cret-for-client-credentials";
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Resource] = "not-a-uri"
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ClientCredentialsToken, WellKnownHttpMethods.Post,
            fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// The multi-value twin of <see cref="ClientCredentialsWithResourceProducesArrayAudience"/>:
    /// repeated <c>resource</c> parameters
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>'s genuine
    /// multi-resource wire form) at the <c>client_credentials</c> grant all become the grant
    /// itself, aggregated the same way
    /// <see cref="RepeatedResourceParametersAggregateAtDirectAuthorize"/> proves for the
    /// authorization-code family.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsWithRepeatedResourceProducesArrayAudience()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials));
        const string ClientSecret = "s3cret-for-client-credentials";
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret
        };
        fields.Add(OAuthRequestParameterNames.Resource, ResourceA);
        fields.Add(OAuthRequestParameterNames.Resource, ResourceB);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ClientCredentialsToken, WellKnownHttpMethods.Post,
            fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(response.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 §2.2</see>: the RFC
    /// 8693 §4.5 SAML-to-OAuth refresh-token mint carries the exchange's granted audience onto the
    /// minted <c>ServerRefreshTokenIssuedState.Resource</c>, so a LATER <c>refresh_token</c> grant
    /// redeeming it narrows against the real grant instead of failing closed with "none were
    /// granted".
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeRefreshMintCarriesGrantForLaterNarrowing()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            //BuildRefreshToken (the redemption endpoint refreshing this exchange-minted token
            //below) is gated by OAuthAuthorizationCode, not OAuthRefreshToken — refresh redemption
            //is part of the authorization_code family's endpoint chain regardless of which grant
            //originally minted the refresh token being redeemed.
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthRefreshToken));

        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) => ValueTask.FromResult(true);
        host.Server.OAuth().ValidateTokenExchangeTokenAsync =
            static (token, tokenType, registration, context, ct) =>
                ValueTask.FromResult<ValidatedSecurityToken?>(
                    new ValidatedSecurityToken { Subject = SubjectId, Scope = WellKnownScopes.OpenId });
        host.Server.OAuth().AuthorizeTokenExchangeAsync =
            static (subject, actor, request, registration, context, ct) =>
                ValueTask.FromResult<TokenExchangeAuthorization?>(
                    new TokenExchangeAuthorization
                    {
                        Subject = subject.Subject,
                        Scope = subject.Scope ?? string.Empty,
                        Audience = [ResourceA, ResourceB],
                        IssuedTokenType = TokenType.RefreshToken
                    });

        RequestFields exchangeFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.SubjectToken] = "subject-token-blob",
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.AccessToken)
        };
        ServerHttpResponse exchangeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.TokenExchangeToken, WellKnownHttpMethods.Post,
            exchangeFields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, exchangeResponse.StatusCode, exchangeResponse.Body);

        using JsonDocument exchangeBody = JsonDocument.Parse(exchangeResponse.Body);
        string mintedRefreshToken = exchangeBody.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        //A resource NOT in the exchange's granted audience is refused invalid_target, not silently
        //accepted — proving the grant carried onto the refresh state is actually enforced. Checked
        //BEFORE the successful narrowed refresh below: a rejected refresh must not rotate/consume
        //the refresh token (RFC 9700 §2.2.2 rotation applies only on a SUCCESSFUL exchange), so the
        //ordering itself is part of what this test proves.
        ServerHttpResponse rejectedRefresh = await RefreshAsync(
            host, material, mintedRefreshToken, requestResource: UngrantedResource).ConfigureAwait(false);
        Assert.AreEqual(400, rejectedRefresh.StatusCode);
        AssertErrorCode(rejectedRefresh, OAuthErrors.InvalidTarget);

        //A subset of the exchange's granted audience succeeds and narrows the refreshed aud.
        ServerHttpResponse narrowedRefresh = await RefreshAsync(
            host, material, mintedRefreshToken, requestResource: ResourceA).ConfigureAwait(false);
        Assert.AreEqual(200, narrowedRefresh.StatusCode, narrowedRefresh.Body);
        List<string> narrowedAud = DecodeAudienceFromTokenResponse(narrowedRefresh.Body);
        Assert.HasCount(1, narrowedAud);
        Assert.AreEqual(ResourceA, narrowedAud[0]);
    }


    /// <summary>
    /// <see cref="AccessTokenAudPolicy.Suppressed"/> wins even over a validated, populated RFC 8707
    /// <c>resource</c> request — the deployment's explicit choice overrides
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>'s SHOULD to
    /// audience-restrict, per <see cref="Rfc9068AccessTokenProducer"/>'s own remarks.
    /// </summary>
    [TestMethod]
    public async Task SuppressedAudPolicyOmitsAudEvenWithValidatedResource()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities);
        host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);

        //ResolvePolicyAsync runs unconditionally at dispatch entry (EndpointServer step 2.5) and
        //ApplyRfc6749WithPkce sets AccessTokenAudPolicy.Optional there, so setting it directly on a
        //pre-dispatch ExchangeContext would be clobbered before the token endpoint ever reads it.
        //Wrap the profile's own resolver instead: run the normal profile resolution, then override
        //just this one axis to Suppressed for this request.
        host.Server.OAuth().ResolvePolicyAsync = async (registration, ctx, ct) =>
        {
            await PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, ctx, ct).ConfigureAwait(false);
            ctx.SetAccessTokenAudPolicy(AccessTokenAudPolicy.Suppressed);
        };

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = verifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, WellKnownHttpMethods.Post,
            tokenFields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument responseDoc = JsonDocument.Parse(tokenResponse.Body);
        string accessToken = responseDoc.RootElement.GetProperty("access_token").GetString()!;
        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], BaseMemoryPool.Shared);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Aud, out _),
            "AccessTokenAudPolicy.Suppressed must win even over a validated, populated RFC 8707 resource.");
    }


    private async Task<ServerHttpResponse> PushAsync(
        TestHostShell host, VerifierKeyMaterial material, string? resource, string? scope = null)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope ?? WellKnownScopes.OpenId
        };
        if(resource is not null)
        {
            parFields[OAuthRequestParameterNames.Resource] = resource;
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Drives PAR + authorize for a single <paramref name="resource"/> and returns (code, PKCE verifier).</summary>
    private Task<(string Code, string Verifier)> PushAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material, string? resource, string? scope = null) =>
        PushAuthorizeAsync(host, material, resource is null ? null : [resource], scope);


    /// <summary>
    /// Drives PAR + authorize for <paramref name="resources"/> and returns (code, PKCE verifier).
    /// Each entry becomes its OWN repeated <c>resource</c> field occurrence (<see cref="RequestFields.Add"/>)
    /// — the genuine RFC 8707 §2 multi-resource wire form — never a single space-joined value.
    /// </summary>
    private async Task<(string Code, string Verifier)> PushAuthorizeAsync(
        TestHostShell host, VerifierKeyMaterial material, IReadOnlyList<string>? resources, string? scope = null)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope ?? WellKnownScopes.OpenId
        };
        if(resources is not null)
        {
            foreach(string resource in resources)
            {
                parFields.Add(OAuthRequestParameterNames.Resource, resource);
            }
        }

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = await ExtractRequestUriAsync(parResponse).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        return (ExtractCode(authorizeResponse.Location!), pkce.EncodedVerifier);
    }


    private Task<ServerHttpResponse> TokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string code, string verifier, string? requestResource = null) =>
        TokenAsync(host, material, code, verifier, requestResource is null ? null : [requestResource]);


    /// <summary>
    /// Redeems <paramref name="code"/> at the token endpoint. Each entry of
    /// <paramref name="requestResources"/> becomes its OWN repeated <c>resource</c> field
    /// occurrence (<see cref="RequestFields.Add"/>), proving the token endpoint's own read
    /// aggregates repeated parameters the same way PAR/authorize do.
    /// </summary>
    private async Task<ServerHttpResponse> TokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string code, string verifier,
        IReadOnlyList<string>? requestResources)
    {
        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = verifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        if(requestResources is not null)
        {
            foreach(string requestResource in requestResources)
            {
                tokenFields.Add(OAuthRequestParameterNames.Resource, requestResource);
            }
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private Task<ServerHttpResponse> RefreshAsync(
        TestHostShell host, VerifierKeyMaterial material, string refreshToken, string? requestResource) =>
        RefreshAsync(host, material, refreshToken, requestResource is null ? null : [requestResource]);


    /// <summary>
    /// Refreshes <paramref name="refreshToken"/>. Each entry of <paramref name="requestResources"/>
    /// becomes its OWN repeated <c>resource</c> field occurrence (<see cref="RequestFields.Add"/>),
    /// proving the refresh endpoint's own read aggregates repeated parameters too.
    /// </summary>
    private async Task<ServerHttpResponse> RefreshAsync(
        TestHostShell host, VerifierKeyMaterial material, string refreshToken, IReadOnlyList<string>? requestResources)
    {
        RequestFields refreshFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        if(requestResources is not null)
        {
            foreach(string requestResource in requestResources)
            {
                refreshFields.Add(OAuthRequestParameterNames.Resource, requestResource);
            }
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            refreshFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static Task<string> ExtractRequestUriAsync(ServerHttpResponse parResponse)
    {
        using JsonDocument parBody = JsonDocument.Parse(parResponse.Body);

        return Task.FromResult(parBody.RootElement.GetProperty("request_uri").GetString()!);
    }


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

        throw new InvalidOperationException($"Authorize redirect did not carry a code parameter. Got: {location}");
    }


    private static string ExtractStringProperty(string json, string propertyName)
    {
        using JsonDocument doc = JsonDocument.Parse(json);

        return doc.RootElement.GetProperty(propertyName).GetString()!;
    }


    /// <summary>
    /// Decodes the issued access token from a token-endpoint response body and returns its
    /// <c>aud</c> claim values. PINS the RFC 7519 §4.1.3 JSON array wire shape — fails the
    /// assertion below on a bare string — because that shape is this producer's own rule
    /// (<c>JwtPayloadExtensions.ForAccessToken</c> always emits an array, including a single
    /// audience) and every caller's array-shape assertions depend on the decoder actually
    /// enforcing it rather than silently tolerating a dual shape.
    /// </summary>
    private static List<string> DecodeAudienceFromTokenResponse(string tokenResponseBody)
    {
        using JsonDocument responseDoc = JsonDocument.Parse(tokenResponseBody);
        string accessToken = responseDoc.RootElement.GetProperty("access_token").GetString()!;

        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], BaseMemoryPool.Shared);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);

        JsonElement aud = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);
        Assert.AreEqual(JsonValueKind.Array, aud.ValueKind,
            $"aud must always be the RFC 7519 §4.1.3 JSON array shape, never a bare string. Payload: {payload.RootElement}");

        return aud.EnumerateArray().Select(e => e.GetString()!).ToList();
    }


    /// <summary>
    /// Adds the <see cref="KeyUsageContext.JarSigning"/> slot (reusing <paramref name="material"/>'s
    /// already-registered signing key) to a <see cref="TestHostShell.RegisterDpopClient"/>
    /// registration, so a single client can both sign a JAR and receive an access token —
    /// <see cref="TestHostShell.RegisterClient"/>/<see cref="TestHostShell.RegisterJarSigningClient"/>
    /// register JAR verification only, with no <see cref="KeyUsageContext.AccessTokenIssuance"/> key.
    /// </summary>
    private static void UpgradeToJarSigningCapable(TestHostShell host, VerifierKeyMaterial material)
    {
        ClientRecord previous = material.Registration;
        Dictionary<KeyUsageContext, SigningKeySet> signingKeys = new(previous.SigningKeys)
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet { Current = [material.SigningKeyId] }
        };
        ClientRecord updated = previous with
        {
            SigningKeys = signingKeys
        };
        host.Server.UpdateClient(previous, updated, new ExchangeContext());
        material.Registration = updated;
    }


    private static void AssertErrorCode(ServerHttpResponse response, string expectedCode)
    {
        string expectedFragment = $"\"error\":\"{expectedCode}\"";
        Assert.Contains(expectedFragment, response.Body, StringComparison.Ordinal,
            $"Expected error '{expectedCode}' in response body. Got: {response.Body}");
    }
}
