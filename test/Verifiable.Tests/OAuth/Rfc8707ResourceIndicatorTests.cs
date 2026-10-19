using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Jarm;
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
/// and the JAR §2.1 JSON-array resource claim form. A row that starts the HTTP host
/// (<see cref="TestHostShell.StartHttpHostAsync(CancellationToken)"/>) or uses a
/// <see cref="RawAuthCodeWirePushers"/> driver runs over the real loopback listener; every other row
/// dispatches in-process through
/// <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>.
/// The real-wire resource-pinned array-<c>aud</c> capstone and the refresh-narrowing exchange live in
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

    /// <summary>
    /// The <c>invalid_target</c> JSON body every parse-time refusal of a malformed <c>resource</c>
    /// value answers with, regardless of which grammar part failed
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its
    /// value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]. The URI MUST NOT
    /// include a fragment component.").
    /// </summary>
    private static string MalformedResourceIndicatorBody { get; } =
        $"{{\"error\":\"{OAuthErrors.InvalidTarget}\",\"error_description\":\"The resource parameter " +
        "must be an absolute URI (RFC 3986 section 4.3) without a fragment.\"}";

    /// <summary>
    /// The <c>error_description</c> text every parse-time refusal of a malformed <c>resource</c>
    /// value carries, whether it rides a JSON body (<see cref="MalformedResourceIndicatorBody"/>) or
    /// the query of an error redirect
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section
    /// 4.1.2.1</see>).
    /// </summary>
    private static string MalformedResourceIndicatorDescription { get; } =
        "The resource parameter must be an absolute URI (RFC 3986 section 4.3) without a fragment.";

    /// <summary>
    /// The <c>state</c> claim every request object <see cref="BuildResourceJarAsync"/> signs carries,
    /// so a row can assert the error redirect echoes the request object's own <c>state</c>.
    /// </summary>
    private static string ResourceJarState { get; } = "state-fold-resource";

    private static Uri ClientBaseUri { get; } = new(ClientId);
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        ServerHttpResponse response = await PushAsync(host, material, "not-a-uri").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// A repeated <c>resource</c> parameter (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC
    /// 8707 section 2</see>'s multi-resource wire form) where one occurrence is a well-formed URI and
    /// the OTHER is empty is a request naming exactly that one indicator: the PAR request is
    /// accepted and the redeemed <c>aud</c> carries the one indicator. A blank element inside a
    /// request object's <c>resource</c> claim is a different fact, not a parameter sent without a
    /// value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestDropsAnEmptyResourceOccurrenceMixedWithValidOne()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ["", ResourceA]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.AreSequenceEqual([ResourceA], DecodeAudienceFromTokenResponse(tokenResponse.Body));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "The URI MUST
    /// NOT include a fragment component."
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsResourceWithFragmentWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        ServerHttpResponse response = await PushAsync(
            host, material, "https://api.example.com/orders#frag").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "Its value
    /// MUST be an absolute URI". A relative value has no scheme
    /// (<see cref="ResourceIndicator.Parse"/> finds no <c>:</c> before a
    /// character the <c>scheme</c> production disallows) and must be refused on every platform, not
    /// merely on Windows where <see cref="UriKind.Absolute"/> alone would already fail it.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsRelativeResourceWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        ServerHttpResponse response = await PushAsync(host, material, "/relative/path").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see> places no
    /// scheme restriction on the resource value — "Its value MUST be an absolute URI ... The URI
    /// MUST NOT include a fragment component", nothing more. A non-https/http/urn absolute URI
    /// (here <c>mailto:</c>, chosen because it has no authority component at all — the strongest
    /// case that this is genuinely scheme-agnostic, not merely "any scheme with a host") must be
    /// ACCEPTED, proving the shape gate does not allowlist schemes.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestAcceptsNonAllowlistedSchemeAbsoluteUri()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        ServerHttpResponse response = await PushAsync(
            host, material, "https://api.example.com/orders?scope=read").ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "Its value
    /// MUST be an absolute URI". A Windows-style path carries a backslash, a character none of the
    /// <c>scheme</c>, <c>path</c> or <c>query</c> productions admit
    /// (<see cref="ResourceIndicator.Parse"/>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>), so
    /// the grammar itself refuses it, never .NET's implicit path-to-<c>file:</c>-URI coercion, which
    /// this reader never consults, exactly like the Unix leading-slash case
    /// <see cref="PushedAuthorizationRequestRejectsRelativeResourceWithInvalidTarget"/> covers.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestRejectsWindowsStylePathWithInvalidTarget()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        ServerHttpResponse response = await PushAsync(host, material, @"C:\Windows\System32").ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// The mirror of the two grammar tests above: <c>file:///srv/resources/orders</c> is an
    /// <c>absolute-URI</c> with an empty authority (the <c>//</c> after the scheme's <c>:</c> is
    /// present, so <see cref="ResourceIndicator.Parse"/> reads a genuine,
    /// deliberate <c>file:</c> indicator; <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>
    /// places no scheme restriction) and must be ACCEPTED, a genuinely different shape from the
    /// Windows path above, which carries no <c>//</c> and no scheme at all.
    /// </summary>
    [TestMethod]
    public async Task PushedAuthorizationRequestAcceptsExplicitFileSchemeResource()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Resource] = "not-a-uri"
        };
        ExchangeContext context = [];
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/callback",
            [OAuthRequestParameterNames.Resource] = "not-a-uri"
        };
        ExchangeContext context = [];
        context.SetSubjectId(SubjectId);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            fields, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsNull(response.Location,
            "An unregistered redirect_uri must never be redirected to, regardless of any other request defect.");
        AssertErrorCode(response, OAuthErrors.InvalidRequest);
        Assert.Contains("not among the registered redirect URIs", response.Body, StringComparison.Ordinal,
            $"The refusal must name the unregistered redirect_uri, not a different bare-400 gate. Body: {response.Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section
    /// 4.1.2.1</see>: "If the request fails due to a missing, invalid, or mismatching redirection URI,
    /// or if the client identifier is missing or invalid, the authorization server SHOULD inform the
    /// resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid
    /// redirection URI." A direct authorize GET over the listener carries a <c>redirect_uri</c> that
    /// is not registered and a <c>resource</c> whose host carries U+212A (KELVIN SIGN), outside
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 section 2</see>'s
    /// US-ASCII grammar, a defect that would otherwise answer with an <c>invalid_target</c> error
    /// redirect. The answer is a 400 with no <c>Location</c> header, and its body names the
    /// unregistered <c>redirect_uri</c>, not the resource.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task DirectAuthorizeOverTheWireDoesNotRedirectToAnUnregisteredRedirectUriWithANonAsciiResourceAsync()
    {
        const string unregisteredRedirectUri = "https://attacker.example.com/callback";
        string resource = "https://" + char.ConvertFromUtf32(0x212A) + "ey.example/";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        List<KeyValuePair<string, string>> fields = BuildAuthorizationFields(pkce, resource);
        int redirectUriIndex = fields.FindIndex(
            static field => field.Key == OAuthRequestParameterNames.RedirectUri);
        fields[redirectUriIndex] = new(OAuthRequestParameterNames.RedirectUri, unregisteredRedirectUri);

        Uri authorizeUri = RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment, fields);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.IsNull(response.Headers.Location,
            "An unregistered redirect_uri must never be redirected to, regardless of any other request defect.");
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", body, StringComparison.Ordinal, body);
        Assert.Contains("not among the registered redirect URIs", body, StringComparison.Ordinal, body);
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, Capabilities).ConfigureAwait(false);

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
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see>'s array
    /// form of the <c>resource</c> claim can carry a blank element alongside a well-formed one. A
    /// blank element has no indicator to contribute, so the JAR projection
    /// (<c>AuthCodeRequestObjectExtensions.ProjectAuthCode</c>'s <c>ReadResourceClaim</c>) must
    /// treat the whole claim as malformed rather than silently dropping the blank entry and
    /// carrying the well-formed one alone into <see cref="AuthCodeRequestObject.Resource"/>. A blank
    /// element inside a claim is not a parameter sent without a value, so
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>'s
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// does not reach it, unlike an empty form occurrence, which the query-string twin
    /// (<c>ReadResource</c>, proven by
    /// <see cref="PushedAuthorizationRequestDropsAnEmptyResourceOccurrenceMixedWithValidOne"/>) drops.
    /// Constructed directly against <see cref="JarVerified"/>, a supported public
    /// entry point — because a genuinely blank JSON array element, once it crosses the wire and is
    /// re-parsed into the verified claims dictionary, is a runtime shape
    /// (<c>List&lt;object&gt;</c>) whose own empty-string filtering already collapses the claim to
    /// the single well-formed entry before <c>ReadResourceClaim</c> ever runs; driving the same
    /// defect through a real signed JAR round-trip would exercise that filtering instead of the
    /// fix. The resulting projected <see cref="AuthCodeRequestObject.Resource"/> is checked against
    /// RFC 8707 section 2's own resource-indicator shape (an absolute URI with no fragment
    /// component), the same grammar <c>ValidateResourceIndicatorsShape</c> applies downstream via
    /// <see cref="ResourceIndicator.Parse"/>, whose rejection is what
    /// ultimately produces <c>invalid_target</c> on the wire: silently dropping the blank entry would leave a bare,
    /// well-formed resource indicator here; failing closed leaves a value that itself is not one.
    /// </summary>
    [TestMethod]
    public void JarResourceClaimWithMixedEmptyAndValidEntriesProjectsToAMalformedIndicator()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();
        var claims = new Dictionary<string, object?>()
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
        JarVerified verified = new([], claims, now, now, now.AddMinutes(5));

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, Capabilities, PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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
        ExchangeContext context = [];
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
    /// request". A well-formed <c>resource</c> the application does not consider acceptable is
    /// denied through the ordinary authorize-decision seam with
    /// <see cref="AuthorizationDenialReason.InvalidTarget"/>, mapped to
    /// <c>invalid_target</c> — distinct from the library's own shape gate above, which never
    /// invokes the application seam at all.
    /// </summary>
    [TestMethod]
    public async Task ApplicationDenialWithInvalidTargetReasonProducesInvalidTargetError()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, _, _, _) => ValueTask.FromResult(
                    evaluation.RequestedResource is { Count: > 0 }
                        ? AuthorizationRequestDecision.Deny(AuthorizationDenialReason.InvalidTarget)
                        : AuthorizationRequestDecision.Permit());
        }).ConfigureAwait(false);

        string requestUri = await ExtractRequestUriAsync(
            await PushAsync(host, material, UngrantedResource).ConfigureAwait(false)).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, requestResource: UngrantedResource).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode);
        AssertErrorCode(tokenResponse, OAuthErrors.InvalidTarget);

        //Discriminator: the refusal did not consume the code — a resource inside the granted set
        //still redeems it.
        ServerHttpResponse redeemedResponse = await TokenAsync(
            host, material, code, verifier, requestResource: ResourceA).ConfigureAwait(false);
        Assert.AreEqual(200, redeemedResponse.StatusCode, redeemedResponse.Body);
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, resource: null).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, requestResource: ResourceA).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode);
        AssertErrorCode(tokenResponse, OAuthErrors.InvalidTarget);

        //Discriminator: the refusal did not consume the code — a resourceless redemption (nothing
        //to narrow, nothing requested) still succeeds.
        ServerHttpResponse redeemedResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(200, redeemedResponse.StatusCode, redeemedResponse.Body);
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        ServerHttpResponse refreshResponse = await RefreshAsync(
            host, material, refreshToken, requestResource: UngrantedResource).ConfigureAwait(false);

        Assert.AreEqual(400, refreshResponse.StatusCode);
        AssertErrorCode(refreshResponse, OAuthErrors.InvalidTarget);

        //Discriminator: the refusal did not consume the refresh token — a resource inside the
        //granted set still refreshes it.
        ServerHttpResponse refreshedResponse = await RefreshAsync(
            host, material, refreshToken, requestResource: ResourceA).ConfigureAwait(false);
        Assert.AreEqual(200, refreshedResponse.StatusCode, refreshedResponse.Body);
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        await UpgradeToJarSigningCapableAsync(host, material).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
            parFields, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = await ExtractRequestUriAsync(parResponse).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        await UpgradeToJarSigningCapableAsync(host, material).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        PkceParameters directPkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields directFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = directPkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Resource] = ResourceA
        };
        ExchangeContext directContext = [];
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
        ExchangeContext jarContext = [];
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
    /// &quot;resource&quot; parameters MAY be used" — the direct (non-PAR) authorize path's own
    /// <c>ReadResource</c> read aggregates every repeated occurrence, not merely the PAR path's.
    /// </summary>
    [TestMethod]
    public async Task RepeatedResourceParametersAggregateAtDirectAuthorize()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        fields.Add(OAuthRequestParameterNames.Resource, ResourceA);
        fields.Add(OAuthRequestParameterNames.Resource, ResourceB);
        ExchangeContext context = [];
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
    /// it into two. The refusal answers the fixed malformed-resource <c>invalid_target</c> body, and
    /// the request trace names the first part of the value as received that fails
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>'s
    /// <c>absolute-URI</c> grammar: the space is a character no <c>path-abempty</c> segment admits,
    /// so the fault is <c>Path</c>.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task SpaceJoinedSingleResourceValueFailsShapeGateAtPushedAuthorizationRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(SpaceJoinedSingleResourceValueFailsShapeGateAtPushedAuthorizationRequest));
        _ = root.Start();

        ServerHttpResponse response = await PushAsync(
            host, material, $"{ResourceA} {ResourceB}").ConfigureAwait(false);

        root.Stop();

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidTarget);
        Assert.AreEqual(MalformedResourceIndicatorBody, response.Body);
        Assert.AreSequenceEqual(["Path"], ReadMalformedResourceFaultNames(capture, root));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// A PAR request whose only <c>resource</c> occurrence is empty is a request without a
    /// <c>resource</c> parameter: it is accepted, and the redeemed <c>aud</c> is the one the same
    /// request has with the parameter absent (<see cref="NoResourceAnywhereFallsBackToScopeToAudienceAsArray"/>).
    /// A blank element inside a request object's <c>resource</c> claim is a different fact, not a
    /// parameter sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceValueAtPushedAuthorizationRequestIsOmitted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, [""]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.AreSequenceEqual(["https://rs.example.com"], DecodeAudienceFromTokenResponse(tokenResponse.Body));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A code redemption whose only <c>resource</c> occurrence is
    /// empty is a redemption without a <c>resource</c> parameter: the full granted set applies, as
    /// <see cref="CodeRedemptionWithNoRequestResourceAppliesTheFullGrantedSetAsArrayAud"/> asserts for the
    /// parameter absent. A blank element inside a request object's <c>resource</c> claim is a
    /// different fact, not a parameter sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceValueAtCodeRedemptionIsOmitted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await TokenAsync(
            host, material, code, verifier, requestResource: "").ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(tokenResponse.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// The all-whitespace counterpart of <see cref="EmptyResourceValueAtCodeRedemptionIsOmitted"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see> makes
    /// only a parameter sent WITHOUT a value an omitted one, and a whitespace-only value is a value
    /// that
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see> refuses
    /// (<c>invalid_target</c>, "missing, unknown, or malformed") at CODE REDEMPTION, by the step's own
    /// occurrence check (<c>ValidateResourceOccurrences</c>) before the presented
    /// <c>code</c> is ever looked up, so the refusal is byte-identical for a code that was never
    /// issued and one that was; a subsequent presentation with a correctly-shaped
    /// <c>resource</c> redeems the live code. The refusal answers the fixed malformed-resource
    /// <c>invalid_target</c> body, and each refusal's request trace names the first part of the
    /// value as received that fails
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>'s
    /// <c>scheme</c> production: a space is no <c>ALPHA</c>, so the fault is <c>Scheme</c>.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task WhitespaceResourceValueIsMalformedAtCodeRedemption()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(WhitespaceResourceValueIsMalformedAtCodeRedemption));
        _ = root.Start();

        ServerHttpResponse whitespaceResourceResponse = await TokenAsync(
            host, material, code, verifier, requestResource: "   ").ConfigureAwait(false);
        ServerHttpResponse unknownCodeWhitespaceResourceResponse = await TokenAsync(
            host, material, "code-never-issued-by-this-host", verifier, requestResource: "   ").ConfigureAwait(false);

        root.Stop();

        Assert.AreEqual(400, whitespaceResourceResponse.StatusCode);
        AssertErrorCode(whitespaceResourceResponse, OAuthErrors.InvalidTarget);
        Assert.AreEqual(MalformedResourceIndicatorBody, whitespaceResourceResponse.Body);
        Assert.AreSequenceEqual(["Scheme", "Scheme"], ReadMalformedResourceFaultNames(capture, root));
        Assert.AreEqual(unknownCodeWhitespaceResourceResponse.StatusCode, whitespaceResourceResponse.StatusCode);
        Assert.AreEqual(unknownCodeWhitespaceResourceResponse.Body, whitespaceResourceResponse.Body,
            "A live code's existence must not be discoverable from an all-whitespace resource value's refusal.");

        ServerHttpResponse successfulRedemption = await TokenAsync(
            host, material, code, verifier, requestResource: ResourceA).ConfigureAwait(false);
        Assert.AreEqual(200, successfulRedemption.StatusCode, successfulRedemption.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A refresh whose only <c>resource</c> occurrence is empty is
    /// a refresh without a <c>resource</c> parameter: the full granted set stays in force. A blank
    /// element inside a request object's <c>resource</c> claim is a different fact, not a parameter
    /// sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceValueAtRefreshIsOmitted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        ServerHttpResponse refreshResponse = await RefreshAsync(
            host, material, refreshToken, requestResource: "").ConfigureAwait(false);

        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        List<string> aud = DecodeAudienceFromTokenResponse(refreshResponse.Body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// The all-whitespace counterpart of <see cref="EmptyResourceValueAtRefreshIsOmitted"/>:
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see> makes
    /// only a parameter sent WITHOUT a value an omitted one, and a whitespace-only value is a value
    /// that
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see> refuses
    /// (<c>invalid_target</c>) at REFRESH, by the same request-only shape check, before the presented
    /// <c>refresh_token</c> is ever looked up, so the refusal is byte-identical for a refresh token
    /// that was never issued and one that was; a subsequent presentation with a correctly-shaped
    /// <c>resource</c> refreshes. The refusal answers the fixed malformed-resource
    /// <c>invalid_target</c> body, and each refusal's request trace names the first part of the
    /// value as received that fails
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>'s
    /// <c>scheme</c> production: a space is no <c>ALPHA</c>, so the fault is <c>Scheme</c>.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task WhitespaceResourceValueIsMalformedAtRefresh()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(WhitespaceResourceValueIsMalformedAtRefresh));
        _ = root.Start();

        ServerHttpResponse whitespaceResourceRefresh = await RefreshAsync(
            host, material, refreshToken, requestResource: "   ").ConfigureAwait(false);
        ServerHttpResponse unknownTokenWhitespaceResourceRefresh = await RefreshAsync(
            host, material, "refresh-token-never-issued-by-this-host", requestResource: "   ").ConfigureAwait(false);

        root.Stop();

        Assert.AreEqual(400, whitespaceResourceRefresh.StatusCode);
        AssertErrorCode(whitespaceResourceRefresh, OAuthErrors.InvalidTarget);
        Assert.AreEqual(MalformedResourceIndicatorBody, whitespaceResourceRefresh.Body);
        Assert.AreSequenceEqual(["Scheme", "Scheme"], ReadMalformedResourceFaultNames(capture, root));
        Assert.AreEqual(unknownTokenWhitespaceResourceRefresh.StatusCode, whitespaceResourceRefresh.StatusCode);
        Assert.AreEqual(unknownTokenWhitespaceResourceRefresh.Body, whitespaceResourceRefresh.Body,
            "A live refresh token's existence must not be discoverable from an all-whitespace resource value's refusal.");

        ServerHttpResponse successfulRefresh = await RefreshAsync(
            host, material, refreshToken, requestResource: ResourceA).ConfigureAwait(false);
        Assert.AreEqual(200, successfulRefresh.StatusCode, successfulRefresh.Body);
    }


    /// <summary>
    /// The real-wire twin of <see cref="WhitespaceResourceValueIsMalformedAtCodeRedemption"/>: the same
    /// step-level refusal, proven through actual HTTP <c>application/x-www-form-urlencoded</c>
    /// decoding rather than <see cref="RequestFields"/> built directly. A whitespace-only value is a
    /// value (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>
    /// makes only a parameter sent without a value an omitted one) that
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see> refuses
    /// (<c>invalid_target</c>), alone or MIXED valid-then-whitespace as a repeated <c>resource</c>
    /// occurrence (the genuine multi-value wire form: two separate <c>resource=</c> parameters,
    /// never one space-joined value) — byte-identical for an unknown code and the still-unconsumed
    /// live one, touching NO grant-store operation on the refusal, with a successful
    /// correctly-shaped control. Every refusal answers the fixed malformed-resource
    /// <c>invalid_target</c> body and its request trace names the first part of the occurrence as
    /// received that fails <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986
    /// Appendix A</see>'s <c>scheme</c> production, <c>Scheme</c>, the whitespace-only occurrence
    /// being the one refused in the mixed case too.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task WhitespaceResourceValueIsMalformedAtCodeRedemptionOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(WhitespaceResourceValueIsMalformedAtCodeRedemptionOverRealWireAsync));
        _ = root.Start();

        foreach(string[] malformedResources in new[] { new[] { "   " }, new[] { ResourceA, "   " } })
        {
            int beforeLive = hosted.StorageObservations.Count;
            (int liveStatus, string liveBody) = await PostTokenAsync(host, segment, code, verifier, malformedResources).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeLive,
                $"a malformed resource occurrence over the real wire at code redemption, live code ('{string.Join(",", malformedResources)}')");

            int beforeUnknown = hosted.StorageObservations.Count;
            (int unknownStatus, string unknownBody) = await PostTokenAsync(
                host, segment, "code-never-issued-by-this-host", verifier, malformedResources).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown,
                $"a malformed resource occurrence over the real wire at code redemption, unknown code ('{string.Join(",", malformedResources)}')");

            Assert.AreEqual(400, liveStatus, liveBody);
            Assert.Contains($"\"error\":\"{OAuthErrors.InvalidTarget}\"", liveBody, StringComparison.Ordinal);
            Assert.AreEqual(MalformedResourceIndicatorBody, liveBody);
            Assert.AreEqual(unknownStatus, liveStatus);
            Assert.AreEqual(unknownBody, liveBody,
                "A live code's existence must not be discoverable from a malformed resource value's refusal over the real wire.");
        }

        root.Stop();

        Assert.AreSequenceEqual(
            ["Scheme", "Scheme", "Scheme", "Scheme"], ReadMalformedResourceFaultNames(capture, root));

        (int okStatus, string okBody) = await PostTokenAsync(host, segment, code, verifier, [ResourceA]).ConfigureAwait(false);
        Assert.AreEqual(200, okStatus, okBody);
    }


    /// <summary>
    /// The real-wire twin of <see cref="WhitespaceResourceValueIsMalformedAtRefresh"/>: the same
    /// refusal proven through actual HTTP form decoding. A whitespace-only value is a value
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>
    /// makes only a parameter sent without a value an omitted one) that
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see> refuses,
    /// alone or as a MIXED valid-then-whitespace repeated <c>resource</c> occurrence,
    /// byte-identical for an unknown refresh token and the usable live one, touching NO
    /// grant-store operation on the refusal, with a successful correctly-shaped control. Every
    /// refusal answers the fixed malformed-resource <c>invalid_target</c> body and its request trace
    /// names the first part of the occurrence as received that fails
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>'s
    /// <c>scheme</c> production, <c>Scheme</c>, the whitespace-only occurrence being the one
    /// refused in the mixed case too.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task WhitespaceResourceValueIsMalformedAtRefreshOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(WhitespaceResourceValueIsMalformedAtRefreshOverRealWireAsync));
        _ = root.Start();

        foreach(string[] malformedResources in new[] { new[] { "   " }, new[] { ResourceA, "   " } })
        {
            int beforeLive = hosted.StorageObservations.Count;
            (int liveStatus, string liveBody) = await PostRefreshAsync(host, segment, refreshToken, malformedResources).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeLive,
                $"a malformed resource occurrence over the real wire at refresh, live token ('{string.Join(",", malformedResources)}')");

            int beforeUnknown = hosted.StorageObservations.Count;
            (int unknownStatus, string unknownBody) = await PostRefreshAsync(
                host, segment, "refresh-token-never-issued-by-this-host", malformedResources).ConfigureAwait(false);
            hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown,
                $"a malformed resource occurrence over the real wire at refresh, unknown token ('{string.Join(",", malformedResources)}')");

            Assert.AreEqual(400, liveStatus, liveBody);
            Assert.Contains($"\"error\":\"{OAuthErrors.InvalidTarget}\"", liveBody, StringComparison.Ordinal);
            Assert.AreEqual(MalformedResourceIndicatorBody, liveBody);
            Assert.AreEqual(unknownStatus, liveStatus);
            Assert.AreEqual(unknownBody, liveBody,
                "A live refresh token's existence must not be discoverable from a malformed resource value's refusal over the real wire.");
        }

        root.Stop();

        Assert.AreSequenceEqual(
            ["Scheme", "Scheme", "Scheme", "Scheme"], ReadMalformedResourceFaultNames(capture, root));

        (int okStatus, string okBody) = await PostRefreshAsync(host, segment, refreshToken, [ResourceA]).ConfigureAwait(false);
        Assert.AreEqual(200, okStatus, okBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) Over the real wire a code redemption form carrying a bare
    /// <c>resource=</c> is a redemption without a <c>resource</c> parameter: the request proceeds and
    /// the full granted set applies. A blank element inside a request object's <c>resource</c> claim
    /// is a different fact, not a parameter sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceValueIsOmittedAtCodeRedemptionOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(host, segment, code, verifier, [""]).ConfigureAwait(false);

        Assert.AreEqual(200, status, body);
        List<string> aud = DecodeAudienceFromTokenResponse(body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) Over the real wire a code redemption form carrying
    /// <c>resource=&amp;resource=</c> followed by a granted indicator names exactly that one
    /// indicator: the empty occurrence is dropped and the redeemed <c>aud</c> narrows to the one.
    /// A blank element inside a request object's <c>resource</c> claim is a different fact, not a
    /// parameter sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceOccurrenceMixedWithValidOneNarrowsAtCodeRedemptionOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(
            host, segment, code, verifier, ["", ResourceA]).ConfigureAwait(false);

        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([ResourceA], DecodeAudienceFromTokenResponse(body));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) Over the real wire a refresh form carrying a bare
    /// <c>resource=</c> is a refresh without a <c>resource</c> parameter: the request proceeds and
    /// the full granted set stays in force. A blank element inside a request object's
    /// <c>resource</c> claim is a different fact, not a parameter sent without a value, and stays
    /// refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceValueIsOmittedAtRefreshOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        (int status, string body) = await PostRefreshAsync(host, segment, refreshToken, [""]).ConfigureAwait(false);

        Assert.AreEqual(200, status, body);
        List<string> aud = DecodeAudienceFromTokenResponse(body);
        Assert.HasCount(2, aud);
        Assert.Contains(ResourceA, aud);
        Assert.Contains(ResourceB, aud);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) Over the real wire a refresh form carrying an empty
    /// <c>resource</c> occurrence followed by a granted indicator names exactly that one indicator:
    /// the empty occurrence is dropped and the refreshed <c>aud</c> narrows to the one. A blank
    /// element inside a request object's <c>resource</c> claim is a different fact, not a parameter
    /// sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task EmptyResourceOccurrenceMixedWithValidOneNarrowsAtRefreshOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        (string code, string verifier) = await PushAuthorizeAsync(
            host, material, [ResourceA, ResourceB]).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await TokenAsync(host, material, code, verifier).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractStringProperty(tokenResponse.Body, "refresh_token");

        (int status, string body) = await PostRefreshAsync(
            host, segment, refreshToken, ["", ResourceA]).ConfigureAwait(false);

        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([ResourceA], DecodeAudienceFromTokenResponse(body));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// Over the real wire, at each form ingress of the authorization request (the pushed request and
    /// the direct authorization request), a bare <c>resource=</c> is a request without a
    /// <c>resource</c> parameter: the authorization proceeds and the redeemed <c>aud</c> is the one
    /// the same request has with the parameter absent
    /// (<see cref="NoResourceAnywhereFallsBackToScopeToAudienceAsArray"/>). A blank element inside a
    /// request object's <c>resource</c> claim is a different fact, not a parameter sent without a
    /// value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    [DataRow(ResourceDeliveryMode.Pushed)]
    [DataRow(ResourceDeliveryMode.DirectAuthorize)]
    public async Task AnEmptyResourceValueIsOmittedAtEveryAuthorizationFormReceiptAsync(ResourceDeliveryMode mode)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, mode, "", pkce, TestContext.CancellationToken).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, []).ConfigureAwait(false);

        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual(["https://rs.example.com"], DecodeAudienceFromTokenResponse(body));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// Over the real wire, at each form ingress of the authorization request (the pushed request and
    /// the direct authorization request), an empty <c>resource</c> occurrence followed by a
    /// well-formed one names exactly that one indicator: the empty occurrence is dropped and the
    /// redeemed <c>aud</c> carries the one. A blank element inside a request object's
    /// <c>resource</c> claim is a different fact, not a parameter sent without a value, and stays
    /// refused as malformed.
    /// </summary>
    [TestMethod]
    [DataRow(ResourceDeliveryMode.Pushed)]
    [DataRow(ResourceDeliveryMode.DirectAuthorize)]
    public async Task AnEmptyResourceOccurrenceMixedWithValidOneIsDroppedAtEveryAuthorizationFormReceiptAsync(
        ResourceDeliveryMode mode)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        List<KeyValuePair<string, string>> fields = BuildAuthorizationFields(pkce, "");
        fields.Add(new(OAuthRequestParameterNames.Resource, ResourceA));
        string code = await (mode switch
        {
            ResourceDeliveryMode.Pushed =>
                PushAndExtractCodeAsync(host, segment, fields, TestContext.CancellationToken),
            ResourceDeliveryMode.DirectAuthorize =>
                DirectAuthorizeAndExtractCodeAsync(host, segment, fields, TestContext.CancellationToken),
            _ => throw new NotSupportedException($"Unsupported {nameof(ResourceDeliveryMode)}: {mode}.")
        }).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, []).ConfigureAwait(false);

        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([ResourceA], DecodeAudienceFromTokenResponse(body));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A <c>client_credentials</c> request whose only
    /// <c>resource</c> occurrence is empty is a request without a <c>resource</c> parameter: it is
    /// granted the same audience the request with the parameter absent is. A blank element inside a
    /// request object's <c>resource</c> claim is a different fact, not a parameter sent without a
    /// value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsTreatsAnEmptyResourceValueAsOmitted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        const string ClientSecret = "s3cret-for-client-credentials";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        RequestFields absentResourceFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret
        };
        RequestFields emptyResourceFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.Resource] = ""
        };

        ServerHttpResponse absentResourceResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ClientCredentialsToken, WellKnownHttpMethods.Post,
            absentResourceFields, [], TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse emptyResourceResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ClientCredentialsToken, WellKnownHttpMethods.Post,
            emptyResourceFields, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, absentResourceResponse.StatusCode, absentResourceResponse.Body);
        Assert.AreEqual(200, emptyResourceResponse.StatusCode, emptyResourceResponse.Body);
        Assert.IsFalse(AccessTokenCarriesAudienceClaim(absentResourceResponse.Body),
            "The request with the resource parameter absent is issued no aud claim.");
        Assert.IsFalse(AccessTokenCarriesAudienceClaim(emptyResourceResponse.Body),
            "The request with an empty resource parameter is issued what the request with the parameter absent is.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) A <c>client_credentials</c> request carrying an empty
    /// <c>resource</c> occurrence followed by a well-formed one names exactly that one indicator, and
    /// the issued <c>aud</c> carries the one. A blank element inside a request object's
    /// <c>resource</c> claim is a different fact, not a parameter sent without a value, and stays
    /// refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsDropsAnEmptyResourceOccurrenceMixedWithValidOne()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        const string ClientSecret = "s3cret-for-client-credentials";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret
        };
        fields.Add(OAuthRequestParameterNames.Resource, "");
        fields.Add(OAuthRequestParameterNames.Resource, ResourceA);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ClientCredentialsToken, WellKnownHttpMethods.Post,
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreSequenceEqual([ResourceA], DecodeAudienceFromTokenResponse(response.Body));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) Over the real loopback listener, a
    /// <c>client_credentials</c> request whose only <c>resource</c> occurrence is empty is a request
    /// without a <c>resource</c> parameter: it answers 200 and is issued the same access token shape
    /// the request with the parameter absent is, which carries no <c>aud</c> claim. A blank element
    /// inside a request object's <c>resource</c> claim is a different fact, not a parameter sent
    /// without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsTreatsAnEmptyResourceValueAsOmittedOverTheWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        ServerHttpResponse absentResourceResponse = await PostClientCredentialsOverTheWireAsync(
            host, segment, []).ConfigureAwait(false);
        ServerHttpResponse emptyResourceResponse = await PostClientCredentialsOverTheWireAsync(
            host, segment, [""]).ConfigureAwait(false);

        Assert.AreEqual(200, absentResourceResponse.StatusCode, absentResourceResponse.Body);
        Assert.AreEqual(200, emptyResourceResponse.StatusCode, emptyResourceResponse.Body);
        Assert.IsFalse(AccessTokenCarriesAudienceClaim(absentResourceResponse.Body),
            "The request with the resource parameter absent is issued no aud claim.");
        Assert.IsFalse(AccessTokenCarriesAudienceClaim(emptyResourceResponse.Body),
            "The request with an empty resource parameter is issued what the request with the parameter absent is.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 section 3.1</see>:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request."
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">Section 3.2</see> repeats the
    /// sentence for the token endpoint.) Over the real loopback listener, a
    /// <c>client_credentials</c> request carrying an empty <c>resource</c> occurrence followed by a
    /// well-formed one names exactly that one indicator: it answers 200 and the issued <c>aud</c>
    /// carries the one. A blank element inside a request object's <c>resource</c> claim is a
    /// different fact, not a parameter sent without a value, and stays refused as malformed.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsDropsAnEmptyResourceOccurrenceMixedWithValidOneOverTheWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        ServerHttpResponse response = await PostClientCredentialsOverTheWireAsync(
            host, segment, ["", ResourceA]).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreSequenceEqual([ResourceA], DecodeAudienceFromTokenResponse(response.Body));
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        const string ClientSecret = "s3cret-for-client-credentials";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

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
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        const string ClientSecret = "s3cret-for-client-credentials";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

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
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        const string ClientSecret = "s3cret-for-client-credentials";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

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
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            //BuildRefreshToken (the redemption endpoint refreshing this exchange-minted token
            //below) is gated by OAuthAuthorizationCode, not OAuthRefreshToken — refresh redemption
            //is part of the authorization_code family's endpoint chain regardless of which grant
            //originally minted the refresh token being redeemed.
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthRefreshToken)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) => ValueTask.FromResult(true);

            candidateIntegration.ValidateTokenExchangeTokenAsync =
                static (token, tokenType, registration, context, ct) =>
                    ValueTask.FromResult<ValidatedSecurityToken?>(
                        new ValidatedSecurityToken { Subject = SubjectId, Scope = WellKnownScopes.OpenId });

            candidateIntegration.AuthorizeTokenExchangeAsync =
                static (subject, actor, request, registration, context, ct) =>
                    ValueTask.FromResult<TokenExchangeAuthorization?>(
                        new TokenExchangeAuthorization
                        {
                            Subject = subject.Subject,
                            Scope = subject.Scope ?? string.Empty,
                            Audience = [ResourceA, ResourceB],
                            IssuedTokenType = TokenType.RefreshToken
                        });
        }).ConfigureAwait(false);

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
            exchangeFields, [], TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);

        (string code, string verifier) = await PushAuthorizeAsync(host, material, ResourceA).ConfigureAwait(false);

        //ResolvePolicyAsync runs unconditionally at dispatch entry (EndpointServer step 2.5) and
        //ApplyRfc6749WithPkce sets AccessTokenAudPolicy.Optional there, so setting it directly on a
        //pre-dispatch ExchangeContext would be clobbered before the token endpoint ever reads it.
        //Wrap the profile's own resolver instead: run the normal profile resolution, then override
        //just this one axis to Suppressed for this request.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolvePolicyAsync = async (registration, ctx, ct) =>
            {
                await PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, ctx, ct).ConfigureAwait(false);
                ctx.SetAccessTokenAudPolicy(AccessTokenAudPolicy.Suppressed);
            };
        }).ConfigureAwait(false);

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
            tokenFields, [], TestContext.CancellationToken).ConfigureAwait(false);

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


    /// <summary>
    /// The path by which a fold row's resource indicator reaches the authorization server, so one
    /// <see cref="AuthorizeForResourceAsync"/> can drive every wire shape the fold must survive.
    /// </summary>
    internal enum ResourceDeliveryMode
    {
        /// <summary>Pushed to the PAR endpoint, then the pinned authorize GET redeems <c>request_uri</c>.</summary>
        Pushed,

        /// <summary>Every parameter addressed directly to the authorize endpoint's query string.</summary>
        DirectAuthorize,

        /// <summary>A signed request object presented directly to the authorize endpoint's <c>request</c> parameter.</summary>
        RequestObjectByValue,

        /// <summary>A signed request object pushed to the PAR endpoint, then redeemed through <c>request_uri</c>.</summary>
        RequestObjectAtPushedEndpoint
    }


    /// <summary>
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization#canonical-server-uri">
    /// The MCP authorization canonical-server-uri section</see>: "implementations SHOULD accept
    /// uppercase scheme and host components for robustness and interoperability." Read together
    /// with <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 section
    /// 6.2.2.1</see> ("the scheme and host are case-insensitive and therefore should be normalized
    /// to lowercase") and <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707
    /// section 2</see> ("The authorization server may use the exact &quot;resource&quot; value as
    /// the audience or it may map from that value to a more general URI or abstract identifier for
    /// the given resource."): whichever of the four request paths
    /// carries an upper-case scheme-and-host resource indicator, the redeemed <c>aud</c> is the
    /// canonical, lower-case spelling. Every case runs inside a <see cref="ServedCultureScope"/> set
    /// to "tr-TR", so a fold that lowered the ASCII <c>I</c> the Turkish way (to U+0131) would fail
    /// every case here.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(ResourceDeliveryMode.Pushed)]
    [DataRow(ResourceDeliveryMode.DirectAuthorize)]
    [DataRow(ResourceDeliveryMode.RequestObjectByValue)]
    [DataRow(ResourceDeliveryMode.RequestObjectAtPushedEndpoint)]
    public async Task AnUppercaseSchemeAndHostResourceIsGrantedTheCanonicalAudienceAsync(ResourceDeliveryMode mode)
    {
        const string resource = "HTTPS://API.Example.COM/Path?Q=1";
        const string expectedAudience = "https://api.example.com/Path?Q=1";

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, mode, resource, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, []).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([expectedAudience], DecodeAudienceFromTokenResponse(body));

        int expectedRequests = mode is ResourceDeliveryMode.Pushed or ResourceDeliveryMode.RequestObjectAtPushedEndpoint ? 3 : 2;
        culture.AssertEveryRequestWasServedUnder("tr-TR", expectedRequests);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 section
    /// 6.2.2.1</see>: "the scheme and host are case-insensitive and therefore should be normalized
    /// to lowercase". <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">
    /// RFC 8707 section 2.2</see>: a token request's resource narrows the granted set. A token
    /// request naming the granted indicator in a different scheme/host spelling narrows to it,
    /// by the folded comparison key, and the minted <c>aud</c> carries the GRANTED spelling. The
    /// first case names the upper-case spelling at the code redemption and no resource at the
    /// refresh; the second names no resource at the code redemption and both spellings at the
    /// refresh, which narrows to the granted indicator once.
    /// </summary>
    /// <param name="redemptionResources">The <c>resource</c> occurrences the code redemption names.</param>
    /// <param name="refreshResources">The <c>resource</c> occurrences the refresh names.</param>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(new[] { "HTTPS://API.EXAMPLE.COM/x" }, new string[] { })]
    [DataRow(new string[] { }, new[] { "HTTPS://API.EXAMPLE.COM/x", "https://api.example.com/x" })]
    public async Task NarrowingMatchesAGrantedResourceByItsKeyAsync(string[] redemptionResources, string[] refreshResources)
    {
        const string grantedResource = "https://api.example.com/x";

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, grantedResource, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(
            host, segment, code, pkce.EncodedVerifier, redemptionResources).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([grantedResource], DecodeAudienceFromTokenResponse(body));

        (int refreshStatus, string refreshBody) = await PostRefreshAsync(
            host, segment, ExtractStringProperty(body, "refresh_token"), refreshResources).ConfigureAwait(false);
        Assert.AreEqual(200, refreshStatus, refreshBody);
        Assert.AreSequenceEqual([grantedResource], DecodeAudienceFromTokenResponse(refreshBody));

        culture.AssertEveryRequestWasServedUnder("tr-TR", 4);
    }


    /// <summary>
    /// A <see cref="ServedCultureScope"/> leaves <see cref="CultureInfo.DefaultThreadCurrentCulture"/>
    /// on disposal exactly as it found it: <see langword="null"/> when no default was set before the
    /// scope, and the same culture instance when one was, so a culture row changes nothing a later
    /// test in the process observes. The row sets the value it starts from and restores the value it
    /// found in <c>finally</c>; it is marked <c>[DoNotParallelize]</c> because the default is
    /// process-wide. The row proves this library's test infrastructure, and no specification clause
    /// applies.
    /// </summary>
    /// <param name="defaultCultureNameBefore">The name of the default thread culture set before the scope, or <see langword="null"/> for none.</param>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(null)]
    [DataRow("fi-FI")]
    public async Task TheServedCultureScopeRestoresTheDefaultThreadCultureItFoundAsync(string? defaultCultureNameBefore)
    {
        CultureInfo? defaultCultureOfTheProcess = CultureInfo.DefaultThreadCurrentCulture;
        CultureInfo? defaultCultureBefore = defaultCultureNameBefore is null ? null : new CultureInfo(defaultCultureNameBefore);

        try
        {
            CultureInfo.DefaultThreadCurrentCulture = defaultCultureBefore;

            await using TestHostShell host = new(TimeProvider);
            using(await ServedCultureScope.CreateAsync(host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false))
            {
                Assert.AreEqual("tr-TR", CultureInfo.DefaultThreadCurrentCulture?.Name);
            }

            Assert.AreSame(defaultCultureBefore, CultureInfo.DefaultThreadCurrentCulture,
                $"Expected the default thread culture '{defaultCultureBefore?.Name ?? "null"}' after disposal; "
                + $"observed '{CultureInfo.DefaultThreadCurrentCulture?.Name ?? "null"}'.");
        }
        finally
        {
            CultureInfo.DefaultThreadCurrentCulture = defaultCultureOfTheProcess;
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 section
    /// 6.2.2.1</see>: "The other generic syntax components are assumed to be case-sensitive unless
    /// specifically defined otherwise by the scheme", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.3">RFC 9110 section 4.2.3</see>:
    /// "The scheme and host are case-insensitive and normally provided in lowercase; all other
    /// components are compared in a case-sensitive manner." A token request naming a resource that
    /// differs from a granted one only in the case of a part outside the scheme and host (the path
    /// of <c>https://api.example.com/x</c>, the <c>Example:Thing</c> remainder of
    /// <c>urn:Example:Thing</c>) names a different resource, so it is not in the granted set and is
    /// refused with <c>invalid_target</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 section 2.2</see>:
    /// "such policy may limit the acceptable resources to those that were originally granted by the
    /// resource owner or a subset thereof."), with this library's one fixed description for a
    /// resource that was not granted, which names no value.
    /// </summary>
    /// <param name="grantedResource">The <c>resource</c> the authorization request granted.</param>
    /// <param name="requestedResource">The <c>resource</c> the token request names.</param>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("https://api.example.com/x", "https://api.example.com/X")]
    [DataRow("urn:Example:Thing", "urn:example:thing")]
    public async Task NarrowingRefusesAResourceThatDiffersOnlyInTheCaseOfAKeyedPartAsync(
        string grantedResource, string requestedResource)
    {
        await AssertNarrowingIsRefusedAsNotGrantedAsync(grantedResource, requestedResource).ConfigureAwait(false);
    }


    /// <summary>
    /// The comparison key is the exact spelling apart from the case of the scheme and the host
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.1">RFC 3986 section 6.2.1</see>:
    /// "If two URIs, when considered as character strings, are identical, then it is safe to
    /// conclude that they are equivalent"), so a token request naming a spelling that
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2">RFC 3986 section 6.2.2</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.3">section 6.2.3</see>
    /// call equivalent to a granted one, but that this library does not normalize, names a
    /// resource that is not in the granted set and is refused with <c>invalid_target</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 section 2.2</see>:
    /// "such policy may limit the acceptable resources to those that were originally granted by the
    /// resource owner or a subset thereof."), with this library's one fixed description for a
    /// resource that was not granted, which names no value. The four pairs are the clauses the
    /// library does not apply:
    /// an empty path against <c>/</c> (section 6.2.3: "a URI that uses the generic syntax for
    /// authority with an empty path should be normalized to a path of &quot;/&quot;"), an explicit
    /// default port against no port (section 6.2.3: "an explicit &quot;:port&quot;, for which the port
    /// is empty or the default for the scheme, is equivalent to one where the port and its
    /// &quot;:&quot; delimiter are elided and thus should be removed by scheme-based
    /// normalization"), a path with dot-segments against the path without them (section 6.2.2.3:
    /// "URI normalizers should remove dot-segments by applying the remove_dot_segments algorithm to
    /// the path"), and a percent-encoded octet spelled with lower-case hexadecimal digits against
    /// the upper-case spelling (section 6.2.2.1: "the hexadecimal digits within a percent-encoding
    /// triplet (e.g., &quot;%3a&quot; versus &quot;%3A&quot;) are case-insensitive and therefore
    /// should be normalized to use uppercase letters for the digits A-F").
    /// </summary>
    /// <param name="grantedResource">The <c>resource</c> the authorization request granted.</param>
    /// <param name="requestedResource">The equivalent spelling the token request names.</param>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("https://api.example.com", "https://api.example.com/")]
    [DataRow("https://api.example.com/x", "https://api.example.com:443/x")]
    [DataRow("https://api.example.com/b", "https://api.example.com/a/../b")]
    [DataRow("https://api.example.com/A%2fB", "https://api.example.com/A%2FB")]
    public async Task NarrowingRefusesAnEquivalentSpellingTheLibraryDoesNotNormalizeAsync(
        string grantedResource, string requestedResource)
    {
        await AssertNarrowingIsRefusedAsNotGrantedAsync(grantedResource, requestedResource).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 section
    /// 6.2.2.1</see>: "The other generic syntax components are assumed to be case-sensitive"; only
    /// the scheme and host fold; a path, query and percent-encoded octet keep their exact spelling.
    /// A PIN: this resource has nothing for the fold to touch, guarding against a fold that reaches
    /// further than the scheme and host.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task PathQueryAndPercentEncodingKeepTheirSpellingAsync()
    {
        const string resource = "https://api.example.com/A%2fB?X=Y";

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, resource, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, []).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([resource], DecodeAudienceFromTokenResponse(body));

        culture.AssertEveryRequestWasServedUnder("tr-TR", 3);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC 3986 section 3.2.2</see>:
    /// "Although host is case-insensitive, producers and normalizers should use lowercase for
    /// registered names and hexadecimal addresses for the sake of uniformity, while only using
    /// uppercase letters for percent-encodings."; an <c>IP-literal</c> is lowered like any other
    /// host (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">section 6.2.2.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">Appendix A</see>), while a port
    /// and a percent-encoded octet keep their exact spelling. Only the scheme
    /// and host of an authority fold; nothing else in it does.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("HTTPS://[2001:DB8::1]:8443/P", "https://[2001:db8::1]:8443/P")]
    [DataRow("FOO://B%C3%BCCHER.EXAMPLE/x", "foo://b%C3%BCcher.example/x")]
    public async Task OnlyTheSchemeAndHostOfAnAuthorityAreFoldedAsync(string resource, string expectedAudience)
    {
        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, resource, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, []).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([expectedAudience], DecodeAudienceFromTokenResponse(body));

        culture.AssertEveryRequestWasServedUnder("tr-TR", 3);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 section 3.1</see>:
    /// "Although schemes are case-insensitive, the canonical form is lowercase and documents that
    /// specify schemes must do so with lowercase letters." An indicator with
    /// no authority (no <c>//</c> follows the scheme's <c>:</c>) folds only its scheme; the rest of
    /// its spelling, having no host to fold, is untouched, so <c>URN:Example:Thing</c> and
    /// <c>urn:example:thing</c> are NOT the same comparison key, unlike an authority's host.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("URN:Example:Thing", null, "urn:Example:Thing")]
    [DataRow("URN:example:thing", "urn:example:thing", "urn:example:thing")]
    public async Task TheSchemeOfAnIndicatorWithoutAnAuthorityIsFoldedAsync(
        string resource, string? requestedResource, string expectedAudience)
    {
        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, resource, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<string> requestedResources = requestedResource is null ? [] : [requestedResource];
        (int status, string body) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, requestedResources).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([expectedAudience], DecodeAudienceFromTokenResponse(body));

        culture.AssertEveryRequestWasServedUnder("tr-TR", 3);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">RFC 3986 section 3.2.2</see>:
    /// a registered name's percent-encoded octets represent a UTF-8 sequence; an internationalized
    /// domain name's A-label (<c>xn--</c>) form is itself ASCII, so it folds like any other host
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">section 6.2.2.1</see>);
    /// the path segment stays exactly as sent.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task AnIdnHostInItsALabelFormIsAcceptedAndFoldedAsync()
    {
        const string resource = "HTTPS://XN--BCHER-KVA.EXAMPLE/Items";
        const string expectedAudience = "https://xn--bcher-kva.example/Items";

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, resource, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, []).ConfigureAwait(false);
        Assert.AreEqual(200, status, body);
        Assert.AreSequenceEqual([expectedAudience], DecodeAudienceFromTokenResponse(body));

        culture.AssertEveryRequestWasServedUnder("tr-TR", 3);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 section 2</see>: "The
    /// ABNF notation defines its terminal values to be non-negative integers (codepoints) based on
    /// the US-ASCII coded character set". A code point above U+007F anywhere in the <c>resource</c>
    /// value (in its host, its path, or its scheme) is outside that set, so
    /// <see cref="ResourceIndicator.Parse"/> refuses it and the pushed
    /// request answers <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707
    /// section 2.1</see>'s <c>invalid_target</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its
    /// value MUST be an absolute URI"). Each case is refused with the fixed malformed-resource
    /// description.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("https://AP", 0x0130, ".EXAMPLE/")]
    [DataRow("https://ap", 0x0131, ".example/")]
    [DataRow("https://", 0x212A, "ey.example/")]
    [DataRow("https://", 0x017F, "erver.example/")]
    [DataRow("https://api.example.com/", 0x017F, "")]
    [DataRow("F", 0x0130, "LE://host.example/share")]
    [DataRow("f", 0x0131, "le://host.example/share")]
    [DataRow("", 0x212A, "ey://host.example/")]
    [DataRow("http", 0x017F, "://api.example.com/")]
    public async Task ANonAsciiResourceIndicatorIsRefusedAtThePushedRequestAsync(
        string resourcePrefix, int nonAsciiCodePoint, string resourceSuffix)
    {
        string resource = resourcePrefix + char.ConvertFromUtf32(nonAsciiCodePoint) + resourceSuffix;

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, BuildAuthorizationFields(pkce, resource), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(MalformedResourceIndicatorBody, body);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.1">RFC 3986 section 2.1</see>: "A
    /// percent-encoded octet is encoded as a character triplet, consisting of the percent character
    /// &quot;%&quot; followed by the two hexadecimal digits representing that octet's numeric
    /// value.";
    /// <c>%GG</c>, <c>%2</c> and <c>%2G</c> each violate that triplet.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>'s
    /// <c>pchar = unreserved / pct-encoded / sub-delims / ":" / "@"</c> admits none of a backslash,
    /// <c>[</c>, <c>]</c>, <c>^</c>, <c>{</c>, <c>}</c>, <c>|</c> or a backtick in a path segment.
    /// The last case, an empty fragment (<c>x#</c>), fails the fragment check
    /// <see cref="ResourceIndicator.Parse"/> makes and is refused with the
    /// same description.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("https://api.example.com/%GG", 0, "")]
    [DataRow("https://api.example.com/p%2", 0, "")]
    [DataRow("https://api.example.com/%2G", 0, "")]
    [DataRow("https://api.example.com/a", 0x5C, "b")]
    [DataRow("https://api.example.com/a[b]", 0, "")]
    [DataRow("https://api.example.com/a^b", 0, "")]
    [DataRow("https://api.example.com/a{b}", 0, "")]
    [DataRow("https://api.example.com/a|b", 0, "")]
    [DataRow("https://api.example.com/a`b", 0, "")]
    [DataRow("https://api.example.com/x#", 0, "")]
    public async Task AResourceIndicatorOutsideTheRfc3986GrammarIsRefusedAtThePushedRequestAsync(
        string resourcePrefix, int disallowedCodePoint, string resourceSuffix)
    {
        string resource = disallowedCodePoint == 0
            ? resourcePrefix
            : resourcePrefix + char.ConvertFromUtf32(disallowedCodePoint) + resourceSuffix;

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, BuildAuthorizationFields(pkce, resource), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(MalformedResourceIndicatorBody, body);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1">RFC 9110 section 4.2.1</see>:
    /// "A sender MUST NOT generate an &quot;http&quot; URI with an empty host identifier. A recipient that
    /// processes such a URI reference MUST reject it as invalid.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2">section 4.2.2</see> says the
    /// same of an &quot;https&quot; URI. <c>http://</c>, <c>https://</c> and <c>https:///path</c> each
    /// carry an authority whose host is empty; <c>http:api.example.com</c> and
    /// <c>https:api.example.com</c> carry no <c>//</c> after the scheme's <c>:</c> at all, so they have
    /// no authority component to begin with
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 section 3.1</see>),
    /// though RFC 3986 alone would admit them as a bare <c>path-rootless</c> value. Each is refused
    /// with the malformed-resource <c>invalid_target</c> body.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("https://")]
    [DataRow("https:///path")]
    [DataRow("https:api.example.com")]
    [DataRow("http://")]
    [DataRow("http:api.example.com")]
    public async Task AnHttpIndicatorWithoutAHostIsRefusedAsync(string resource)
    {
        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, BuildAuthorizationFields(pkce, resource), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(MalformedResourceIndicatorBody, body);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: the
    /// <c>resource</c> "value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see> reads
    /// <c>scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )</c>, so a scheme has at least one
    /// character; <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">section 3.1</see>
    /// says "Scheme names consist of a sequence of characters beginning with a letter". A value whose
    /// first character is the <c>:</c> that ends a scheme (<c>:foo</c>, <c>://api.example.com/</c>)
    /// has an empty scheme and is no absolute URI. Each value is refused at the pushed request with the
    /// 400 malformed-resource body, the request trace names the <c>scheme</c> as the failing part, and
    /// the same value at the <c>client_credentials</c> token request over the listener answers the
    /// same 400 body and mints no token. The pushed request and the <c>client_credentials</c> grant
    /// are the two places this method drives.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(":foo")]
    [DataRow("://api.example.com/")]
    public async Task AResourceIndicatorWithAnEmptySchemeIsRefusedAtThePushedRequestAndTheClientCredentialsGrantAsync(string resource)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: Capabilities.Add(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(AResourceIndicatorWithAnEmptySchemeIsRefusedAtThePushedRequestAndTheClientCredentialsGrantAsync));
        _ = root.Start();

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, BuildAuthorizationFields(pkce, resource), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(MalformedResourceIndicatorBody, body);

        await AssertClientCredentialsIsRefusedAsync(host, segment, resource).ConfigureAwait(false);

        root.Stop();

        Assert.AreSequenceEqual(["Scheme", "Scheme"], ReadMalformedResourceFaultNames(capture, root));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 section 4.2.4</see>:
    /// "Before making use of an &quot;http&quot; or &quot;https&quot; URI reference received from an
    /// untrusted source, a recipient SHOULD parse for userinfo and treat its presence as an error; it
    /// is likely being used to obscure the authority for the sake of phishing attacks." An
    /// <c>http</c> or <c>https</c> <c>resource</c> indicator that carries a <c>userinfo</c>
    /// subcomponent (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986
    /// section 3.2.1</see>: "The user information, if present, is followed by a commercial at-sign
    /// (&quot;@&quot;) that delimits it from the host.") is refused at the pushed request with
    /// <c>invalid_target</c>, and the request trace names the userinfo as the failing part.
    /// <c>https://api.example.com@other.example/</c> reads as one host and names another.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("https://User:Pa%41ss@api.example:8443/A%2fB?X=Y")]
    [DataRow("https://user@api.example/")]
    [DataRow("https://api.example.com@other.example/")]
    public async Task AnHttpIndicatorWithUserInformationIsRefusedAsync(string resource)
    {
        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(AnHttpIndicatorWithUserInformationIsRefusedAsync));
        _ = root.Start();

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, BuildAuthorizationFields(pkce, resource), TestContext.CancellationToken).ConfigureAwait(false);

        root.Stop();

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(MalformedResourceIndicatorBody, body);

        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        ActivityEvent[] malformedEvents = [.. inTrace
            .SelectMany(activity => activity.Events)
            .Where(activityEvent => string.Equals(
                activityEvent.Name, OAuthEventNames.MalformedResourceIndicator, StringComparison.Ordinal))];
        Assert.HasCount(1, malformedEvents);

        KeyValuePair<string, object?> faultTag = malformedEvents[0].Tags.Single(tag =>
            string.Equals(tag.Key, OAuthEventNames.ResourceIndicatorFaultTagName, StringComparison.Ordinal));
        Assert.AreEqual("HttpUserInfo", faultTag.Value);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// A rule of this library, not a specification clause, stated here because RFC 8707 itself imposes no logging duty: every
    /// refusal of a malformed <c>resource</c> value is a decision recorded as a value, never merely a
    /// side effect on the wire. The pushed request's dispatch trace carries exactly one
    /// <see cref="OAuthEventNames.MalformedResourceIndicator"/> event, whose
    /// <see cref="OAuthEventNames.ResourceIndicatorFaultTagName"/> tag names the specific grammar part
    /// that failed, and that event carries no tag holding the presented value itself: the record
    /// names the failure, never the rejected secret or personal data it might carry. For an
    /// <c>http</c> or <c>https</c> value the authority's faults are named before the path's, so a
    /// value with an empty host or no authority is recorded by that fault whatever its path holds.
    /// The refusal itself is <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707
    /// section 2.1</see>'s <c>invalid_target</c>.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("https://api.example.com/%GG", 0, "", "PercentEncoding")]
    [DataRow("https://", 0x212A, "ey.example/", "NonAscii")]
    [DataRow("https://api.example.com/x#", 0, "", "Fragment")]
    [DataRow("https:///bad^", 0, "", "HttpHost")]
    [DataRow("https:bad^", 0, "", "HttpAuthority")]
    public async Task AMalformedResourceIsRecordedOnTheRequestTraceByItsFailingPartAsync(
        string resourcePrefix, int nonAsciiCodePoint, string resourceSuffix, string expectedFaultName)
    {
        string resource = nonAsciiCodePoint == 0
            ? resourcePrefix
            : resourcePrefix + char.ConvertFromUtf32(nonAsciiCodePoint) + resourceSuffix;

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(AMalformedResourceIsRecordedOnTheRequestTraceByItsFailingPartAsync));
        _ = root.Start();

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, BuildAuthorizationFields(pkce, resource), TestContext.CancellationToken).ConfigureAwait(false);

        root.Stop();

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(MalformedResourceIndicatorBody, body);

        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId);
        ActivityEvent[] malformedEvents = [.. inTrace
            .SelectMany(activity => activity.Events)
            .Where(activityEvent => string.Equals(
                activityEvent.Name, OAuthEventNames.MalformedResourceIndicator, StringComparison.Ordinal))];
        Assert.HasCount(1, malformedEvents);

        ActivityEvent malformedEvent = malformedEvents[0];
        KeyValuePair<string, object?> faultTag = malformedEvent.Tags.Single(tag =>
            string.Equals(tag.Key, OAuthEventNames.ResourceIndicatorFaultTagName, StringComparison.Ordinal));
        Assert.AreEqual(expectedFaultName, faultTag.Value);

        bool isPresentedValueCarried = malformedEvent.Tags.Any(tag =>
            string.Equals(tag.Value?.ToString(), resource, StringComparison.Ordinal));
        Assert.IsFalse(isPresentedValueCarried,
            $"The '{OAuthEventNames.MalformedResourceIndicator}' event must never carry the presented value as a tag.");

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// The receipt at which <see cref="ANonAsciiResourceIndicatorIsRefusedAtEveryOtherReceiptAsync"/>
    /// presents its non-ASCII resource indicator, one receipt per case.
    /// </summary>
    internal enum NonAsciiResourceReceipt
    {
        /// <summary>Every parameter addressed directly to the authorize endpoint's query string.</summary>
        DirectAuthorize,

        /// <summary>A signed request object presented directly to the authorize endpoint's <c>request</c> parameter.</summary>
        RequestObjectByValue,

        /// <summary>A signed request object pushed to the PAR endpoint.</summary>
        RequestObjectAtPushedEndpoint,

        /// <summary>The token request that redeems an authorization code, live or unknown.</summary>
        CodeRedemption,

        /// <summary>The token request of the <c>client_credentials</c> grant.</summary>
        ClientCredentials
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see>: "If
    /// the authorization server fails to parse the provided value(s) or does not consider the
    /// resource(s) acceptable, it should reject the request with an error response using the error
    /// code "invalid_target" as the value of the "error" parameter". The value is not an absolute URI
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its
    /// value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]") because
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 section 2</see> bases its
    /// grammar on "the US-ASCII coded character set" and the host carries U+212A (KELVIN SIGN). The
    /// same refusal answers at every receipt that reads a <c>resource</c>: a direct authorize request
    /// and a request object by value answer the error redirect of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section 4.1.2.1</see>
    /// (whose <c>error_description</c> "MUST NOT include characters outside the set %x20-21 /
    /// %x23-5B / %x5D-7E"), a request object at the pushed endpoint and the <c>client_credentials</c>
    /// token request answer the 400 JSON body, and a code redemption answers the same 400 body for a
    /// live code and for a code this host never issued, byte for byte, before any flow-state store
    /// operation runs, so the refusal does not tell the two apart and consumes nothing: the live code
    /// redeems with a well-formed request afterwards. The five receipts are cases of one method
    /// because each differs from the others only in the request it sends; each case is served under
    /// "tr-TR".
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(NonAsciiResourceReceipt.DirectAuthorize)]
    [DataRow(NonAsciiResourceReceipt.RequestObjectByValue)]
    [DataRow(NonAsciiResourceReceipt.RequestObjectAtPushedEndpoint)]
    [DataRow(NonAsciiResourceReceipt.CodeRedemption)]
    [DataRow(NonAsciiResourceReceipt.ClientCredentials)]
    public async Task ANonAsciiResourceIndicatorIsRefusedAtEveryOtherReceiptAsync(NonAsciiResourceReceipt receipt)
    {
        string resource = "https://" + char.ConvertFromUtf32(0x212A) + "ey.example/";

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        ImmutableHashSet<CapabilityIdentifier> capabilities = receipt is NonAsciiResourceReceipt.ClientCredentials
            ? ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)
            : Capabilities;
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        await (receipt switch
        {
            NonAsciiResourceReceipt.DirectAuthorize =>
                AssertDirectAuthorizeIsRefusedByRedirectAsync(host, segment, pkce, resource),
            NonAsciiResourceReceipt.RequestObjectByValue =>
                AssertRequestObjectByValueIsRefusedByRedirectAsync(host, material, segment, pkce, resource),
            NonAsciiResourceReceipt.RequestObjectAtPushedEndpoint =>
                AssertRequestObjectAtPushedEndpointIsRefusedAsync(host, material, segment, pkce, resource),
            NonAsciiResourceReceipt.CodeRedemption =>
                AssertCodeRedemptionIsRefusedIdenticallyAsync(host, material, segment, pkce, resource),
            NonAsciiResourceReceipt.ClientCredentials =>
                AssertClientCredentialsIsRefusedAsync(host, segment, resource),
            _ => throw new NotSupportedException($"Unsupported {nameof(NonAsciiResourceReceipt)}: {receipt}.")
        }).ConfigureAwait(false);

        int expectedRequests = receipt is NonAsciiResourceReceipt.CodeRedemption ? 5 : 1;
        culture.AssertEveryRequestWasServedUnder("tr-TR", expectedRequests);
    }


    /// <summary>
    /// The receipt at which <see cref="AWhitespaceBearingResourceIsRefusedWithItsFailingPartAsync"/>
    /// presents its whitespace-bearing resource, one receipt per case.
    /// </summary>
    internal enum WhitespaceResourceReceipt
    {
        /// <summary>Every parameter addressed directly to the authorize endpoint's query string.</summary>
        DirectAuthorize,

        /// <summary>The token request of the <c>client_credentials</c> grant.</summary>
        ClientCredentials
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see>: "If
    /// the authorization server fails to parse the provided value(s) or does not consider the
    /// resource(s) acceptable, it should reject the request with an error response using the error
    /// code "invalid_target" as the value of the "error" parameter". A <c>resource</c> occurrence that
    /// carries whitespace is not an absolute URI
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its
    /// value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]"), and the refusal
    /// answers the fixed malformed-resource description at every receipt that reads the field: the
    /// direct authorize request answers the error redirect of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section
    /// 4.1.2.1</see>, the <c>client_credentials</c> token request the 400 JSON body. The request trace
    /// names the first part of the occurrence as received that fails
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>'s
    /// grammar: a whitespace-only occurrence fails the <c>scheme</c> production (a space is no
    /// <c>ALPHA</c>), a space inside the path fails <c>pchar</c>, a space inside the host fails
    /// <c>reg-name</c>.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow(WhitespaceResourceReceipt.DirectAuthorize, "   ", "Scheme")]
    [DataRow(WhitespaceResourceReceipt.DirectAuthorize, "https://cal.example.com/x y", "Path")]
    [DataRow(WhitespaceResourceReceipt.DirectAuthorize, "https://cal example.com/", "Authority")]
    [DataRow(WhitespaceResourceReceipt.ClientCredentials, "   ", "Scheme")]
    [DataRow(WhitespaceResourceReceipt.ClientCredentials, "https://cal.example.com/x y", "Path")]
    [DataRow(WhitespaceResourceReceipt.ClientCredentials, "https://cal example.com/", "Authority")]
    public async Task AWhitespaceBearingResourceIsRefusedWithItsFailingPartAsync(
        WhitespaceResourceReceipt receipt, string resource, string expectedFaultName)
    {
        await using TestHostShell host = new(TimeProvider);
        ImmutableHashSet<CapabilityIdentifier> capabilities = receipt is WhitespaceResourceReceipt.ClientCredentials
            ? ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)
            : Capabilities;
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        using TraceTreeCapture capture = new();
        using Activity root = new(nameof(AWhitespaceBearingResourceIsRefusedWithItsFailingPartAsync));
        _ = root.Start();

        await (receipt switch
        {
            WhitespaceResourceReceipt.DirectAuthorize =>
                AssertDirectAuthorizeIsRefusedByRedirectAsync(host, segment, pkce, resource),
            WhitespaceResourceReceipt.ClientCredentials =>
                AssertClientCredentialsIsRefusedAsync(host, segment, resource),
            _ => throw new NotSupportedException($"Unsupported {nameof(WhitespaceResourceReceipt)}: {receipt}.")
        }).ConfigureAwait(false);

        root.Stop();

        Assert.AreSequenceEqual([expectedFaultName], ReadMalformedResourceFaultNames(capture, root));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">section 2.2</see>: a refresh
    /// token request whose <c>resource</c> is not an absolute URI is refused with
    /// <c>invalid_target</c> before the presented <c>refresh_token</c> is correlated to any grant
    /// ("In the case of a "refresh_token" or "authorization_code" grant type request, such policy
    /// may limit the acceptable resources to those that were originally granted"). The refusal names only the
    /// resource, so it is the same 400 body, byte for byte, for a live refresh token and for one this
    /// host never issued, and no flow-state store operation runs for either; a refresh naming no
    /// resource succeeds afterwards with a new <c>refresh_token</c>, so the refusals consumed and
    /// rotated nothing. The value carries U+212A (KELVIN SIGN), outside
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 section 2</see>'s
    /// US-ASCII grammar.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task ANonAsciiResourceAtRefreshIsRefusedBeforeCorrelationAsync()
    {
        string resource = "https://" + char.ConvertFromUtf32(0x212A) + "ey.example/";

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, ResourceA, pkce, TestContext.CancellationToken).ConfigureAwait(false);
        (int tokenStatus, string tokenBody) = await PostTokenAsync(host, segment, code, pkce.EncodedVerifier, []).ConfigureAwait(false);
        Assert.AreEqual(200, tokenStatus, tokenBody);
        string refreshToken = ExtractStringProperty(tokenBody, "refresh_token");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        int beforeLive = hosted.StorageObservations.Count;
        (int liveStatus, string liveBody) = await PostRefreshAsync(host, segment, refreshToken, [resource]).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeLive,
            "a non-ASCII resource at refresh, live refresh token");

        int beforeUnknown = hosted.StorageObservations.Count;
        (int unknownStatus, string unknownBody) = await PostRefreshAsync(
            host, segment, "refresh-token-never-issued-by-this-host", [resource]).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown,
            "a non-ASCII resource at refresh, unknown refresh token");

        Assert.AreEqual(400, liveStatus, liveBody);
        Assert.AreEqual(MalformedResourceIndicatorBody, liveBody);
        Assert.AreEqual(unknownStatus, liveStatus);
        Assert.AreEqual(unknownBody, liveBody,
            "A live refresh token's existence must not be discoverable from a non-ASCII resource value's refusal.");

        (int okStatus, string okBody) = await PostRefreshAsync(host, segment, refreshToken, []).ConfigureAwait(false);
        Assert.AreEqual(200, okStatus, okBody);
        string rotatedRefreshToken = ExtractStringProperty(okBody, "refresh_token");
        Assert.IsFalse(string.IsNullOrEmpty(rotatedRefreshToken), okBody);
        Assert.AreNotEqual(refreshToken, rotatedRefreshToken);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 6);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see>: "a
    /// single "resource" parameter value is represented as a JSON string while multiple values are
    /// represented as an array of strings." An array claim with an element that is not an absolute
    /// URI (an empty string, <c>["", ResourceA]</c>) or is not a string at all (a number,
    /// <c>[ResourceA, 5]</c>) is not an array of resource indicators
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>: "Its
    /// value MUST be an absolute URI"), so the whole claim is refused and no element is dropped to
    /// leave the well-formed one behind: a request object presented by value answers the
    /// <c>invalid_target</c> error redirect of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section
    /// 4.1.2.1</see> carrying the request object's own <c>state</c>.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [DataRow("", ResourceA)]
    [DataRow(ResourceA, 5)]
    public async Task ARequestObjectResourceArrayWithAMalformedElementIsRefusedAsync(
        object firstElement, object secondElement)
    {
        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildResourceClaimJarAsync(
            host, material, pkce, new object[] { firstElement, secondElement }, TestContext.CancellationToken).ConfigureAwait(false);
        Uri authorizeUri = RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ]);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);

        AssertErrorRedirect(
            (int)response.StatusCode, response.Headers.Location, OAuthErrors.InvalidTarget,
            MalformedResourceIndicatorDescription, ResourceJarState);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 1);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section
    /// 4.1.2.1</see>: "Values for the "error_description" parameter MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E." The application's decision seam denies a request
    /// with <see cref="AuthorizationDenialReason.InvalidTarget"/> and a description carrying U+00E9
    /// (LATIN SMALL LETTER E WITH ACUTE) and two U+0022 (QUOTATION MARK); the error redirect's
    /// <c>error_description</c> is that text with the characters outside the set removed
    /// ("Refused:  and quoted", two spaces where the letter stood), beside the request's own
    /// <c>state</c> and the <c>invalid_target</c> code
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see>).
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task AnApplicationDenialDescriptionReachesTheRedirectInsideTheRfc6749CharsetAsync()
    {
        const string state = "state-application-denial";
        string deniedDescription = "Refused: " + char.ConvertFromUtf32(0x00E9) + " and "
            + char.ConvertFromUtf32(0x0022) + "quoted" + char.ConvertFromUtf32(0x0022);

        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (_, _, _, _) => ValueTask.FromResult(
                    AuthorizationRequestDecision.Deny(AuthorizationDenialReason.InvalidTarget, deniedDescription));
        }).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        List<KeyValuePair<string, string>> fields = BuildAuthorizationFields(pkce, ResourceA);
        fields.Add(new(OAuthRequestParameterNames.State, state));
        (int parStatusCode, string parBody, Uri? authorizeLocation, int authorizeStatusCode) =
            await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
                host, segment, ClientId, SubjectId, fields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, parStatusCode, parBody);
        AssertErrorRedirect(authorizeStatusCode, authorizeLocation, OAuthErrors.InvalidTarget, "Refused:  and quoted", state);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 2);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section
    /// 4.1.2.1</see>: &quot;Values for the &quot;error_description&quot; parameter MUST NOT include
    /// characters outside the set %x20-21 / %x23-5B / %x5D-7E.&quot; The application's decision seam
    /// denies a request with <see cref="AuthorizationDenialReason.InvalidTarget"/> and a description
    /// carrying U+00E9 (LATIN SMALL LETTER E WITH ACUTE) and two U+0022 (QUOTATION MARK), and the
    /// request pushed <c>response_mode</c> <c>jwt</c>
    /// (<see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-2.3">JWT Secured
    /// Authorization Response Mode for OAuth 2.0 section 2.3</see>), so the authorize answer is a
    /// redirect carrying a signed <c>response</c>. The <c>error_description</c> inside that signed
    /// response is the same text with the characters outside the set removed
    /// (&quot;Refused:  and quoted&quot;, two spaces where the letter stood), beside the request's
    /// <c>state</c> and the <c>invalid_target</c> code
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see>).
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public async Task AnApplicationDenialDescriptionInASignedResponseIsInsideTheRfc6749CharsetAsync()
    {
        const string state = "state-application-denial-signed";
        string deniedDescription = "Refused: " + char.ConvertFromUtf32(0x00E9) + " and "
            + char.ConvertFromUtf32(0x0022) + "quoted" + char.ConvertFromUtf32(0x0022);

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        await host.UpdateSigningKeysAsync(
            material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary().Add(
                KeyUsageContext.AuthorizationResponseSigning,
                new SigningKeySet { Current = [material.SigningKeyId] })).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (_, _, _, _) => ValueTask.FromResult(
                    AuthorizationRequestDecision.Deny(AuthorizationDenialReason.InvalidTarget, deniedDescription));
        }).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        List<KeyValuePair<string, string>> fields = BuildAuthorizationFields(pkce, ResourceA);
        fields.Add(new(OAuthRequestParameterNames.State, state));
        fields.Add(new(OAuthRequestParameterNames.ResponseMode, JarmResponseModes.Jwt));
        (int parStatusCode, string parBody, Uri? authorizeLocation, int authorizeStatusCode) =
            await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
                host, segment, ClientId, SubjectId, fields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, parStatusCode, parBody);
        Assert.AreEqual(302, authorizeStatusCode);
        Assert.IsNotNull(authorizeLocation, "A signed authorize answer is a redirect carrying a Location header.");

        const string responseMarker = "?response=";
        string wireLocation = authorizeLocation.OriginalString;
        int responseStart = wireLocation.IndexOf(responseMarker, StringComparison.Ordinal);
        Assert.IsGreaterThan(-1, responseStart, $"The redirect carries the signed response. Location: {wireLocation}");
        string responseJwt = Uri.UnescapeDataString(
            wireLocation[(responseStart + responseMarker.Length)..].Split('&')[0]);

        ValueTask<PublicKeyMemory?> ResolveKey(string _1, string? _2, CancellationToken _3) =>
            ValueTask.FromResult<PublicKeyMemory?>(material.SigningPublicKey);

        JarmResponseValidationResult result = await JarmResponseValidation.ValidateAsync(
            responseJwt,
            material.Registration.IssuerUri!.OriginalString,
            ClientId,
            [WellKnownJwaValues.Es256],
            TimeProvider.GetUtcNow(),
            ResolveKey,
            static payload => JsonSerializerExtensions.Deserialize<Dictionary<string, object?>>(
                payload, TestSetup.DefaultSerializationOptions)
                ?? throw new FormatException("Payload JSON parsed to null."),
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(OAuthErrors.InvalidTarget, result.Error);
        Assert.AreEqual(state, result.State);
        Assert.IsNotNull(result.Parameters);
        Assert.IsTrue(result.Parameters.TryGetValue(OAuthRequestParameterNames.ErrorDescription, out object? description));
        Assert.AreEqual("Refused:  and quoted", description as string);
    }


    /// <summary>
    /// Grants <paramref name="grantedResource"/> at the pushed request over the real loopback
    /// listener, served under "tr-TR", then redeems the code naming <paramref name="requestedResource"/>
    /// and asserts the 400 <c>invalid_target</c> body
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.2">RFC 8707 section 2.2</see>)
    /// whose <c>error_description</c> is this library's one fixed text for a resource that was not
    /// granted, the body holding no part of the requested value.
    /// </summary>
    /// <param name="grantedResource">The <c>resource</c> the authorization request grants.</param>
    /// <param name="requestedResource">The <c>resource</c> the token request names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertNarrowingIsRefusedAsNotGrantedAsync(string grantedResource, string requestedResource)
    {
        await using TestHostShell host = new(TimeProvider);
        using ServedCultureScope culture = await ServedCultureScope.CreateAsync(
            host, "tr-TR", TestContext.CancellationToken).ConfigureAwait(false);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);
        _ = host.SeedTestSubject(subject: SubjectId);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, grantedResource, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        (int status, string body) = await PostTokenAsync(
            host, segment, code, pkce.EncodedVerifier, [requestedResource]).ConfigureAwait(false);
        Assert.AreEqual(400, status, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidTarget}\"", body, StringComparison.Ordinal, body);
        Assert.AreEqual(
            "The resource parameter must be a subset of the resource(s) originally granted.",
            ExtractStringProperty(body, "error_description"), body);
        Assert.DoesNotContain(requestedResource, body, StringComparison.Ordinal, body);

        culture.AssertEveryRequestWasServedUnder("tr-TR", 3);
    }


    /// <summary>
    /// Asserts a direct authorize request carrying a non-ASCII <paramref name="resource"/> is refused
    /// with the <c>invalid_target</c> error redirect, echoing the request's <c>state</c>.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="pkce">The PKCE pair whose challenge the request carries.</param>
    /// <param name="resource">The <c>resource</c> value under test.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertDirectAuthorizeIsRefusedByRedirectAsync(
        TestHostShell host, string segment, PkceParameters pkce, string resource)
    {
        const string state = "state-direct-authorize";
        List<KeyValuePair<string, string>> fields = BuildAuthorizationFields(pkce, resource);
        fields.Add(new(OAuthRequestParameterNames.State, state));

        Uri authorizeUri = RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment, fields);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);

        AssertErrorRedirect(
            (int)response.StatusCode, response.Headers.Location, OAuthErrors.InvalidTarget,
            MalformedResourceIndicatorDescription, state);
    }


    /// <summary>
    /// Asserts a request object by value carrying a non-ASCII <paramref name="resource"/> is refused
    /// with the <c>invalid_target</c> error redirect, echoing the request object's <c>state</c>.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="material">The registration signing the request object.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="pkce">The PKCE pair whose challenge the request object carries.</param>
    /// <param name="resource">The <c>resource</c> value under test.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertRequestObjectByValueIsRefusedByRedirectAsync(
        TestHostShell host, VerifierKeyMaterial material, string segment, PkceParameters pkce, string resource)
    {
        string compactJar = await BuildResourceJarAsync(
            host, material, pkce, resource, TestContext.CancellationToken).ConfigureAwait(false);
        Uri authorizeUri = RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ]);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);

        AssertErrorRedirect(
            (int)response.StatusCode, response.Headers.Location, OAuthErrors.InvalidTarget,
            MalformedResourceIndicatorDescription, ResourceJarState);
    }


    /// <summary>
    /// Asserts a request object pushed to the PAR endpoint with a non-ASCII <paramref name="resource"/>
    /// is refused with the 400 <c>invalid_target</c> JSON body.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="material">The registration signing the request object.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="pkce">The PKCE pair whose challenge the request object carries.</param>
    /// <param name="resource">The <c>resource</c> value under test.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertRequestObjectAtPushedEndpointIsRefusedAsync(
        TestHostShell host, VerifierKeyMaterial material, string segment, PkceParameters pkce, string resource)
    {
        string compactJar = await BuildResourceJarAsync(
            host, material, pkce, resource, TestContext.CancellationToken).ConfigureAwait(false);
        List<KeyValuePair<string, string>> fields =
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ];

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(MalformedResourceIndicatorBody, body);
    }


    /// <summary>
    /// Asserts a code redemption naming a non-ASCII <paramref name="resource"/> answers the same 400
    /// <c>invalid_target</c> body for a live code and for an unknown one, touching no flow-state store
    /// operation for either, and that the live code then redeems with a well-formed request.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="material">The registration the code is issued to.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="pkce">The PKCE pair the live code is bound to.</param>
    /// <param name="resource">The <c>resource</c> value under test.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertCodeRedemptionIsRefusedIdenticallyAsync(
        TestHostShell host, VerifierKeyMaterial material, string segment, PkceParameters pkce, string resource)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        string code = await AuthorizeForResourceAsync(
            host, material, segment, ResourceDeliveryMode.Pushed, ResourceA, pkce, TestContext.CancellationToken).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        int beforeLive = hosted.StorageObservations.Count;
        (int liveStatus, string liveBody) = await PostTokenAsync(
            host, segment, code, pkce.EncodedVerifier, [resource]).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeLive,
            "a non-ASCII resource at code redemption, live code");

        int beforeUnknown = hosted.StorageObservations.Count;
        (int unknownStatus, string unknownBody) = await PostTokenAsync(
            host, segment, "code-never-issued-by-this-host", pkce.EncodedVerifier, [resource]).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown,
            "a non-ASCII resource at code redemption, unknown code");

        Assert.AreEqual(400, liveStatus, liveBody);
        Assert.AreEqual(MalformedResourceIndicatorBody, liveBody);
        Assert.AreEqual(unknownStatus, liveStatus);
        Assert.AreEqual(unknownBody, liveBody,
            "A live code's existence must not be discoverable from a non-ASCII resource value's refusal.");

        (int okStatus, string okBody) = await PostTokenAsync(
            host, segment, code, pkce.EncodedVerifier, [ResourceA]).ConfigureAwait(false);
        Assert.AreEqual(200, okStatus, okBody);
    }


    /// <summary>
    /// Asserts a <c>client_credentials</c> token request naming a malformed <paramref name="resource"/>
    /// (a non-ASCII value, or one with an empty scheme) is refused with the 400 <c>invalid_target</c>
    /// JSON body.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="resource">The <c>resource</c> value under test.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertClientCredentialsIsRefusedAsync(TestHostShell host, string segment, string resource)
    {
        ServerHttpResponse response = await PostClientCredentialsOverTheWireAsync(
            host, segment, [resource]).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(MalformedResourceIndicatorBody, response.Body);
    }


    /// <summary>
    /// Wires the client secret check of the <c>client_credentials</c> grant on the live server, then
    /// posts a <c>client_credentials</c> token request over the real loopback listener carrying one
    /// <c>resource</c> occurrence per entry of <paramref name="resources"/>, in order, and none when
    /// the list is empty.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="resources">The <c>resource</c> occurrences the request carries.</param>
    /// <returns>The listener's answer.</returns>
    private async Task<ServerHttpResponse> PostClientCredentialsOverTheWireAsync(
        TestHostShell host, string segment, IReadOnlyList<string> resources)
    {
        const string clientSecret = "s3cret-for-client-credentials";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, clientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = clientSecret
        };
        foreach(string resource in resources)
        {
            fields.Add(OAuthRequestParameterNames.Resource, resource);
        }

        return await RawAuthCodeWirePushers.PushNamedEndpointAsync(
            host, segment, WellKnownEndpointNames.ClientCredentialsToken, WellKnownHttpMethods.Post,
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Reads the fault names the request trace recorded, in the order the spans stopped, from every
    /// <see cref="OAuthEventNames.MalformedResourceIndicator"/> event's
    /// <see cref="OAuthEventNames.ResourceIndicatorFaultTagName"/> tag, over the spans of
    /// <paramref name="root"/>'s trace and <paramref name="root"/> itself.
    /// </summary>
    /// <param name="capture">The capture that listened while the request ran.</param>
    /// <param name="root">The stopped activity the request ran under.</param>
    /// <returns>The recorded fault names.</returns>
    private static string[] ReadMalformedResourceFaultNames(TraceTreeCapture capture, Activity root) =>
    [
        .. TraceTreeAssertions.FilterByTrace(capture.StoppedActivities, root.TraceId)
            .Append(root)
            .SelectMany(activity => activity.Events)
            .Where(activityEvent => string.Equals(
                activityEvent.Name, OAuthEventNames.MalformedResourceIndicator, StringComparison.Ordinal))
            .Select(activityEvent => activityEvent.Tags.Single(tag => string.Equals(
                tag.Key, OAuthEventNames.ResourceIndicatorFaultTagName, StringComparison.Ordinal)).Value?.ToString()
                ?? string.Empty)
    ];


    /// <summary>
    /// Asserts an authorization endpoint answer is the error redirect of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 section
    /// 4.1.2.1</see>: a 302 whose <c>Location</c> is the registered redirect URI and whose query
    /// carries the <c>error</c>, <c>error_description</c> and <c>state</c> values, each decoded from
    /// the wire query.
    /// </summary>
    /// <param name="statusCode">The status code of the authorize response.</param>
    /// <param name="location">The <c>Location</c> header of the authorize response.</param>
    /// <param name="expectedError">The expected <c>error</c> code.</param>
    /// <param name="expectedDescription">The expected <c>error_description</c> text.</param>
    /// <param name="expectedState">The expected <c>state</c> value.</param>
    private static void AssertErrorRedirect(
        int statusCode, Uri? location, string expectedError, string expectedDescription, string expectedState)
    {
        Assert.AreEqual(302, statusCode);
        Assert.IsNotNull(location, "An error redirect carries a Location header.");

        string wireLocation = location.OriginalString;
        int queryStart = wireLocation.IndexOf('?', StringComparison.Ordinal);
        Assert.IsGreaterThan(-1, queryStart, $"The error redirect carries a query. Location: {wireLocation}");
        Assert.AreEqual(RedirectUri.OriginalString, wireLocation[..queryStart]);

        Dictionary<string, string> query = [];
        foreach(string pair in wireLocation[(queryStart + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int equalsIndex = pair.IndexOf('=', StringComparison.Ordinal);
            string name = equalsIndex < 0 ? pair : pair[..equalsIndex];
            string value = equalsIndex < 0 ? string.Empty : pair[(equalsIndex + 1)..];
            query[Uri.UnescapeDataString(name.Replace('+', ' '))] = Uri.UnescapeDataString(value.Replace('+', ' '));
        }

        Assert.AreEqual(expectedError, query.GetValueOrDefault(OAuthRequestParameterNames.Error), wireLocation);
        Assert.AreEqual(expectedDescription, query.GetValueOrDefault(OAuthRequestParameterNames.ErrorDescription), wireLocation);
        Assert.AreEqual(expectedState, query.GetValueOrDefault(OAuthRequestParameterNames.State), wireLocation);
    }


    /// <summary>
    /// Builds the shared response_type/client_id/PKCE/redirect_uri/scope/resource field set every
    /// <see cref="ResourceDeliveryMode.Pushed"/> and <see cref="ResourceDeliveryMode.DirectAuthorize"/>
    /// case sends, whether to the PAR endpoint's form body or the authorize endpoint's query string.
    /// </summary>
    /// <param name="pkce">The generated PKCE pair for this case.</param>
    /// <param name="resource">The <c>resource</c> value under test.</param>
    /// <returns>The ordered field list.</returns>
    private static List<KeyValuePair<string, string>> BuildAuthorizationFields(PkceParameters pkce, string resource) =>
    [
        new(OAuthRequestParameterNames.ResponseType, WellKnownResponseTypes.Code),
        new(OAuthRequestParameterNames.ClientId, ClientId),
        new(OAuthRequestParameterNames.CodeChallenge, pkce.EncodedChallenge),
        new(OAuthRequestParameterNames.CodeChallengeMethod, WellKnownCodeChallengeMethods.S256),
        new(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString),
        new(OAuthRequestParameterNames.Scope, WellKnownScopes.OpenId),
        new(OAuthRequestParameterNames.Resource, resource)
    ];


    /// <summary>
    /// Drives <paramref name="mode"/>'s wire shape for <paramref name="resource"/> over the real
    /// listener and returns the authorization code; the one seam every fold row's data case shares,
    /// so each case differs only in the resource value under test, never in how it reaches the server.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="material">The registration signing a request object, when <paramref name="mode"/> needs one.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="mode">The wire shape to drive.</param>
    /// <param name="resource">The <c>resource</c> value under test.</param>
    /// <param name="pkce">The PKCE pair this case redeems with.</param>
    /// <param name="cancellationToken">Cancellation of every wire exchange this drives.</param>
    /// <returns>The authorization code extracted from the authorize redirect.</returns>
    private Task<string> AuthorizeForResourceAsync(
        TestHostShell host, VerifierKeyMaterial material, string segment, ResourceDeliveryMode mode,
        string resource, PkceParameters pkce, CancellationToken cancellationToken) => mode switch
        {
            ResourceDeliveryMode.Pushed =>
                PushAndExtractCodeAsync(host, segment, BuildAuthorizationFields(pkce, resource), cancellationToken),
            ResourceDeliveryMode.DirectAuthorize =>
                DirectAuthorizeAndExtractCodeAsync(host, segment, BuildAuthorizationFields(pkce, resource), cancellationToken),
            ResourceDeliveryMode.RequestObjectByValue =>
                RequestObjectByValueAndExtractCodeAsync(host, material, segment, pkce, resource, cancellationToken),
            ResourceDeliveryMode.RequestObjectAtPushedEndpoint =>
                RequestObjectAtPushedEndpointAndExtractCodeAsync(host, material, segment, pkce, resource, cancellationToken),
            _ => throw new NotSupportedException($"Unsupported {nameof(ResourceDeliveryMode)}: {mode}.")
        };


    /// <summary>Pushes <paramref name="fields"/> to the PAR endpoint and redeems the pinned authorize GET, asserting the 201/302 pair.</summary>
    private static async Task<string> PushAndExtractCodeAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields, CancellationToken cancellationToken)
    {
        (int parStatusCode, string parBody, Uri? location, int authorizeStatusCode) =
            await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
                host, segment, ClientId, SubjectId, fields, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);
        Assert.AreEqual(302, authorizeStatusCode);

        return ExtractCode(location!.ToString());
    }


    /// <summary>Sends <paramref name="fields"/> directly to the authorize endpoint's query string, asserting the 302 redirect.</summary>
    private static async Task<string> DirectAuthorizeAndExtractCodeAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields, CancellationToken cancellationToken)
    {
        Uri authorizeUri = RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment, fields);
        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUri, SubjectId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)response.StatusCode);

        return ExtractCode(response.Headers.Location!.ToString());
    }


    /// <summary>Signs a request object carrying <paramref name="resource"/> and presents it directly at the authorize endpoint.</summary>
    private async Task<string> RequestObjectByValueAndExtractCodeAsync(
        TestHostShell host, VerifierKeyMaterial material, string segment, PkceParameters pkce, string resource, CancellationToken cancellationToken)
    {
        string compactJar = await BuildResourceJarAsync(host, material, pkce, resource, cancellationToken).ConfigureAwait(false);
        List<KeyValuePair<string, string>> fields =
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ];

        return await DirectAuthorizeAndExtractCodeAsync(host, segment, fields, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Signs a request object carrying <paramref name="resource"/> and pushes it to the PAR endpoint.</summary>
    private async Task<string> RequestObjectAtPushedEndpointAndExtractCodeAsync(
        TestHostShell host, VerifierKeyMaterial material, string segment, PkceParameters pkce, string resource, CancellationToken cancellationToken)
    {
        string compactJar = await BuildResourceJarAsync(host, material, pkce, resource, cancellationToken).ConfigureAwait(false);
        List<KeyValuePair<string, string>> fields =
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ];

        return await PushAndExtractCodeAsync(host, segment, fields, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds and signs a request object carrying <paramref name="resource"/> and
    /// <paramref name="pkce"/>'s challenge, after extending <paramref name="material"/> into the
    /// <see cref="KeyUsageContext.JarSigning"/> slot (<see cref="UpgradeToJarSigningCapableAsync"/>).
    /// </summary>
    private Task<string> BuildResourceJarAsync(
        TestHostShell host, VerifierKeyMaterial material, PkceParameters pkce, string resource, CancellationToken cancellationToken) =>
        BuildResourceClaimJarAsync(host, material, pkce, resource, cancellationToken);


    /// <summary>
    /// Builds and signs a request object whose <c>resource</c> claim is <paramref name="resourceClaim"/>
    /// exactly as given (a string, or an array of elements of any JSON type), after extending
    /// <paramref name="material"/> into the <see cref="KeyUsageContext.JarSigning"/> slot; the seam
    /// <see cref="BuildResourceJarAsync"/> and the array-claim rows share.
    /// </summary>
    /// <param name="host">The fixture owning the registration.</param>
    /// <param name="material">The registration signing the request object.</param>
    /// <param name="pkce">The PKCE pair whose challenge the request object carries.</param>
    /// <param name="resourceClaim">The value of the <c>resource</c> claim.</param>
    /// <param name="cancellationToken">Cancellation of the signing call.</param>
    /// <returns>The compact-serialized signed request object.</returns>
    private async Task<string> BuildResourceClaimJarAsync(
        TestHostShell host, VerifierKeyMaterial material, PkceParameters pkce, object resourceClaim, CancellationToken cancellationToken)
    {
        await UpgradeToJarSigningCapableAsync(host, material).ConfigureAwait(false);

        DateTimeOffset issuedAt = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, issuedAt, ClientId, RedirectUri, ResourceJarState, "nonce-fold-resource");
        claims[OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge;
        claims[OAuthRequestParameterNames.Resource] = resourceClaim;

        return await OAuthJarFixtures.BuildSignedJarAsync(material, claims, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Redeems <paramref name="presentedCode"/> at the token endpoint over the real wire, adding one
    /// repeated <c>resource</c> field occurrence per entry of <paramref name="resources"/>; the
    /// class-level token helper the two malformed-resource listener rows and every fold row share.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="presentedCode">The authorization code presented.</param>
    /// <param name="verifier">The PKCE code verifier matching the code's challenge.</param>
    /// <param name="resources">Zero or more repeated <c>resource</c> field occurrences.</param>
    /// <returns>The response's status code and body.</returns>
    private async Task<(int Status, string Body)> PostTokenAsync(
        TestHostShell host, string segment, string presentedCode, string verifier, IReadOnlyList<string> resources)
    {
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        List<KeyValuePair<string, string>> fields =
        [
            new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.AuthorizationCode),
            new(OAuthRequestParameterNames.Code, presentedCode),
            new(OAuthRequestParameterNames.CodeVerifier, verifier),
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.RedirectUri, RedirectUri.OriginalString)
        ];
        foreach(string resource in resources)
        {
            fields.Add(new(OAuthRequestParameterNames.Resource, resource));
        }

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.Host("default").SharedHttpClient!, tokenUri, fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body);
    }


    /// <summary>
    /// Refreshes <paramref name="presentedRefreshToken"/> over the real wire, adding one repeated
    /// <c>resource</c> field occurrence per entry of <paramref name="resources"/>; the class-level
    /// refresh helper <see cref="WhitespaceResourceValueIsMalformedAtRefreshOverRealWireAsync"/> shares.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="presentedRefreshToken">The refresh token presented.</param>
    /// <param name="resources">Zero or more repeated <c>resource</c> field occurrences.</param>
    /// <returns>The response's status code and body.</returns>
    private async Task<(int Status, string Body)> PostRefreshAsync(
        TestHostShell host, string segment, string presentedRefreshToken, IReadOnlyList<string> resources)
    {
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        List<KeyValuePair<string, string>> fields =
        [
            new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.RefreshToken),
            new(OAuthRequestParameterNames.RefreshToken, presentedRefreshToken),
            new(OAuthRequestParameterNames.ClientId, ClientId)
        ];
        foreach(string resource in resources)
        {
            fields.Add(new(OAuthRequestParameterNames.Resource, resource));
        }

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            host.Host("default").SharedHttpClient!, tokenUri, fields, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body);
    }


    private async Task<ServerHttpResponse> PushAsync(
        TestHostShell host, VerifierKeyMaterial material, string? resource, string? scope = null)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
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
            parFields, [],
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
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
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
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = await ExtractRequestUriAsync(parResponse).ConfigureAwait(false);

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
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
            tokenFields, [],
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
            refreshFields, [],
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
    /// Decodes the issued access token from a token-endpoint response body and reports whether its
    /// payload carries an <c>aud</c> claim at all; the counterpart of
    /// <see cref="DecodeAudienceFromTokenResponse"/> for a grant that issues no audience.
    /// </summary>
    /// <param name="tokenResponseBody">The token-endpoint response body.</param>
    /// <returns><see langword="true"/> when the access token payload has an <c>aud</c> member.</returns>
    private static bool AccessTokenCarriesAudienceClaim(string tokenResponseBody)
    {
        using JsonDocument responseDoc = JsonDocument.Parse(tokenResponseBody);
        string accessToken = responseDoc.RootElement.GetProperty("access_token").GetString()!;

        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], BaseMemoryPool.Shared);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);

        return payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Aud, out _);
    }


    /// <summary>
    /// Adds the <see cref="KeyUsageContext.JarSigning"/> slot (reusing <paramref name="material"/>'s
    /// already-registered signing key) to a <see cref="TestHostShell.RegisterDpopClientAsync"/>
    /// registration, so a single client can both sign a JAR and receive an access token —
    /// <see cref="TestHostShell.RegisterClientAsync"/>/<see cref="TestHostShell.RegisterJarSigningClientAsync"/>
    /// register JAR verification only, with no <see cref="KeyUsageContext.AccessTokenIssuance"/> key.
    /// </summary>
    private static async Task UpgradeToJarSigningCapableAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        _ = await host.UpdateAsync(material, previous =>
        {
            Dictionary<KeyUsageContext, SigningKeySet> signingKeys = new(previous.SigningKeys)
            {
                [KeyUsageContext.JarSigning] = new SigningKeySet { Current = [material.SigningKeyId] }
            };

            return previous with
            {
                SigningKeys = signingKeys
            };
        }).ConfigureAwait(false);
    }


    private static void AssertErrorCode(ServerHttpResponse response, string expectedCode)
    {
        string expectedFragment = $"\"error\":\"{expectedCode}\"";
        Assert.Contains(expectedFragment, response.Body, StringComparison.Ordinal,
            $"Expected error '{expectedCode}' in response body. Got: {response.Body}");
    }
}
