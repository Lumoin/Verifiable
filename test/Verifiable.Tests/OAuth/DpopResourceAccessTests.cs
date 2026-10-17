using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// In-process rows for <see cref="DpopResourceAccess.DecideAsync"/>: the arguments an application passes that are its
/// own configuration, which it is answered for with an exception before any decision, never with a decision on the
/// request; and the decision on a <c>Bearer</c> presentation of a validated token where DPoP-bound access tokens are
/// required, which no application answering that presentation before validating the token reaches over the wire; and
/// the target URI a proof's <c>jti</c> is claimed at when the application names one target by two spellings.
/// </summary>
[TestClass]
internal sealed class DpopResourceAccessTests
{
    /// <summary>The test context, carrying the run's cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>: "htu: The HTTP target
    /// URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts.",
    /// with <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "The htu claim matches the
    /// HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.",
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2">RFC 9110 Section 4.2</see>: "Although requests
    /// might target any URI scheme, the following schemes are inherent to HTTP servers", http and https, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">Section 4.2.4</see>: "A sender MUST NOT generate
    /// the userinfo subcomponent (and its "@" delimiter) when an "http" or "https" URI reference is generated within a
    /// message as a target URI or field value." The target URI an application names its resource by is the absolute
    /// http or https URI with no userinfo, query or fragment that a proof's <c>htu</c> is held to and the resource's
    /// nonces are issued for. A target URI of any other shape is the application's own argument and is refused with
    /// <see cref="ArgumentException"/> naming <c>request</c>, before any decision. The rows: a relative URI; an https URI
    /// with a query; an https URI with a fragment; an ftp URI; an https URI with userinfo.
    /// </summary>
    /// <param name="row">
    /// The target URI: <see cref="RelativeRow"/>, <see cref="QueryRow"/>, <see cref="FragmentRow"/>, <see cref="FtpRow"/>
    /// or <see cref="UserInfoRow"/>.
    /// </param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(RelativeRow)]
    [DataRow(QueryRow)]
    [DataRow(FragmentRow)]
    [DataRow(FtpRow)]
    [DataRow(UserInfoRow)]
    public async Task DecideRefusesATargetUriNoProofCanNameAsTheCallersArgumentAsync(string row)
    {
        Uri targetUri = row switch
        {
            RelativeRow => new Uri("/protected", UriKind.Relative),
            QueryRow => new Uri("https://rs.example/protected?view=full"),
            FragmentRow => new Uri("https://rs.example/protected#top"),
            FtpRow => new Uri("ftp://rs.example/protected"),
            UserInfoRow => new Uri("https://user@rs.example/protected"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown target URI row.")
        };
        DpopResourceRequest request = new()
        {
            AccessToken = "access-token",
            IsDpopPresentation = true,
            HttpMethod = "GET",
            TargetUri = targetUri,
            DpopFieldLines = []
        };

        ArgumentException refusal = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await DpopResourceAccess.DecideAsync(Integration, request, [], TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.AreEqual("request", refusal.ParamName);
    }


    /// <summary>
    /// The row whose target URI is relative. A constant, not a property, because a DataRow attribute argument must be a
    /// compile-time constant.
    /// </summary>
    private const string RelativeRow = "relative";

    /// <summary>
    /// The row whose target URI carries a query. A constant, not a property, because a DataRow attribute argument must
    /// be a compile-time constant.
    /// </summary>
    private const string QueryRow = "query";

    /// <summary>
    /// The row whose target URI carries a fragment. A constant, not a property, because a DataRow attribute argument
    /// must be a compile-time constant.
    /// </summary>
    private const string FragmentRow = "fragment";

    /// <summary>
    /// The row whose target URI has the ftp scheme. A constant, not a property, because a DataRow attribute argument
    /// must be a compile-time constant.
    /// </summary>
    private const string FtpRow = "ftp";

    /// <summary>
    /// The row whose target URI carries userinfo. A constant, not a property, because a DataRow attribute argument must
    /// be a compile-time constant.
    /// </summary>
    private const string UserInfoRow = "userinfo";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "To limit this,
    /// servers MUST only accept DPoP proofs for a limited time after their creation (preferably only for a relatively
    /// brief period on the order of seconds or minutes)." The freshness window an application's resource holds a proof's
    /// <c>iat</c> to either way of its clock is the application's own configuration. A window of minus one second names
    /// no time a proof is accepted for and is refused with <see cref="ArgumentException"/> naming <c>integration</c>,
    /// before any decision.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DecideRefusesANegativeFreshnessWindowAsTheCallersArgumentAsync()
    {
        ResourceServerIntegration integration = new()
        {
            TrustedIssuer = new Uri("https://issuer.test/tenant-a"),
            ExpectedAudience = "test-resource-server",
            ResolveVerificationKeyAsync = static (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null),
            TimeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch),
            DpopFreshnessWindow = TimeSpan.FromSeconds(-1)
        };
        DpopResourceRequest request = new()
        {
            AccessToken = "access-token",
            IsDpopPresentation = true,
            HttpMethod = "GET",
            TargetUri = new Uri("https://rs.example/protected"),
            DpopFieldLines = []
        };

        ArgumentException refusal = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await DpopResourceAccess.DecideAsync(integration, request, [], TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.AreEqual("integration", refusal.ParamName);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449].", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If the request lacks
    /// any authentication information (e.g., the client was unaware that authentication is necessary or attempted using
    /// an unsupported authentication method), the resource server SHOULD NOT include an error code or other error
    /// information." At a resource requiring DPoP-bound access tokens, a validated access token bound to no key and
    /// presented under the <c>Bearer</c> scheme is denied: 401, an empty body, and exactly two fields, the one
    /// <c>WWW-Authenticate</c> value
    /// <c>DPoP realm="protected", scope="openid", algs="ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519", resource_metadata="https://rs.example/.well-known/oauth-protected-resource"</c>
    /// with no <c>error</c> and no <c>Bearer</c> challenge, and
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DecideRefusesABearerPresentationWhereDpopBoundAccessTokensAreRequiredAsync()
    {
        DpopResourceRequest request = new()
        {
            AccessToken = "access-token",
            IsDpopPresentation = false,
            IsSenderConstrained = false,
            HttpMethod = "GET",
            TargetUri = new Uri("https://rs.example/protected"),
            DpopFieldLines = [],
            IsDpopBoundAccessTokenRequired = true,
            Realm = "protected",
            Scope = "openid",
            ResourceMetadata = new Uri("https://rs.example/.well-known/oauth-protected-resource")
        };

        DpopResourceDecision decision = await DpopResourceAccess.DecideAsync(
            Integration, request, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(DpopResourceDecisionKind.Deny, decision.Kind);
        Assert.IsFalse(decision.IsPermitted, "A denial grants no access.");
        ServerHttpResponse response = Assert.IsInstanceOfType<ServerHttpResponse>(decision.Response);
        Assert.AreEqual(401, response.StatusCode);
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
        Assert.HasCount(2, response.Headers, "The challenge and the exposure field, no other field.");
        Assert.AreEqual(
            "DPoP realm=\"protected\", scope=\"openid\", algs=\"ES256 ES384 ES512 ES256K RS256 RS384 RS512 PS256 PS384 PS512 EdDSA Ed25519\", resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource\"",
            response.Headers["WWW-Authenticate"]);
        Assert.AreEqual("WWW-Authenticate, DPoP-Nonce", response.Headers["Access-Control-Expose-Headers"]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP
    /// proof JWT would be accepted to prevent multiple uses of the same DPoP proof. HTTP requests to the same URI for
    /// which the jti value has been seen before would be declined.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of
    /// [RFC3986]) before comparing the htu claim.", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 Section 6.2.2.1</see> reads "the
    /// scheme and host are case-insensitive and therefore should be normalized to lowercase" and
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.3">Section 6.2.3</see> names the scheme's default
    /// port. <c>https://RS.example:443/protected</c> and <c>https://rs.example/protected</c> name one target URI. One
    /// validated proof carrying the <c>jti</c> <c>shared-jti</c>, decided with its DPoP-bound access token first at the
    /// one spelling and then at the other, is claimed through the application's slot at the one normalized target
    /// <c>https://rs.example/protected</c> both times: the first decision permits, the second is denied with 401 and
    /// <c>invalid_dpop_proof</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DecideClaimsAProofJtiAtTheNormalizedTargetUriAsync()
    {
        FakeTimeProvider time = new(TestClock.CanonicalEpoch);
        InMemoryDpopReplayCache cache = new(time);
        ConcurrentQueue<string> claimedTargets = new();
        ResourceServerIntegration integration = new()
        {
            TrustedIssuer = new Uri("https://issuer.test/tenant-a"),
            ExpectedAudience = "test-resource-server",
            ResolveVerificationKeyAsync = static (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null),
            TimeProvider = time,
            ValidateDpopProofAsync = (request, _) => ValueTask.FromResult(DpopProofValidationResult.Success(
                new DpopProofClaims
                {
                    Htm = request.HttpMethod,
                    Htu = request.HttpUrl,
                    Iat = time.GetUtcNow(),
                    Jti = "shared-jti",
                    Nonce = ResourceNonce
                },
                BoundThumbprint)),
            IssueDpopNonceAsync = static (_, _, _, _) => ValueTask.FromResult(ResourceNonce),
            ValidateDpopNonceAsync = (_, _, _, _, _) => ValueTask.FromResult(DpopNonceValidationResult.Success(
                new DpopNoncePayload { Kid = "resource-nonce-key", IssuedAt = time.GetUtcNow() })),
            ConsultDpopProofJtiAsync = (jti, targetUri, recordUntil, context, cancellationToken) =>
            {
                claimedTargets.Enqueue(targetUri.OriginalString);

                return cache.ConsultAsync(jti, targetUri, recordUntil, context, cancellationToken);
            }
        };

        DpopResourceDecision first = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(new Uri("https://RS.example:443/protected")), [], TestContext.CancellationToken).ConfigureAwait(false);
        DpopResourceDecision second = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(new Uri("https://rs.example/protected")), [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(DpopResourceDecisionKind.Permit, first.Kind, "The first presentation of the proof is served.");
        Assert.AreEqual(DpopResourceDecisionKind.Deny, second.Kind, "The proof presented again at the same target URI is refused.");
        ServerHttpResponse refusal = Assert.IsInstanceOfType<ServerHttpResponse>(second.Response);
        Assert.AreEqual(401, refusal.StatusCode);
        Assert.AreEqual(
            "{\"error\":\"invalid_dpop_proof\",\"error_description\":\"The DPoP proof jti has been presented previously.\"}", refusal.Body);
        string[] targets = [.. claimedTargets];
        Assert.HasCount(2, targets, "Each decision claims the proof's jti once.");
        Assert.AreEqual("https://rs.example/protected", targets[0], "The first claim names the normalized target URI.");
        Assert.AreEqual("https://rs.example/protected", targets[1], "The second claim names the same normalized target URI.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to
    /// the same URI for which the jti value has been seen before would be declined.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of
    /// [RFC3986]) before comparing the htu claim.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.2">RFC 3986 Section 6.2.2.2</see>: "These URIs
    /// should be normalized by decoding any percent-encoded octet that corresponds to an unreserved character, as
    /// described in Section 2.3.", a space being no unreserved character. <c>https://rs.example/a%20</c> and
    /// <c>https://RS.example:443/a%20</c> name one target URI. One validated proof carrying the <c>jti</c>
    /// <c>shared-jti</c>, decided with its DPoP-bound access token at <c>https://rs.example/a%20</c> over an application
    /// whose slot is an <see cref="InMemoryDpopReplayCache"/>, is permitted; the same <c>jti</c> then claimed directly at
    /// that cache at <c>https://RS.example:443/a%20</c> is answered <see cref="JtiReplayOutcome.Replayed"/>,
    /// and the cache holds one record.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DecideAndADirectClaimNameATargetEndingInAnEncodedSpaceByOneRecordAsync()
    {
        FakeTimeProvider time = new(TestClock.CanonicalEpoch);
        InMemoryDpopReplayCache cache = new(time);
        ResourceServerIntegration integration = new()
        {
            TrustedIssuer = new Uri("https://issuer.test/tenant-a"),
            ExpectedAudience = "test-resource-server",
            ResolveVerificationKeyAsync = static (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null),
            TimeProvider = time,
            ValidateDpopProofAsync = (request, _) => ValueTask.FromResult(DpopProofValidationResult.Success(
                new DpopProofClaims
                {
                    Htm = request.HttpMethod,
                    Htu = request.HttpUrl,
                    Iat = time.GetUtcNow(),
                    Jti = "shared-jti",
                    Nonce = ResourceNonce
                },
                BoundThumbprint)),
            IssueDpopNonceAsync = static (_, _, _, _) => ValueTask.FromResult(ResourceNonce),
            ValidateDpopNonceAsync = (_, _, _, _, _) => ValueTask.FromResult(DpopNonceValidationResult.Success(
                new DpopNoncePayload { Kid = "resource-nonce-key", IssuedAt = time.GetUtcNow() })),
            ConsultDpopProofJtiAsync = cache.ConsultAsync
        };

        DpopResourceDecision decision = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(new Uri("https://rs.example/a%20")), [], TestContext.CancellationToken).ConfigureAwait(false);
        JtiReplayOutcome directClaim = await cache.ConsultAsync(
            "shared-jti", new Uri("https://RS.example:443/a%20"), time.GetUtcNow() + TimeSpan.FromMinutes(1), [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(DpopResourceDecisionKind.Permit, decision.Kind, "The first presentation of the proof is served.");
        Assert.AreEqual(
            JtiReplayOutcome.Replayed, directClaim, "The direct claim names the target the decision claimed the jti at.");
        Assert.AreEqual(1, cache.Count, "One target URI is one record.");
    }


    /// <summary>
    /// The decision is recorded on the span <see cref="ResourceServerIntegration.StartTraceActivity"/> answers as that
    /// decision alone: <see cref="OAuthTagNames.DpopResourceCheck"/> is "absent on a <c>Permit</c>", and
    /// <see cref="ServerTagNames.ErrorCode"/> names the answer's error code only where the answer carries one. With the
    /// slot answering the activity current at the call, a test-started activity the application reuses for every decision,
    /// a presentation of a DPoP-bound access token with no proof is decided first and refused (<c>proof_absent</c>,
    /// <c>use_dpop_nonce</c>) and a presentation with a valid proof carrying the resource's nonce is decided next and
    /// permitted; the activity then carries <see cref="OAuthTagNames.DpopResourceDecision"/> <c>Permit</c> and neither
    /// <see cref="OAuthTagNames.DpopResourceCheck"/> nor <see cref="ServerTagNames.ErrorCode"/>, no entry of either
    /// left among its tags, and it is not stopped.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AReusedSpanCarriesTheLastDecisionAloneAsync()
    {
        FakeTimeProvider time = new(TestClock.CanonicalEpoch);
        InMemoryDpopReplayCache cache = new(time);
        ResourceServerIntegration integration = ReusedSpanIntegration(time, cache.ConsultAsync);
        Uri targetUri = new("https://rs.example/protected");
        using Activity reused = new(nameof(AReusedSpanCarriesTheLastDecisionAloneAsync));

        _ = reused.Start();
        DpopResourceDecision refused = await DpopResourceAccess.DecideAsync(
            integration, PresentationWithoutProofAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false);
        DpopResourceDecision permitted = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false);
        bool isStoppedByTheDecisions = reused.IsStopped;
        reused.Stop();

        Assert.AreEqual(DpopResourceDecisionKind.Deny, refused.Kind, "The presentation without a proof is refused.");
        Assert.AreEqual(DpopResourceDecisionKind.Permit, permitted.Kind, "The presentation with a valid proof is permitted.");
        Assert.IsFalse(isStoppedByTheDecisions, "The application's own activity is not stopped by the library.");
        Assert.AreEqual(nameof(DpopResourceDecisionKind.Permit), reused.GetTagItem(OAuthTagNames.DpopResourceDecision) as string);
        Assert.IsNull(reused.GetTagItem(OAuthTagNames.DpopResourceCheck), "A permit carries no refusing check.");
        Assert.IsNull(reused.GetTagItem(ServerTagNames.ErrorCode), "A permit carries no error code.");
        Assert.DoesNotContain(
            tag => tag.Key == OAuthTagNames.DpopResourceCheck, reused.TagObjects,
            "The span holds no entry for the earlier decision's refusing check, not one with no value.");
        Assert.DoesNotContain(
            tag => tag.Key == ServerTagNames.ErrorCode, reused.TagObjects,
            "The span holds no entry for the earlier decision's error code, not one with no value.");
    }


    /// <summary>
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for
    /// HTTP spans</see>: "For HTTP status codes in the 5xx range, as well as any other code the client failed to
    /// interpret, span status SHOULD be set to Error." An <see cref="DpopResourceDecisionKind.IndeterminateDeny"/> is
    /// answered 500 and sets the status <see cref="ActivityStatusCode.Error"/> and <see cref="ServerTagNames.ErrorType"/>
    /// <c>500</c>; an error that happened in the span stands, so a later decision on a span the application reuses
    /// sets its own decision tags and leaves both in place. With the slot answering the activity current at the call, a
    /// test-started activity the application reuses for every decision, and the <c>jti</c> claim answering
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/> once and <see cref="JtiReplayOutcome.FirstUse"/> next, a
    /// presentation with a valid proof carrying the resource's nonce is decided twice: the first decision is an
    /// <see cref="DpopResourceDecisionKind.IndeterminateDeny"/>, the second a <see cref="DpopResourceDecisionKind.Permit"/>;
    /// the activity then carries the status <see cref="ActivityStatusCode.Error"/>, <see cref="ServerTagNames.ErrorType"/>
    /// <c>500</c>, <see cref="OAuthTagNames.DpopResourceDecision"/> <c>Permit</c> and no
    /// <see cref="OAuthTagNames.DpopResourceCheck"/> or <see cref="ServerTagNames.ErrorCode"/> entry, and it is not
    /// stopped.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AServerErrorOfAnEarlierDecisionStandsOnAReusedSpanAsync()
    {
        FakeTimeProvider time = new(TestClock.CanonicalEpoch);
        int claimCount = 0;
        ResourceServerIntegration integration = ReusedSpanIntegration(
            time,
            (_, _, _, _, _) => ValueTask.FromResult(Interlocked.Increment(ref claimCount) == 1
                ? JtiReplayOutcome.StoreUnavailable
                : JtiReplayOutcome.FirstUse));
        Uri targetUri = new("https://rs.example/protected");
        using Activity reused = new(nameof(AServerErrorOfAnEarlierDecisionStandsOnAReusedSpanAsync));

        _ = reused.Start();
        DpopResourceDecision failedClosed = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false);
        DpopResourceDecision permitted = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false);
        bool isStoppedByTheDecisions = reused.IsStopped;
        reused.Stop();

        Assert.AreEqual(
            DpopResourceDecisionKind.IndeterminateDeny, failedClosed.Kind, "A jti store that cannot record the proof fails closed.");
        Assert.AreEqual(DpopResourceDecisionKind.Permit, permitted.Kind, "The proof's first recorded use is served.");
        Assert.IsFalse(isStoppedByTheDecisions, "The application's own activity is not stopped by the library.");
        Assert.AreEqual(ActivityStatusCode.Error, reused.Status, "The server error of the earlier decision stands.");
        Assert.AreEqual("500", reused.GetTagItem(ServerTagNames.ErrorType) as string, "The earlier decision's error.type stands.");
        Assert.AreEqual(nameof(DpopResourceDecisionKind.Permit), reused.GetTagItem(OAuthTagNames.DpopResourceDecision) as string);
        Assert.DoesNotContain(
            tag => tag.Key == OAuthTagNames.DpopResourceCheck, reused.TagObjects, "A permit carries no refusing check.");
        Assert.DoesNotContain(
            tag => tag.Key == ServerTagNames.ErrorCode, reused.TagObjects, "A permit carries no error code.");
    }


    /// <summary>
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for
    /// HTTP spans</see>: "For HTTP status codes in the 4xx range span status MUST be left unset in case of
    /// SpanKind.SERVER" and "Span Status MUST be left unset if HTTP status code was in the 1xx, 2xx or 3xx ranges". A
    /// <see cref="DpopResourceDecisionKind.Deny"/> is a 4xx answer and a <see cref="DpopResourceDecisionKind.Permit"/>
    /// sets no status, so both leave the status and <see cref="ServerTagNames.ErrorType"/> the application set on its
    /// own span as it set them. With the slot answering the activity current at the call, a test-started activity on
    /// which the test sets the status <see cref="ActivityStatusCode.Error"/> and <see cref="ServerTagNames.ErrorType"/>
    /// <c>application-error</c> before any decision, a presentation of a DPoP-bound access token with no proof is
    /// decided first and refused, and a presentation with a valid proof carrying the resource's nonce next and
    /// permitted; the activity then carries the status <see cref="ActivityStatusCode.Error"/>,
    /// <see cref="ServerTagNames.ErrorType"/> <c>application-error</c> and
    /// <see cref="OAuthTagNames.DpopResourceDecision"/> <c>Permit</c>, and it is not stopped.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnErrorTheApplicationSetOnItsSpanStandsAcrossDecisionsAsync()
    {
        FakeTimeProvider time = new(TestClock.CanonicalEpoch);
        InMemoryDpopReplayCache cache = new(time);
        ResourceServerIntegration integration = ReusedSpanIntegration(time, cache.ConsultAsync);
        Uri targetUri = new("https://rs.example/protected");
        using Activity reused = new(nameof(AnErrorTheApplicationSetOnItsSpanStandsAcrossDecisionsAsync));

        _ = reused.Start();
        _ = reused.SetStatus(ActivityStatusCode.Error);
        _ = reused.SetTag(ServerTagNames.ErrorType, "application-error");
        DpopResourceDecision refused = await DpopResourceAccess.DecideAsync(
            integration, PresentationWithoutProofAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false);
        DpopResourceDecision permitted = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false);
        bool isStoppedByTheDecisions = reused.IsStopped;
        reused.Stop();

        Assert.AreEqual(DpopResourceDecisionKind.Deny, refused.Kind, "The presentation without a proof is refused.");
        Assert.AreEqual(DpopResourceDecisionKind.Permit, permitted.Kind, "The presentation with a valid proof is permitted.");
        Assert.IsFalse(isStoppedByTheDecisions, "The application's own activity is not stopped by the library.");
        Assert.AreEqual(ActivityStatusCode.Error, reused.Status, "The status the application set stands.");
        Assert.AreEqual(
            "application-error", reused.GetTagItem(ServerTagNames.ErrorType) as string, "The error.type the application set stands.");
        Assert.AreEqual(nameof(DpopResourceDecisionKind.Permit), reused.GetTagItem(OAuthTagNames.DpopResourceDecision) as string);
    }


    /// <summary>
    /// <see href="https://opentelemetry.io/docs/specs/semconv/http/http-spans/">OpenTelemetry semantic conventions for
    /// HTTP spans</see>: "If the request fails with an error before response status code was sent or received,
    /// error.type SHOULD be set to exception type (its fully-qualified class name, if applicable) or a
    /// component-specific low cardinality error identifier." An exception a slot raises is no decision, so the span
    /// <see cref="ResourceServerIntegration.StartTraceActivity"/> answers carries the error alone. With the slot
    /// answering the activity current at the call, a test-started activity the application reuses for every decision, a
    /// presentation with a valid proof carrying the resource's nonce is decided first and permitted, and the same
    /// presentation is decided next with the <c>jti</c> claim raising <see cref="InvalidOperationException"/>, which
    /// passes to the caller; the activity then carries the status <see cref="ActivityStatusCode.Error"/> and
    /// <see cref="ServerTagNames.ErrorType"/> <c>System.InvalidOperationException</c>, no
    /// <see cref="OAuthTagNames.DpopResourceDecision"/>, <see cref="OAuthTagNames.DpopResourceCheck"/> or
    /// <see cref="ServerTagNames.ErrorCode"/> entry, and it is not stopped.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnExceptionAfterADecisionLeavesTheReusedSpanCarryingTheErrorAloneAsync()
    {
        FakeTimeProvider time = new(TestClock.CanonicalEpoch);
        InMemoryDpopReplayCache cache = new(time);
        int claimCount = 0;
        ResourceServerIntegration integration = ReusedSpanIntegration(
            time,
            (jti, targetUri, recordUntil, context, cancellationToken) => Interlocked.Increment(ref claimCount) == 1
                ? cache.ConsultAsync(jti, targetUri, recordUntil, context, cancellationToken)
                : throw new InvalidOperationException("The jti store raised."));
        Uri targetUri = new("https://rs.example/protected");
        using Activity reused = new(nameof(AnExceptionAfterADecisionLeavesTheReusedSpanCarryingTheErrorAloneAsync));

        _ = reused.Start();
        DpopResourceDecision permitted = await DpopResourceAccess.DecideAsync(
            integration, BoundPresentationAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await DpopResourceAccess.DecideAsync(
                integration, BoundPresentationAt(targetUri), [], TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);
        bool isStoppedByTheDecisions = reused.IsStopped;
        reused.Stop();

        Assert.AreEqual(DpopResourceDecisionKind.Permit, permitted.Kind, "The first presentation of the proof is served.");
        Assert.IsFalse(isStoppedByTheDecisions, "The application's own activity is not stopped by the library.");
        Assert.AreEqual(ActivityStatusCode.Error, reused.Status, "An exception a slot raises sets the status Error.");
        Assert.AreEqual(
            typeof(InvalidOperationException).FullName, reused.GetTagItem(ServerTagNames.ErrorType) as string,
            "error.type is the exception type's fully-qualified name.");
        Assert.DoesNotContain(
            tag => tag.Key == OAuthTagNames.DpopResourceDecision, reused.TagObjects,
            "An exception is no decision: the earlier decision's kind is not left on the span.");
        Assert.DoesNotContain(
            tag => tag.Key == OAuthTagNames.DpopResourceCheck, reused.TagObjects, "An exception names no refusing check.");
        Assert.DoesNotContain(
            tag => tag.Key == ServerTagNames.ErrorCode, reused.TagObjects, "An exception carries no answer's error code.");
    }


    /// <summary>
    /// A resource server integration whose every slot is wired for <see cref="BoundPresentationAt"/>: the proof
    /// validation answers a proof carrying the <c>jti</c> <c>reused-span-jti</c> and the resource's nonce, issued at
    /// <paramref name="time"/>'s instant and bound to <see cref="BoundThumbprint"/>; the nonce issuance answers
    /// <see cref="ResourceNonce"/> and its validation succeeds; the <c>jti</c> claim is <paramref name="consultJti"/>;
    /// and <see cref="ResourceServerIntegration.StartTraceActivity"/> answers <see cref="Activity.Current"/>, the
    /// activity a test starts and reuses for every decision.
    /// </summary>
    /// <param name="time">The integration's clock.</param>
    /// <param name="consultJti">The <c>jti</c> claim.</param>
    /// <returns>The integration.</returns>
    private static ResourceServerIntegration ReusedSpanIntegration(FakeTimeProvider time, ConsultDpopProofJtiDelegate consultJti) => new()
    {
        TrustedIssuer = new Uri("https://issuer.test/tenant-a"),
        ExpectedAudience = "test-resource-server",
        ResolveVerificationKeyAsync = static (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null),
        TimeProvider = time,
        ValidateDpopProofAsync = (request, _) => ValueTask.FromResult(DpopProofValidationResult.Success(
            new DpopProofClaims
            {
                Htm = request.HttpMethod,
                Htu = request.HttpUrl,
                Iat = time.GetUtcNow(),
                Jti = "reused-span-jti",
                Nonce = ResourceNonce
            },
            BoundThumbprint)),
        IssueDpopNonceAsync = static (_, _, _, _) => ValueTask.FromResult(ResourceNonce),
        ValidateDpopNonceAsync = (_, _, _, _, _) => ValueTask.FromResult(DpopNonceValidationResult.Success(
            new DpopNoncePayload { Kid = "resource-nonce-key", IssuedAt = time.GetUtcNow() })),
        ConsultDpopProofJtiAsync = consultJti,
        StartTraceActivity = static (_, _, _, _) => Activity.Current
    };


    /// <summary>
    /// A presentation of a DPoP-bound access token bound to <see cref="BoundThumbprint"/> under the <c>DPoP</c> scheme,
    /// a GET of <paramref name="targetUri"/> carrying one proof.
    /// </summary>
    /// <param name="targetUri">The target URI the resource names the request by.</param>
    /// <returns>The presentation.</returns>
    private static DpopResourceRequest BoundPresentationAt(Uri targetUri) => new()
    {
        AccessToken = "access-token",
        IsDpopPresentation = true,
        IsSenderConstrained = true,
        BoundThumbprint = BoundThumbprint,
        HttpMethod = "GET",
        TargetUri = targetUri,
        DpopFieldLines = ["proof"],
        Realm = "protected"
    };


    /// <summary>
    /// A presentation of a DPoP-bound access token bound to <see cref="BoundThumbprint"/> under the <c>DPoP</c> scheme,
    /// a GET of <paramref name="targetUri"/> carrying no proof, which the resource answers with its nonce challenge.
    /// </summary>
    /// <param name="targetUri">The target URI the resource names the request by.</param>
    /// <returns>The presentation.</returns>
    private static DpopResourceRequest PresentationWithoutProofAt(Uri targetUri) => new()
    {
        AccessToken = "access-token",
        IsDpopPresentation = true,
        IsSenderConstrained = true,
        BoundThumbprint = BoundThumbprint,
        HttpMethod = "GET",
        TargetUri = targetUri,
        DpopFieldLines = [],
        Realm = "protected"
    };


    /// <summary>The JWK SHA-256 Thumbprint the presented token is bound to and the proof's key has, the value of RFC 9449 Figure 11.</summary>
    private static string BoundThumbprint { get; } = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    /// <summary>The nonce the resource issues and every proof carries.</summary>
    private static string ResourceNonce { get; } = "resource-nonce";


    /// <summary>
    /// A resource server integration with no DPoP slot wired: the argument checks run before any slot is read, and a
    /// <c>Bearer</c> presentation where DPoP-bound access tokens are required is answered before any slot is read, so
    /// none is needed.
    /// </summary>
    private static ResourceServerIntegration Integration { get; } = new()
    {
        TrustedIssuer = new Uri("https://issuer.test/tenant-a"),
        ExpectedAudience = "test-resource-server",
        ResolveVerificationKeyAsync = static (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null),
        TimeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch)
    };
}
