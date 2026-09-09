using System;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Foundation;
using Verifiable.OAuth.StatusList;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListTokenFetch.FetchAsync"/> — the Status List Request/Response half of
/// the Token Status List HTTP binding, driven by the shared canned
/// <see cref="ScriptedOutboundTransport"/> so the request the guarded fetch composes and the answer it
/// classifies are both observable without a socket. "The default Status List request and response
/// mechanism uses HTTP semantics and Content negotiation as defined in [RFC9110]."
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token
/// Status List, Section 8.1</see>,
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Section
/// 8.2</see> and
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Section
/// 11.4</see>.
/// </summary>
[TestClass]
internal sealed class StatusListTokenFetchTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The Status List Token URL every scripted route in this class answers for.</summary>
    private const string ListUrl = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>A same-origin path the Status Provider redirects to.</summary>
    private const string SameOriginTarget = "https://example.com/statuslists/1/current";

    /// <summary>A second same-origin path, for a chain longer than the hop bound.</summary>
    private const string SecondSameOriginTarget = "https://example.com/statuslists/1/current/2";

    /// <summary>A target on a different origin than <see cref="ListUrl"/>.</summary>
    private const string CrossOriginTarget = "https://other.example/statuslists/1";

    /// <summary>The JWT-format media type, from Section 8.1's list of media types.</summary>
    private const string StatusListJwtMediaType = "application/statuslist+jwt";

    /// <summary>The CWT-format media type, from Section 8.1's list of media types.</summary>
    private const string StatusListCwtMediaType = "application/statuslist+cwt";

    /// <summary>The response-body bound each fetch in this class carries.</summary>
    private const long MaxResponseBytes = 64 * 1024;

    /// <summary>
    /// The served body's text: three dot-separated base64url segments, the shape Section 8.2 names for a
    /// JWT-format response ("the JWS Compact Serialization form for a Status List Token in JWT format").
    /// The fetch treats the body as opaque bytes — parsing and verifying it is
    /// <see cref="StatusListTokenVerification"/>'s job — so the token's content is immaterial here and only
    /// its byte-for-byte survival across the fetch is asserted.
    /// </summary>
    private const string CompactTokenText = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJodHRwczovL2V4YW1wbGUuY29tIn0.c2lnbmF0dXJl";


    /// <summary>The served body's bytes.</summary>
    private static byte[] CompactTokenBody => Encoding.ASCII.GetBytes(CompactTokenText);


    /// <summary>
    /// "The Status Provider MUST return the Status List Token in response to an HTTP GET request to the URI
    /// provided in the Referenced Token" and Section 8.1's non-normative request example sends
    /// <c>Accept: application/statuslist+jwt</c> — one media type per format, from Section 8.1's list:
    /// "application/statuslist+jwt" for Status List Token in JWT format, "application/statuslist+cwt" for
    /// Status List Token in CWT format.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token
    /// Status List, Section 8.1</see>.
    /// </summary>
    /// <param name="format">The requested wire format.</param>
    /// <param name="mediaType">The media type that format negotiates with.</param>
    [TestMethod]
    [DataRow(StatusListTokenFormat.Jwt, StatusListJwtMediaType)]
    [DataRow(StatusListTokenFormat.Cwt, StatusListCwtMediaType)]
    public async Task RequestIsAnHttpGetNegotiatingTheFormatsMediaType(StatusListTokenFormat format, string mediaType)
    {
        ScriptedOutboundTransport transport = Serving(ListUrl, Answer(200, mediaType, CompactTokenBody));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), format, Context(OutboundFetchPolicy.SecureDefault), transport.Delegate,
            MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, transport.Calls, "One dereference of the uri makes exactly one request.");
        Assert.AreEqual("GET", transport.Calls[0].Method,
            "Section 8.1 obliges the Status Provider to answer an HTTP GET, so the fetch MUST issue one.");
        Assert.AreEqual(new Uri(ListUrl), transport.Calls[0].Target,
            "The request goes to the uri provided in the Referenced Token.");
        Assert.AreEqual(mediaType, transport.Calls[0].Headers.Accept,
            "Section 8.1's request example negotiates the requested format's media type through Accept.");
        Assert.IsTrue(result.IsFetched, "A conforming answer is a successful fetch.");
    }


    /// <summary>
    /// "The body of such an HTTP response contains the raw Status List Token, that means … the JWS Compact
    /// Serialization form for a Status List Token in JWT format." The fetch hands those bytes on unchanged
    /// and surfaces the content type it validated them against.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ASuccessfulResponseSurfacesTheRawTokenBytesAndItsContentType()
    {
        ScriptedOutboundTransport transport = Serving(ListUrl, Answer(200, StatusListJwtMediaType, CompactTokenBody));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.Fetched, result.Outcome, "A conforming 200 answer is Fetched.");
        Assert.IsTrue(result.Body.Span.SequenceEqual(CompactTokenBody),
            "The raw Status List Token MUST reach the caller byte for byte, not re-encoded.");
        Assert.AreEqual(StatusListJwtMediaType, result.ContentType,
            "The content type the answer was validated against is surfaced to the caller.");
        Assert.AreEqual(200, result.StatusCode, "The terminal response's status code is surfaced.");
        Assert.AreEqual(new Uri(ListUrl), result.FinalUri, "No redirect was involved, so the final uri is the requested one.");
        Assert.AreEqual(0, result.RedirectCount, "No redirect hop was followed.");
    }


    /// <summary>
    /// "A successful response that contains a Status List Token MUST use an HTTP status code in the 2xx
    /// range." — the whole range, not only 200, so a Status Provider answering 203 or 299 is answering
    /// successfully.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    /// <param name="status">A successful status code inside the 2xx range.</param>
    [TestMethod]
    [DataRow(200)]
    [DataRow(203)]
    [DataRow(299)]
    public async Task AnyStatusCodeInTheTwoHundredRangeIsASuccessfulResponse(int status)
    {
        ScriptedOutboundTransport transport = Serving(ListUrl, Answer(status, StatusListJwtMediaType, CompactTokenBody));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.Fetched, result.Outcome,
            $"HTTP {status} is in the 2xx range, so it MUST be treated as a successful response.");
        Assert.AreEqual(status, result.StatusCode, "The successful response's own status code is surfaced.");
        Assert.IsTrue(result.Body.Span.SequenceEqual(CompactTokenBody), "The token bytes reach the caller unchanged.");
    }


    /// <summary>
    /// "A successful response that contains a Status List Token MUST use an HTTP status code in the 2xx
    /// range." — an answer outside that range therefore contains no Status List Token, whether it reports the
    /// list absent (404), the provider broken (500), or the caller's stored copy still usable (304, which
    /// RFC 9110 classes as "Redirection to a previously stored result" and which transfers no representation).
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4">RFC 9110, Section 15.4</see>.
    /// </summary>
    /// <param name="status">A status code outside the 2xx range.</param>
    [TestMethod]
    [DataRow(404)]
    [DataRow(500)]
    [DataRow(304)]
    public async Task AStatusCodeOutsideTheTwoHundredRangeCarriesNoStatusListToken(int status)
    {
        ScriptedOutboundTransport transport = Serving(ListUrl, ScriptedOutboundResponse.WithStatus(status));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.UnsuccessfulStatus, result.Outcome,
            $"HTTP {status} is outside the 2xx range, so no Status List Token was obtained.");
        Assert.AreEqual(status, result.StatusCode, "The unsuccessful answer's status code is surfaced to the caller.");
        Assert.IsTrue(result.Body.IsEmpty, "No token body is offered from an unsuccessful response.");
    }


    /// <summary>
    /// "A response MAY also choose to redirect the client to another URI using an HTTP status code in the 3xx
    /// range, which clients SHOULD follow." Following is the caller's policy decision, since "HTTP clients
    /// that follow 3xx (Redirection) status codes MUST be aware of the possible dangers of redirects, such as
    /// infinite redirection loops … HTTP clients MUST follow the guidance provided in Section 15.4 of
    /// [RFC9110] for handling redirects": a same-origin hop within the configured bound is taken, and the
    /// caller learns where the token actually came from.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Section
    /// 11.4</see>.
    /// </summary>
    [TestMethod]
    public async Task ASameOriginRedirectIsFollowedWhenThePolicyPermitsTheHop()
    {
        ScriptedOutboundTransport transport = new(new()
        {
            [ListUrl] = ScriptedOutboundResponse.RedirectTo(302, SameOriginTarget),
            [SameOriginTarget] = Answer(200, StatusListJwtMediaType, CompactTokenBody)
        });

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(FollowingSameOrigin), transport.Delegate,
            MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.Fetched, result.Outcome,
            "A 3xx a client SHOULD follow, followed within the policy's bound, ends in the redirected answer.");
        Assert.AreEqual(1, result.RedirectCount, "Exactly one redirect hop was taken.");
        Assert.AreEqual(new Uri(SameOriginTarget), result.FinalUri, "The final uri names where the token was served from.");
        Assert.HasCount(2, transport.Calls, "The redirect is followed by a second request, made by the caller's own transport.");
        Assert.IsTrue(result.Body.Span.SequenceEqual(CompactTokenBody), "The redirected answer's token bytes reach the caller.");
    }


    /// <summary>
    /// The redirect a client SHOULD follow is a SHOULD, not a MUST, and Section 11.4's danger — "infinite
    /// redirection loops, since they can be used for denial-of-service attacks on clients" — is why the
    /// secure default follows none: the 3xx is reported, and the redirect target is never contacted.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Token
    /// Status List, Section 11.4</see>.
    /// </summary>
    [TestMethod]
    public async Task ARedirectIsNotFollowedUnderThePolicyThatFollowsNone()
    {
        ScriptedOutboundTransport transport = new(new()
        {
            [ListUrl] = ScriptedOutboundResponse.RedirectTo(302, SameOriginTarget),
            [SameOriginTarget] = Answer(200, StatusListJwtMediaType, CompactTokenBody)
        });

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.RedirectNotFollowed, result.Outcome,
            "A policy that follows no redirect reports the 3xx rather than taking it.");
        Assert.HasCount(1, transport.Calls, "The redirect target MUST NOT be contacted when the redirect is not followed.");
        Assert.IsTrue(result.Body.IsEmpty, "An unfollowed redirect yields no Status List Token.");
    }


    /// <summary>
    /// RFC 9110 Section 15.4's redirect guidance the Section 11.4 MUST points at is what makes a redirect off
    /// the Status Provider's own origin a hop the caller has to have authorized: under a same-origin policy
    /// the cross-origin hop is refused rather than dereferenced.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Token
    /// Status List, Section 11.4</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4">RFC 9110, Section 15.4</see>.
    /// </summary>
    [TestMethod]
    public async Task ACrossOriginRedirectIsRefusedUnderASameOriginPolicy()
    {
        ScriptedOutboundTransport transport = new(new()
        {
            [ListUrl] = ScriptedOutboundResponse.RedirectTo(302, CrossOriginTarget),
            [CrossOriginTarget] = Answer(200, StatusListJwtMediaType, CompactTokenBody)
        });

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(FollowingSameOrigin), transport.Delegate,
            MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.PolicyDenied, result.Outcome,
            "A hop off the Status Provider's origin is denied by the same-origin policy, not followed.");
        Assert.HasCount(1, transport.Calls, "The cross-origin target MUST NOT be contacted.");
    }


    /// <summary>
    /// "HTTP clients that follow 3xx (Redirection) status codes MUST be aware of the possible dangers of
    /// redirects, such as infinite redirection loops, since they can be used for denial-of-service attacks on
    /// clients." A chain longer than the configured hop bound therefore stops rather than looping, and yields
    /// no Status List Token.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Token
    /// Status List, Section 11.4</see>.
    /// </summary>
    [TestMethod]
    public async Task ARedirectChainLongerThanTheHopBoundStopsWithoutAToken()
    {
        ScriptedOutboundTransport transport = new(new()
        {
            [ListUrl] = ScriptedOutboundResponse.RedirectTo(302, SameOriginTarget),
            [SameOriginTarget] = ScriptedOutboundResponse.RedirectTo(302, SecondSameOriginTarget),
            [SecondSameOriginTarget] = Answer(200, StatusListJwtMediaType, CompactTokenBody)
        });

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt,
            Context(OutboundFetchPolicy.SecureDefault with { Redirects = RedirectMode.SameOrigin, MaxRedirects = 1 }),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsFetched, "A chain beyond the hop bound MUST NOT yield a Status List Token.");
        Assert.AreEqual(StatusListTokenFetchOutcome.RedirectNotFollowed, result.Outcome,
            "The chain stops at the bound rather than following further.");
        Assert.HasCount(2, transport.Calls, "Only the hops inside the bound were requested.");
    }


    /// <summary>
    /// Section 8.1 binds the request to "HTTP semantics … as defined in [RFC9110]" against the uri provided in
    /// the Referenced Token, and that uri arrives inside a token minted by a third party. The Status List
    /// Token fetch therefore runs behind the same policed outbound seam every other dereference of
    /// semi-trusted data does: an unencrypted or internal target is refused before anything is put on the wire.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token
    /// Status List, Section 8.1</see>.
    /// </summary>
    /// <param name="target">A target the secure default refuses.</param>
    [TestMethod]
    [DataRow("http://example.com/statuslists/1")]
    [DataRow("https://127.0.0.1/statuslists/1")]
    [DataRow("https://169.254.169.254/statuslists/1")]
    public async Task ARefusedTargetIsNeverPutOnTheWire(string target)
    {
        ScriptedOutboundTransport transport = Serving(target, Answer(200, StatusListJwtMediaType, CompactTokenBody));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(target), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.PolicyDenied, result.Outcome,
            $"'{target}' is refused by the outbound policy before the Status Provider is contacted.");
        Assert.IsEmpty(transport.Calls, "A refused target MUST NOT reach the transport at all.");
    }


    /// <summary>
    /// "In the successful response, the Status Provider MUST use the following content-type: …
    /// 'application/statuslist+jwt' for Status List Token in JWT format …" and "In the case of
    /// 'application/statuslist+jwt', the response MUST be of type JWT and follow the rules of Section 5.1."
    /// An answer typed as the other format is therefore not the token that was asked for.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AnAnswerTypedAsTheOtherFormatIsNotTheRequestedToken()
    {
        ScriptedOutboundTransport transport = Serving(ListUrl, Answer(200, StatusListCwtMediaType, CompactTokenBody));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.ContentTypeMismatch, result.Outcome,
            "A CWT-typed answer does not satisfy a request for the JWT format's content type.");
        Assert.AreEqual(StatusListCwtMediaType, result.ContentType, "The content type actually answered with is surfaced.");
        Assert.IsTrue(result.Body.IsEmpty, "A wrongly typed answer offers no Status List Token to read.");
    }


    /// <summary>
    /// "In the successful response, the Status Provider MUST use the following content-type" is a requirement
    /// on the media type, which RFC 9110 allows to be "followed by semicolon-delimited parameters … in the
    /// form of name/value pairs" and whose "type and subtype tokens are case-insensitive". A conforming
    /// Status Provider that adds a <c>charset</c> parameter or capitalizes the type has still used the
    /// required content type.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110, Section 8.3.1</see>.
    /// </summary>
    /// <param name="contentType">A spelling of the JWT format's content type.</param>
    [TestMethod]
    [DataRow("application/statuslist+jwt; charset=utf-8")]
    [DataRow("application/statuslist+jwt;charset=UTF-8")]
    [DataRow("Application/StatusList+JWT")]
    public async Task TheRequiredContentTypeIsMatchedOnTheMediaTypeAlone(string contentType)
    {
        ScriptedOutboundTransport transport = Serving(ListUrl, Answer(200, contentType, CompactTokenBody));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.Fetched, result.Outcome,
            $"'{contentType}' carries the required media type, so the answer is the requested Status List Token.");
        Assert.AreEqual(contentType, result.ContentType, "The content type is surfaced exactly as it was received.");
        Assert.IsTrue(result.Body.Span.SequenceEqual(CompactTokenBody), "The token bytes reach the caller.");
    }


    /// <summary>
    /// "In the successful response, the Status Provider MUST use the following content-type" — an answer
    /// carrying no content type at all has not, so it is not a Status List Token response even when its status
    /// code is in the 2xx range.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AnAnswerWithoutAContentTypeIsNotAStatusListTokenResponse()
    {
        ScriptedOutboundTransport transport = Serving(
            ListUrl,
            ScriptedOutboundResponse.WithBody(200, HttpHeaderSet.Empty, new TaggedMemory<byte>(CompactTokenBody, Tag.Empty)));

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.ContentTypeMismatch, result.Outcome,
            "An answer that used no content type has not used the content type the Status Provider MUST use.");
        Assert.IsNull(result.ContentType, "There is no content type to surface.");
    }


    /// <summary>
    /// The Status Provider is a third-party host the Relying Party dereferences a semi-trusted uri against, so
    /// its transport failing is an ordinary outcome of "no statement about the status … can be made", reported
    /// to the caller rather than thrown at it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ATransportFailureIsReportedRatherThanThrown()
    {
        OutboundTransportDelegate failing = (request, context, cancellationToken) =>
            throw new InvalidOperationException("The Status Provider refused the connection.");

        StatusListTokenFetchResult result = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            failing, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(StatusListTokenFetchOutcome.TransportFailed, result.Outcome,
            "A transport fault is a fetch outcome, not an exception the caller must catch.");
        Assert.AreEqual(new Uri(ListUrl), result.FinalUri, "The uri the fetch was attempted against is surfaced.");
    }


    /// <summary>
    /// Cancellation is the caller's own instruction, not a Status Provider failure, so it propagates rather
    /// than being classified as a transport fault — otherwise a cancelled request would be indistinguishable
    /// from a Status Provider that could not be reached.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token
    /// Status List, Section 8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task CancellationPropagatesInsteadOfBecomingATransportFailure()
    {
        OutboundTransportDelegate cancelling = (request, context, cancellationToken) =>
            throw new OperationCanceledException("The caller cancelled the Status List Token fetch.");

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await StatusListTokenFetch.FetchAsync(
                new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
                cancelling, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false));
    }


    /// <summary>
    /// A Status List can be large by design and its uri comes out of a third-party token, so the caller's
    /// upper bound on the answer travels with the request rather than being applied only after the whole body
    /// has been buffered — the bound the transport is asked to stop reading at.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task TheCallersResponseBoundTravelsOnTheRequest()
    {
        ScriptedOutboundTransport transport = Serving(ListUrl, Answer(200, StatusListJwtMediaType, CompactTokenBody));

        _ = await StatusListTokenFetch.FetchAsync(
            new Uri(ListUrl), StatusListTokenFormat.Jwt, Context(OutboundFetchPolicy.SecureDefault),
            transport.Delegate, MaxResponseBytes, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, transport.Calls, "One request was made.");
        Assert.IsNotNull(transport.Calls[0].MaxResponseBytes, "The request carries the caller's response bound.");
        Assert.AreEqual(MaxResponseBytes, transport.Calls[0].MaxResponseBytes!.Value,
            "The bound the caller passed is the bound the transport is asked to honour.");
    }


    /// <summary>
    /// The secure default relaxed to follow same-origin redirects, the shape Section 11.4's guidance describes
    /// for a caller that opts into following the 3xx a Status Provider "MAY also choose to redirect" with.
    /// </summary>
    private static OutboundFetchPolicy FollowingSameOrigin =>
        OutboundFetchPolicy.SecureDefault with { Redirects = RedirectMode.SameOrigin, MaxRedirects = 2 };


    /// <summary>
    /// A fresh per-call exchange context carrying <paramref name="policy"/>, the shared factory every guarded
    /// outbound fetch in the suite reads its policy from.
    /// </summary>
    /// <param name="policy">The outbound-fetch policy governing the fetch.</param>
    /// <returns>The context to hand to the fetch.</returns>
    private static ExchangeContext Context(OutboundFetchPolicy policy) => TestHostShell.ExchangeContextWith(policy);


    /// <summary>
    /// A scripted transport whose only route is <paramref name="url"/>, answered with
    /// <paramref name="response"/>.
    /// </summary>
    /// <param name="url">The absolute request URL the route answers for.</param>
    /// <param name="response">The scripted answer.</param>
    /// <returns>The scripted transport.</returns>
    private static ScriptedOutboundTransport Serving(string url, ScriptedOutboundResponse response) =>
        new(new() { [url] = response });


    /// <summary>
    /// A scripted answer carrying <paramref name="status"/>, a <c>Content-Type</c> of
    /// <paramref name="contentType"/>, and <paramref name="body"/> as the raw Status List Token.
    /// </summary>
    /// <param name="status">The HTTP status code to answer with.</param>
    /// <param name="contentType">The <c>Content-Type</c> field value.</param>
    /// <param name="body">The response body's bytes.</param>
    /// <returns>The scripted answer.</returns>
    private static ScriptedOutboundResponse Answer(int status, string contentType, byte[] body) =>
        ScriptedOutboundResponse.WithBody(
            status,
            HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, contentType)),
            new TaggedMemory<byte>(body, Tag.Empty));
}
