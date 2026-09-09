using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Transport;
using Verifiable.OAuth.Client;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Core;

/// <summary>
/// Tests that the guarded <see cref="OutboundFetch"/> and the two thin header views that ride on
/// the same store — <see cref="RequestHeaders"/> for an inbound request and
/// <see cref="ResponseHeaders"/> for a client response — carry and read HTTP fields through
/// <see cref="HttpHeaderSet"/>. The transport is canned: a caller-composed set reaches it
/// unchanged, its answers' <c>Location</c> and <c>Content-Type</c> are read back through the set,
/// and a field received as repeated lines survives the whole round trip as separate values.
/// </summary>
[TestClass]
internal sealed class OutboundFetchHeaderTests
{
    private const string JsonMediaType = "application/json";
    private const string FirstHop = "https://relying-party.example/metadata";
    private const string SecondHop = "https://relying-party.example/metadata/v2";

    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110, Section 8.3</see>: "A
    /// sender that generates a message containing content SHOULD generate a Content-Type header field in
    /// that message unless the intended media type of the enclosed representation is unknown to the
    /// sender." The sender composes that field onto the request's <see cref="HttpHeaderSet"/>, and the
    /// transport that would put it on the wire receives exactly the set that was composed.
    /// </summary>
    [TestMethod]
    public async Task TheTransportReceivesTheHeaderSetTheSenderComposed()
    {
        ScriptedOutboundTransport transport = new();
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault);
        OutboundRequest request = new()
        {
            Target = new Uri(FirstHop),
            Method = "GET",
            Headers = HttpHeaderSet.FromPairs(
                (WellKnownHttpHeaderNames.ContentType, JsonMediaType),
                (WellKnownHttpHeaderNames.Accept, "application/jwt")),
        };

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            request, context, transport.Delegate, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Fetched, result.Outcome, "The single allowed hop is fetched.");
        Assert.HasCount(1, transport.Calls, "Exactly one request reaches the transport.");
        Assert.AreEqual(JsonMediaType, transport.Calls[0].Headers.ContentType, "RFC 9110 Section 8.3: the Content-Type the sender generated is what the transport receives.");
        Assert.AreEqual("application/jwt", transport.Calls[0].Headers.Accept, "The transport receives every field the sender composed, not only the first.");
        Assert.AreEqual(2, transport.Calls[0].Headers.Count, "The transport receives the composed set unchanged.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-10.2.2">RFC 9110, Section 10.2.2</see>:
    /// "For 3xx (Redirection) responses, the Location value refers to the preferred target resource for
    /// automatically redirecting the request." The redirect loop reads that value off the response's
    /// <see cref="HttpHeaderSet"/>, so a 302 whose <c>Location</c> is composed through the set is
    /// followed to the resource it names.
    /// </summary>
    [TestMethod]
    public async Task ARedirectIsFollowedThroughTheLocationFieldOnTheHeaderSet()
    {
        ScriptedOutboundTransport transport = new(new()
        {
            [FirstHop] = ScriptedOutboundResponse.WithHeaders(302, HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.Location, SecondHop))),
            [SecondHop] = ScriptedOutboundResponse.WithHeaders(200, HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, JsonMediaType))),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 3,
        });

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get(FirstHop), context, transport.Delegate, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Fetched, result.Outcome, "RFC 9110 Section 10.2.2: the preferred target resource is fetched.");
        Assert.AreEqual(1, result.RedirectCount, "Exactly one redirection was taken.");
        Assert.AreEqual(new Uri(SecondHop), result.FinalUri, "RFC 9110 Section 10.2.2: the Location value read off the header set is the resource the loop went to.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>: "Field
    /// names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol
    /// (HTTP) Field Name Registry"". A server that spells the redirection's field name in lower case has
    /// sent the same field, and the loop follows it.
    /// </summary>
    [TestMethod]
    public async Task ALowerCaseLocationFieldNameIsStillFollowed()
    {
        ScriptedOutboundTransport transport = new(new()
        {
            [FirstHop] = ScriptedOutboundResponse.WithHeaders(302, HttpHeaderSet.FromPairs(("location", SecondHop))),
            [SecondHop] = ScriptedOutboundResponse.WithStatus(200),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault with
        {
            Redirects = RedirectMode.PolicyChecked,
            MaxRedirects = 3,
        });

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get(FirstHop), context, transport.Delegate, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Fetched, result.Outcome, "RFC 9110 Section 5.1: a lower-case field name is the same field, so the redirection is followed.");
        Assert.AreEqual(new Uri(SecondHop), result.FinalUri, "RFC 9110 Section 5.1: the lower-case Location field names the target resource.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3">RFC 9110, Section 8.3</see>: "The
    /// "Content-Type" header field indicates the media type of the associated representation: either the
    /// representation enclosed in the message content or the selected representation, as determined by
    /// the message semantics." The caller reads that media type off the terminal response's
    /// <see cref="HttpHeaderSet"/> before deciding how to parse the body.
    /// </summary>
    [TestMethod]
    public async Task TheTerminalResponsesContentTypeIsReadThroughTheHeaderSet()
    {
        ScriptedOutboundTransport transport = new(new()
        {
            [FirstHop] = ScriptedOutboundResponse.WithHeaders(200, HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, "application/entity-statement+jwt"))),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault);

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get(FirstHop), context, transport.Delegate, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(OutboundFetchOutcome.Fetched, result.Outcome, "The terminal response is fetched.");
        Assert.IsNotNull(result.Response, "A fetched result carries the terminal response.");
        Assert.AreEqual("application/entity-statement+jwt", result.Response.Headers.ContentType, "RFC 9110 Section 8.3: the media type of the associated representation is read off the response's header set.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "The
    /// order in which field lines with the same name are received is therefore significant to the
    /// interpretation of the field value; a proxy MUST NOT change the order of these field line values
    /// when forwarding a message." A response that arrives with two <c>Link</c> field lines therefore
    /// reaches the caller as two values in the received order, never as one comma-joined value.
    /// </summary>
    [TestMethod]
    public async Task TwoReceivedFieldLinesBothReachTheCaller()
    {
        HttpHeaderSet responseHeaders = new HttpHeaderSet.Builder()
            .AddValues("Link", ["<https://relying-party.example/a>; rel=\"next\"", "<https://relying-party.example/b>; rel=\"last\""])
            .Build();
        ScriptedOutboundTransport transport = new(new()
        {
            [FirstHop] = ScriptedOutboundResponse.WithHeaders(200, responseHeaders),
        });
        ExchangeContext context = Context(OutboundFetchPolicy.SecureDefault);

        OutboundFetchResult result = await OutboundFetch.FetchAsync(
            Get(FirstHop), context, transport.Delegate, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.Response, "A fetched result carries the terminal response.");

        IReadOnlyList<string> links = result.Response.Headers.GetValues("Link");

        Assert.HasCount(2, links, "RFC 9110 Section 5.3: both received field lines reach the caller.");
        Assert.AreEqual("<https://relying-party.example/a>; rel=\"next\"", links[0], "RFC 9110 Section 5.3: the order in which field lines with the same name are received is significant.");
        Assert.AreEqual("<https://relying-party.example/b>; rel=\"last\"", links[1], "RFC 9110 Section 5.3: a proxy MUST NOT change the order of these field line values.");
        Assert.AreEqual(1, result.Response.Headers.Count, "Two field lines with the same name are one field.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "A
    /// recipient MAY combine multiple field lines within a field section that have the same field name
    /// into one field line, without changing the semantics of the message, by appending each subsequent
    /// field line value to the initial field line value in order". A server-side matcher decides whether
    /// to take that MAY: an inbound field received as two lines is not a single value, so
    /// <see cref="RequestHeaders.TryGetSingle"/> reports no single value while
    /// <see cref="RequestHeaders.TryGetAll"/> hands back both in received order.
    /// </summary>
    [TestMethod]
    public void AnInboundFieldReceivedTwiceHasNoSingleValueButBothValues()
    {
        Dictionary<string, string[]> received = new(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Accept] = [JsonMediaType, "application/jwt"],
        };

        RequestHeaders headers = new(received);

        Assert.AreEqual(1, headers.Count, "RFC 9110 Section 5.3: two field lines with the same name are one field.");
        Assert.IsTrue(headers.Contains("accept"), "RFC 9110 Section 5.1: the field is found under any casing.");
        Assert.IsFalse(headers.TryGetSingle(WellKnownHttpHeaderNames.Accept, out string? single), "RFC 9110 Section 5.3: a field received as two field lines has no single value.");
        Assert.IsNull(single, "No single value is handed back for a field received as two field lines.");
        Assert.IsTrue(headers.TryGetAll(WellKnownHttpHeaderNames.Accept, out IReadOnlyList<string>? all), "RFC 9110 Section 5.3: every received field line is available to a matcher that wants them.");
        Assert.IsNotNull(all, "The values of a present field are handed back.");
        Assert.HasCount(2, all, "RFC 9110 Section 5.3: both received field lines are kept.");
        Assert.AreEqual(JsonMediaType, all[0], "RFC 9110 Section 5.3: the received order is significant.");
        Assert.AreEqual("application/jwt", all[1], "RFC 9110 Section 5.3: the received order is significant.");
        Assert.HasCount(2, headers.Headers.GetValues("ACCEPT"), "The view and its backing header set surface the same field lines.");
        Assert.AreEqual(JsonMediaType, headers.Headers.GetValues("ACCEPT")[0], "The view and its backing header set surface the same order.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110, Section 5.3</see>: "A
    /// recipient MAY combine multiple field lines within a field section that have the same field name
    /// into one field line". A framework that surfaces an ordinal-keyed map can hand
    /// <see cref="RequestHeaders(IReadOnlyDictionary{string, string[]})"/> the same name under two
    /// castings as separate keys (<c>X-Foo</c> and <c>x-foo</c>); the receive-side factory still groups
    /// them case-insensitively into one field carrying both values.
    /// </summary>
    [TestMethod]
    public void ADictionaryCarryingACasingCollidingNameYieldsOneFieldWithBothValues()
    {
        Dictionary<string, string[]> received = new(StringComparer.Ordinal)
        {
            ["X-Foo"] = ["first"],
            ["x-foo"] = ["second"],
        };

        RequestHeaders headers = new(received);

        Assert.AreEqual(1, headers.Count, "RFC 9110 Section 5.3: a recipient MAY combine field lines with the same name (case-insensitively) into one field.");
        Assert.IsTrue(headers.TryGetAll("X-Foo", out IReadOnlyList<string>? all), "The grouped field is present under either casing.");
        Assert.IsNotNull(all, "The grouped field carries values.");
        Assert.HasCount(2, all, "Both casing-colliding dictionary entries contribute their values.");
        Assert.AreEqual("first", all[0], "The dictionary's enumeration order is preserved.");
        Assert.AreEqual("second", all[1], "The dictionary's enumeration order is preserved.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.1">RFC 9110, Section 5.1</see>: "Field
    /// names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol
    /// (HTTP) Field Name Registry"". A client reading a protocol field off a response therefore spells the
    /// name in whatever casing it holds, and a field the response never carried reads as absent.
    /// </summary>
    [TestMethod]
    public void AClientReadsAResponseFieldCaseInsensitively()
    {
        ResponseHeaders headers = new()
        {
            Headers = HttpHeaderSet.FromPairs(("content-type", JsonMediaType)),
        };

        Assert.AreEqual(JsonMediaType, headers.TryGetSingle("CONTENT-TYPE"), "RFC 9110 Section 5.1: field names are case-insensitive.");
        Assert.AreEqual(JsonMediaType, headers.TryGetSingle(WellKnownHttpHeaderNames.ContentType), "RFC 9110 Section 5.1: the registered spelling reads the same field.");
        Assert.IsNull(headers.TryGetSingle(WellKnownHttpHeaderNames.Location), "A field the response never carried reads as absent.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5">RFC 9110, Section 5</see>: "HTTP uses
    /// "fields" to provide data in the form of extensible name/value pairs with a registered key
    /// namespace. Fields are sent and received within the header and trailer sections of messages". A
    /// response whose header section carried no field names none.
    /// </summary>
    [TestMethod]
    public void AnEmptyResponseHeaderSectionNamesNoField()
    {
        ResponseHeaders headers = ResponseHeaders.Empty;

        Assert.AreEqual(0, headers.Headers.Count, "RFC 9110 Section 5: an empty header section carries no name/value pair.");
        Assert.IsEmpty(headers.Headers.Names, "RFC 9110 Section 5: the empty header section names no field.");
        Assert.IsNull(headers.TryGetSingle(WellKnownHttpHeaderNames.ContentType), "No field is readable from an empty header section.");
    }


    /// <summary>
    /// Builds the exchange context the guarded fetch reads its policy from.
    /// </summary>
    /// <param name="policy">The policy every hop is validated against.</param>
    private static ExchangeContext Context(OutboundFetchPolicy policy)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(policy);

        return context;
    }


    /// <summary>
    /// A bodyless <c>GET</c> of <paramref name="url"/> carrying no request fields.
    /// </summary>
    /// <param name="url">The absolute target URL.</param>
    private static OutboundRequest Get(string url) =>
        new() { Target = new Uri(url), Method = "GET" };
}
