using System;
using System.Collections.Generic;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Tests for <see cref="WebFingerClient.ComputeQueryUri"/> — the pure query-URI construction per
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4">RFC 7033 §4</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.1">§4.1</see>. These are T1 (client-side
/// query construction) of the conformance matrix; they exercise ONLY the pure URI builder, never a network
/// call — see <see cref="WebFingerClientBehaviorTests"/> for the resolve-delegate behavior.
/// </summary>
[TestClass]
internal sealed class WebFingerQueryConstructionTests
{
    /// <summary>
    /// WF-1 / WF-14 / WF-64 / WF-65: the query URI's scheme is ALWAYS <c>https</c> — exhaustively, across a
    /// range of hosts, resources (including ones that themselves carry the literal text <c>http://</c>), and
    /// relation filters (including one carrying <c>http</c>-looking text). No input yields an <c>http</c>
    /// scheme because <see cref="WebFingerClient.ComputeQueryUri"/> has no code path that emits one.
    /// </summary>
    [TestMethod]
    public void WF1WF14_SchemeIsAlwaysHttpsExhaustively()
    {
        (string Host, string Resource, IReadOnlyList<string> Rel)[] scenarios =
        [
            ("example.com", "acct:alice@example.com", []),
            ("example.com", "http://evil.example/should-not-flip-the-query-scheme", []),
            ("example.com", "acct:alice@example.com", ["http://webfinger.net/rel/profile-page"]),
            ("example.com:8080", "acct:alice@example.com", []),
            ("sub.example.org", "mailto:alice@example.com", ["https://webfinger.net/rel/avatar", "urn:example:http-in-rel-text"]),
            ("EXAMPLE.COM", "acct:bob@EXAMPLE.COM", [])
        ];

        foreach((string host, string resource, IReadOnlyList<string> rel) in scenarios)
        {
            Uri uri = WebFingerClient.ComputeQueryUri(host, resource, rel);

            Assert.AreEqual(Uri.UriSchemeHttps, uri.Scheme,
                $"host='{host}' resource='{resource}' MUST yield an https query URI.");
        }
    }


    /// <summary>
    /// WF-3: the path component is ALWAYS <c>/.well-known/webfinger</c>, regardless of the resource, host, or
    /// relation filters supplied.
    /// </summary>
    [TestMethod]
    public void WF3_PathIsAlwaysTheWellKnownWebFingerPath()
    {
        Uri noRel = WebFingerClient.ComputeQueryUri("example.com", "acct:alice@example.com", []);
        Uri manyRel = WebFingerClient.ComputeQueryUri(
            "example.com", "acct:alice@example.com", ["urn:example:a", "urn:example:b"]);

        Assert.AreEqual(WellKnownWebFingerValues.WellKnownPath, noRel.AbsolutePath);
        Assert.AreEqual(WellKnownWebFingerValues.WellKnownPath, manyRel.AbsolutePath);
    }


    /// <summary>
    /// WF-4 / WF-5: the query component is present and non-empty both when zero relation filters are supplied
    /// (the <c>resource</c> parameter alone still produces a query) and when multiple are supplied.
    /// </summary>
    [TestMethod]
    public void WF4WF5_QueryComponentIsNonEmptyForZeroAndMultipleRelFilters()
    {
        Uri zeroRel = WebFingerClient.ComputeQueryUri("example.com", "acct:alice@example.com", []);
        Uri multiRel = WebFingerClient.ComputeQueryUri(
            "example.com", "acct:alice@example.com", ["urn:example:a", "urn:example:b", "urn:example:c"]);

        Assert.IsFalse(string.IsNullOrEmpty(zeroRel.Query), "A zero-rel query MUST still carry a query component (resource).");
        Assert.IsFalse(string.IsNullOrEmpty(multiRel.Query), "A multi-rel query MUST carry a non-empty query component.");
    }


    /// <summary>
    /// WF-6 / WF-11 (client side): the <c>resource</c> parameter appears in the query EXACTLY once, regardless
    /// of how many relation filters are also present.
    /// </summary>
    [TestMethod]
    public void WF6WF11_ResourceParameterAppearsExactlyOnce()
    {
        Uri uri = WebFingerClient.ComputeQueryUri(
            "example.com", "acct:alice@example.com", ["urn:example:a", "urn:example:b"]);

        List<(string Name, string Value)> parameters = ParseQueryParameters(uri);
        int resourceCount = parameters.FindAll(p => string.Equals(p.Name, WellKnownWebFingerValues.ResourceParameterName, StringComparison.Ordinal)).Count;

        Assert.AreEqual(1, resourceCount, "The resource parameter MUST appear exactly once.");
    }


    /// <summary>
    /// WF-6 negative: a <see langword="null"/> <c>resource</c> throws <see cref="ArgumentNullException"/>
    /// (the null-specific branch of the underlying guard).
    /// </summary>
    [TestMethod]
    public void WF6_NullResourceThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            WebFingerClient.ComputeQueryUri("example.com", null!, []));
    }


    /// <summary>
    /// WF-6 negative: an empty or whitespace-only <c>resource</c> throws <see cref="ArgumentException"/> — a
    /// query with no query target is not a well-formed WebFinger query.
    /// </summary>
    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    public void WF6_EmptyOrWhitespaceResourceThrowsArgumentException(string resource)
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            WebFingerClient.ComputeQueryUri("example.com", resource, []));
    }


    /// <summary>
    /// WF-7 / WF-23 / WF-24: the <c>rel</c> parameter is OPTIONAL and repeatable — zero, one, or many terms all
    /// produce a well-formed URI, and each supplied term surfaces as its own <c>rel</c> occurrence.
    /// </summary>
    [TestMethod]
    public void WF7WF23WF24_RelParameterCardinalityIsZeroOneOrMany()
    {
        Uri zero = WebFingerClient.ComputeQueryUri("example.com", "acct:alice@example.com", []);
        Uri one = WebFingerClient.ComputeQueryUri("example.com", "acct:alice@example.com", ["urn:example:a"]);
        Uri many = WebFingerClient.ComputeQueryUri(
            "example.com", "acct:alice@example.com", ["urn:example:a", "urn:example:b", "urn:example:c"]);

        Assert.HasCount(0, RelValues(zero), "Absent rel filters MUST still yield a well-formed URI with zero rel occurrences.");
        Assert.HasCount(1, RelValues(one));
        Assert.HasCount(3, RelValues(many));
    }


    /// <summary>
    /// WF-8: the <c>resource</c> query value, once percent-decoded, is exactly the supplied query target —
    /// including characters (space, <c>&amp;</c>, <c>=</c>, <c>@</c>, non-ASCII) that require encoding to
    /// survive the query component intact.
    /// </summary>
    [TestMethod]
    public void WF8_ResourceRoundTripsExactlyThroughPercentEncoding()
    {
        const string resource = "acct:alice bob & carol=dave é@example.com";

        Uri uri = WebFingerClient.ComputeQueryUri("example.com", resource, []);
        string encodedResource = SingleQueryValue(uri, WellKnownWebFingerValues.ResourceParameterName);

        Assert.AreEqual(resource, Uri.UnescapeDataString(encodedResource));
    }


    /// <summary>
    /// WF-9: each <c>rel</c> query value, once percent-decoded, is exactly the corresponding supplied relation
    /// type, and relation values round-trip in the order they were supplied.
    /// </summary>
    [TestMethod]
    public void WF9_RelValuesRoundTripExactlyThroughPercentEncoding()
    {
        string[] relFilters = ["http://webfinger.net/rel/profile page", "urn:example:rel with space & more"];

        Uri uri = WebFingerClient.ComputeQueryUri("example.com", "acct:alice@example.com", relFilters);
        List<string> decoded = RelValues(uri).ConvertAll(Uri.UnescapeDataString);

        Assert.HasCount(relFilters.Length, decoded);
        Assert.AreEqual(relFilters[0], decoded[0]);
        Assert.AreEqual(relFilters[1], decoded[1]);
    }


    /// <summary>
    /// WF-10: a value carrying an internal space is percent-encoded as <c>%20</c> — the raw query string never
    /// contains a literal space character, for either the <c>resource</c> or a <c>rel</c> value.
    /// </summary>
    [TestMethod]
    public void WF10_InternalSpaceIsPercentEncodedNeverRaw()
    {
        Uri uri = WebFingerClient.ComputeQueryUri(
            "example.com", "acct:john doe@example.com", ["urn:example:rel with space"]);

        Assert.IsFalse(uri.Query.Contains(' ', StringComparison.Ordinal), "The raw query string MUST NOT contain a literal space.");
        Assert.Contains("%20", uri.Query, "A space MUST be percent-encoded as %20.");
    }


    /// <summary>
    /// WF-2: the query is issued to the supplied <paramref name="host"/> verbatim — both in the common case
    /// where the caller passes the resource's own host, and when the caller explicitly supplies a DIFFERENT
    /// host (an out-of-band override, per §4's "SHOULD query the host, unless … out-of-band information").
    /// </summary>
    [TestMethod]
    public void WF2_QueryTargetsTheSuppliedHostIncludingAnExplicitOverride()
    {
        Uri sameHost = WebFingerClient.ComputeQueryUri("example.com", "acct:alice@example.com", []);
        Uri overriddenHost = WebFingerClient.ComputeQueryUri("relay.example.org", "acct:alice@example.com", []);

        Assert.AreEqual("example.com", sameHost.Host);
        Assert.AreEqual("relay.example.org", overriddenHost.Host,
            "An explicit host differing from the resource's own host MUST be honoured, not silently replaced.");
    }


    /// <summary>Extracts the single value of a query parameter expected to occur exactly once.</summary>
    private static string SingleQueryValue(Uri uri, string name)
    {
        List<(string Name, string Value)> parameters = ParseQueryParameters(uri);
        List<string> matches = parameters.FindAll(p => string.Equals(p.Name, name, StringComparison.Ordinal))
            .ConvertAll(p => p.Value);

        Assert.HasCount(1, matches, $"Expected exactly one '{name}' query parameter.");

        return matches[0];
    }


    /// <summary>Extracts every (still percent-encoded) <c>rel</c> query value, in occurrence order.</summary>
    private static List<string> RelValues(Uri uri)
    {
        List<(string Name, string Value)> parameters = ParseQueryParameters(uri);

        return parameters.FindAll(p => string.Equals(p.Name, WellKnownWebFingerValues.RelParameterName, StringComparison.Ordinal))
            .ConvertAll(p => p.Value);
    }


    /// <summary>
    /// Splits a URI's raw query component into name/value pairs, preserving order and multiplicity, without
    /// percent-decoding either side — the decode step is the caller's responsibility so round-trip tests can
    /// assert on the exact decoded value.
    /// </summary>
    private static List<(string Name, string Value)> ParseQueryParameters(Uri uri)
    {
        List<(string Name, string Value)> result = [];
        string query = uri.Query;
        if(string.IsNullOrEmpty(query))
        {
            return result;
        }

        //Uri.Query includes the leading '?'.
        string[] pairs = query[1..].Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach(string pair in pairs)
        {
            int separatorIndex = pair.IndexOf('=', StringComparison.Ordinal);
            string name = separatorIndex >= 0 ? pair[..separatorIndex] : pair;
            string value = separatorIndex >= 0 ? pair[(separatorIndex + 1)..] : string.Empty;
            result.Add((name, value));
        }

        return result;
    }
}
