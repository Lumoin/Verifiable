using System;
using System.Text.RegularExpressions;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Tests for the wire constants in <see cref="WellKnownWebFingerValues"/> — the well-known path, JRD media
/// type, query parameter names, and the CORS header name/wildcard fixed by
/// <see href="https://www.rfc-editor.org/rfc/rfc7033">RFC 7033</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc5785">RFC 5785</see>. These are T6 of the conformance matrix.
/// </summary>
[TestClass]
internal sealed class WellKnownWebFingerValuesTests
{
    //RFC 3986 §3.3 pchar = unreserved / pct-encoded / sub-delims / ":" / "@"; segment-nz = 1*pchar. This
    //fixed-literal sanity check does not need the pct-encoded alternative.
    private static readonly Regex SegmentNzPattern = new(@"^[A-Za-z0-9\-._~!$&'()*+,;=:@]+$");


    /// <summary>The JRD media type registered by RFC 7033 §10.2.</summary>
    [TestMethod]
    public void JrdMediaTypeIsApplicationJrdPlusJson()
    {
        Assert.AreEqual("application/jrd+json", WellKnownWebFingerValues.JrdMediaType);
    }


    /// <summary>The §4.1 query parameter names: <c>resource</c> and <c>rel</c>.</summary>
    [TestMethod]
    public void QueryParameterNamesAreResourceAndRel()
    {
        Assert.AreEqual("resource", WellKnownWebFingerValues.ResourceParameterName);
        Assert.AreEqual("rel", WellKnownWebFingerValues.RelParameterName);
    }


    /// <summary>The §5 CORS header name and the least-restrictive wildcard value.</summary>
    [TestMethod]
    public void CorsHeaderNameAndWildcardAreTheStandardValues()
    {
        Assert.AreEqual("Access-Control-Allow-Origin", WellKnownWebFingerValues.AccessControlAllowOriginHeaderName);
        Assert.AreEqual("*", WellKnownWebFingerValues.AccessControlAllowOriginWildcard);
    }


    /// <summary>
    /// REF-5: the well-known path begins with <c>/.well-known/</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5785#section-3">RFC 5785 §3</see>, and pairs ONLY with
    /// <c>https</c> — no code path in <see cref="WebFingerClient.ComputeQueryUri"/> ever places it under a
    /// different scheme.
    /// </summary>
    [TestMethod]
    public void REF5_WellKnownPathBeginsWithTheRegisteredPrefixAndPairsOnlyWithHttps()
    {
        Assert.StartsWith("/.well-known/", WellKnownWebFingerValues.WellKnownPath);

        Uri uri = WebFingerClient.ComputeQueryUri("example.com", "acct:alice@example.com", []);

        Assert.AreEqual(WellKnownWebFingerValues.WellKnownPath, uri.AbsolutePath);
        Assert.AreEqual(Uri.UriSchemeHttps, uri.Scheme);
    }


    /// <summary>
    /// REF-7: the registered well-known name conforms to RFC 3986's <c>segment-nz</c> (one or more
    /// <c>pchar</c>) — non-empty and carrying no path separator.
    /// </summary>
    [TestMethod]
    public void REF7_WellKnownSuffixIsAValidNonEmptySegmentNz()
    {
        string suffix = WellKnownWebFingerValues.WellKnownSuffix;

        Assert.IsFalse(string.IsNullOrEmpty(suffix));
        Assert.DoesNotContain("/", suffix, "A segment-nz MUST NOT carry a path separator.");
        Assert.IsTrue(SegmentNzPattern.IsMatch(suffix), $"'{suffix}' MUST be a valid RFC 3986 segment-nz.");
        Assert.AreEqual("/.well-known/" + suffix, WellKnownWebFingerValues.WellKnownPath);
    }
}
