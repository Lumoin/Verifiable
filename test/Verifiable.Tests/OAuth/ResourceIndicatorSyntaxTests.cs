using System.Globalization;
using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// One normative case per test method for <see cref="ResourceIndicatorSyntax"/>, each method's
/// cases carried as its data rows. Every row runs under the Turkish culture so a row that passes
/// there proves the reader's case handling is culture-free.
/// </summary>
[TestClass]
internal sealed class ResourceIndicatorSyntaxTests
{
    /// <summary>
    /// Runs <paramref name="assertions"/> with <see cref="CultureInfo.CurrentCulture"/> set to
    /// <c>tr-TR</c> on this thread, passing the culture's name observed right after the switch so
    /// every caller can assert it, and restores the prior culture in <c>finally</c>. Under tr-TR a
    /// culture-aware lowering maps an ASCII <c>I</c> to U+0131 (dotless i), so a row that passes
    /// here proves <see cref="ResourceIndicatorSyntax"/> folds without consulting the thread's
    /// culture. The setting is per-thread, so no <c>[DoNotParallelize]</c> is needed.
    /// </summary>
    /// <param name="assertions">
    /// The assertions to run under the Turkish culture; receives the observed culture name.
    /// </param>
    private static void RunUnderTurkishCulture(Action<string> assertions)
    {
        CultureInfo originalCulture = CultureInfo.CurrentCulture;

        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            assertions(CultureInfo.CurrentCulture.Name);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    /// <summary>
    /// A valid indicator's scheme letters, and its host letters when it has an authority, fold to
    /// lowercase outside percent triplets; every other character keeps its spelling
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.1">RFC 3986 section 3.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2">section 3.2.2</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">section 6.2.2.1</see>).
    /// </summary>
    [TestMethod]
    [DataRow("HTTPS://API.Example.COM/Path?Q=1", "https://api.example.com/Path?Q=1")]
    [DataRow("HTTPS://WIKI.EXAMPLE/INDEX", "https://wiki.example/INDEX")]
    [DataRow("FOO://User:Pa%41ss@API.EXAMPLE:443/A%2fB?X=Y", "foo://User:Pa%41ss@api.example:443/A%2fB?X=Y")]
    [DataRow("HTTPS://[2001:DB8::1]:8443/P", "https://[2001:db8::1]:8443/P")]
    [DataRow("FOO://B%C3%BCCHER.EXAMPLE/x", "foo://b%C3%BCcher.example/x")]
    [DataRow("FILE:///C:/Data", "file:///C:/Data")]
    [DataRow("HTTPS://XN--BCHER-KVA.EXAMPLE/", "https://xn--bcher-kva.example/")]
    [DataRow("URN:Example:Thing", "urn:Example:Thing")]
    public void FoldLowersOnlyTheAsciiLettersOfTheSchemeAndHost(string indicator, string expected)
    {
        RunUnderTurkishCulture(observedCultureName =>
        {
            Assert.AreEqual(expected, ResourceIndicatorSyntax.Fold(indicator));
            Assert.AreEqual("tr-TR", observedCultureName);
        });
    }

    /// <summary>
    /// A code point above U+007F anywhere in the indicator is refused, whichever component holds
    /// it, before any component-specific rule is applied
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-2">RFC 3986 section 2</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 section 2</see>). Each
    /// look-alike code point is built from its value, never typed raw: U+0130 (Latin capital I
    /// with dot above), U+0131 (dotless i), U+212A (Kelvin sign), U+017F (long s).
    /// </summary>
    [TestMethod]
    [DataRow("https://AP", 0x0130, ".EXAMPLE/", ResourceIndicatorFault.NonAscii)]
    [DataRow("https://ap", 0x0131, ".example/", ResourceIndicatorFault.NonAscii)]
    [DataRow("https://", 0x212A, "ey.example/", ResourceIndicatorFault.NonAscii)]
    [DataRow("https://", 0x017F, "erver.example/", ResourceIndicatorFault.NonAscii)]
    [DataRow("https://api.example.com/", 0x017F, "", ResourceIndicatorFault.NonAscii)]
    [DataRow("F", 0x0130, "LE://host.example/share", ResourceIndicatorFault.NonAscii)]
    [DataRow("f", 0x0131, "le://host.example/share", ResourceIndicatorFault.NonAscii)]
    [DataRow("", 0x212A, "ey://host.example/", ResourceIndicatorFault.NonAscii)]
    [DataRow("http", 0x017F, "://api.example.com/", ResourceIndicatorFault.NonAscii)]
    [DataRow("https://api.example.com/", -1, "", ResourceIndicatorFault.None)]
    public void CheckRefusesEveryCodePointOutsideAscii(string prefix, int codePointOrSentinel, string suffix, ResourceIndicatorFault expectedFault)
    {
        string indicator = codePointOrSentinel < 0
            ? prefix + suffix
            : prefix + char.ConvertFromUtf32(codePointOrSentinel) + suffix;

        RunUnderTurkishCulture(observedCultureName =>
        {
            Assert.AreEqual(expectedFault, ResourceIndicatorSyntax.Check(indicator));
            Assert.AreEqual("tr-TR", observedCultureName);
        });
    }

    /// <summary>
    /// <see cref="ResourceIndicatorSyntax.Check(ReadOnlySpan{char})"/> names the first part of the
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A"><c>absolute-URI</c></see>
    /// grammar that fails, scanning left to right: a missing or malformed <c>scheme</c>, a
    /// malformed <c>pct-encoded</c> triplet
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-2.1">section 2.1</see>), a character
    /// outside <c>pchar</c> in the path
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">Appendix A</see>), a
    /// character outside <c>query</c>, a <c>#</c> (RFC 8707 forbids a fragment), a malformed
    /// <c>authority</c>, and, for <c>http</c> or <c>https</c>, a missing authority, an empty host
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.1">RFC 9110 section 4.2.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.2">section 4.2.2</see>) or a
    /// <c>userinfo</c>: "a recipient SHOULD parse for userinfo and treat its presence as an error"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">section 4.2.4</see>). A
    /// scheme other than <c>http</c> and <c>https</c> keeps the <c>userinfo</c> that
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2.1">RFC 3986 section 3.2.1</see>
    /// defines, so <c>ftp://user@host/</c> and the path <c>urn:user@example</c> are admitted.
    /// <c>absolute-URI</c> is <c>scheme ":" hier-part [ "?" query ]</c> and <c>scheme</c> is
    /// <c>ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )</c>, so a value whose first character is a
    /// <c>%</c> or a control character has no scheme, even when a well-formed triplet or a later
    /// <c>:</c> follows (<c>%41x:y</c>); a value that begins with <c>#</c> opens a fragment,
    /// which no <c>absolute-URI</c> has, and is named as one (<c>#x</c>). The parts are named in the
    /// order of <see href="https://www.rfc-editor.org/rfc/rfc3986#section-3">RFC 3986 section 3</see>'s
    /// "hierarchical sequence of components referred to as the scheme, authority, path, query, and
    /// fragment", the <c>http</c> and <c>https</c> rules on the authority included, so a value that
    /// fails in its authority and in its path is named by its authority: <c>https:///bad^</c> by its
    /// empty host, <c>https:bad^</c> by its missing authority and <c>https://user@host/bad^</c> by its
    /// <c>userinfo</c>.
    /// </summary>
    [TestMethod]
    [DataRow("", ResourceIndicatorFault.Empty)]
    [DataRow("not-a-uri", ResourceIndicatorFault.Scheme)]
    [DataRow("/relative/path", ResourceIndicatorFault.Scheme)]
    [DataRow("1http://x.example/", ResourceIndicatorFault.Scheme)]
    [DataRow("ht tp://x.example/", ResourceIndicatorFault.Scheme)]
    [DataRow(":", ResourceIndicatorFault.Scheme)]
    [DataRow(":foo", ResourceIndicatorFault.Scheme)]
    [DataRow("://api.example.com/", ResourceIndicatorFault.Scheme)]
    [DataRow(":/path", ResourceIndicatorFault.Scheme)]
    [DataRow("%41x:y", ResourceIndicatorFault.Scheme)]
    [DataRow("\x01x:y", ResourceIndicatorFault.Scheme)]
    [DataRow("#x", ResourceIndicatorFault.Fragment)]
    [DataRow("https://api.example.com/%GG", ResourceIndicatorFault.PercentEncoding)]
    [DataRow("https://api.example.com/p%2", ResourceIndicatorFault.PercentEncoding)]
    [DataRow("https://api.example.com/%2G", ResourceIndicatorFault.PercentEncoding)]
    [DataRow("https://api.example.com/a\\b", ResourceIndicatorFault.Path)]
    [DataRow("https://api.example.com/a[b]", ResourceIndicatorFault.Path)]
    [DataRow("https://api.example.com/a^b", ResourceIndicatorFault.Path)]
    [DataRow("https://api.example.com/a{b}", ResourceIndicatorFault.Path)]
    [DataRow("https://api.example.com/a|b", ResourceIndicatorFault.Path)]
    [DataRow("https://api.example.com/a`b", ResourceIndicatorFault.Path)]
    [DataRow("C:\\Windows\\System32", ResourceIndicatorFault.Path)]
    [DataRow("https://api.example.com/x#", ResourceIndicatorFault.Fragment)]
    [DataRow("https://api.example.com/x?q=a#b", ResourceIndicatorFault.Fragment)]
    [DataRow("https://api.example.com/x?q=^", ResourceIndicatorFault.Query)]
    [DataRow("https://[::1/x", ResourceIndicatorFault.Authority)]
    [DataRow("https://api.example.com:8x/", ResourceIndicatorFault.Authority)]
    [DataRow("https://user@@api.example.com/", ResourceIndicatorFault.Authority)]
    [DataRow("https://[::1]x/", ResourceIndicatorFault.Authority)]
    [DataRow("https://", ResourceIndicatorFault.HttpHost)]
    [DataRow("https:///path", ResourceIndicatorFault.HttpHost)]
    [DataRow("HTTP://", ResourceIndicatorFault.HttpHost)]
    [DataRow("https:api.example.com", ResourceIndicatorFault.HttpAuthority)]
    [DataRow("https:/path", ResourceIndicatorFault.HttpAuthority)]
    [DataRow("https://user@api.example/", ResourceIndicatorFault.HttpUserInfo)]
    [DataRow("https://user:pass@api.example/", ResourceIndicatorFault.HttpUserInfo)]
    [DataRow("https://api.example.com@other.example/", ResourceIndicatorFault.HttpUserInfo)]
    [DataRow("HTTP://u@h/", ResourceIndicatorFault.HttpUserInfo)]
    [DataRow("https:///bad^", ResourceIndicatorFault.HttpHost)]
    [DataRow("https:bad^", ResourceIndicatorFault.HttpAuthority)]
    [DataRow("https://user@host/bad^", ResourceIndicatorFault.HttpUserInfo)]
    [DataRow("ftp://user@host/", ResourceIndicatorFault.None)]
    [DataRow("urn:user@example", ResourceIndicatorFault.None)]
    [DataRow("foo://b%C3%BCcher.example/x", ResourceIndicatorFault.None)]
    [DataRow("https://api.example.com:65536/", ResourceIndicatorFault.None)]
    [DataRow("https://[v1.fe]/x", ResourceIndicatorFault.None)]
    [DataRow("https://256.1.1.1/", ResourceIndicatorFault.None)]
    [DataRow("mailto:resource-owner@example.com", ResourceIndicatorFault.None)]
    [DataRow("file:///srv/resources/orders", ResourceIndicatorFault.None)]
    [DataRow("urn:example:thing", ResourceIndicatorFault.None)]
    [DataRow("https://api.example.com/A%2fB?X=Y", ResourceIndicatorFault.None)]
    [DataRow("https://api.example.com", ResourceIndicatorFault.None)]
    public void CheckNamesTheFirstPartThatFails(string indicator, ResourceIndicatorFault expectedFault)
    {
        RunUnderTurkishCulture(observedCultureName =>
        {
            Assert.AreEqual(expectedFault, ResourceIndicatorSyntax.Check(indicator));
            Assert.AreEqual("tr-TR", observedCultureName);
        });
    }

    /// <summary>
    /// Every <c>host</c> alternative of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986 Appendix A</see>'s
    /// <c>IP-literal</c> - the nine <c>IPv6address</c> forms over <c>h16</c> and <c>ls32</c>, and
    /// <c>IPvFuture</c> - is read against its own grammar, not merely a bracket-balance check.
    /// </summary>
    [TestMethod]
    [DataRow("[::1]", ResourceIndicatorFault.None)]
    [DataRow("[::]", ResourceIndicatorFault.None)]
    [DataRow("[2001:db8::1]", ResourceIndicatorFault.None)]
    [DataRow("[1:2:3:4:5:6:7:8]", ResourceIndicatorFault.None)]
    [DataRow("[::ffff:192.0.2.1]", ResourceIndicatorFault.None)]
    [DataRow("[1:2:3:4:5:6:7::]", ResourceIndicatorFault.None)]
    [DataRow("[fe80::1:2]", ResourceIndicatorFault.None)]
    [DataRow("[1:2:3:4:5:6:192.0.2.1]", ResourceIndicatorFault.None)]
    [DataRow("[v1.fe]", ResourceIndicatorFault.None)]
    [DataRow("[V7.a:b]", ResourceIndicatorFault.None)]
    [DataRow("[1:2:3:4:5:6:7:8:9]", ResourceIndicatorFault.Authority)]
    [DataRow("[1::2::3]", ResourceIndicatorFault.Authority)]
    [DataRow("[::ffff:192.0.2.256]", ResourceIndicatorFault.Authority)]
    [DataRow("[::ffff:192.0.2.01]", ResourceIndicatorFault.Authority)]
    [DataRow("[12345::1]", ResourceIndicatorFault.Authority)]
    [DataRow("[g::1]", ResourceIndicatorFault.Authority)]
    [DataRow("[vX.a]", ResourceIndicatorFault.Authority)]
    [DataRow("[v1.]", ResourceIndicatorFault.Authority)]
    [DataRow("[]", ResourceIndicatorFault.Authority)]
    [DataRow("[1:2:3:4:5:6:7]", ResourceIndicatorFault.Authority)]
    public void CheckReadsEveryIpLiteralForm(string host, ResourceIndicatorFault expectedFault)
    {
        string indicator = "https://" + host + "/";

        RunUnderTurkishCulture(observedCultureName =>
        {
            Assert.AreEqual(expectedFault, ResourceIndicatorSyntax.Check(indicator));
            Assert.AreEqual("tr-TR", observedCultureName);
        });
    }

    /// <summary>
    /// A rule of this library, not a specification clause: the comparison key of a stored
    /// value <see cref="ResourceIndicatorSyntax.Check(ReadOnlySpan{char})"/> refuses is the value
    /// itself, so a stored value outside the grammar (an IRI, or any other value outside the ASCII
    /// grammar) compares by simple string identity
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.1">RFC 3986 section 6.2.1</see>).
    /// </summary>
    [TestMethod]
    [DataRow("HTTPS://API.EXAMPLE.COM/x", "https://api.example.com/x")]
    [DataRow("https://api.example.com/%GG", "https://api.example.com/%GG")]
    [DataRow("HTTPS://API.EXAMPLE.COM/%GG", "HTTPS://API.EXAMPLE.COM/%GG")]
    public void ComparisonKeyFoldsAnAcceptedIndicatorAndKeepsAnyOtherValue(string value, string expected)
    {
        RunUnderTurkishCulture(observedCultureName =>
        {
            Assert.AreEqual(expected, ResourceIndicatorSyntax.ComparisonKey(value));
            Assert.AreEqual("tr-TR", observedCultureName);
        });
    }

    /// <summary>
    /// A rule of this library, not a specification clause: <c>Fold</c> is total, so an
    /// indicator <see cref="ResourceIndicatorSyntax.Check(ReadOnlySpan{char})"/> refuses is
    /// returned unchanged rather than partially folded. The look-alike code point is built from
    /// its value, never typed raw: U+0130 (Latin capital I with dot above).
    /// </summary>
    [TestMethod]
    [DataRow("HTTPS://API.EXAMPLE.COM/x#", -1, "")]
    [DataRow("HTTPS://AP", 0x0130, ".EXAMPLE/")]
    public void FoldReturnsAValueTheCheckRefusesUnchanged(string prefix, int codePointOrSentinel, string suffix)
    {
        string indicator = codePointOrSentinel < 0
            ? prefix + suffix
            : prefix + char.ConvertFromUtf32(codePointOrSentinel) + suffix;

        RunUnderTurkishCulture(observedCultureName =>
        {
            Assert.AreEqual(indicator, ResourceIndicatorSyntax.Fold(indicator));
            Assert.AreEqual("tr-TR", observedCultureName);
        });
    }
}
