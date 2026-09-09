using System;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proves <see cref="TrustedListIdentifier"/> realises the shape and comparison of the value an OID4VP 1.0
/// §6.1.1.2 <c>etsi_tl</c> entry carries — "The identifier of a Trusted List as specified in ETSI TS 119 612",
/// per <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
/// Presentations 1.0, Section 6.1.1.2</see>: an absolute http or https URL with a host, compared as an ordinal
/// string per <see href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986, Section 6.2.1</see>'s
/// simple-string-comparison, so a false negative fails a match closed rather than admitting a normalisation the
/// specification does not require.
/// </summary>
[TestClass]
internal sealed class TrustedListIdentifierTests
{
    /// <summary>The Section 6.1.1.2 non-normative example <c>etsi_tl</c> value.</summary>
    private const string ExampleTrustedListIdentifier = "https://lotl.example.com";


    /// <summary>
    /// Proves <see cref="TrustedListIdentifier.TryCreate(string, out TrustedListIdentifier)"/> accepts the
    /// Section 6.1.1.2 example value and preserves it verbatim, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.2</see>.
    /// </summary>
    [TestMethod]
    public void TryCreateAcceptsTheSectionExampleTrustedListIdentifier()
    {
        bool created = TrustedListIdentifier.TryCreate(ExampleTrustedListIdentifier, out TrustedListIdentifier identifier);

        Assert.IsTrue(created, "§6.1.1.2: the example etsi_tl identifier is a well-formed absolute https URL and must be accepted.");
        Assert.AreEqual(ExampleTrustedListIdentifier, identifier.Value, "§6.1.1.2: the identifier is preserved as its original string.");
    }


    /// <summary>
    /// Proves the constructor accepts an absolute http URL — a Trusted List's distribution point may use either
    /// http or https, per <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.2</see>.
    /// </summary>
    [TestMethod]
    public void ConstructorAcceptsAnHttpTrustedListIdentifier()
    {
        var identifier = new TrustedListIdentifier("http://tl.example.com/tsl");

        Assert.AreEqual("http://tl.example.com/tsl", identifier.Value, "§6.1.1.2: an absolute http URL with a host is a valid Trusted List identifier.");
    }


    /// <summary>
    /// Proves a relative path is refused by both <see cref="TrustedListIdentifier.TryCreate(string, out TrustedListIdentifier)"/>
    /// and the constructor — a Trusted List identifier is an absolute URL, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.2</see>.
    /// </summary>
    [TestMethod]
    public void RelativePathIsRefused()
    {
        bool created = TrustedListIdentifier.TryCreate("some/relative/path", out _);

        Assert.IsFalse(created, "§6.1.1.2: a relative path is not an absolute Trusted List identifier and TryCreate fails closed.");
        Assert.ThrowsExactly<ArgumentException>(static () => new TrustedListIdentifier("some/relative/path"), "§6.1.1.2: constructing an identifier from a relative path throws.");
    }


    /// <summary>
    /// Proves a non-http(s) absolute value — the cross-platform <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>
    /// trap — is refused by both <see cref="TrustedListIdentifier.TryCreate(string, out TrustedListIdentifier)"/>
    /// and the constructor, since a Trusted List identifier uses the http or https scheme, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.2</see>.
    /// </summary>
    /// <param name="value">The non-http(s) candidate value.</param>
    [TestMethod]
    [DataRow("ftp://tl.example.com/tsl")]
    [DataRow("mailto:tl@example.com")]
    [DataRow("urn:example:trusted-list")]
    public void NonHttpSchemeIsRefused(string value)
    {
        bool created = TrustedListIdentifier.TryCreate(value, out _);

        Assert.IsFalse(created, "§6.1.1.2: a non-http(s) scheme is not a Trusted List identifier and TryCreate fails closed.");
        Assert.ThrowsExactly<ArgumentException>(() => new TrustedListIdentifier(value), "§6.1.1.2: constructing an identifier from a non-http(s) value throws.");
    }


    /// <summary>
    /// Proves a query-bearing URL is ACCEPTED — a Trusted List identifier is a scheme-information URI or
    /// distribution point (<see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
    /// ETSI TS 119 612</see> clause 5.3.16) that may legitimately bear a query, so unlike
    /// <c>Verifiable.Core.Model.Federation.EntityIdentifier</c> the query is not rejected; refusing it would
    /// fail a valid <c>etsi_tl</c> value closed, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.2</see>.
    /// </summary>
    [TestMethod]
    public void QueryBearingUrlIsAccepted()
    {
        bool created = TrustedListIdentifier.TryCreate("https://lotl.example.com?tenant=a", out TrustedListIdentifier identifier);

        Assert.IsTrue(created, "ETSI TS 119 612 clause 5.3.16: a Trusted List distribution point may carry a query, so TryCreate accepts it.");
        Assert.AreEqual("https://lotl.example.com?tenant=a", identifier.Value, "The query is preserved verbatim on the identifier's ordinal-compared value.");
    }


    /// <summary>
    /// Proves <see cref="TrustedListIdentifier.TryCreate(string, out TrustedListIdentifier)"/> fails closed on a
    /// null, empty or whitespace value without throwing — the fail-closed shape a wire reader needs, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.2</see>.
    /// </summary>
    /// <param name="value">The null, empty or whitespace candidate value.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void NullOrWhitespaceValueIsRefused(string? value)
    {
        bool created = TrustedListIdentifier.TryCreate(value, out TrustedListIdentifier identifier);

        Assert.IsFalse(created, "§6.1.1.2: a null, empty or whitespace value is not a Trusted List identifier and TryCreate fails closed.");
        Assert.AreEqual(default, identifier, "§6.1.1.2: a refused TryCreate yields the default identifier.");
    }


    /// <summary>
    /// Proves equality and hashing are ordinal on the original string, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986, Section 6.2.1</see>'s simple string
    /// comparison: two spellings differing only by a trailing slash are unequal, and equal spellings agree on
    /// hash code — a false negative fails a §6.1.1.2 match closed.
    /// </summary>
    [TestMethod]
    public void EqualityIsOrdinalOnTheOriginalString()
    {
        var identifier = new TrustedListIdentifier(ExampleTrustedListIdentifier);
        var sameSpelling = new TrustedListIdentifier(ExampleTrustedListIdentifier);
        var withTrailingSlash = new TrustedListIdentifier(ExampleTrustedListIdentifier + "/");

        Assert.AreEqual(identifier, sameSpelling, "RFC 3986 §6.2.1: identical spellings are equal.");
        Assert.AreEqual(identifier.GetHashCode(), sameSpelling.GetHashCode(), "RFC 3986 §6.2.1: identical spellings agree on GetHashCode.");
        Assert.AreNotEqual(identifier, withTrailingSlash, "RFC 3986 §6.2.1: a trailing-slash spelling is a distinct string and compares unequal.");
    }


    /// <summary>
    /// Proves <see cref="TrustedListIdentifier.ToString"/> returns the original identifier string, the form a
    /// §6.1.1.2 <c>etsi_tl</c> value carries, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 6.1.1.2</see>.
    /// </summary>
    [TestMethod]
    public void ToStringReturnsTheValue()
    {
        var identifier = new TrustedListIdentifier(ExampleTrustedListIdentifier);

        Assert.AreEqual(ExampleTrustedListIdentifier, identifier.ToString(), "§6.1.1.2: ToString renders the identifier's original string.");
    }
}
