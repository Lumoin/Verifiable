using System.Collections.Generic;
using System.Text;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Tests for the shipped JRD parser <see cref="WebFingerJrdJsonParsing.ParseJrd"/> — the
/// <see href="https://www.rfc-editor.org/rfc/rfc7033#section-4.4">RFC 7033 §4.4</see> JSON Resource
/// Descriptor shape, and the §8.5 client-side interpretation rules as expressed through
/// <see cref="WebFingerClient.FindLinkHref"/>. These are T3 of the conformance matrix. Every fixture is
/// driven through the REAL shipped parser (never a hand-rolled one), fed as UTF-8 bytes wrapped in the
/// project's tracked <see cref="TaggedMemory{T}"/> carrier — mirroring how a fetched response body is
/// carried in production.
/// </summary>
[TestClass]
internal sealed class WebFingerJrdParsingTests
{
    /// <summary>WF-28: an unrecognised top-level member is ignored, not a parse error.</summary>
    [TestMethod]
    public void WF28_UnknownTopLevelMemberIsIgnoredNotAnError()
    {
        const string json = """
        {"subject":"acct:alice@example.com","unknown_member":{"foo":["bar",1,true,null]},"links":[]}
        """;

        JsonResourceDescriptor? descriptor = Parse(json);

        Assert.IsNotNull(descriptor, "An unrecognised member MUST be ignored, not treated as a parse error.");
        Assert.AreEqual("acct:alice@example.com", descriptor!.Subject);
    }


    /// <summary>
    /// WF-29: a <c>subject</c> that differs from the resource the client requested is preserved verbatim, not
    /// rejected or rewritten — the parser has no notion of "the requested resource" to compare against.
    /// </summary>
    [TestMethod]
    public void WF29_SubjectDifferingFromTheRequestedResourceIsPreservedNotRejected()
    {
        const string requestedResource = "acct:alice@example.com";
        const string json = """{"subject":"acct:alice.canonical@example.org"}""";

        JsonResourceDescriptor? descriptor = Parse(json);

        Assert.IsNotNull(descriptor);
        Assert.AreNotEqual(requestedResource, descriptor!.Subject, "The fixture intentionally differs from the requested resource.");
        Assert.AreEqual("acct:alice.canonical@example.org", descriptor.Subject,
            "A subject differing from the query target MUST be preserved verbatim, never rejected.");
    }


    /// <summary>WF-30: an absent <c>subject</c> parses to <see langword="null"/>, not a parse failure.</summary>
    [TestMethod]
    public void WF30_AbsentSubjectParsesToNull()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"aliases":[]}""");

        Assert.IsNotNull(descriptor);
        Assert.IsNull(descriptor!.Subject);
    }


    /// <summary>WF-31: an absent <c>aliases</c> member parses to an empty list.</summary>
    [TestMethod]
    public void WF31_AbsentAliasesParsesToEmpty()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"subject":"acct:alice@example.com"}""");

        Assert.IsNotNull(descriptor);
        Assert.IsEmpty(descriptor!.Aliases);
    }


    /// <summary>WF-32: an absent <c>properties</c> member parses to an empty map.</summary>
    [TestMethod]
    public void WF32_AbsentPropertiesParsesToEmpty()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"subject":"acct:alice@example.com"}""");

        Assert.IsNotNull(descriptor);
        Assert.IsEmpty(descriptor!.Properties);
    }


    /// <summary>
    /// WF-32: a JSON <c>null</c> property value is preserved distinctly from a key that is entirely absent — a
    /// consumer can tell "the value is unset" from "the value was never named".
    /// </summary>
    [TestMethod]
    public void WF32_NullPropertyValueIsPreservedDistinctlyFromAnAbsentKey()
    {
        const string json = """
        {"properties":{"http://example.com/ns/a":null,"http://example.com/ns/b":"value"}}
        """;

        JsonResourceDescriptor? descriptor = Parse(json);

        Assert.IsNotNull(descriptor);
        Assert.IsTrue(descriptor!.Properties.ContainsKey("http://example.com/ns/a"), "A JSON null value MUST still leave the key present.");
        Assert.IsNull(descriptor.Properties["http://example.com/ns/a"]);
        Assert.AreEqual("value", descriptor.Properties["http://example.com/ns/b"]);
        Assert.IsFalse(descriptor.Properties.ContainsKey("http://example.com/ns/c"), "A key never mentioned in the JRD MUST NOT appear at all.");
    }


    /// <summary>
    /// WF-33: link order is preserved exactly as parsed, and <see cref="WebFingerClient.FindLinkHref"/> returns
    /// the FIRST matching relation — order MAY be read as preference (§4.4.4).
    /// </summary>
    [TestMethod]
    public void WF33_LinkOrderIsPreservedAndFindLinkHrefReturnsTheFirstMatch()
    {
        const string json = """
        {"links":[
            {"rel":"urn:webfinger:did","href":"did:webs:example.com:FIRST"},
            {"rel":"urn:webfinger:did","href":"did:webs:example.com:SECOND"}
        ]}
        """;

        JsonResourceDescriptor? descriptor = Parse(json);

        Assert.IsNotNull(descriptor);
        Assert.HasCount(2, descriptor!.Links);
        Assert.AreEqual("did:webs:example.com:FIRST", descriptor.Links[0].Href);
        Assert.AreEqual("did:webs:example.com:SECOND", descriptor.Links[1].Href);
        Assert.AreEqual("did:webs:example.com:FIRST", WebFingerClient.FindLinkHref(descriptor, "urn:webfinger:did"),
            "Order MAY be read as preference (§4.4.4); the first match wins.");
    }


    /// <summary>
    /// WF-34: an absent <c>links</c> member parses to an empty list, and
    /// <see cref="WebFingerClient.FindLinkHref"/> reports <see langword="null"/> rather than throwing when there
    /// is nothing to match.
    /// </summary>
    [TestMethod]
    public void WF34_AbsentLinksParsesToEmptyAndFindLinkHrefReturnsNullWithoutThrowing()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"subject":"acct:alice@example.com"}""");

        Assert.IsNotNull(descriptor);
        Assert.IsEmpty(descriptor!.Links);
        Assert.IsNull(WebFingerClient.FindLinkHref(descriptor, "urn:webfinger:did"));
    }


    /// <summary>WF-37: an absent link <c>type</c> parses to <see langword="null"/>.</summary>
    [TestMethod]
    public void WF37_AbsentLinkTypeParsesToNull()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"links":[{"rel":"urn:webfinger:did"}]}""");

        Assert.IsNotNull(descriptor);
        Assert.HasCount(1, descriptor!.Links);
        Assert.IsNull(descriptor.Links[0].Type);
    }


    /// <summary>
    /// WF-38: an absent link <c>href</c> parses to <see langword="null"/>, and
    /// <see cref="WebFingerClient.FindLinkHref"/> reports <see langword="null"/> gracefully even though the
    /// relation itself DID match.
    /// </summary>
    [TestMethod]
    public void WF38_AbsentLinkHrefParsesToNullAndFindLinkHrefReturnsNullGracefully()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"links":[{"rel":"urn:webfinger:did"}]}""");

        Assert.IsNotNull(descriptor);
        Assert.IsNull(descriptor!.Links[0].Href);
        Assert.IsNull(WebFingerClient.FindLinkHref(descriptor, "urn:webfinger:did"),
            "A matched relation with no href MUST report null, not throw.");
    }


    /// <summary>
    /// WF-42: a JSON object carrying a DUPLICATE <c>titles</c> language key is not a parse error — the reader
    /// simply reads both member tokens, and the last value wins (structural on a <see cref="Dictionary{TKey,TValue}"/>).
    /// </summary>
    [TestMethod]
    public void WF42_DuplicateTitlesLanguageKeyDoesNotThrowAndLastValueWins()
    {
        const string json = """
        {"links":[{"rel":"urn:webfinger:did","titles":{"en-us":"Alice","en-us":"Alice Cooper"}}]}
        """;

        JsonResourceDescriptor? descriptor = Parse(json);

        Assert.IsNotNull(descriptor);
        Assert.HasCount(1, descriptor!.Links);
        Assert.AreEqual("Alice Cooper", descriptor.Links[0].Titles["en-us"],
            "A duplicated language tag MUST NOT be treated as an error, and the last value wins.");
    }


    /// <summary>WF-43: a consumer can select any title by its language tag, not only the first one parsed.</summary>
    [TestMethod]
    public void WF43_ConsumerCanSelectAnyTitleByLanguageTag()
    {
        const string json = """
        {"links":[{"rel":"urn:webfinger:did","titles":{"en-us":"Alice","und":"Alice (default)"}}]}
        """;

        JsonResourceDescriptor? descriptor = Parse(json);

        Assert.IsNotNull(descriptor);
        IReadOnlyDictionary<string, string> titles = descriptor!.Links[0].Titles;
        Assert.AreEqual("Alice", titles["en-us"]);
        Assert.AreEqual("Alice (default)", titles["und"]);
    }


    /// <summary>WF-44: an absent <c>titles</c> member parses to an empty map.</summary>
    [TestMethod]
    public void WF44_AbsentTitlesParsesToEmpty()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"links":[{"rel":"urn:webfinger:did"}]}""");

        Assert.IsNotNull(descriptor);
        Assert.IsEmpty(descriptor!.Links[0].Titles);
    }


    /// <summary>WF-45: an absent link <c>properties</c> member parses to an empty map.</summary>
    [TestMethod]
    public void WF45_AbsentLinkPropertiesParsesToEmpty()
    {
        JsonResourceDescriptor? descriptor = Parse("""{"links":[{"rel":"urn:webfinger:did"}]}""");

        Assert.IsNotNull(descriptor);
        Assert.IsEmpty(descriptor!.Links[0].Properties);
    }


    /// <summary>
    /// WF-58 / WF-59 / WF-60 (§8.5): a client interprets only the relation type it asked for and silently
    /// ignores every OTHER link relation present in the JRD — including ones it does not understand — without
    /// ever surfacing an error for them.
    /// </summary>
    [TestMethod]
    public void WF58WF59WF60_ClientInterpretsOnlyTheRequestedRelAndIgnoresUnrecognisedOnesWithoutError()
    {
        const string json = """
        {"links":[
            {"rel":"urn:example:not-understood-by-this-client","href":"https://example.com/unrelated"},
            {"rel":"urn:webfinger:did","href":"did:webs:example.com:AID"},
            {"rel":"http://webfinger.net/rel/avatar","href":"https://example.com/avatar.png"}
        ]}
        """;

        JsonResourceDescriptor? descriptor = Parse(json);

        Assert.IsNotNull(descriptor);
        Assert.AreEqual("did:webs:example.com:AID", WebFingerClient.FindLinkHref(descriptor!, "urn:webfinger:did"),
            "Only the requested relation is interpreted.");
        Assert.IsNull(WebFingerClient.FindLinkHref(descriptor!, "urn:example:not-a-link-in-the-fixture"),
            "A relation this client neither requested nor understands is ignored, never an error.");
    }


    /// <summary>Parses a JRD fixture through the shipped parser, wrapping the UTF-8 bytes in the tracked carrier.</summary>
    private static JsonResourceDescriptor? Parse(string json)
    {
        TaggedMemory<byte> bytes = new(Encoding.UTF8.GetBytes(json), BufferTags.Json);

        return WebFingerJrdJsonParsing.ParseJrd(bytes.Span);
    }
}
