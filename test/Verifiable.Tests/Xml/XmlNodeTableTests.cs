using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Conformance tests for <see cref="XmlNodeTable.TryParse"/>: the encoding front end, the data-model
/// normalizations of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">Extensible Markup Language
/// (XML) 1.0 (Fifth Edition)</see> sections 2.11, 3.3.3 and 4.1 that
/// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1
/// requires of the processor preparing the XPath data model, the namespace processing of
/// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
/// Edition)</see>, and pooled-buffer custody.
/// </summary>
[TestClass]
internal sealed class XmlNodeTableTests
{
    private static string S(ReadOnlySpan<byte> octets)
    {
        return Encoding.UTF8.GetString(octets);
    }


    private static XmlNodeTable ParseAccepting(byte[] documentOctets, BaseMemoryPool pool)
    {
        bool isAccepted = XmlNodeTable.TryParse(documentOctets, pool, out XmlNodeTable? table, out XmlReadError error);
        Assert.IsTrue(isAccepted, $"The document must be accepted but was refused with {error.Failure} at offset {error.ByteOffset}.");

        return table!;
    }


    private static XmlReadError ParseExpectingRefusal(byte[] documentOctets, BaseMemoryPool pool)
    {
        bool isAccepted = XmlNodeTable.TryParse(documentOctets, pool, out XmlNodeTable? table, out XmlReadError error);
        table?.Dispose();
        Assert.IsFalse(isAccepted, "The document must be refused.");

        return error;
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.1: "Implementations MUST use XML processors that support UTF-8 and UTF-16" — a UTF-8
    /// document is accepted with and without a byte order mark, per
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3, under which entities encoded in UTF-8 MAY begin with the byte order mark.
    /// </summary>
    [TestMethod]
    public void Utf8WithAndWithoutByteOrderMarkIsAccepted()
    {
        using var withoutBom = ParseAccepting("<a/>"u8.ToArray(), BaseMemoryPool.Shared);
        Assert.AreEqual("a", S(withoutBom.LocalNameOf(withoutBom.DocumentElementIndex)));

        byte[] withBomOctets = [0xEF, 0xBB, 0xBF, .. "<a/>"u8];
        using var withBom = ParseAccepting(withBomOctets, BaseMemoryPool.Shared);
        Assert.AreEqual("a", S(withBom.LocalNameOf(withBom.DocumentElementIndex)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3: "Entities encoded in UTF-16 MUST ... begin with the Byte Order Mark"; "XML
    /// processors MUST be able to use this character to differentiate between UTF-8 and UTF-16 encoded
    /// documents." Both byte orders are accepted and transcoded once.
    /// </summary>
    [TestMethod]
    public void Utf16WithByteOrderMarkIsAcceptedInBothByteOrders()
    {
        byte[] bigEndian = [0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes("<a x=\"v\"/>")];
        using var bigEndianTable = ParseAccepting(bigEndian, BaseMemoryPool.Shared);
        Assert.AreEqual("a", S(bigEndianTable.LocalNameOf(bigEndianTable.DocumentElementIndex)));
        Assert.AreEqual("v", S(bigEndianTable.AttributeValueOf(bigEndianTable.DocumentElementIndex, 0)));

        byte[] littleEndian = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("<a x=\"v\"/>")];
        using var littleEndianTable = ParseAccepting(littleEndian, BaseMemoryPool.Shared);
        Assert.AreEqual("a", S(littleEndianTable.LocalNameOf(littleEndianTable.DocumentElementIndex)));
    }


    /// <summary>
    /// Proves the encoding ruling of this surface over
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> Appendix F,
    /// which autodetects byte-order-mark-less UTF-16 from the 16-bit pattern of <c>&lt;?xml</c>: a UTF-16
    /// document without a byte order mark is accepted exactly when it begins with that unambiguous
    /// pattern, in either byte order.
    /// </summary>
    [TestMethod]
    public void BomlessUtf16BeginningWithXmlDeclarationPatternIsAccepted()
    {
        byte[] littleEndian = Encoding.Unicode.GetBytes("<?xml version=\"1.0\"?><a/>");
        using var littleEndianTable = ParseAccepting(littleEndian, BaseMemoryPool.Shared);
        Assert.AreEqual("a", S(littleEndianTable.LocalNameOf(littleEndianTable.DocumentElementIndex)));

        byte[] bigEndian = Encoding.BigEndianUnicode.GetBytes("<?xml version=\"1.0\"?><a/>");
        using var bigEndianTable = ParseAccepting(bigEndian, BaseMemoryPool.Shared);
        Assert.AreEqual("a", S(bigEndianTable.LocalNameOf(bigEndianTable.DocumentElementIndex)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3: "It is a fatal error when an XML processor encounters an entity with an encoding
    /// that it is unable to process." This surface parses only UTF-8 and UTF-16, so a document declaring
    /// <c>ISO-8859-1</c> is refused — conformant, since
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1
    /// makes only UTF-8 and UTF-16 required and ISO-8859-1 merely recommended.
    /// </summary>
    [TestMethod]
    public void Iso88591EncodingDeclarationIsRefused()
    {
        XmlReadError error = ParseExpectingRefusal("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.InvalidEncoding, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3: "it is a fatal error for an entity including an encoding declaration to be
    /// presented to the XML processor in an encoding other than that named in the declaration" — a UTF-8
    /// document declaring <c>UTF-16</c> is refused.
    /// </summary>
    [TestMethod]
    public void DeclaredUtf16OverUtf8OctetsIsRefused()
    {
        XmlReadError error = ParseExpectingRefusal("<?xml version=\"1.0\" encoding=\"UTF-16\"?><a/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.InvalidEncoding, error.Failure);
    }


    /// <summary>
    /// Proves the refusal of encodings outside UTF-8 and UTF-16 by their
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> Appendix F
    /// signatures: a UCS-4 byte order mark and the EBCDIC <c>&lt;?xm</c> signature are both refused as
    /// <see cref="XmlReadFailure.InvalidEncoding"/>.
    /// </summary>
    [TestMethod]
    public void Ucs4ByteOrderMarkAndEbcdicSignatureAreRefused()
    {
        byte[] ucs4 = [0xFF, 0xFE, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00];
        Assert.AreEqual(XmlReadFailure.InvalidEncoding, ParseExpectingRefusal(ucs4, BaseMemoryPool.Shared).Failure);

        byte[] ebcdic = [0x4C, 0x6F, 0xA7, 0x94, 0x93];
        Assert.AreEqual(XmlReadFailure.InvalidEncoding, ParseExpectingRefusal(ebcdic, BaseMemoryPool.Shared).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3: "it is a fatal error if an entity encoded in UTF-8 contains any ill-formed code
    /// unit sequences, as defined in section 3.9 of Unicode" — refused, never replaced.
    /// </summary>
    [TestMethod]
    public void IllFormedUtf8SequenceIsRefused()
    {
        byte[] document = [.. "<a>"u8, 0xC0, 0xAF, .. "</a>"u8];
        XmlReadError error = ParseExpectingRefusal(document, BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, error.Failure);
        Assert.AreEqual(3L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3's fatal-error rule applied to UTF-16: an unpaired high surrogate code unit is not
    /// well-formed UTF-16 and is refused, never replaced.
    /// </summary>
    [TestMethod]
    public void UnpairedSurrogateInUtf16IsRefused()
    {
        byte[] document = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("<a>"), 0x00, 0xD8, .. Encoding.Unicode.GetBytes("</a>")];
        XmlReadError error = ParseExpectingRefusal(document, BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.IllFormedUtf16, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.1: "the leading byte order mark is treated as an artifact of encoding and stripped from
    /// the UCS character data (subsequent zero width non-breaking spaces appearing within the UTF-16 data
    /// are not removed)."
    /// </summary>
    [TestMethod]
    public void Utf16ByteOrderMarkIsStrippedButInteriorZeroWidthNoBreakSpaceIsKept()
    {
        byte[] document = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("<a>﻿x</a>")];
        using var table = ParseAccepting(document, BaseMemoryPool.Shared);

        int text = table.FirstChildOf(table.DocumentElementIndex);
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(text));
        Assert.AreEqual("﻿x", S(table.ValueOf(text)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.1: "All consecutive characters are placed into a single text node", with CDATA sections
    /// replaced by their character content and character references resolved — one run of text, a
    /// character reference and a CDATA section coalesce into a single text node.
    /// </summary>
    [TestMethod]
    public void ConsecutiveCharacterDataCoalescesIntoOneTextNode()
    {
        using var table = ParseAccepting("<a>x&#65;<![CDATA[y]]>z</a>"u8.ToArray(), BaseMemoryPool.Shared);

        int element = table.DocumentElementIndex;
        int text = table.FirstChildOf(element);
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(text));
        Assert.AreEqual("xAyz", S(table.ValueOf(text)));
        Assert.AreEqual(-1, table.NextSiblingOf(text), "All consecutive character data must land in one text node.");
    }


    /// <summary>
    /// Proves the XPath data model shape <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">
    /// Canonical XML 1.0</see> section 2.1 requires: "Each element node can have child nodes of type
    /// element, text, processing instruction, and comment" — a comment between two runs of character data
    /// is its own node and splits the text into two text nodes.
    /// </summary>
    [TestMethod]
    public void CommentSplitsCharacterDataIntoTwoTextNodes()
    {
        using var table = ParseAccepting("<a>x<!--c-->y</a>"u8.ToArray(), BaseMemoryPool.Shared);

        int element = table.DocumentElementIndex;
        int first = table.FirstChildOf(element);
        int comment = table.NextSiblingOf(first);
        int second = table.NextSiblingOf(comment);
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(first));
        Assert.AreEqual("x", S(table.ValueOf(first)));
        Assert.AreEqual(XmlNodeKind.Comment, table.KindOf(comment));
        Assert.AreEqual("c", S(table.ValueOf(comment)));
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(second));
        Assert.AreEqual("y", S(table.ValueOf(second)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 production [66] <c>CharRef</c>: "If the character reference begins with \"&amp;#x\",
    /// the digits and letters up to the terminating ; provide a hexadecimal representation of the
    /// character's code point ... If it begins just with \"&amp;#\", the digits ... provide a decimal
    /// representation", and section 4.6: the predefined entities <c>amp</c>, <c>lt</c>, <c>gt</c>,
    /// <c>apos</c>, <c>quot</c> resolve to their characters.
    /// </summary>
    [TestMethod]
    public void CharacterAndPredefinedEntityReferencesResolve()
    {
        using var table = ParseAccepting("<a>&#65;&#x42;&amp;&lt;&gt;&apos;&quot;</a>"u8.ToArray(), BaseMemoryPool.Shared);

        int text = table.FirstChildOf(table.DocumentElementIndex);
        Assert.AreEqual("AB&<>'\"", S(table.ValueOf(text)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 well-formedness constraint Entity Declared: "In a document without any DTD ... the
    /// Name given in the entity reference MUST match that in an entity declaration ... except that
    /// well-formed documents need not declare any of the following entities: amp, lt, gt, apos, quot."
    /// With every DOCTYPE refused, any other entity reference is refused.
    /// </summary>
    [TestMethod]
    public void EntityReferenceBeyondTheFivePredefinedIsRefused()
    {
        XmlReadError inText = ParseExpectingRefusal("<a>&nbsp;</a>"u8.ToArray(), BaseMemoryPool.Shared);
        XmlReadError inAttribute = ParseExpectingRefusal("<a x=\"&nbsp;\"/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.UndeclaredEntity, inText.Failure);
        Assert.AreEqual(XmlReadFailure.UndeclaredEntity, inAttribute.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 well-formedness constraint Legal Character: "Characters referred to using character
    /// references MUST match the production for Char." A reference to a surrogate code point, to a code
    /// point beyond U+10FFFF and to the forbidden control U+0000 are all refused.
    /// </summary>
    [TestMethod]
    public void CharacterReferencesOutsideCharProductionAreRefused()
    {
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, ParseExpectingRefusal("<a>&#xD800;</a>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, ParseExpectingRefusal("<a>&#x110000;</a>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, ParseExpectingRefusal("<a>&#0;</a>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.2 production [2] <c>Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] |
    /// [#x10000-#x10FFFF]</c>: a literal control character outside the production, here form feed #xC, is
    /// refused.
    /// </summary>
    [TestMethod]
    public void LiteralControlCharacterOutsideCharProductionIsRefused()
    {
        byte[] document = [.. "<a>"u8, 0x0C, .. "</a>"u8];
        XmlReadError error = ParseExpectingRefusal(document, BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.InvalidCharacter, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.11: "the XML processor MUST behave as if it normalized all line breaks in external
    /// parsed entities (including the document entity) on input, before parsing, by translating both the
    /// two-character sequence #xD #xA and any #xD that is not followed by #xA to a single #xA character."
    /// </summary>
    [TestMethod]
    public void LineEndsNormalizeInTextCommentsAndProcessingInstructions()
    {
        using var table = ParseAccepting("<a>x\r\ny\rz<!--c\r\nd--><?p e\rf?></a>"u8.ToArray(), BaseMemoryPool.Shared);

        int element = table.DocumentElementIndex;
        int text = table.FirstChildOf(element);
        int comment = table.NextSiblingOf(text);
        int instruction = table.NextSiblingOf(comment);
        Assert.AreEqual("x\ny\nz", S(table.ValueOf(text)));
        Assert.AreEqual("c\nd", S(table.ValueOf(comment)));
        Assert.AreEqual("e\nf", S(table.ValueOf(instruction)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.3.3: "For a white space character (#x20, #xD, #xA, #x9), append a space character
    /// (#x20) to the normalized value" after the section 2.11 line-end normalization, under which a
    /// literal #xD #xA pair is first one #xA and therefore one space, and section 2.7's CDATA treatment
    /// of every undeclared attribute: no leading/trailing trim and no space collapsing applies.
    /// </summary>
    [TestMethod]
    public void AttributeLiteralWhitespaceNormalizesToSingleSpacesWithoutCollapsing()
    {
        using var table = ParseAccepting("<a x=\"u\r\nv\tw\" y=\" p  q \"/>"u8.ToArray(), BaseMemoryPool.Shared);

        int element = table.DocumentElementIndex;
        Assert.AreEqual("u v w", S(table.AttributeValueOf(element, 0)), "A CRLF pair must normalize to one #xA before becoming one space.");
        Assert.AreEqual(" p  q ", S(table.AttributeValueOf(element, 1)), "The CDATA rule neither trims nor collapses spaces.");
    }


    /// <summary>
    /// Proves the third normalization example row of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.3.3, whose attribute specification <c>a="&amp;#xd;&amp;#xd;A&amp;#xa;&amp;#xa;B&amp;#xd;&amp;#xa;"</c>
    /// normalizes, when <c>a</c> is CDATA, to <c>#xD #xD A #xA #xA B #xD #xA</c>: "if the unnormalized
    /// attribute value contains a character reference to a white space character other than space (#x20),
    /// the normalized value contains the referenced character itself".
    /// </summary>
    [TestMethod]
    public void AttributeCharacterReferencesToWhitespaceStayLiteralPerSpecExample()
    {
        using var table = ParseAccepting("<e a=\"&#xd;&#xd;A&#xa;&#xa;B&#xd;&#xa;\"/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual("\r\rA\n\nB\r\n", S(table.AttributeValueOf(table.DocumentElementIndex, 0)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> sections 6.1 and 6.2: a prefixed element resolves through its prefix declaration,
    /// an unprefixed element through the default namespace, a prefixed attribute through its prefix, and
    /// "The namespace name for an unprefixed attribute name always has no value."
    /// </summary>
    [TestMethod]
    public void ElementAndAttributeNamesResolveToNamespaceUriPrefixAndLocalName()
    {
        using var table = ParseAccepting("<b:root xmlns:b=\"urn:x\" xmlns=\"urn:d\"><child b:a=\"1\" a=\"2\"/></b:root>"u8.ToArray(), BaseMemoryPool.Shared);

        int root = table.DocumentElementIndex;
        Assert.AreEqual("b", S(table.PrefixOf(root)));
        Assert.AreEqual("root", S(table.LocalNameOf(root)));
        Assert.AreEqual("urn:x", S(table.NamespaceUriOf(root)));

        int child = table.FirstChildOf(root);
        Assert.AreEqual("", S(table.PrefixOf(child)));
        Assert.AreEqual("urn:d", S(table.NamespaceUriOf(child)), "An unprefixed element takes the default namespace.");
        Assert.AreEqual("urn:x", S(table.AttributeNamespaceUriOf(child, 0)));
        Assert.AreEqual("a", S(table.AttributeLocalNameOf(child, 0)));
        Assert.AreEqual("", S(table.AttributeNamespaceUriOf(child, 1)), "An unprefixed attribute name always has no namespace.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 6.2: "The attribute value in a default namespace declaration MAY be empty.
    /// This has the same effect, within the scope of the declaration, of there being no default
    /// namespace."
    /// </summary>
    [TestMethod]
    public void EmptyDefaultNamespaceDeclarationUndeclaresTheDefault()
    {
        using var table = ParseAccepting("<a xmlns=\"urn:x\"><b xmlns=\"\"/></a>"u8.ToArray(), BaseMemoryPool.Shared);

        int outer = table.DocumentElementIndex;
        int inner = table.FirstChildOf(outer);
        Assert.AreEqual("urn:x", S(table.NamespaceUriOf(outer)));
        Assert.AreEqual("", S(table.NamespaceUriOf(inner)), "Inside xmlns=\"\" there is no default namespace.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 5 namespace constraint No Prefix Undeclaring: "In a namespace declaration
    /// for a prefix ..., the attribute value MUST NOT be empty." Prefix undeclaring exists only in
    /// XML 1.1.
    /// </summary>
    [TestMethod]
    public void PrefixUndeclarationIsRefused()
    {
        XmlReadError error = ParseExpectingRefusal("<a xmlns:p=\"\"/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.PrefixUndeclarationProhibited, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 5 namespace constraint Prefix Declared: "The namespace prefix, unless it is
    /// xml or xmlns, MUST have been declared in a namespace declaration attribute in either the start-tag
    /// of the element where the prefix is used or in an ancestor element."
    /// </summary>
    [TestMethod]
    public void UndeclaredPrefixOnElementOrAttributeIsRefused()
    {
        XmlReadError onElement = ParseExpectingRefusal("<p:a/>"u8.ToArray(), BaseMemoryPool.Shared);
        XmlReadError onAttribute = ParseExpectingRefusal("<a p:x=\"1\"/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.UndeclaredPrefix, onElement.Failure);
        Assert.AreEqual(XmlReadFailure.UndeclaredPrefix, onAttribute.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3 namespace constraint Reserved Prefixes and Namespace Names: "The prefix
    /// xmlns is used only to declare namespace bindings ... It MUST NOT be declared", and "Element names
    /// MUST NOT have the prefix xmlns."
    /// </summary>
    [TestMethod]
    public void XmlnsPrefixDeclarationAndXmlnsElementPrefixAreRefused()
    {
        XmlReadError declaration = ParseExpectingRefusal("<a xmlns:xmlns=\"urn:x\"/>"u8.ToArray(), BaseMemoryPool.Shared);
        XmlReadError elementName = ParseExpectingRefusal("<xmlns:e/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, declaration.Failure);
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, elementName.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3 namespace constraint Reserved Prefixes and Namespace Names: "The prefix
    /// xml is by definition bound to the namespace name http://www.w3.org/XML/1998/namespace. It MAY, but
    /// need not, be declared, and MUST NOT be bound to any other namespace name."
    /// </summary>
    [TestMethod]
    public void XmlPrefixAcceptsOnlyItsDefinedNamespaceName()
    {
        using var declaredCorrectly = ParseAccepting("<a xmlns:xml=\"http://www.w3.org/XML/1998/namespace\"/>"u8.ToArray(), BaseMemoryPool.Shared);
        Assert.AreEqual(1, declaredCorrectly.NamespaceDeclarationCountOf(declaredCorrectly.DocumentElementIndex));

        XmlReadError wrongBinding = ParseExpectingRefusal("<a xmlns:xml=\"urn:x\"/>"u8.ToArray(), BaseMemoryPool.Shared);
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, wrongBinding.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3 namespace constraint Reserved Prefixes and Namespace Names: "Other
    /// prefixes MUST NOT be bound to this namespace name [the xml namespace], and it MUST NOT be declared
    /// as the default namespace", and for the xmlns namespace name: "Other prefixes MUST NOT be bound to
    /// this namespace name, and it MUST NOT be declared as the default namespace."
    /// </summary>
    [TestMethod]
    public void ReservedNamespaceNamesRefuseOtherBindings()
    {
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, ParseExpectingRefusal("<a xmlns:p=\"http://www.w3.org/XML/1998/namespace\"/>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, ParseExpectingRefusal("<a xmlns=\"http://www.w3.org/XML/1998/namespace\"/>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, ParseExpectingRefusal("<a xmlns:p=\"http://www.w3.org/2000/xmlns/\"/>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, ParseExpectingRefusal("<a xmlns=\"http://www.w3.org/2000/xmlns/\"/>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3: the <c>xml</c> prefix "MAY, but need not, be declared" — an undeclared
    /// <c>xml:space</c> attribute resolves to the xml namespace through the implicit binding.
    /// </summary>
    [TestMethod]
    public void ImplicitXmlPrefixResolvesWithoutDeclaration()
    {
        using var table = ParseAccepting("<a xml:space=\"preserve\"/>"u8.ToArray(), BaseMemoryPool.Shared);

        int element = table.DocumentElementIndex;
        Assert.AreEqual("http://www.w3.org/XML/1998/namespace", S(table.AttributeNamespaceUriOf(element, 0)));
        Assert.IsTrue(table.TryResolvePrefix(element, "xml"u8, out ReadOnlySpan<byte> uri));
        Assert.AreEqual("http://www.w3.org/XML/1998/namespace", S(uri));
    }


    /// <summary>
    /// Proves the relative namespace URI refusal of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1:
    /// "implementations of XML canonicalization MUST report an operation failure on documents containing
    /// relative namespace URIs." Discrimination is syntactic per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">IETF RFC 3986 section 4.2</see>: a
    /// reference without a scheme is relative.
    /// </summary>
    [TestMethod]
    public void RelativeNamespaceUriIsRefused()
    {
        Assert.AreEqual(XmlReadFailure.RelativeNamespaceUri, ParseExpectingRefusal("<a xmlns=\"relative/path\"/>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
        Assert.AreEqual(XmlReadFailure.RelativeNamespaceUri, ParseExpectingRefusal("<a xmlns:p=\"#fragment\"/>"u8.ToArray(), BaseMemoryPool.Shared).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 well-formedness constraint Unique Att Spec: "An attribute name MUST NOT appear more
    /// than once in the same start-tag or empty-element tag."
    /// </summary>
    [TestMethod]
    public void LiteralDuplicateAttributeIsRefused()
    {
        XmlReadError error = ParseExpectingRefusal("<a x=\"1\" x=\"2\"/>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.DuplicateAttribute, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 6.3 namespace constraint Attributes Unique: no tag may contain two
    /// attributes that "have qualified names with the same local part and with prefixes which have been
    /// bound to namespace names that are identical", exercised with the spec's own <c>bad</c> example;
    /// the spec's <c>good</c> counterexamples stay accepted "because the default namespace does not apply
    /// to attribute names."
    /// </summary>
    [TestMethod]
    public void ExpandedDuplicateAttributeIsRefusedAndSpecCounterexamplesAccepted()
    {
        XmlReadError error = ParseExpectingRefusal(
            "<x xmlns:n1=\"http://www.w3.org\" xmlns:n2=\"http://www.w3.org\"><bad n1:a=\"1\" n2:a=\"2\"/></x>"u8.ToArray(),
            BaseMemoryPool.Shared);
        Assert.AreEqual(XmlReadFailure.DuplicateAttribute, error.Failure);

        using var table = ParseAccepting(
            "<x xmlns:n1=\"http://www.w3.org\" xmlns=\"http://www.w3.org\"><good a=\"1\" n1:a=\"2\"/></x>"u8.ToArray(),
            BaseMemoryPool.Shared);
        Assert.AreEqual(2, table.AttributeCountOf(table.FirstChildOf(table.DocumentElementIndex)));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 well-formedness constraint Element Type Match: "The Name in an element's end-tag MUST
    /// match the element type in the start-tag."
    /// </summary>
    [TestMethod]
    public void MismatchedEndTagIsRefused()
    {
        XmlReadError error = ParseExpectingRefusal("<a></b>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.MismatchedTag, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 6.1: "The scope of a namespace declaration declaring a prefix extends from
    /// the beginning of the start-tag in which it appears to the end of the corresponding end-tag,
    /// excluding the scope of any inner declarations with the same NSAttName part." An inner
    /// redeclaration shadows and the outer binding returns after it closes.
    /// </summary>
    [TestMethod]
    public void InnerNamespaceRedeclarationShadowsAndOuterReturns()
    {
        using var table = ParseAccepting("<a xmlns:p=\"urn:1\"><b xmlns:p=\"urn:2\"><p:c/></b><p:d/></a>"u8.ToArray(), BaseMemoryPool.Shared);

        int a = table.DocumentElementIndex;
        int b = table.FirstChildOf(a);
        int c = table.FirstChildOf(b);
        int d = table.NextSiblingOf(b);
        Assert.AreEqual("urn:2", S(table.NamespaceUriOf(c)), "The inner declaration shadows the outer one.");
        Assert.AreEqual("urn:1", S(table.NamespaceUriOf(d)), "The outer binding applies again after the inner scope closes.");

        Assert.IsTrue(table.TryResolvePrefix(c, "p"u8, out ReadOnlySpan<byte> atC));
        Assert.AreEqual("urn:2", S(atC));
        Assert.IsTrue(table.TryResolvePrefix(d, "p"u8, out ReadOnlySpan<byte> atD));
        Assert.AreEqual("urn:1", S(atD));
    }


    /// <summary>
    /// Proves the XPath data model shape of
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1:
    /// "There exists a single root node whose children are processing instruction nodes and comment nodes
    /// to represent information outside of the document element", "Whitespace outside of the root
    /// document element MUST be discarded", and section 2.2's document order — node indices ascend in
    /// document order.
    /// </summary>
    [TestMethod]
    public void RootChildrenAndDocumentOrderMatchTheDataModel()
    {
        using var table = ParseAccepting("<?p1 d?> <!--c--> <r>t</r> <?p2 e?>"u8.ToArray(), BaseMemoryPool.Shared);

        Assert.AreEqual(XmlNodeKind.Root, table.KindOf(table.RootIndex));
        int first = table.FirstChildOf(table.RootIndex);
        int second = table.NextSiblingOf(first);
        int third = table.NextSiblingOf(second);
        int fourth = table.NextSiblingOf(third);
        Assert.AreEqual(XmlNodeKind.ProcessingInstruction, table.KindOf(first));
        Assert.AreEqual("p1", S(table.LocalNameOf(first)));
        Assert.AreEqual(XmlNodeKind.Comment, table.KindOf(second));
        Assert.AreEqual(XmlNodeKind.Element, table.KindOf(third));
        Assert.AreEqual(XmlNodeKind.ProcessingInstruction, table.KindOf(fourth));
        Assert.AreEqual(-1, table.NextSiblingOf(fourth));
        Assert.IsTrue(first < second && second < third && third < fourth, "Node indices ascend in document order.");

        int text = table.FirstChildOf(third);
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(text));
        Assert.AreEqual(third, table.ParentOf(text));
        Assert.AreEqual(table.RootIndex, table.ParentOf(third));
    }


    /// <summary>
    /// Proves the namespace declaration accessors carry the axis data
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1
    /// requires: "An element E has namespace nodes that represent its namespace declarations as well as
    /// any namespace declarations made by its ancestors that have not been overridden in E's
    /// declarations" — the element's own declarations are exposed per element and the inherited ones are
    /// reconstructable through <see cref="XmlNodeTable.TryResolvePrefix"/>.
    /// </summary>
    [TestMethod]
    public void NamespaceDeclarationsArePerElementAndInScopeContextIsReconstructable()
    {
        using var table = ParseAccepting("<a xmlns:p=\"urn:1\" xmlns=\"urn:d\"><b/></a>"u8.ToArray(), BaseMemoryPool.Shared);

        int a = table.DocumentElementIndex;
        int b = table.FirstChildOf(a);
        Assert.AreEqual(2, table.NamespaceDeclarationCountOf(a));
        Assert.AreEqual("p", S(table.NamespaceDeclarationPrefixOf(a, 0)));
        Assert.AreEqual("urn:1", S(table.NamespaceDeclarationUriOf(a, 0)));
        Assert.AreEqual("", S(table.NamespaceDeclarationPrefixOf(a, 1)));
        Assert.AreEqual("urn:d", S(table.NamespaceDeclarationUriOf(a, 1)));

        Assert.AreEqual(0, table.NamespaceDeclarationCountOf(b));
        Assert.IsTrue(table.TryResolvePrefix(b, "p"u8, out ReadOnlySpan<byte> inherited));
        Assert.AreEqual("urn:1", S(inherited), "Ancestor declarations must be reconstructable at the descendant.");
        Assert.IsTrue(table.TryResolvePrefix(b, ""u8, out ReadOnlySpan<byte> inheritedDefault));
        Assert.AreEqual("urn:d", S(inheritedDefault));
        Assert.IsFalse(table.TryResolvePrefix(b, "q"u8, out _));
    }


    /// <summary>
    /// Proves the DOCTYPE prohibition at the parse surface with the refusal offset in original document
    /// coordinates: a document type declaration behind a UTF-8 byte order mark is refused at the offset
    /// of its <c>&lt;</c> in the input octets.
    /// </summary>
    [TestMethod]
    public void DoctypeRefusalOffsetIsInOriginalDocumentCoordinates()
    {
        byte[] document = [0xEF, 0xBB, 0xBF, .. "<!DOCTYPE a><a/>"u8];
        XmlReadError error = ParseExpectingRefusal(document, BaseMemoryPool.Shared);

        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, error.Failure);
        Assert.AreEqual(3L, error.ByteOffset);
    }


    /// <summary>
    /// Proves the pooled-buffer custody of the parse surface: every buffer rented for a successful parse
    /// is returned once the table is disposed, observed through the house pool's own rent and return
    /// counters.
    /// </summary>
    [TestMethod]
    public void SuccessfulParseAndDisposeReturnsEveryRentedBuffer()
    {
        using var metered = new MeteredHousePool();

        bool isAccepted = XmlNodeTable.TryParse(
            "<a xmlns:p=\"urn:1\"><b p:x=\"1\">text &amp; more<!--c--><?pi d?></b></a>"u8.ToArray(),
            metered.Pool,
            out XmlNodeTable? table,
            out XmlReadError error);
        Assert.IsTrue(isAccepted, $"Refused with {error.Failure} at {error.ByteOffset}.");
        Assert.IsGreaterThan(0L, metered.RentedCount, "The parse must rent from the supplied pool.");

        table!.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount, "Every rented buffer must be returned on dispose.");
    }


    /// <summary>
    /// Proves the pooled-buffer custody of the refusal path: a refused parse returns every rented buffer
    /// before <see cref="XmlNodeTable.TryParse"/> reports the refusal, for both a UTF-8 document and a
    /// UTF-16 document that rents a transcoding buffer.
    /// </summary>
    [TestMethod]
    public void RefusedParseReturnsEveryRentedBuffer()
    {
        using var metered = new MeteredHousePool();

        bool isAccepted = XmlNodeTable.TryParse("<a><b>&undeclared;</b></a>"u8.ToArray(), metered.Pool, out XmlNodeTable? table, out _);
        using(table)
        {
            Assert.IsFalse(isAccepted);
            Assert.IsNull(table);
            Assert.AreEqual(0L, metered.OutstandingCount, "A refusal must return every rented buffer.");
        }

        byte[] utf16Document = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("<a></b>")];
        bool isUtf16Accepted = XmlNodeTable.TryParse(utf16Document, metered.Pool, out XmlNodeTable? utf16Table, out _);
        using(utf16Table)
        {
            Assert.IsFalse(isUtf16Accepted);
            Assert.IsNull(utf16Table);
            Assert.AreEqual(0L, metered.OutstandingCount, "The transcoding buffer must be returned on refusal too.");
        }
    }


    /// <summary>
    /// Proves the table copies everything it exposes into its own pooled storage: the accessors stay
    /// valid after the caller's document octets are mutated, so the table's lifetime is independent of
    /// the input memory.
    /// </summary>
    [TestMethod]
    public void TableIsIndependentOfTheInputOctetsAfterParse()
    {
        byte[] document = "<a x=\"v\">t</a>"u8.ToArray();
        using var table = ParseAccepting(document, BaseMemoryPool.Shared);

        Array.Clear(document);
        int element = table.DocumentElementIndex;
        Assert.AreEqual("a", S(table.LocalNameOf(element)));
        Assert.AreEqual("v", S(table.AttributeValueOf(element, 0)));
        Assert.AreEqual("t", S(table.ValueOf(table.FirstChildOf(element))));
    }
}
