using System.Collections.Generic;
using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Conformance tests for <see cref="XmlSpanReader"/>, the forward-only UTF-8 tokenizer: acceptance and
/// refusal per the productions and well-formedness constraints of
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">Extensible Markup Language (XML) 1.0 (Fifth
/// Edition)</see> and the name syntax of
/// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
/// Edition)</see>.
/// </summary>
[TestClass]
internal sealed class XmlSpanReaderTests
{
    /// <summary>
    /// One token lifted out of the reader's ref struct world for list-based assertions.
    /// </summary>
    private sealed record TokenSnapshot(XmlTokenKind Kind, string Name, string Value, long ByteOffset);


    private static List<TokenSnapshot> ReadAll(ReadOnlySpan<byte> document, out bool hasFailed, out XmlReadError error)
    {
        var reader = new XmlSpanReader(document);
        var tokens = new List<TokenSnapshot>();
        while(reader.TryRead(out XmlToken token))
        {
            tokens.Add(new TokenSnapshot(token.Kind, Encoding.UTF8.GetString(token.Name), Encoding.UTF8.GetString(token.Value), token.ByteOffset));
        }

        hasFailed = reader.HasFailed;
        error = reader.Error;

        return tokens;
    }


    private static XmlReadError ReadExpectingRefusal(ReadOnlySpan<byte> document)
    {
        _ = ReadAll(document, out bool hasFailed, out XmlReadError error);
        Assert.IsTrue(hasFailed, "The reader must refuse this document.");

        return error;
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 productions [40] <c>STag ::= '&lt;' Name (S Attribute)* S? '&gt;'</c>,
    /// [41] <c>Attribute ::= Name Eq AttValue</c>, [42] <c>ETag ::= '&lt;/' Name S? '&gt;'</c> and
    /// section 3 production [43] <c>content</c>: a start-tag with an attribute, character data and an
    /// end-tag tokenize in document order with their names and raw values.
    /// </summary>
    [TestMethod]
    public void StartTagAttributeTextAndEndTagTokenize()
    {
        List<TokenSnapshot> tokens = ReadAll("<a x=\"1\">t</a>"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.HasCount(5, tokens);
        Assert.AreEqual(XmlTokenKind.ElementStart, tokens[0].Kind);
        Assert.AreEqual("a", tokens[0].Name);
        Assert.AreEqual(XmlTokenKind.Attribute, tokens[1].Kind);
        Assert.AreEqual("x", tokens[1].Name);
        Assert.AreEqual("1", tokens[1].Value);
        Assert.AreEqual(XmlTokenKind.ElementStartClose, tokens[2].Kind);
        Assert.AreEqual(XmlTokenKind.Text, tokens[3].Kind);
        Assert.AreEqual("t", tokens[3].Value);
        Assert.AreEqual(XmlTokenKind.ElementEnd, tokens[4].Kind);
        Assert.AreEqual("a", tokens[4].Name);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 production [44] <c>EmptyElemTag ::= '&lt;' Name (S Attribute)* S? '/&gt;'</c>: an
    /// empty-element tag closes with its own token kind instead of a start-tag close.
    /// </summary>
    [TestMethod]
    public void EmptyElementTagYieldsEmptyClose()
    {
        List<TokenSnapshot> tokens = ReadAll("<a/>"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.HasCount(2, tokens);
        Assert.AreEqual(XmlTokenKind.ElementStart, tokens[0].Kind);
        Assert.AreEqual(XmlTokenKind.ElementEmptyClose, tokens[1].Kind);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.8 production [23] <c>XMLDecl ::= '&lt;?xml' VersionInfo EncodingDecl? SDDecl? S? '?&gt;'</c>:
    /// a declaration at the very start of the document tokenizes as <see cref="XmlTokenKind.XmlDeclaration"/>
    /// and the reader captures the declared encoding name.
    /// </summary>
    [TestMethod]
    public void XmlDeclarationAtDocumentStartTokenizesAndCapturesEncoding()
    {
        var reader = new XmlSpanReader("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><a/>"u8);

        Assert.IsTrue(reader.TryRead(out XmlToken token));
        Assert.AreEqual(XmlTokenKind.XmlDeclaration, token.Kind);
        Assert.AreEqual("UTF-8", Encoding.UTF8.GetString(reader.DeclaredEncoding));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.8 production [24] <c>VersionInfo ::= S 'version' Eq (...)</c>, which makes the version
    /// information mandatory in the XML declaration: a declaration carrying only an encoding is refused.
    /// </summary>
    [TestMethod]
    public void XmlDeclarationWithoutVersionIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<?xml encoding=\"UTF-8\"?><a/>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.8 production [26] <c>VersionNum ::= '1.' [0-9]+</c>: a version number outside the
    /// <c>1.x</c> family is refused.
    /// </summary>
    [TestMethod]
    public void XmlDeclarationVersionOutsideOnePointFamilyIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<?xml version=\"2.0\"?><a/>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.9 production [32] <c>SDDecl ::= S 'standalone' Eq (("'" ('yes' | 'no') "'") | ...)</c>:
    /// a standalone value other than <c>yes</c> or <c>no</c> is refused.
    /// </summary>
    [TestMethod]
    public void XmlDeclarationStandaloneOutsideYesNoIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<?xml version=\"1.0\" standalone=\"maybe\"?><a/>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.8, under which the XML declaration may appear only at the very beginning of the document:
    /// after leading white space, <c>&lt;?xml</c> can only be a processing instruction whose target is
    /// reserved by section 2.6 production [17] <c>PITarget ::= Name - (('X' | 'x') ('M' | 'm')
    /// ('L' | 'l'))</c>, so it is refused.
    /// </summary>
    [TestMethod]
    public void XmlDeclarationAfterLeadingWhitespaceIsRefusedAsReservedTarget()
    {
        XmlReadError error = ReadExpectingRefusal(" <?xml version=\"1.0\"?><a/>"u8);

        Assert.AreEqual(XmlReadFailure.InvalidName, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.5: "For compatibility, the string \"--\" (double-hyphen) MUST NOT occur within
    /// comments."
    /// </summary>
    [TestMethod]
    public void DoubleHyphenInsideCommentIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a><!-- x -- y --></a>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.5: "Note that the grammar does not allow a comment ending in <c>---&gt;</c>." The
    /// spec's own non-well-formed example <c>&lt;!-- B+, B, or B---&gt;</c> is refused.
    /// </summary>
    [TestMethod]
    public void CommentEndingInThreeHyphensIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a><!-- B+, B, or B---></a>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.5 production [15]: a comment's content between <c>&lt;!--</c> and <c>--&gt;</c> is
    /// delivered, single hyphens included, matching <c>((Char - '-') | ('-' (Char - '-')))*</c>.
    /// </summary>
    [TestMethod]
    public void CommentContentIsDeliveredRaw()
    {
        List<TokenSnapshot> tokens = ReadAll("<a><!-- declarations for <head> & <body> --></a>"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.AreEqual(XmlTokenKind.Comment, tokens[2].Kind);
        Assert.AreEqual(" declarations for <head> & <body> ", tokens[2].Value);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.7: "Within a CDATA section, only the CDEnd string is recognized as markup, so that left
    /// angle brackets and ampersands may occur in their literal form". The spec's own example content
    /// <c>&lt;greeting&gt;Hello, world!&lt;/greeting&gt;</c> is delivered raw.
    /// </summary>
    [TestMethod]
    public void CDataSectionContentIsDeliveredRaw()
    {
        List<TokenSnapshot> tokens = ReadAll("<a><![CDATA[<greeting>Hello, world!</greeting>]]></a>"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.AreEqual(XmlTokenKind.CDataSection, tokens[2].Kind);
        Assert.AreEqual("<greeting>Hello, world!</greeting>", tokens[2].Value);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.6 production [16] <c>PI ::= '&lt;?' PITarget (S (Char* - (Char* '?&gt;' Char*)))?
    /// '?&gt;'</c>: target and instruction content are delivered separately, and a PI with no content
    /// carries an empty value.
    /// </summary>
    [TestMethod]
    public void ProcessingInstructionSplitsTargetAndContent()
    {
        List<TokenSnapshot> tokens = ReadAll("<a><?target data here?><?empty?></a>"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.AreEqual(XmlTokenKind.ProcessingInstruction, tokens[2].Kind);
        Assert.AreEqual("target", tokens[2].Name);
        Assert.AreEqual("data here", tokens[2].Value);
        Assert.AreEqual(XmlTokenKind.ProcessingInstruction, tokens[3].Kind);
        Assert.AreEqual("empty", tokens[3].Name);
        Assert.AreEqual("", tokens[3].Value);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.6 production [17] <c>PITarget ::= Name - (('X' | 'x') ('M' | 'm') ('L' | 'l'))</c>: "The
    /// target names \"XML\", \"xml\", and so on are reserved for standardization". A PI targeting
    /// <c>xml</c> in any case combination outside the document start is refused.
    /// </summary>
    [TestMethod]
    public void ProcessingInstructionWithReservedTargetIsRefused()
    {
        XmlReadError lowerError = ReadExpectingRefusal("<a><?xml data?></a>"u8);
        XmlReadError upperError = ReadExpectingRefusal("<a><?XML data?></a>"u8);

        Assert.AreEqual(XmlReadFailure.InvalidName, lowerError.Failure);
        Assert.AreEqual(XmlReadFailure.InvalidName, upperError.Failure);
    }


    /// <summary>
    /// Proves the DOCTYPE prohibition of this reading surface over
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8
    /// production [28] <c>doctypedecl</c>: any document type declaration is refused outright with the
    /// offset of its <c>&lt;</c>, closing the entity-expansion and external-entity attack classes.
    /// </summary>
    [TestMethod]
    public void DoctypeIsRefusedAtItsOffset()
    {
        XmlReadError error = ReadExpectingRefusal("<!DOCTYPE greeting SYSTEM \"hello.dtd\"><greeting>Hello, world!</greeting>"u8);

        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, error.Failure);
        Assert.AreEqual(0L, error.ByteOffset);
    }


    /// <summary>
    /// Proves the DOCTYPE prohibition also refuses an internal-subset billion-laughs payload, the attack
    /// class <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.2 entity declarations enable, before any entity machinery can engage.
    /// </summary>
    [TestMethod]
    public void DoctypeWithInternalSubsetEntitiesIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;\">]><lolz>&lol2;</lolz>"u8);

        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c> with section 2.8 production
    /// [27] <c>Misc ::= Comment | PI | S</c>: white space outside the document element tokenizes as
    /// <see cref="XmlTokenKind.WhitespaceOutsideRoot"/>, while other character data there is refused.
    /// </summary>
    [TestMethod]
    public void WhitespaceOutsideRootTokenizesAndOtherContentThereIsRefused()
    {
        List<TokenSnapshot> tokens = ReadAll("  <a/>\r\n"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.AreEqual(XmlTokenKind.WhitespaceOutsideRoot, tokens[0].Kind);
        Assert.AreEqual(XmlTokenKind.WhitespaceOutsideRoot, tokens[^1].Kind);

        XmlReadError error = ReadExpectingRefusal("<a/>text"u8);
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1: "There is exactly one element, called the root, or document element, no part of which
    /// appears in the content of any other element." A second top-level element is refused.
    /// </summary>
    [TestMethod]
    public void SecondRootElementIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a/><b/>"u8);

        Assert.AreEqual(XmlReadFailure.MultipleRootElements, error.Failure);
        Assert.AreEqual(4L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.4: the right angle bracket "MUST, for compatibility, be escaped using \"&amp;gt;\" or a
    /// character reference when it appears in the string \"]]&gt;\" in content, when that string is not
    /// marking the end of a CDATA section." A literal <c>]]&gt;</c> in character data is refused.
    /// </summary>
    [TestMethod]
    public void CDataSectionCloseInCharacterDataIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a>x]]>y</a>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.3 production [10] <c>AttValue ::= '"' ([^&lt;&amp;"] | Reference)* '"'</c>, which
    /// excludes a literal <c>&lt;</c> from attribute values: section 2.4 states the left angle bracket
    /// "MUST NOT appear in their literal form" outside markup.
    /// </summary>
    [TestMethod]
    public void LessThanInAttributeValueIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a x=\"<\"/>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 production [40] <c>STag ::= '&lt;' Name (S Attribute)* S? '&gt;'</c>: every attribute
    /// must be preceded by white space, so two attribute specifications with none between them are
    /// refused.
    /// </summary>
    [TestMethod]
    public void AttributeWithoutPrecedingWhitespaceIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a x=\"1\"y=\"2\"/>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 production [41] <c>Attribute ::= Name Eq AttValue</c> with section 2.3 production
    /// [10]: an attribute without an equals sign, and an unquoted attribute value, are both refused.
    /// </summary>
    [TestMethod]
    public void AttributeWithoutEqualsOrQuotesIsRefused()
    {
        XmlReadError missingEquals = ReadExpectingRefusal("<a x \"1\"/>"u8);
        XmlReadError unquoted = ReadExpectingRefusal("<a x=1/>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, missingEquals.Failure);
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, unquoted.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.3 productions [4] <c>NameStartChar</c> and [5] <c>Name ::= NameStartChar
    /// (NameChar)*</c>: "Disallowed initial characters for Names include digits, diacritics, the full
    /// stop and the hyphen." An element name starting with a digit is refused.
    /// </summary>
    [TestMethod]
    public void NameStartingWithDigitIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<1a/>"u8);

        Assert.AreEqual(XmlReadFailure.InvalidName, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 4 productions [7]-[11], under which a qualified name is
    /// <c>Prefix ':' LocalPart</c> with both sides <c>NCName</c>: names with two colons, a leading colon
    /// or a trailing colon are refused.
    /// </summary>
    [TestMethod]
    public void ColonMisplacementInQualifiedNameIsRefused()
    {
        XmlReadError doubleColon = ReadExpectingRefusal("<a:b:c/>"u8);
        XmlReadError leadingColon = ReadExpectingRefusal("<:a/>"u8);
        XmlReadError trailingColon = ReadExpectingRefusal("<a:/>"u8);

        Assert.AreEqual(XmlReadFailure.InvalidName, doubleColon.Failure);
        Assert.AreEqual(XmlReadFailure.InvalidName, leadingColon.Failure);
        Assert.AreEqual(XmlReadFailure.InvalidName, trailingColon.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c>: documents whose octets end
    /// inside a tag, inside a comment, inside a CDATA section, inside an attribute value, before the root
    /// element closes, or before any root element appears, are all refused as ending unexpectedly.
    /// </summary>
    [TestMethod]
    public void TruncationAtEveryStructuralBoundaryIsRefused()
    {
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<a"u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<a "u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<a x=\"1"u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<a><!-- x"u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<a><![CDATA[x"u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<a>text"u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<a></a"u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal("<?pi?>"u8).Failure);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, ReadExpectingRefusal(""u8).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1: elements "delimited by start- and end-tags, nest properly within each other" — an
    /// end-tag with no open element violates the <c>content</c> production and is refused.
    /// </summary>
    [TestMethod]
    public void EndTagWithoutOpenElementIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a/></a>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }


    /// <summary>
    /// Proves the documented depth bound of this reading surface: nesting at
    /// <see cref="XmlSpanReader.MaximumElementDepth"/> (1024) elements is accepted and one level deeper is
    /// refused as <see cref="XmlReadFailure.DepthLimitExceeded"/> — a refusal, not a crash, hang or stack
    /// overflow, because the reader is iterative.
    /// </summary>
    [TestMethod]
    public void DepthLimitAcceptsFullDepthAndRefusesOneDeeper()
    {
        static byte[] BuildNested(int depthCount)
        {
            var builder = new StringBuilder();
            for(int i = 0; i < depthCount; ++i)
            {
                builder.Append("<e>");
            }

            for(int i = 0; i < depthCount; ++i)
            {
                builder.Append("</e>");
            }

            return Encoding.UTF8.GetBytes(builder.ToString());
        }

        _ = ReadAll(BuildNested(XmlSpanReader.MaximumElementDepth), out bool hasFailedAtLimit, out _);
        Assert.IsFalse(hasFailedAtLimit, "Nesting exactly at the documented limit must be accepted.");

        _ = ReadAll(BuildNested(XmlSpanReader.MaximumElementDepth + 1), out bool hasFailedOverLimit, out XmlReadError error);
        Assert.IsTrue(hasFailedOverLimit);
        Assert.AreEqual(XmlReadFailure.DepthLimitExceeded, error.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3: "it is a fatal error if an entity encoded in UTF-8 contains any ill-formed code
    /// unit sequences" — an ill-formed sequence where the reader decodes a name is refused, never
    /// substituted with a replacement character.
    /// </summary>
    [TestMethod]
    public void IllFormedUtf8InNameIsRefused()
    {
        byte[] document = [(byte)'<', 0xFF, (byte)'a', (byte)'/', (byte)'>'];
        XmlReadError error = ReadExpectingRefusal(document);

        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, error.Failure);
    }


    /// <summary>
    /// Proves the byte offset tracking of the reader: token offsets locate each token's first octet in
    /// the input, the position refusals are reported against per the result-shaped surface of
    /// <see cref="XmlReadError"/>.
    /// </summary>
    [TestMethod]
    public void TokenByteOffsetsLocateTokensInTheInput()
    {
        List<TokenSnapshot> tokens = ReadAll("<a x=\"1\">t</a>"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.AreEqual(0L, tokens[0].ByteOffset);
        Assert.AreEqual(3L, tokens[1].ByteOffset);
        Assert.AreEqual(8L, tokens[2].ByteOffset);
        Assert.AreEqual(9L, tokens[3].ByteOffset);
        Assert.AreEqual(10L, tokens[4].ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.10: "An XML processor MUST always pass all characters in a document that are not markup
    /// through to the application" — white space between elements inside the root is character data, not
    /// discardable markup.
    /// </summary>
    [TestMethod]
    public void WhitespaceInsideRootIsTextNotDiscarded()
    {
        List<TokenSnapshot> tokens = ReadAll("<a> <b/> </a>"u8, out bool hasFailed, out _);

        Assert.IsFalse(hasFailed);
        Assert.AreEqual(XmlTokenKind.Text, tokens[2].Kind);
        Assert.AreEqual(" ", tokens[2].Value);
        Assert.AreEqual(XmlTokenKind.Text, tokens[5].Kind);
        Assert.AreEqual(" ", tokens[5].Value);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] with section 2.8 production [27] <c>Misc ::= Comment | PI | S</c>:
    /// a CDATA section is not <c>Misc</c>, so it is refused outside the document element.
    /// </summary>
    [TestMethod]
    public void CDataSectionOutsideRootIsRefused()
    {
        XmlReadError error = ReadExpectingRefusal("<a/><![CDATA[x]]>"u8);

        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
    }
}
