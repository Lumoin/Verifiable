using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Shared refusal assertions for the adversarial suites: every refused document must come back through
/// the result-shaped surface of <see cref="XmlNodeTable.TryParse"/> with the correct
/// <see cref="XmlReadFailure"/> and with every pooled buffer returned, observed through
/// <see cref="MeteredHousePool"/> accounting.
/// </summary>
internal static class XmlAdversarialParsing
{
    /// <summary>
    /// Parses octets that must be refused and proves the refusal path returned every rented buffer.
    /// </summary>
    /// <param name="documentOctets">The adversarial document octets.</param>
    /// <returns>The refusal for the caller's reason and offset assertions.</returns>
    public static XmlReadError ParseRefusedWithBalancedPool(byte[] documentOctets)
    {
        using var metered = new MeteredHousePool();
        bool isAccepted = XmlNodeTable.TryParse(documentOctets, metered.Pool, out XmlNodeTable? table, out XmlReadError error);
        table?.Dispose();
        Assert.IsFalse(isAccepted, "The document must be refused.");
        Assert.IsNull(table, "A refusal must not hand out a table.");
        Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned on the refusal path.");

        return error;
    }


    /// <summary>
    /// Parses octets truncated mid-structure and proves the refusal is
    /// <see cref="XmlReadFailure.UnexpectedEndOfDocument"/> reported at the end of the octets, with the
    /// pool balanced.
    /// </summary>
    /// <param name="documentOctets">The truncated document octets.</param>
    public static void AssertTruncationRefusal(byte[] documentOctets)
    {
        XmlReadError error = ParseRefusedWithBalancedPool(documentOctets);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, error.Failure);
        Assert.AreEqual((long)documentOctets.Length, error.ByteOffset, "A truncation refusal is determined at the end of the octets.");
    }
}


/// <summary>
/// Adversarial hardening tests for <see cref="XmlNodeTable.TryParse"/>: hostile documents — DOCTYPE
/// payloads, reference misuse, ill-formed encodings, truncations and forbidden markup sequences — are
/// refused through the result-shaped surface with the correct <see cref="XmlReadFailure"/> and a usable
/// byte offset, never a crash, a hang or a wrong acceptance, and every refusal path returns its pooled
/// buffers.
/// </summary>
[TestClass]
internal sealed class XmlReaderAdversarialTests
{
    /// <summary>
    /// Proves the DOCTYPE prohibition of this reading surface over
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8
    /// production [22] <c>prolog ::= XMLDecl? Misc* (doctypedecl Misc*)?</c>: a document type declaration
    /// in either prolog position — at the document start or after the XML declaration — is refused as
    /// <see cref="XmlReadFailure.DoctypeProhibited"/> at the offset of its <c>&lt;</c>.
    /// </summary>
    [TestMethod]
    public void DoctypeInEitherPrologPositionIsRefusedAtItsOffset()
    {
        XmlReadError atStart = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<!DOCTYPE a><a/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, atStart.Failure);
        Assert.AreEqual(0L, atStart.ByteOffset);

        const string AfterDeclaration = "<?xml version=\"1.0\"?><!DOCTYPE a><a/>";
        XmlReadError afterDeclaration = XmlAdversarialParsing.ParseRefusedWithBalancedPool(Encoding.UTF8.GetBytes(AfterDeclaration));
        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, afterDeclaration.Failure);
        Assert.AreEqual((long)AfterDeclaration.IndexOf("<!DOCTYPE", StringComparison.Ordinal), afterDeclaration.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3 production [43] <c>content ::= CharData? ((element | Reference | CDSect | PI | Comment)
    /// CharData?)*</c>, which admits no <c>doctypedecl</c> inside an element: a document type declaration
    /// in element content is doubly illegal and is refused as
    /// <see cref="XmlReadFailure.DoctypeProhibited"/>.
    /// </summary>
    [TestMethod]
    public void DoctypeInsideRootContentIsRefused()
    {
        const string Document = "<a><!DOCTYPE b></a>";
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(Encoding.UTF8.GetBytes(Document));

        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, error.Failure);
        Assert.AreEqual((long)Document.IndexOf("<!DOCTYPE", StringComparison.Ordinal), error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c> with section 2.8 production
    /// [27] <c>Misc ::= Comment | PI | S</c>, which admits no <c>doctypedecl</c> after the root element:
    /// the declaration is malformed there and is refused as
    /// <see cref="XmlReadFailure.DoctypeProhibited"/>.
    /// </summary>
    [TestMethod]
    public void DoctypeAfterRootElementIsRefused()
    {
        const string Document = "<a/><!DOCTYPE a>";
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(Encoding.UTF8.GetBytes(Document));

        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, error.Failure);
        Assert.AreEqual((long)Document.IndexOf("<!DOCTYPE", StringComparison.Ordinal), error.ByteOffset);
    }


    /// <summary>
    /// Proves against the classic billion-laughs payload of nested entity declarations (<see
    /// href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 4.2):
    /// the refusal is <see cref="XmlReadFailure.DoctypeProhibited"/> at the offset of the
    /// <c>&lt;!DOCTYPE</c> itself, before any entity machinery can engage, so no expansion ever happens.
    /// </summary>
    [TestMethod]
    public void BillionLaughsPayloadIsRefusedBeforeAnyExpansion()
    {
        var payload = new StringBuilder("<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">");
        for(int i = 2; i <= 9; ++i)
        {
            payload.Append(CultureInfo.InvariantCulture, $"<!ENTITY lol{i} \"");
            for(int j = 0; j < 10; ++j)
            {
                payload.Append(CultureInfo.InvariantCulture, $"&lol{i - 1};");
            }

            payload.Append("\">");
        }

        payload.Append("]><lolz>&lol9;</lolz>");
        string document = payload.ToString();
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(Encoding.UTF8.GetBytes(document));

        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, error.Failure);
        Assert.AreEqual((long)document.IndexOf("<!DOCTYPE", StringComparison.Ordinal), error.ByteOffset, "The refusal must precede every entity declaration.");
    }


    /// <summary>
    /// Proves against external-entity payloads: a <c>doctypedecl</c> per <see
    /// href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8
    /// production [28] <c>doctypedecl::= '&lt;!DOCTYPE' S Name (S ExternalID)? S? ('[' intSubset ']' S?)?
    /// '&gt;'</c> carrying a SYSTEM external entity is refused as <see
    /// cref="XmlReadFailure.DoctypeProhibited"/> at the declaration's own offset, before any identifier
    /// could be resolved.
    /// </summary>
    [TestMethod]
    public void ExternalEntityPayloadIsRefusedBeforeAnyResolution()
    {
        const string Document = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><r>&xxe;</r>";
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(Encoding.UTF8.GetBytes(Document));

        Assert.AreEqual(XmlReadFailure.DoctypeProhibited, error.Failure);
        Assert.AreEqual((long)Document.IndexOf("<!DOCTYPE", StringComparison.Ordinal), error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 well-formedness constraint Entity Declared: "In a document without any DTD ... the
    /// Name given in the entity reference MUST match that in an entity declaration ... except that
    /// well-formed documents need not declare any of the following entities: amp, lt, gt, apos, quot."
    /// With every DOCTYPE refused there is never a DTD, so an unknown entity reference is refused as
    /// <see cref="XmlReadFailure.UndeclaredEntity"/> in character data and in an attribute value alike.
    /// </summary>
    [TestMethod]
    public void EntityReferenceBeyondThePredefinedFiveIsRefusedInTextAndAttribute()
    {
        XmlReadError inText = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&unknown;</a>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.UndeclaredEntity, inText.Failure);
        Assert.AreEqual(3L, inText.ByteOffset, "The refusal locates the ampersand of the reference.");

        XmlReadError inAttribute = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a x=\"&unknown;\"/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.UndeclaredEntity, inAttribute.Failure);
        Assert.AreEqual(6L, inAttribute.ByteOffset, "The refusal locates the ampersand of the reference.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 production [68] <c>EntityRef ::= '&amp;' Name ';'</c> with section 2.4: "The ampersand
    /// character (&amp;) and the left angle bracket (&lt;) MUST NOT appear in their literal form, except
    /// when used as markup delimiters" — <c>&amp;amp</c> without its terminating semicolon and a bare
    /// <c>&amp;</c> match no <c>Reference</c> production and are refused as
    /// <see cref="XmlReadFailure.MalformedMarkup"/>, in character data and in an attribute value alike.
    /// </summary>
    [TestMethod]
    public void EntityReferenceWithoutTerminatingSemicolonIsRefused()
    {
        XmlReadError inText = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&amp</a>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, inText.Failure);
        Assert.AreEqual(3L, inText.ByteOffset);

        XmlReadError inAttribute = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a x=\"&amp\"/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, inAttribute.Failure);

        XmlReadError bareAmpersand = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&</a>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, bareAmpersand.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 well-formedness constraint Legal Character: "Characters referred to using character
    /// references MUST match the production for Char", whose section 2.2 production [2] excludes the
    /// surrogate block <c>[#xD800-#xDFFF]</c> — references to both ends of the block, hexadecimal and
    /// decimal, are refused as <see cref="XmlReadFailure.InvalidCharacterReference"/>.
    /// </summary>
    [TestMethod]
    public void CharacterReferenceIntoTheSurrogateBlockIsRefused()
    {
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#xD800;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#xDFFF;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#55296;</a>"u8.ToArray()).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 well-formedness constraint Legal Character over the lower bound of section 2.2
    /// production [2] <c>Char</c>, which starts at <c>#x9</c> and never includes <c>#x0</c>: references
    /// to U+0000 in decimal and hexadecimal are refused as
    /// <see cref="XmlReadFailure.InvalidCharacterReference"/>.
    /// </summary>
    [TestMethod]
    public void CharacterReferenceToZeroIsRefused()
    {
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#0;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#x0;</a>"u8.ToArray()).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.1 well-formedness constraint Legal Character over the upper bound of section 2.2
    /// production [2] <c>Char</c>, which ends at <c>#x10FFFF</c>: references one past the codespace and a
    /// digit run long enough to overflow a machine integer are both refused as
    /// <see cref="XmlReadFailure.InvalidCharacterReference"/> — the accumulator must saturate, never wrap
    /// around into an accepted code point.
    /// </summary>
    [TestMethod]
    public void CharacterReferenceBeyondTheCodespaceIsRefused()
    {
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#x110000;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#1114112;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#xFFFFFFFFFFFFFFFF41;</a>"u8.ToArray()).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.2 production [2] <c>Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] |
    /// [#x10000-#x10FFFF]</c>, under which the C0 controls other than tab, line feed and carriage return
    /// are excluded: character references to them are refused as
    /// <see cref="XmlReadFailure.InvalidCharacterReference"/> per the Legal Character well-formedness
    /// constraint of section 4.1.
    /// </summary>
    [TestMethod]
    public void CharacterReferenceToForbiddenControlIsRefused()
    {
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#x1;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#x8;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#xB;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#xC;</a>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.InvalidCharacterReference, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>&#x1F;</a>"u8.ToArray()).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3: "it is a fatal error if an entity encoded in UTF-8 contains any ill-formed code
    /// unit sequences, as defined in section 3.9 of Unicode" — overlong encodings (a two-byte and a
    /// three-byte encoding of <c>/</c>) are refused as <see cref="XmlReadFailure.IllFormedUtf8"/> at the
    /// offending offset, never decoded to the character they smuggle.
    /// </summary>
    [TestMethod]
    public void OverlongUtf8SequenceIsRefused()
    {
        byte[] twoByteOverlong = [.. "<a>"u8, 0xC0, 0xAF, .. "</a>"u8];
        XmlReadError twoByte = XmlAdversarialParsing.ParseRefusedWithBalancedPool(twoByteOverlong);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, twoByte.Failure);
        Assert.AreEqual(3L, twoByte.ByteOffset);

        byte[] threeByteOverlong = [.. "<a>"u8, 0xE0, 0x80, 0xAF, .. "</a>"u8];
        XmlReadError threeByte = XmlAdversarialParsing.ParseRefusedWithBalancedPool(threeByteOverlong);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, threeByte.Failure);
        Assert.AreEqual(3L, threeByte.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3's fatal-error rule for ill-formed UTF-8: a multibyte sequence cut short — mid-document
    /// by a following ASCII octet and at the end of the octets — is refused as
    /// <see cref="XmlReadFailure.IllFormedUtf8"/>, never completed or replaced.
    /// </summary>
    [TestMethod]
    public void TruncatedUtf8MultibyteSequenceIsRefused()
    {
        byte[] interior = [.. "<a>"u8, 0xE2, 0x82, .. "</a>"u8];
        XmlReadError interiorError = XmlAdversarialParsing.ParseRefusedWithBalancedPool(interior);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, interiorError.Failure);
        Assert.AreEqual(3L, interiorError.ByteOffset);

        byte[] atEnd = [.. "<a>"u8, 0xE2, 0x82];
        XmlReadError atEndError = XmlAdversarialParsing.ParseRefusedWithBalancedPool(atEnd);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, atEndError.Failure);
        Assert.AreEqual(3L, atEndError.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3's fatal-error rule for ill-formed UTF-8: a continuation octet with no lead octet
    /// before it is refused as <see cref="XmlReadFailure.IllFormedUtf8"/>.
    /// </summary>
    [TestMethod]
    public void LoneUtf8ContinuationByteIsRefused()
    {
        byte[] document = [.. "<a>"u8, 0x80, .. "</a>"u8];
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(document);

        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, error.Failure);
        Assert.AreEqual(3L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3's fatal-error rule for ill-formed UTF-8: lead octets outside every well-formed
    /// sequence — <c>0xF5</c>, beyond the last valid four-byte lead, and <c>0xFF</c>, never valid — are
    /// refused as <see cref="XmlReadFailure.IllFormedUtf8"/>.
    /// </summary>
    [TestMethod]
    public void InvalidUtf8LeadByteIsRefused()
    {
        byte[] beyondCodespaceLead = [.. "<a>"u8, 0xF5, 0x80, 0x80, 0x80, .. "</a>"u8];
        XmlReadError beyondLead = XmlAdversarialParsing.ParseRefusedWithBalancedPool(beyondCodespaceLead);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, beyondLead.Failure);
        Assert.AreEqual(3L, beyondLead.ByteOffset);

        byte[] neverValidLead = [.. "<a>"u8, 0xFF, .. "</a>"u8];
        XmlReadError neverValid = XmlAdversarialParsing.ParseRefusedWithBalancedPool(neverValidLead);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf8, neverValid.Failure);
        Assert.AreEqual(3L, neverValid.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3, under which the Byte Order Mark "is an encoding signature" that fixes the code unit
    /// byte order: octets whose actual order is the opposite of the mark's decode into code units that do
    /// not begin production [1] <c>document</c> — here <c>&lt;a/&gt;</c> byte-swapped into CJK-block
    /// characters — and are refused as <see cref="XmlReadFailure.MalformedMarkup"/> at offset zero, never
    /// re-guessed under the other byte order and accepted.
    /// </summary>
    [TestMethod]
    public void Utf16ContentMismatchedWithItsByteOrderMarkIsRefused()
    {
        byte[] littleEndianMarkBigEndianContent = [0xFF, 0xFE, .. Encoding.BigEndianUnicode.GetBytes("<a/>")];
        XmlReadError littleEndianMark = XmlAdversarialParsing.ParseRefusedWithBalancedPool(littleEndianMarkBigEndianContent);
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, littleEndianMark.Failure);
        Assert.AreEqual(0L, littleEndianMark.ByteOffset);

        byte[] bigEndianMarkLittleEndianContent = [0xFE, 0xFF, .. Encoding.Unicode.GetBytes("<a/>")];
        XmlReadError bigEndianMark = XmlAdversarialParsing.ParseRefusedWithBalancedPool(bigEndianMarkLittleEndianContent);
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, bigEndianMark.Failure);
        Assert.AreEqual(0L, bigEndianMark.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3's fatal-error rule applied to UTF-16: an odd trailing octet that completes no code
    /// unit and a high surrogate whose low surrogate the octets end before are refused as
    /// <see cref="XmlReadFailure.IllFormedUtf16"/> at the offset of the incomplete unit in the input
    /// octets.
    /// </summary>
    [TestMethod]
    public void TruncatedUtf16CodeUnitOrSurrogatePairIsRefused()
    {
        byte[] oddTrailingOctet = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("<a/>"), 0x41];
        XmlReadError oddOctet = XmlAdversarialParsing.ParseRefusedWithBalancedPool(oddTrailingOctet);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf16, oddOctet.Failure);
        Assert.AreEqual(10L, oddOctet.ByteOffset);

        byte[] highSurrogateAtEnd = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("<a>"), 0x00, 0xD8];
        XmlReadError highSurrogate = XmlAdversarialParsing.ParseRefusedWithBalancedPool(highSurrogateAtEnd);
        Assert.AreEqual(XmlReadFailure.IllFormedUtf16, highSurrogate.Failure);
        Assert.AreEqual(8L, highSurrogate.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c> at the tag-open boundary class:
    /// octets ending at a bare <c>&lt;</c> and inside a tag name never complete the production and are
    /// refused as <see cref="XmlReadFailure.UnexpectedEndOfDocument"/>.
    /// </summary>
    [TestMethod]
    public void TruncationInsideTagNameIsRefused()
    {
        XmlAdversarialParsing.AssertTruncationRefusal("<"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a"u8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 production [41] <c>Attribute ::= Name Eq AttValue</c> at the attribute boundary class:
    /// octets ending inside the attribute name, after <c>Eq</c> with no value, and inside the quoted
    /// value are refused as <see cref="XmlReadFailure.UnexpectedEndOfDocument"/>.
    /// </summary>
    [TestMethod]
    public void TruncationInsideAttributeIsRefused()
    {
        XmlAdversarialParsing.AssertTruncationRefusal("<a x"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a x="u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a x=\"v"u8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 production [40] <c>STag ::= '&lt;' Name (S Attribute)* S? '&gt;'</c> at the
    /// between-attributes boundary class: octets ending in the white space after a complete attribute,
    /// before the tag closes, are refused as <see cref="XmlReadFailure.UnexpectedEndOfDocument"/>.
    /// </summary>
    [TestMethod]
    public void TruncationBetweenAttributesIsRefused()
    {
        XmlAdversarialParsing.AssertTruncationRefusal("<a x=\"1\" "u8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.7 production [18] <c>CDSect ::= CDStart CData CDEnd</c> at the CDATA boundary class:
    /// octets ending inside section content before <c>]]&gt;</c> and inside the <c>&lt;![CDATA[</c>
    /// marker itself are refused as <see cref="XmlReadFailure.UnexpectedEndOfDocument"/>.
    /// </summary>
    [TestMethod]
    public void TruncationInsideCDataSectionIsRefused()
    {
        XmlAdversarialParsing.AssertTruncationRefusal("<a><![CDATA[x"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a><![CD"u8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.5 production [15] <c>Comment</c> at the comment boundary class: octets ending inside
    /// comment content, on a pending double hyphen before <c>&gt;</c>, at a bare <c>&lt;!</c>, and inside
    /// a <c>&lt;!DOCTYP</c> candidate are all refused as
    /// <see cref="XmlReadFailure.UnexpectedEndOfDocument"/>.
    /// </summary>
    [TestMethod]
    public void TruncationInsideCommentIsRefused()
    {
        XmlAdversarialParsing.AssertTruncationRefusal("<a><!--x"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a><!--x--"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<!"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<!DOCTYP"u8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.6 production [16] <c>PI</c> and section 2.8 production [23] <c>XMLDecl</c> at the
    /// processing instruction boundary class: octets ending inside instruction content before
    /// <c>?&gt;</c> and inside the XML declaration are refused as
    /// <see cref="XmlReadFailure.UnexpectedEndOfDocument"/>.
    /// </summary>
    [TestMethod]
    public void TruncationInsideProcessingInstructionIsRefused()
    {
        XmlAdversarialParsing.AssertTruncationRefusal("<a><?p d"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<?xml version=\"1.0\""u8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c> at the root-close boundary
    /// class: octets ending with the root still open — directly after its start-tag, after character
    /// data, after a closed child, and inside its end-tag — are refused as
    /// <see cref="XmlReadFailure.UnexpectedEndOfDocument"/>.
    /// </summary>
    [TestMethod]
    public void TruncationBeforeRootCloseIsRefused()
    {
        XmlAdversarialParsing.AssertTruncationRefusal("<a>"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a>text"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a><b></b>"u8.ToArray());
        XmlAdversarialParsing.AssertTruncationRefusal("<a></a"u8.ToArray());
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.5: "For compatibility, the string \"--\" (double-hyphen) MUST NOT occur within
    /// comments", and "Note that the grammar does not allow a comment ending in ---&gt;." An interior
    /// double hyphen inside and outside the root and a comment ending in three hyphens are refused as
    /// <see cref="XmlReadFailure.MalformedMarkup"/> at the offending hyphen pair.
    /// </summary>
    [TestMethod]
    public void DoubleHyphenInsideCommentIsRefusedAtItsOffset()
    {
        XmlReadError insideRoot = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a><!--x--y--></a>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, insideRoot.Failure);
        Assert.AreEqual(8L, insideRoot.ByteOffset);

        XmlReadError threeHyphenEnd = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a><!--x---></a>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, threeHyphenEnd.Failure);
        Assert.AreEqual(8L, threeHyphenEnd.ByteOffset);

        XmlReadError inProlog = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<!-- -- --><a/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, inProlog.Failure);
        Assert.AreEqual(5L, inProlog.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.4 production [14] <c>CharData ::= [^&lt;&amp;]* - ([^&lt;&amp;]* ']]&gt;'
    /// [^&lt;&amp;]*)</c> and its compatibility rule: the right angle bracket "MUST, for compatibility,
    /// be escaped using \"&amp;gt;\" or a character reference when it appears in the string \"]]&gt;\" in
    /// content, when that string is not marking the end of a CDATA section." Literal <c>]]&gt;</c> in
    /// character data is refused as <see cref="XmlReadFailure.MalformedMarkup"/>; the escaped form
    /// <c>]]&amp;gt;</c> is accepted and yields the text <c>]]&gt;</c>, whose escaping on the way back
    /// out is the canonicalizer's concern.
    /// </summary>
    [TestMethod]
    public void CDataCloseDelimiterInCharacterDataIsRefusedAndEscapedFormIsAccepted()
    {
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a>x]]>y</a>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, error.Failure);
        Assert.AreEqual(4L, error.ByteOffset);

        using var metered = new MeteredHousePool();
        bool isAccepted = XmlNodeTable.TryParse("<a>]]&gt;</a>"u8.ToArray(), metered.Pool, out XmlNodeTable? table, out XmlReadError escapedError);
        Assert.IsTrue(isAccepted, $"The escaped form must be accepted but was refused with {escapedError.Failure} at {escapedError.ByteOffset}.");
        Assert.AreEqual("]]>", Encoding.UTF8.GetString(table!.ValueOf(table.FirstChildOf(table.DocumentElementIndex))));
        table.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 3.1 well-formedness constraint Unique Att Spec: "An attribute name MUST NOT appear more
    /// than once in the same start-tag or empty-element tag" — the literal duplicate is refused as
    /// <see cref="XmlReadFailure.DuplicateAttribute"/> at the offset of the later specification.
    /// </summary>
    [TestMethod]
    public void LiteralDuplicateAttributeIsRefusedAtTheLaterSpecification()
    {
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a x=\"1\" x=\"2\"/>"u8.ToArray());

        Assert.AreEqual(XmlReadFailure.DuplicateAttribute, error.Failure);
        Assert.AreEqual(9L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 6.3 namespace constraint Attributes Unique: no tag may contain two
    /// attributes that "have qualified names with the same local part and with prefixes which have been
    /// bound to namespace names that are identical" — <c>p:a</c> and <c>q:a</c> with both prefixes bound
    /// to the same namespace name are refused as <see cref="XmlReadFailure.DuplicateAttribute"/> even
    /// though their literal names differ.
    /// </summary>
    [TestMethod]
    public void NamespaceExpandedDuplicateAttributeIsRefused()
    {
        const string Document = "<r xmlns:p=\"urn:same\" xmlns:q=\"urn:same\"><e p:a=\"1\" q:a=\"2\"/></r>";
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(Encoding.UTF8.GetBytes(Document));

        Assert.AreEqual(XmlReadFailure.DuplicateAttribute, error.Failure);
        Assert.AreEqual((long)Document.IndexOf("q:a", StringComparison.Ordinal), error.ByteOffset);
    }
}
