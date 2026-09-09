using System.Globalization;
using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Adversarial hardening tests for <see cref="XmlNodeTable.TryParse"/> over namespace abuse, document
/// structure violations, degenerate inputs and resource-bound payloads: refusal with the correct <see
/// cref="XmlReadFailure"/> and a usable byte offset — or acceptance with the correctly parsed shape under
/// bounded pooled memory — never a crash, a hang or a wrong acceptance. Pooled-buffer custody is proven on
/// every path through <see cref="MeteredHousePool"/> accounting. The throughput characterisation of the
/// resource-bound payloads — whether parsing and duplicate detection stay linear rather than quadratic —
/// lives in <c>Verifiable.Benchmarks</c>'s <c>XmlReaderAdversarialLimitsBenchmarks</c>.
/// </summary>
[TestClass]
internal sealed class XmlReaderAdversarialLimitsTests
{
    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3 namespace constraint Reserved Prefixes and Namespace Names: "The prefix
    /// xmlns is used only to declare namespace bindings ... It MUST NOT be declared" — the declaration
    /// <c>xmlns:xmlns</c> is refused as <see cref="XmlReadFailure.ReservedPrefixMisuse"/>.
    /// </summary>
    [TestMethod]
    public void XmlnsPrefixDeclarationIsRefused()
    {
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns:xmlns=\"urn:x\"/>"u8.ToArray());

        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, error.Failure);
        Assert.AreEqual(3L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3 namespace constraint Reserved Prefixes and Namespace Names: the prefix
    /// <c>xml</c> "MUST NOT be bound to any other namespace name" than
    /// <c>http://www.w3.org/XML/1998/namespace</c> — rebinding it is refused as
    /// <see cref="XmlReadFailure.ReservedPrefixMisuse"/>.
    /// </summary>
    [TestMethod]
    public void XmlPrefixReboundToAnotherNamespaceNameIsRefused()
    {
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns:xml=\"urn:not-the-xml-namespace\"/>"u8.ToArray());

        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, error.Failure);
        Assert.AreEqual(3L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 3 namespace constraint Reserved Prefixes and Namespace Names for the xml
    /// namespace name: "Other prefixes MUST NOT be bound to this namespace name, and it MUST NOT be
    /// declared as the default namespace" — both bindings are refused as
    /// <see cref="XmlReadFailure.ReservedPrefixMisuse"/>.
    /// </summary>
    [TestMethod]
    public void XmlNamespaceNameBoundToAnotherPrefixOrAsDefaultIsRefused()
    {
        XmlReadError otherPrefix = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns:p=\"http://www.w3.org/XML/1998/namespace\"/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, otherPrefix.Failure);

        XmlReadError asDefault = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns=\"http://www.w3.org/XML/1998/namespace\"/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.ReservedPrefixMisuse, asDefault.Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 5 namespace constraint No Prefix Undeclaring: "In a namespace declaration
    /// for a prefix (i.e., where the NSAttName is a PrefixedAttName), the attribute value MUST NOT be
    /// empty." The empty prefixed declaration is refused as
    /// <see cref="XmlReadFailure.PrefixUndeclarationProhibited"/> — distinct from the relative-URI
    /// refusal, and distinct from <c>xmlns=""</c>, which lawfully un-declares the default namespace.
    /// </summary>
    [TestMethod]
    public void EmptyPrefixedNamespaceDeclarationIsRefused()
    {
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns:p=\"\"/>"u8.ToArray());

        Assert.AreEqual(XmlReadFailure.PrefixUndeclarationProhibited, error.Failure);
        Assert.AreEqual(3L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
    /// section 2.1: "implementations of XML canonicalization MUST report an operation failure on
    /// documents containing relative namespace URIs", with relativity discriminated syntactically per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">IETF RFC 3986 section 4.2</see> — a
    /// reference without a scheme is relative. A bare path, the dot-segment forms, a fragment-only
    /// reference and a scheme-less network-path reference are all refused as
    /// <see cref="XmlReadFailure.RelativeNamespaceUri"/>.
    /// </summary>
    [TestMethod]
    public void RelativeNamespaceUriShapesAreRefused()
    {
        Assert.AreEqual(XmlReadFailure.RelativeNamespaceUri, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns=\"relative/path\"/>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.RelativeNamespaceUri, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns:p=\"./x\"/>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.RelativeNamespaceUri, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns:p=\"../x\"/>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.RelativeNamespaceUri, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns=\"#frag\"/>"u8.ToArray()).Failure);
        Assert.AreEqual(XmlReadFailure.RelativeNamespaceUri, XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a xmlns:p=\"//example.com/x\"/>"u8.ToArray()).Failure);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1: "There is exactly one element, called the root, or document element, no part of which
    /// appears in the content of any other element." A second top-level element — after an empty-element
    /// root and after a start/end pair — is refused as
    /// <see cref="XmlReadFailure.MultipleRootElements"/> at the second root's <c>&lt;</c>.
    /// </summary>
    [TestMethod]
    public void SecondRootElementIsRefusedAtItsOffset()
    {
        XmlReadError afterEmptyElement = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a/><b/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MultipleRootElements, afterEmptyElement.Failure);
        Assert.AreEqual(4L, afterEmptyElement.ByteOffset);

        XmlReadError afterStartEndPair = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a></a><b></b>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MultipleRootElements, afterStartEndPair.Failure);
        Assert.AreEqual(7L, afterStartEndPair.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c> with section 2.8 production
    /// [27] <c>Misc ::= Comment | PI | S</c>: outside the document element only white space, comments and
    /// processing instructions may appear, so character data before or after the root is refused as
    /// <see cref="XmlReadFailure.MalformedMarkup"/> at the offending octet.
    /// </summary>
    [TestMethod]
    public void CharacterDataOutsideTheRootElementIsRefused()
    {
        XmlReadError before = XmlAdversarialParsing.ParseRefusedWithBalancedPool("x<a/>"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, before.Failure);
        Assert.AreEqual(0L, before.ByteOffset);

        XmlReadError after = XmlAdversarialParsing.ParseRefusedWithBalancedPool("<a/>x"u8.ToArray());
        Assert.AreEqual(XmlReadFailure.MalformedMarkup, after.Failure);
        Assert.AreEqual(4L, after.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c>, which requires the element:
    /// zero octets contain no document element and are refused as
    /// <see cref="XmlReadFailure.UnexpectedEndOfDocument"/> at offset zero.
    /// </summary>
    [TestMethod]
    public void EmptyInputIsRefused()
    {
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool([]);

        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, error.Failure);
        Assert.AreEqual(0L, error.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c> over inputs that are a byte
    /// order mark and nothing else: the mark is an artifact of encoding, so the document behind it is
    /// empty and refused as <see cref="XmlReadFailure.UnexpectedEndOfDocument"/> — for UTF-8 at the
    /// offset after the mark, for UTF-16 at offset zero of the empty once-transcoded form.
    /// </summary>
    [TestMethod]
    public void ByteOrderMarkOnlyInputIsRefused()
    {
        byte[] utf8MarkOnly = [0xEF, 0xBB, 0xBF];
        XmlReadError utf8Error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(utf8MarkOnly);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, utf8Error.Failure);
        Assert.AreEqual(3L, utf8Error.ByteOffset);

        byte[] utf16LittleEndianMarkOnly = [0xFF, 0xFE];
        XmlReadError littleEndianError = XmlAdversarialParsing.ParseRefusedWithBalancedPool(utf16LittleEndianMarkOnly);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, littleEndianError.Failure);
        Assert.AreEqual(0L, littleEndianError.ByteOffset);

        byte[] utf16BigEndianMarkOnly = [0xFE, 0xFF];
        XmlReadError bigEndianError = XmlAdversarialParsing.ParseRefusedWithBalancedPool(utf16BigEndianMarkOnly);
        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, bigEndianError.Failure);
        Assert.AreEqual(0L, bigEndianError.ByteOffset);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.1 production [1] <c>document ::= prolog element Misc*</c>: white space alone is a valid
    /// prolog but no document element ever appears, so the input is refused as
    /// <see cref="XmlReadFailure.UnexpectedEndOfDocument"/> at its end.
    /// </summary>
    [TestMethod]
    public void WhitespaceOnlyInputIsRefused()
    {
        byte[] document = "  \t\r\n"u8.ToArray();
        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(document);

        Assert.AreEqual(XmlReadFailure.UnexpectedEndOfDocument, error.Failure);
        Assert.AreEqual((long)document.Length, error.ByteOffset);
    }


    /// <summary>
    /// Proves at the parse surface: the documented bound <see cref="XmlSpanReader.MaximumElementDepth"/>
    /// (1024) is exact — nesting at the bound is accepted with the pool balanced after disposal, and
    /// nesting one deeper (1025) is refused as <see cref="XmlReadFailure.DepthLimitExceeded"/> at the
    /// over-limit start-tag with the pool balanced on the refusal path, never a stack overflow, because
    /// parsing is iterative.
    /// </summary>
    [TestMethod]
    public void DepthAtTheDocumentedLimitIsAcceptedAndOneDeeperIsRefused()
    {
        static byte[] BuildNested(int depthCount)
        {
            var builder = new StringBuilder(depthCount * 8);
            for(int i = 0; i < depthCount; ++i)
            {
                builder.Append("<d>");
            }

            for(int i = 0; i < depthCount; ++i)
            {
                builder.Append("</d>");
            }

            return Encoding.UTF8.GetBytes(builder.ToString());
        }

        using var metered = new MeteredHousePool();
        bool isAccepted = XmlNodeTable.TryParse(BuildNested(XmlSpanReader.MaximumElementDepth), metered.Pool, out XmlNodeTable? table, out XmlReadError acceptedError);
        Assert.IsTrue(isAccepted, $"Nesting at the documented limit must be accepted but was refused with {acceptedError.Failure} at {acceptedError.ByteOffset}.");
        table!.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned after disposal.");

        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(BuildNested(XmlSpanReader.MaximumElementDepth + 1));
        Assert.AreEqual(XmlReadFailure.DepthLimitExceeded, error.Failure);
        Assert.AreEqual(3L * XmlSpanReader.MaximumElementDepth, error.ByteOffset, "The refusal locates the start-tag that would exceed the limit.");
    }


    /// <summary>
    /// Proves for oversized attribute values: a single eight-mebibyte attribute value parses to the
    /// correct length, with every buffer rented from the caller's pool and returned on disposal. The
    /// throughput characterisation of this shape lives in <c>Verifiable.Benchmarks</c>'s
    /// <c>XmlReaderAdversarialLimitsBenchmarks.EightMebibyteAttributeValueParses</c>.
    /// </summary>
    [TestMethod]
    public void EightMebibyteAttributeValueParsesWithPooledCustody()
    {
        const int ValueLength = 8 * 1024 * 1024;
        byte[] prefix = "<a x=\""u8.ToArray();
        byte[] suffix = "\"/>"u8.ToArray();
        byte[] document = new byte[prefix.Length + ValueLength + suffix.Length];
        prefix.CopyTo(document, 0);
        document.AsSpan(prefix.Length, ValueLength).Fill((byte)'v');
        suffix.CopyTo(document, prefix.Length + ValueLength);

        using var metered = new MeteredHousePool();
        bool isAccepted = XmlNodeTable.TryParse(document, metered.Pool, out XmlNodeTable? table, out XmlReadError error);

        Assert.IsTrue(isAccepted, $"The oversized attribute value must parse but was refused with {error.Failure} at {error.ByteOffset}.");
        int parsedValueLength = table!.AttributeValueOf(table.DocumentElementIndex, 0).Length;
        Assert.AreEqual(ValueLength, parsedValueLength);
        Assert.IsGreaterThan(0L, metered.RentedCount, "Parsing must rent from the supplied pool.");
        table.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned after disposal.");
    }


    /// <summary>
    /// Proves for oversized names: an element whose name is eight mebibytes of name characters parses to
    /// the correct length, with every buffer rented from the caller's pool and returned on disposal. The
    /// throughput characterisation of this shape lives in <c>Verifiable.Benchmarks</c>'s
    /// <c>XmlReaderAdversarialLimitsBenchmarks.EightMebibyteElementNameParses</c>.
    /// </summary>
    [TestMethod]
    public void EightMebibyteElementNameParsesWithPooledCustody()
    {
        const int NameLength = 8 * 1024 * 1024;
        byte[] document = new byte[1 + NameLength + 2];
        document[0] = (byte)'<';
        document.AsSpan(1, NameLength).Fill((byte)'n');
        document[1 + NameLength] = (byte)'/';
        document[2 + NameLength] = (byte)'>';

        using var metered = new MeteredHousePool();
        bool isAccepted = XmlNodeTable.TryParse(document, metered.Pool, out XmlNodeTable? table, out XmlReadError error);

        Assert.IsTrue(isAccepted, $"The oversized element name must parse but was refused with {error.Failure} at {error.ByteOffset}.");
        int parsedNameLength = table!.LocalNameOf(table.DocumentElementIndex).Length;
        Assert.AreEqual(NameLength, parsedNameLength);
        table.Dispose();
        Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned after disposal.");
    }


    /// <summary>
    /// Proves for adversarial attribute counts: a start-tag carrying twenty thousand attributes whose
    /// duplicate sits last is refused as <see cref="XmlReadFailure.DuplicateAttribute"/> per the Unique
    /// Att Spec well-formedness constraint of <see
    /// href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1, with
    /// the pool balanced on the refusal path. The throughput characterisation of duplicate detection —
    /// whether it stays near-linear rather than quadratic in the attribute count — lives in
    /// <c>Verifiable.Benchmarks</c>'s
    /// <c>XmlReaderAdversarialLimitsBenchmarks.TwentyThousandAttributesWithTrailingDuplicateAreRefused</c>.
    /// </summary>
    [TestMethod]
    public void TwentyThousandAttributesWithTrailingDuplicateAreRefused()
    {
        const int AttributeCount = 20_000;
        var builder = new StringBuilder(AttributeCount * 16);
        builder.Append("<a");
        for(int i = 0; i < AttributeCount; ++i)
        {
            builder.Append(CultureInfo.InvariantCulture, $" a{i}=\"v\"");
        }

        builder.Append(" a0=\"duplicate\"/>");

        XmlReadError error = XmlAdversarialParsing.ParseRefusedWithBalancedPool(Encoding.UTF8.GetBytes(builder.ToString()));

        Assert.AreEqual(XmlReadFailure.DuplicateAttribute, error.Failure);
    }
}
