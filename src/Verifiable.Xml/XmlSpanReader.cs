using System.Buffers;
using System.Text;

namespace Verifiable.Xml;

/// <summary>
/// A forward-only tokenizer over a UTF-8 XML document held in a <see cref="ReadOnlySpan{T}"/> of bytes,
/// implementing the document grammar of
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">Extensible Markup Language (XML) 1.0 (Fifth
/// Edition)</see> with the name syntax of
/// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third Edition)</see>,
/// with no platform XML dependency.
/// </summary>
/// <remarks>
/// <para>
/// The reader is iterative, never recursive, and tracks element depth with the single documented limit
/// <see cref="MaximumElementDepth"/> of 1024: a document nesting elements deeper is refused with
/// <see cref="XmlReadFailure.DepthLimitExceeded"/> instead of risking stack or memory exhaustion. Any
/// document type declaration is refused with <see cref="XmlReadFailure.DoctypeProhibited"/>, closing the
/// entity-expansion and external-entity attack classes at this layer.
/// </para>
/// <para>
/// Tokens carry raw octets: character and entity references are not resolved and the line-end
/// normalization of section 2.11 and attribute-value normalization of section 3.3.3 are not applied here —
/// <see cref="XmlNodeTable"/> performs them when it builds the document table. The reader decodes octets
/// only where the grammar requires character classification (names and the structures around them); it
/// presumes the span is well-formed UTF-8 whose characters match production <c>Char</c> of section 2.2, as
/// established by the <see cref="XmlNodeTable.TryParse"/> front end. Ill-formed sequences encountered
/// where the reader does decode are refused with <see cref="XmlReadFailure.IllFormedUtf8"/>, never
/// replaced.
/// </para>
/// <para>
/// Reading is result-shaped: <see cref="TryRead"/> returns <see langword="false"/> at the end of the
/// document or on a refusal, and <see cref="HasFailed"/> with <see cref="Error"/> distinguishes the two.
/// </para>
/// </remarks>
public ref struct XmlSpanReader
{
    /// <summary>
    /// The maximum element nesting depth the reader accepts. Deeper nesting is refused with
    /// <see cref="XmlReadFailure.DepthLimitExceeded"/>.
    /// </summary>
    public const int MaximumElementDepth = 1024;

    /// <summary>The UTF-8 document octets being tokenized.</summary>
    private readonly ReadOnlySpan<byte> document;

    /// <summary>The offset added to every reported byte position.</summary>
    private readonly long baseByteOffset;

    /// <summary>The current position in <see cref="document"/>.</summary>
    private int position;

    /// <summary>The current element nesting depth.</summary>
    private int depth;

    /// <summary>Whether the reader is between an element-start token and its closing token.</summary>
    private bool isInsideStartTag;

    /// <summary>Whether the root element has been closed.</summary>
    private bool hasClosedRootElement;

    /// <summary>Whether a refusal has been recorded.</summary>
    private bool hasFailed;

    /// <summary>Whether the document has been read to a well-formed end.</summary>
    private bool hasCompleted;

    /// <summary>The recorded refusal.</summary>
    private XmlReadError error;

    /// <summary>The position of the <c>&lt;</c> of the start-tag currently being read.</summary>
    private int currentStartTagPosition;

    /// <summary>The position of the declared encoding name in the XML declaration.</summary>
    private int declaredEncodingPosition;

    /// <summary>The length of the declared encoding name in the XML declaration.</summary>
    private int declaredEncodingLength;


    /// <summary>
    /// Creates a reader over UTF-8 document octets.
    /// </summary>
    /// <param name="utf8Document">The document octets, without a byte order mark.</param>
    public XmlSpanReader(ReadOnlySpan<byte> utf8Document): this(utf8Document, 0)
    {
    }


    /// <summary>
    /// Creates a reader over UTF-8 document octets with a base added to every reported byte offset, so a
    /// caller that stripped a byte order mark can keep refusal offsets in original document coordinates.
    /// </summary>
    /// <param name="utf8Document">The document octets, without a byte order mark.</param>
    /// <param name="baseByteOffset">The offset added to every reported byte position.</param>
    public XmlSpanReader(ReadOnlySpan<byte> utf8Document, long baseByteOffset)
    {
        document = utf8Document;
        this.baseByteOffset = baseByteOffset;
    }


    /// <summary>
    /// The current read position in the coordinate space the reader was constructed with.
    /// </summary>
    public readonly long BytePosition => baseByteOffset + position;

    /// <summary>
    /// The current element nesting depth.
    /// </summary>
    public readonly int Depth => depth;

    /// <summary>
    /// Whether reading stopped on a refusal; <see cref="Error"/> then carries the reason and offset.
    /// </summary>
    public readonly bool HasFailed => hasFailed;

    /// <summary>
    /// The refusal that stopped reading, when <see cref="HasFailed"/> is set.
    /// </summary>
    public readonly XmlReadError Error => error;

    /// <summary>
    /// The encoding name declared in the XML declaration, or empty when the document declares none. Set
    /// once the <see cref="XmlTokenKind.XmlDeclaration"/> token has been produced.
    /// </summary>
    public readonly ReadOnlySpan<byte> DeclaredEncoding => declaredEncodingLength == 0
        ? default
        : document.Slice(declaredEncodingPosition, declaredEncodingLength);

    /// <summary>
    /// The byte offset of the declared encoding name, in the coordinate space the reader was constructed
    /// with.
    /// </summary>
    public readonly long DeclaredEncodingByteOffset => baseByteOffset + declaredEncodingPosition;


    /// <summary>
    /// Reads the next token.
    /// </summary>
    /// <param name="token">The token read.</param>
    /// <returns>
    /// <see langword="true"/> when a token was produced; <see langword="false"/> at the well-formed end of
    /// the document or on a refusal, distinguished by <see cref="HasFailed"/>.
    /// </returns>
    public bool TryRead(out XmlToken token)
    {
        token = default;
        if(hasFailed || hasCompleted)
        {
            return false;
        }

        if(isInsideStartTag)
        {
            return TryReadInsideStartTag(out token);
        }

        if(position >= document.Length)
        {
            if(depth > 0 || !hasClosedRootElement)
            {
                return Refuse(XmlReadFailure.UnexpectedEndOfDocument, position);
            }

            hasCompleted = true;

            return false;
        }

        if(document[position] == (byte)'<')
        {
            return TryReadMarkup(out token);
        }

        return depth > 0 ? TryReadText(out token) : TryReadWhitespaceOutsideRoot(out token);
    }


    /// <summary>
    /// Records a refusal and stops the reader.
    /// </summary>
    /// <param name="failure">The refusal reason.</param>
    /// <param name="refusalPosition">The position the refusal was determined at.</param>
    /// <returns>Always <see langword="false"/>.</returns>
    private bool Refuse(XmlReadFailure failure, int refusalPosition)
    {
        hasFailed = true;
        error = new XmlReadError(failure, baseByteOffset + refusalPosition);

        return false;
    }


    /// <summary>
    /// Reads a run of character data inside the document element, stopping at markup. The run is raw:
    /// references stay unresolved. The forbidden <c>]]&gt;</c> sequence of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.4
    /// production <c>CharData</c> is refused.
    /// </summary>
    /// <param name="token">The text token.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadText(out XmlToken token)
    {
        token = default;
        int start = position;
        while(position < document.Length)
        {
            byte current = document[position];
            if(current == (byte)'<')
            {
                break;
            }

            if(current == (byte)']' && document[position..].StartsWith("]]>"u8))
            {
                return Refuse(XmlReadFailure.MalformedMarkup, position);
            }

            position++;
        }

        token = new XmlToken(XmlTokenKind.Text, default, document[start..position], baseByteOffset + start, baseByteOffset + start);

        return true;
    }


    /// <summary>
    /// Reads white space outside the document element, the only character data the <c>Misc</c> production
    /// of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 2.8 permits there; anything else is refused.
    /// </summary>
    /// <param name="token">The white space token.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadWhitespaceOutsideRoot(out XmlToken token)
    {
        token = default;
        int start = position;
        while(position < document.Length && XmlCharacters.IsWhitespace(document[position]))
        {
            position++;
        }

        if(position == start)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        token = new XmlToken(XmlTokenKind.WhitespaceOutsideRoot, default, document[start..position], baseByteOffset + start, baseByteOffset + start);

        return true;
    }


    /// <summary>
    /// Dispatches on the markup at the current <c>&lt;</c>.
    /// </summary>
    /// <param name="token">The token read.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadMarkup(out XmlToken token)
    {
        token = default;
        int markupStart = position;
        if(position + 1 >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        byte discriminator = document[position + 1];

        return discriminator switch
        {
            (byte)'/' => TryReadEndTag(markupStart, out token),
            (byte)'!' => TryReadBangMarkup(markupStart, out token),
            (byte)'?' => TryReadProcessingInstructionOrDeclaration(markupStart, out token),
            _ => TryReadStartTag(markupStart, out token)
        };
    }


    /// <summary>
    /// Reads an end-tag per production <c>ETag</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1:
    /// <c>'&lt;/' Name S? '&gt;'</c>.
    /// </summary>
    /// <param name="markupStart">The position of the <c>&lt;</c>.</param>
    /// <param name="token">The end-tag token.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadEndTag(int markupStart, out XmlToken token)
    {
        token = default;
        if(depth == 0)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, markupStart);
        }

        position = markupStart + 2;
        if(!TryScanName(isColonAllowed: true, out int nameStart, out int nameLength))
        {
            return false;
        }

        while(position < document.Length && XmlCharacters.IsWhitespace(document[position]))
        {
            position++;
        }

        if(position >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        if(document[position] != (byte)'>')
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        position++;
        depth--;
        if(depth == 0)
        {
            hasClosedRootElement = true;
        }

        token = new XmlToken(XmlTokenKind.ElementEnd, document.Slice(nameStart, nameLength), default, baseByteOffset + markupStart, baseByteOffset + markupStart);

        return true;
    }


    /// <summary>
    /// Reads markup beginning <c>&lt;!</c>: a comment, a CDATA section, or the refused document type
    /// declaration per the DOCTYPE prohibition of this reading surface.
    /// </summary>
    /// <param name="markupStart">The position of the <c>&lt;</c>.</param>
    /// <param name="token">The token read.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadBangMarkup(int markupStart, out XmlToken token)
    {
        token = default;
        ReadOnlySpan<byte> rest = document[markupStart..];
        if(rest.StartsWith("<!--"u8))
        {
            return TryReadComment(markupStart, out token);
        }

        if(rest.StartsWith("<![CDATA["u8))
        {
            if(depth == 0)
            {
                return Refuse(XmlReadFailure.MalformedMarkup, markupStart);
            }

            return TryReadCDataSection(markupStart, out token);
        }

        if(rest.StartsWith("<!DOCTYPE"u8))
        {
            return Refuse(XmlReadFailure.DoctypeProhibited, markupStart);
        }

        bool isTruncatedCandidate = "<!--"u8.StartsWith(rest) || "<![CDATA["u8.StartsWith(rest) || "<!DOCTYPE"u8.StartsWith(rest);
        if(isTruncatedCandidate)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        return Refuse(XmlReadFailure.MalformedMarkup, markupStart);
    }


    /// <summary>
    /// Reads a comment per production <c>Comment</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.5,
    /// refusing the forbidden interior <c>--</c>: the production admits <c>((Char - '-') | ('-' (Char -
    /// '-')))*</c>, so a double hyphen may appear only as part of the closing <c>--&gt;</c>.
    /// </summary>
    /// <param name="markupStart">The position of the <c>&lt;</c>.</param>
    /// <param name="token">The comment token.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadComment(int markupStart, out XmlToken token)
    {
        token = default;
        int contentStart = markupStart + 4;
        int i = contentStart;
        while(true)
        {
            if(i + 1 >= document.Length)
            {
                return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
            }

            if(document[i] == (byte)'-' && document[i + 1] == (byte)'-')
            {
                if(i + 2 >= document.Length)
                {
                    return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
                }

                if(document[i + 2] != (byte)'>')
                {
                    return Refuse(XmlReadFailure.MalformedMarkup, i);
                }

                break;
            }

            i++;
        }

        token = new XmlToken(XmlTokenKind.Comment, default, document[contentStart..i], baseByteOffset + markupStart, baseByteOffset + contentStart);
        position = i + 3;

        return true;
    }


    /// <summary>
    /// Reads a CDATA section per production <c>CDSect</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.7.
    /// </summary>
    /// <param name="markupStart">The position of the <c>&lt;</c>.</param>
    /// <param name="token">The CDATA token carrying the raw section content.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadCDataSection(int markupStart, out XmlToken token)
    {
        token = default;
        int contentStart = markupStart + 9;
        int endIndex = document[contentStart..].IndexOf("]]>"u8);
        if(endIndex < 0)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        token = new XmlToken(XmlTokenKind.CDataSection, default, document.Slice(contentStart, endIndex), baseByteOffset + markupStart, baseByteOffset + contentStart);
        position = contentStart + endIndex + 3;

        return true;
    }


    /// <summary>
    /// Reads a processing instruction per production <c>PI</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.6,
    /// or the XML declaration when the document begins with <c>&lt;?xml</c> per section 2.8. A target
    /// matching <c>(('X'|'x')('M'|'m')('L'|'l'))</c> anywhere else is reserved by production
    /// <c>PITarget</c> and refused; a target containing a colon violates the NCName requirement of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> section 7 and is refused.
    /// </summary>
    /// <param name="markupStart">The position of the <c>&lt;</c>.</param>
    /// <param name="token">The token read.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadProcessingInstructionOrDeclaration(int markupStart, out XmlToken token)
    {
        token = default;
        bool isDeclarationPosition = markupStart == 0
            && document.Length >= 6
            && document[..5].SequenceEqual("<?xml"u8)
            && (XmlCharacters.IsWhitespace(document[5]) || document[5] == (byte)'?');
        if(isDeclarationPosition)
        {
            return TryReadXmlDeclaration(out token);
        }

        position = markupStart + 2;
        if(!TryScanName(isColonAllowed: false, out int targetStart, out int targetLength))
        {
            return false;
        }

        bool isReservedTarget = targetLength == 3
            && (document[targetStart] is (byte)'x' or (byte)'X')
            && (document[targetStart + 1] is (byte)'m' or (byte)'M')
            && (document[targetStart + 2] is (byte)'l' or (byte)'L');
        if(isReservedTarget)
        {
            return Refuse(XmlReadFailure.InvalidName, targetStart);
        }

        if(position >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        if(document[position..].StartsWith("?>"u8))
        {
            token = new XmlToken(XmlTokenKind.ProcessingInstruction, document.Slice(targetStart, targetLength), default, baseByteOffset + markupStart, baseByteOffset + position);
            position += 2;

            return true;
        }

        if(!XmlCharacters.IsWhitespace(document[position]))
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        while(position < document.Length && XmlCharacters.IsWhitespace(document[position]))
        {
            position++;
        }

        int dataStart = position;
        int endIndex = document[dataStart..].IndexOf("?>"u8);
        if(endIndex < 0)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        token = new XmlToken(XmlTokenKind.ProcessingInstruction, document.Slice(targetStart, targetLength), document.Slice(dataStart, endIndex), baseByteOffset + markupStart, baseByteOffset + dataStart);
        position = dataStart + endIndex + 2;

        return true;
    }


    /// <summary>
    /// Reads the XML declaration per productions <c>XMLDecl</c>, <c>VersionInfo</c>, <c>Eq</c> and
    /// <c>VersionNum</c> of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth
    /// Edition)</see> section 2.8, <c>EncodingDecl</c> and <c>EncName</c> of section 4.3.3 and
    /// <c>SDDecl</c> of section 2.9.
    /// </summary>
    /// <param name="token">The declaration token; its value spans the declaration's interior.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadXmlDeclaration(out XmlToken token)
    {
        token = default;
        int contentStart = 5;
        position = 5;
        if(!TrySkipDeclarationWhitespace(out int leadingWhitespace))
        {
            return false;
        }

        if(leadingWhitespace == 0)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        if(!TryMatchLiteral("version"u8) || !TrySkipEq())
        {
            return hasFailed ? false : Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        if(!TryReadQuotedVersionNumber())
        {
            return false;
        }

        if(!TrySkipDeclarationWhitespace(out int whitespaceAfterVersion))
        {
            return false;
        }

        if(document[position..].StartsWith("?>"u8))
        {
            return CompleteXmlDeclaration(contentStart, out token);
        }

        if(whitespaceAfterVersion == 0)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        if(TryPeekLiteral("encoding"u8))
        {
            if(!TryMatchLiteral("encoding"u8) || !TrySkipEq() || !TryReadQuotedEncodingName())
            {
                return hasFailed ? false : Refuse(XmlReadFailure.MalformedMarkup, position);
            }

            if(!TrySkipDeclarationWhitespace(out int whitespaceAfterEncoding))
            {
                return false;
            }

            if(document[position..].StartsWith("?>"u8))
            {
                return CompleteXmlDeclaration(contentStart, out token);
            }

            if(whitespaceAfterEncoding == 0)
            {
                return Refuse(XmlReadFailure.MalformedMarkup, position);
            }
        }

        if(!TryMatchLiteral("standalone"u8) || !TrySkipEq() || !TryReadQuotedStandaloneValue())
        {
            return hasFailed ? false : Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        if(!TrySkipDeclarationWhitespace(out _))
        {
            return false;
        }

        if(!document[position..].StartsWith("?>"u8))
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        return CompleteXmlDeclaration(contentStart, out token);
    }


    /// <summary>
    /// Produces the XML declaration token once <c>?&gt;</c> has been reached.
    /// </summary>
    /// <param name="contentStart">The position after <c>&lt;?xml</c>.</param>
    /// <param name="token">The declaration token.</param>
    /// <returns>Always <see langword="true"/>.</returns>
    private bool CompleteXmlDeclaration(int contentStart, out XmlToken token)
    {
        token = new XmlToken(XmlTokenKind.XmlDeclaration, default, document[contentStart..position], baseByteOffset, baseByteOffset + contentStart);
        position += 2;

        return true;
    }


    /// <summary>
    /// Skips white space inside the XML declaration, refusing a declaration truncated by the end of the
    /// document.
    /// </summary>
    /// <param name="skippedCount">The number of white space octets skipped.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TrySkipDeclarationWhitespace(out int skippedCount)
    {
        skippedCount = 0;
        while(position < document.Length && XmlCharacters.IsWhitespace(document[position]))
        {
            position++;
            skippedCount++;
        }

        if(position >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        return true;
    }


    /// <summary>
    /// Tells whether the octets at the current position begin with the literal, without consuming.
    /// </summary>
    /// <param name="literal">The literal to test.</param>
    /// <returns><see langword="true"/> when the literal is next.</returns>
    private readonly bool TryPeekLiteral(ReadOnlySpan<byte> literal)
    {
        return document[position..].StartsWith(literal);
    }


    /// <summary>
    /// Consumes the literal at the current position.
    /// </summary>
    /// <param name="literal">The literal to consume.</param>
    /// <returns><see langword="false"/> when the literal is not next; no refusal is recorded.</returns>
    private bool TryMatchLiteral(ReadOnlySpan<byte> literal)
    {
        if(!document[position..].StartsWith(literal))
        {
            return false;
        }

        position += literal.Length;

        return true;
    }


    /// <summary>
    /// Consumes <c>S? '=' S?</c> per production <c>Eq</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8.
    /// </summary>
    /// <returns><see langword="false"/> when there is no equals sign; no refusal is recorded.</returns>
    private bool TrySkipEq()
    {
        while(position < document.Length && XmlCharacters.IsWhitespace(document[position]))
        {
            position++;
        }

        if(position >= document.Length || document[position] != (byte)'=')
        {
            return false;
        }

        position++;
        while(position < document.Length && XmlCharacters.IsWhitespace(document[position]))
        {
            position++;
        }

        return true;
    }


    /// <summary>
    /// Reads the quoted version number per production <c>VersionNum</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.8:
    /// <c>'1.' [0-9]+</c>.
    /// </summary>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryReadQuotedVersionNumber()
    {
        if(!TryReadQuoteCharacter(out byte quote))
        {
            return false;
        }

        if(position + 1 >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        if(document[position] != (byte)'1' || document[position + 1] != (byte)'.')
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        position += 2;
        int digitCount = 0;
        while(position < document.Length && document[position] >= (byte)'0' && document[position] <= (byte)'9')
        {
            position++;
            digitCount++;
        }

        if(digitCount == 0)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        return TryReadClosingQuote(quote);
    }


    /// <summary>
    /// Reads the quoted encoding name per production <c>EncName</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see>
    /// section 4.3.3: <c>[A-Za-z] ([A-Za-z0-9._] | '-')*</c>, recording its position for the encoding
    /// consistency check of the parse front end.
    /// </summary>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryReadQuotedEncodingName()
    {
        if(!TryReadQuoteCharacter(out byte quote))
        {
            return false;
        }

        int nameStart = position;
        while(position < document.Length)
        {
            byte current = document[position];
            bool isFirst = position == nameStart;
            bool isLetter = (current >= (byte)'A' && current <= (byte)'Z') || (current >= (byte)'a' && current <= (byte)'z');
            bool isFollowCharacter = isLetter
                || (current >= (byte)'0' && current <= (byte)'9')
                || current is (byte)'.' or (byte)'_' or (byte)'-';
            if(isFirst ? !isLetter : !isFollowCharacter)
            {
                break;
            }

            position++;
        }

        if(position == nameStart)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        declaredEncodingPosition = nameStart;
        declaredEncodingLength = position - nameStart;

        return TryReadClosingQuote(quote);
    }


    /// <summary>
    /// Reads the quoted standalone value per production <c>SDDecl</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.9:
    /// <c>'yes' | 'no'</c>.
    /// </summary>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryReadQuotedStandaloneValue()
    {
        if(!TryReadQuoteCharacter(out byte quote))
        {
            return false;
        }

        if(!TryMatchLiteral("yes"u8) && !TryMatchLiteral("no"u8))
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        return TryReadClosingQuote(quote);
    }


    /// <summary>
    /// Reads an opening quote character, either <c>"</c> or <c>'</c>.
    /// </summary>
    /// <param name="quote">The quote character read.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryReadQuoteCharacter(out byte quote)
    {
        quote = 0;
        if(position >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        quote = document[position];
        if(quote != (byte)'"' && quote != (byte)'\'')
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        position++;

        return true;
    }


    /// <summary>
    /// Reads the closing quote matching an opening quote.
    /// </summary>
    /// <param name="quote">The quote character that opened the literal.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryReadClosingQuote(byte quote)
    {
        if(position >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        if(document[position] != quote)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        position++;

        return true;
    }


    /// <summary>
    /// Reads the opening of a start-tag or empty-element tag per productions <c>STag</c> and
    /// <c>EmptyElemTag</c> of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth
    /// Edition)</see> section 3.1, refusing a second root element per the <c>document</c> production of
    /// section 2.1, which permits exactly one.
    /// </summary>
    /// <param name="markupStart">The position of the <c>&lt;</c>.</param>
    /// <param name="token">The element-start token.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadStartTag(int markupStart, out XmlToken token)
    {
        token = default;
        if(depth == 0 && hasClosedRootElement)
        {
            return Refuse(XmlReadFailure.MultipleRootElements, markupStart);
        }

        position = markupStart + 1;
        if(!TryScanName(isColonAllowed: true, out int nameStart, out int nameLength))
        {
            return false;
        }

        isInsideStartTag = true;
        currentStartTagPosition = markupStart;
        token = new XmlToken(XmlTokenKind.ElementStart, document.Slice(nameStart, nameLength), default, baseByteOffset + markupStart, baseByteOffset + markupStart);

        return true;
    }


    /// <summary>
    /// Reads the next attribute or the closing of the current start-tag. The grammar
    /// <c>'&lt;' Name (S Attribute)* S? ('&gt;' | '/&gt;')</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 3.1
    /// requires white space before every attribute; an attribute value is read raw between its quotes,
    /// refusing a literal <c>&lt;</c> per production <c>AttValue</c>. The element depth limit
    /// <see cref="MaximumElementDepth"/> is enforced when a start-tag closes with content.
    /// </summary>
    /// <param name="token">The attribute or tag-closing token.</param>
    /// <returns><see langword="true"/> when a token was produced.</returns>
    private bool TryReadInsideStartTag(out XmlToken token)
    {
        token = default;
        int whitespaceCount = 0;
        while(position < document.Length && XmlCharacters.IsWhitespace(document[position]))
        {
            position++;
            whitespaceCount++;
        }

        if(position >= document.Length)
        {
            return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
        }

        byte current = document[position];
        if(current == (byte)'>')
        {
            if(depth == MaximumElementDepth)
            {
                return Refuse(XmlReadFailure.DepthLimitExceeded, currentStartTagPosition);
            }

            int closePosition = position;
            position++;
            depth++;
            isInsideStartTag = false;
            token = new XmlToken(XmlTokenKind.ElementStartClose, default, default, baseByteOffset + closePosition, baseByteOffset + closePosition);

            return true;
        }

        if(current == (byte)'/')
        {
            if(position + 1 >= document.Length)
            {
                return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
            }

            if(document[position + 1] != (byte)'>')
            {
                return Refuse(XmlReadFailure.MalformedMarkup, position + 1);
            }

            int closePosition = position;
            position += 2;
            isInsideStartTag = false;
            if(depth == 0)
            {
                hasClosedRootElement = true;
            }

            token = new XmlToken(XmlTokenKind.ElementEmptyClose, default, default, baseByteOffset + closePosition, baseByteOffset + closePosition);

            return true;
        }

        if(whitespaceCount == 0)
        {
            return Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        int attributeStart = position;
        if(!TryScanName(isColonAllowed: true, out int nameStart, out int nameLength))
        {
            return false;
        }

        if(!TrySkipEq())
        {
            return position >= document.Length
                ? Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length)
                : Refuse(XmlReadFailure.MalformedMarkup, position);
        }

        if(!TryReadQuoteCharacter(out byte quote))
        {
            return false;
        }

        int valueStart = position;
        while(true)
        {
            if(position >= document.Length)
            {
                return Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length);
            }

            byte valueOctet = document[position];
            if(valueOctet == quote)
            {
                break;
            }

            if(valueOctet == (byte)'<')
            {
                return Refuse(XmlReadFailure.MalformedMarkup, position);
            }

            position++;
        }

        token = new XmlToken(XmlTokenKind.Attribute, document.Slice(nameStart, nameLength), document[valueStart..position], baseByteOffset + attributeStart, baseByteOffset + valueStart);
        position++;

        return true;
    }


    /// <summary>
    /// Scans a name at the current position per productions <c>Name</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3
    /// and <c>QName</c>/<c>NCName</c> of
    /// <see href="https://www.w3.org/TR/2009/REC-xml-names-20091208/">Namespaces in XML 1.0 (Third
    /// Edition)</see> sections 3 and 4: when a colon is allowed, at most one may appear and both sides must
    /// be non-empty <c>NCName</c>s.
    /// </summary>
    /// <param name="isColonAllowed">Whether one colon separating prefix and local part is admitted.</param>
    /// <param name="nameStart">The position the name starts at.</param>
    /// <param name="nameLength">The length of the name in octets.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    private bool TryScanName(bool isColonAllowed, out int nameStart, out int nameLength)
    {
        nameStart = position;
        nameLength = 0;
        bool isExpectingStartCharacter = true;
        bool hasSeenColon = false;
        while(position < document.Length)
        {
            byte octet = document[position];
            if(octet == (byte)':')
            {
                if(!isColonAllowed || hasSeenColon || isExpectingStartCharacter)
                {
                    return Refuse(XmlReadFailure.InvalidName, position);
                }

                hasSeenColon = true;
                isExpectingStartCharacter = true;
                position++;
                continue;
            }

            OperationStatus status = Rune.DecodeFromUtf8(document[position..], out Rune rune, out int consumed);
            if(status != OperationStatus.Done)
            {
                return Refuse(XmlReadFailure.IllFormedUtf8, position);
            }

            bool isValid = isExpectingStartCharacter
                ? XmlCharacters.IsNameStartCharacter(rune.Value)
                : XmlCharacters.IsNameCharacter(rune.Value);
            if(!isValid)
            {
                if(isExpectingStartCharacter)
                {
                    return Refuse(XmlReadFailure.InvalidName, position);
                }

                break;
            }

            position += consumed;
            isExpectingStartCharacter = false;
        }

        if(isExpectingStartCharacter)
        {
            return position >= document.Length
                ? Refuse(XmlReadFailure.UnexpectedEndOfDocument, document.Length)
                : Refuse(XmlReadFailure.InvalidName, position);
        }

        nameLength = position - nameStart;

        return true;
    }
}
