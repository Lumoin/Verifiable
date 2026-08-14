namespace Verifiable.Xml;

/// <summary>
/// Bridges <see cref="XmlSignatureModelGrammar"/>'s grammar primitives — built for the <c>ds</c> family but
/// namespace-agnostic in their actual logic — into the XAdES reading surface's own result and failure types:
/// XAdES readers reuse the primitives directly rather than re-implementing them,
/// but report refusals through <see cref="XAdESReadFailure"/>, never <see cref="XmlSignatureReadFailure"/>.
/// </summary>
internal static class XAdESGrammar
{
    /// <summary>The bound this parser enforces on the digit run's length — the largest count a
    /// <see cref="long"/> accumulation never overflows for, and a hardening bound against a pathologically
    /// long digit run rather than a narrowing of the (formally unbounded-precision) <c>xsd:integer</c> lexical
    /// space, the same posture <see cref="XAdESDateTime"/>'s own <c>MaximumYearDigits</c>/
    /// <c>MaximumFractionalSecondDigits</c> bounds take.</summary>
    private const int MaximumIntegerDigits = 18;


    /// <summary>
    /// Translates the refusal <see cref="XmlSignatureModelGrammar.TryValidateAttributeCount"/>,
    /// <see cref="XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex"/>,
    /// <see cref="XmlSignatureModelGrammar.TryDecodeSimpleBase64Content"/>,
    /// <see cref="XmlSignatureModelGrammar.TryReadElementChildren"/>,
    /// <see cref="XmlCanonicalizationMethodInfo.TryRead"/> and <see cref="XmlTransform.TryReadList"/> produce
    /// into its XAdES counterpart. Those six primitives are the only ones this leaf's XAdES readers call that
    /// can themselves produce a refusal, and between them they only ever produce
    /// <see cref="XmlSignatureReadFailure.UnknownCoreAttribute"/>,
    /// <see cref="XmlSignatureReadFailure.UnexpectedElementContent"/>,
    /// <see cref="XmlSignatureReadFailure.InvalidBase64Content"/>,
    /// <see cref="XmlSignatureReadFailure.MissingRequiredAttribute"/> (an <c>InclusiveNamespaces</c>-bearing
    /// <c>ds:CanonicalizationMethod</c> missing its own <c>Algorithm</c>, or a standalone <c>ds:Transforms</c>
    /// element's own <c>Transform</c> missing its <c>Algorithm</c>),
    /// <see cref="XmlSignatureReadFailure.DuplicateCoreChild"/> (a second <c>InclusiveNamespaces</c> or
    /// <c>XPath</c> child of one <c>Transform</c>),
    /// <see cref="XmlSignatureReadFailure.MissingRequiredChild"/> (a standalone <c>ds:Transforms</c> element
    /// with zero <c>Transform</c> children, clause 5.2.9.1's <c>SigPolicyId</c>) or
    /// <see cref="XmlSignatureReadFailure.UnknownCoreElement"/> (a standalone <c>ds:Transforms</c> element's
    /// child that is not <c>ds:Transform</c>) — every other <see cref="XAdESReadFailure"/> member an XAdES
    /// reader in this leaf reports, it constructs directly itself, the same way <see cref="XmlReference"/>'s
    /// own <c>TryRead</c> constructs <see cref="XmlSignatureReadFailure.MissingRequiredChild"/> directly
    /// rather than through a grammar primitive.
    /// </summary>
    /// <param name="error">The grammar-primitive refusal to translate.</param>
    /// <returns>The equivalent XAdES refusal, at the same byte offset.</returns>
    public static XAdESReadError FromGrammarFailure(XmlSignatureReadError error)
    {
        XAdESReadFailure failure = error.Failure switch
        {
            XmlSignatureReadFailure.UnknownCoreAttribute => XAdESReadFailure.UnknownCoreAttribute,
            XmlSignatureReadFailure.UnexpectedElementContent => XAdESReadFailure.UnexpectedElementContent,
            XmlSignatureReadFailure.InvalidBase64Content => XAdESReadFailure.InvalidBase64Content,
            XmlSignatureReadFailure.MissingRequiredAttribute => XAdESReadFailure.MissingRequiredAttribute,
            XmlSignatureReadFailure.DuplicateCoreChild => XAdESReadFailure.DuplicateCoreChild,
            XmlSignatureReadFailure.MissingRequiredChild => XAdESReadFailure.MissingRequiredChild,
            XmlSignatureReadFailure.UnknownCoreElement => XAdESReadFailure.UnknownCoreElement,
            _ => throw new InvalidOperationException($"Grammar primitives an XAdES reader calls must not produce {error.Failure}.")
        };

        return new XAdESReadError(failure, error.ByteOffset);
    }


    /// <summary>
    /// Parses an <c>xsd:boolean</c> lexical value, exact-character, against the four literals
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#boolean">XML Schema Part 2:
    /// Datatypes</see> section 3.2.2 permits: <c>true</c>, <c>false</c>, <c>1</c> and <c>0</c> — and no other
    /// casing or synonym. <c>IncludeType</c>'s <c>referencedData</c> attribute (clause 5.1.4.4.2.1) is this
    /// leaf's first <c>xsd:boolean</c>-typed XAdES attribute; every future one reuses this primitive rather
    /// than a property-local re-implementation.
    /// </summary>
    /// <param name="value">The attribute value.</param>
    /// <param name="result">The parsed boolean on success.</param>
    /// <returns><see langword="true"/> when the value matches one of the four literals.</returns>
    public static bool TryParseXsdBoolean(ReadOnlySpan<byte> value, out bool result)
    {
        if(value.SequenceEqual("true"u8) || value.SequenceEqual("1"u8))
        {
            result = true;

            return true;
        }

        if(value.SequenceEqual("false"u8) || value.SequenceEqual("0"u8))
        {
            result = false;

            return true;
        }

        result = false;

        return false;
    }


    /// <summary>
    /// Parses an <c>xsd:integer</c> lexical value strictly against
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#integer">XML Schema Part 2:
    /// Datatypes</see> section 3.3.13's pattern <c>(\+|-)?[0-9]+</c> — <c>CRLIdentifier</c>'s <c>Number</c>
    /// child (Annex A.1.2/A.1.4) is this leaf's first <c>xsd:integer</c>-typed XAdES element; every future one
    /// reuses this primitive rather than a property-local re-implementation. Leading zeros are accepted (the
    /// lexical space permits them; only the canonical representation forbids them), and a leading sign is
    /// optional; no embedded whitespace or any other character is tolerated. The digit run is bounded to
    /// <see cref="MaximumIntegerDigits"/> — see that constant's own remarks; <c>Number</c> is documented as an
    /// optional disambiguating hint (NOTE 3), never combined arithmetically with anything else this leaf
    /// computes, so the bound narrows nothing the reader's own use of the value depends on.
    /// </summary>
    /// <param name="value">The element's simple-content text.</param>
    /// <param name="isNegative">Whether the value carried a leading <c>'-'</c>.</param>
    /// <param name="magnitude">The parsed magnitude.</param>
    /// <returns><see langword="true"/> when the value matches the grammar exactly.</returns>
    public static bool TryParseXsdInteger(ReadOnlySpan<byte> value, out bool isNegative, out long magnitude)
    {
        isNegative = false;
        magnitude = 0;
        int pos = 0;
        int length = value.Length;
        if(pos < length && (value[pos] == (byte)'+' || value[pos] == (byte)'-'))
        {
            isNegative = value[pos] == (byte)'-';
            ++pos;
        }

        int digitStart = pos;
        while(pos < length && value[pos] >= (byte)'0' && value[pos] <= (byte)'9')
        {
            ++pos;
        }

        int digitCount = pos - digitStart;
        if(digitCount == 0 || digitCount > MaximumIntegerDigits || pos != length)
        {
            isNegative = false;

            return false;
        }

        long accumulated = 0;
        for(int i = digitStart; i < pos; ++i)
        {
            accumulated = (accumulated * 10) + (value[i] - (byte)'0');
        }

        magnitude = accumulated;

        return true;
    }
}
