using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// One <c>ds:CanonicalizationMethod</c> element: its mandatory <c>Algorithm</c> attribute and its optional
/// <c>ec:InclusiveNamespaces</c> child, per section 4.3.1 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> together with section 4.2 of
/// <see href="https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/">Exclusive XML Canonicalization
/// 1.0</see>. The content model is <c>##any</c>, mixed — other children and character data the section
/// declares as permitted algorithm-parameter extensibility are tolerated and left unmodeled.
/// </summary>
public readonly struct XmlCanonicalizationMethodInfo: IEquatable<XmlCanonicalizationMethodInfo>
{
    /// <summary>The table the method's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>CanonicalizationMethod</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int AlgorithmAttributeOrdinal { get; }

    /// <summary>The method's <c>Algorithm</c> URI, exact-character.</summary>
    public ReadOnlySpan<byte> Algorithm => Table.AttributeValueOf(ElementIndex, AlgorithmAttributeOrdinal);

    /// <summary>Whether an <c>ec:InclusiveNamespaces</c> child is present.</summary>
    public bool HasInclusiveNamespaces { get; }

    /// <summary>The <c>InclusiveNamespaces</c> element's own index, or -1 when absent.</summary>
    public int InclusiveNamespacesElementIndex { get; }

    private int PrefixListAttributeOrdinal { get; }

    /// <summary>The <c>PrefixList</c> attribute value as written, un-tokenized.</summary>
    public ReadOnlySpan<byte> PrefixList => HasInclusiveNamespaces && PrefixListAttributeOrdinal >= 0
        ? Table.AttributeValueOf(InclusiveNamespacesElementIndex, PrefixListAttributeOrdinal)
        : ReadOnlySpan<byte>.Empty;


    internal XmlCanonicalizationMethodInfo(XmlNodeTable table, int elementIndex, int algorithmAttributeOrdinal, bool hasInclusiveNamespaces, int inclusiveNamespacesElementIndex, int prefixListAttributeOrdinal)
    {
        Table = table;
        ElementIndex = elementIndex;
        AlgorithmAttributeOrdinal = algorithmAttributeOrdinal;
        HasInclusiveNamespaces = hasInclusiveNamespaces;
        InclusiveNamespacesElementIndex = inclusiveNamespacesElementIndex;
        PrefixListAttributeOrdinal = prefixListAttributeOrdinal;
    }


    /// <summary>
    /// Reads a <c>CanonicalizationMethod</c> element: its mandatory <c>Algorithm</c> and its optional
    /// <c>InclusiveNamespaces</c> child.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XmlCanonicalizationMethodInfo method, out XmlSignatureReadError error)
    {
        method = default;
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Algorithm"u8, out int algorithmOrdinal))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        //The section 4.3.1 CanonicalizationMethodType schema declares Algorithm alone and carries no
        //anyAttribute, exactly like DigestMethod's own schema type — an undeclared un-prefixed attribute is
        //refused the same way here.
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1, out error))
        {
            return false;
        }

        bool hasInclusiveNamespaces = false;
        int inclusiveNamespacesElementIndex = -1;
        int prefixListOrdinal = -1;
        foreach(int child in XmlSignatureModelGrammar.GatherElementChildrenLoosely(table, elementIndex))
        {
            if(!XmlSignatureModelGrammar.IsElement(table, child, XmlSignatureIdentifiers.ExclusiveCanonicalXml10UriUtf8, "InclusiveNamespaces"u8))
            {
                continue;
            }

            if(hasInclusiveNamespaces)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.DuplicateCoreChild, 0);

                return false;
            }

            hasInclusiveNamespaces = true;
            inclusiveNamespacesElementIndex = child;
            _ = XmlSignatureModelGrammar.TryFindAttribute(table, child, "PrefixList"u8, out prefixListOrdinal);
        }

        method = new XmlCanonicalizationMethodInfo(table, elementIndex, algorithmOrdinal, hasInclusiveNamespaces, inclusiveNamespacesElementIndex, prefixListOrdinal);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlCanonicalizationMethodInfo other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlCanonicalizationMethodInfo other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlCanonicalizationMethodInfo left, XmlCanonicalizationMethodInfo right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlCanonicalizationMethodInfo left, XmlCanonicalizationMethodInfo right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:SignatureMethod</c> element: its mandatory <c>Algorithm</c> attribute and its optional
/// <c>HMACOutputLength</c> child, per section 4.3.2 and section 6.3.1.
/// </summary>
/// <remarks>
/// <see cref="HmacOutputLengthValue"/> is parsed structurally only and never acted on: MAC verification is
/// out of scope here, and an application that DOES perform HMAC verification must apply the
/// truncation length itself rather than trusting a value an attacker who does not hold the key could have
/// altered along with everything else in an unauthenticated <c>SignedInfo</c> — the truncation attack
/// RFC 2104 warns of, present here only as a recorded field.
/// </remarks>
public readonly struct XmlSignatureMethodInfo: IEquatable<XmlSignatureMethodInfo>
{
    /// <summary>The table the method's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignatureMethod</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int AlgorithmAttributeOrdinal { get; }

    /// <summary>The method's <c>Algorithm</c> URI, exact-character.</summary>
    public ReadOnlySpan<byte> Algorithm => Table.AttributeValueOf(ElementIndex, AlgorithmAttributeOrdinal);

    /// <summary>Whether an <c>HMACOutputLength</c> child is present.</summary>
    public bool HasHmacOutputLength { get; }

    /// <summary>The parsed <c>HMACOutputLength</c> value in bits; zero when absent.</summary>
    public long HmacOutputLengthValue { get; }


    internal XmlSignatureMethodInfo(XmlNodeTable table, int elementIndex, int algorithmAttributeOrdinal, bool hasHmacOutputLength, long hmacOutputLengthValue)
    {
        Table = table;
        ElementIndex = elementIndex;
        AlgorithmAttributeOrdinal = algorithmAttributeOrdinal;
        HasHmacOutputLength = hasHmacOutputLength;
        HmacOutputLengthValue = hmacOutputLengthValue;
    }


    /// <summary>
    /// Reads a <c>SignatureMethod</c> element: its mandatory <c>Algorithm</c> and its optional
    /// <c>HMACOutputLength</c> child.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XmlSignatureMethodInfo method, out XmlSignatureReadError error)
    {
        method = default;
        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Algorithm"u8, out int algorithmOrdinal))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        //The section 4.3.2 SignatureMethodType schema declares Algorithm alone and carries no anyAttribute,
        //exactly like DigestMethod's own schema type — an undeclared un-prefixed attribute is refused the
        //same way here.
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1, out error))
        {
            return false;
        }

        bool hasHmacOutputLength = false;
        long hmacOutputLengthValue = 0;
        foreach(int child in XmlSignatureModelGrammar.GatherElementChildrenLoosely(table, elementIndex))
        {
            if(!XmlSignatureModelGrammar.IsDsElement(table, child, "HMACOutputLength"u8))
            {
                continue;
            }

            if(hasHmacOutputLength)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.DuplicateCoreChild, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int textNodeIndex, out error) || textNodeIndex < 0
                || !TryParseNonNegativeInteger(table.ValueOf(textNodeIndex), out hmacOutputLengthValue))
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.InvalidHmacOutputLength, 0);

                return false;
            }

            hasHmacOutputLength = true;
        }

        method = new XmlSignatureMethodInfo(table, elementIndex, algorithmOrdinal, hasHmacOutputLength, hmacOutputLengthValue);
        error = default;

        return true;
    }


    /// <summary>
    /// Parses a non-negative decimal integer per the <c>HMACOutputLengthType</c> restriction of
    /// <c>xsd:integer</c>, XML white space trimmed.
    /// </summary>
    private static bool TryParseNonNegativeInteger(ReadOnlySpan<byte> content, out long value)
    {
        int start = 0;
        int end = content.Length;
        while(start < end && XmlCharacters.IsWhitespace(content[start]))
        {
            ++start;
        }

        while(end > start && XmlCharacters.IsWhitespace(content[end - 1]))
        {
            --end;
        }

        ReadOnlySpan<byte> trimmed = content[start..end];
        if(trimmed.Length > 0 && trimmed[0] == (byte)'+')
        {
            trimmed = trimmed[1..];
        }

        if(trimmed.IsEmpty)
        {
            value = 0;

            return false;
        }

        long accumulated = 0;
        foreach(byte octet in trimmed)
        {
            if(octet is < (byte)'0' or > (byte)'9')
            {
                value = 0;

                return false;
            }

            checked
            {
                try
                {
                    accumulated = (accumulated * 10) + (octet - (byte)'0');
                }
                catch(OverflowException)
                {
                    value = 0;

                    return false;
                }
            }
        }

        value = accumulated;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSignatureMethodInfo other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSignatureMethodInfo other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSignatureMethodInfo left, XmlSignatureMethodInfo right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSignatureMethodInfo left, XmlSignatureMethodInfo right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:SignedInfo</c> element: its optional <c>Id</c> attribute, its <c>CanonicalizationMethod</c>,
/// its <c>SignatureMethod</c>, and its one-or-more <c>Reference</c> children, in that order, per section
/// 4.3.
/// </summary>
public readonly struct XmlSignedInfo: IEquatable<XmlSignedInfo>
{
    /// <summary>The table the info's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignedInfo</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>CanonicalizationMethod</c> child.</summary>
    public XmlCanonicalizationMethodInfo CanonicalizationMethod { get; }

    /// <summary>The <c>SignatureMethod</c> child.</summary>
    public XmlSignatureMethodInfo SignatureMethod { get; }

    /// <summary>The <c>Reference</c> children, in document order; at least one.</summary>
    public IReadOnlyList<XmlReference> References { get; }


    internal XmlSignedInfo(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, XmlCanonicalizationMethodInfo canonicalizationMethod, XmlSignatureMethodInfo signatureMethod, IReadOnlyList<XmlReference> references)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        CanonicalizationMethod = canonicalizationMethod;
        SignatureMethod = signatureMethod;
        References = references;
    }


    /// <summary>
    /// Reads a <c>SignedInfo</c> element: <c>CanonicalizationMethod</c>, <c>SignatureMethod</c>, then
    /// <c>Reference+</c>, in that fixed order.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlSignedInfo signedInfo, out XmlSignatureReadError error)
    {
        signedInfo = default;
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out error))
        {
            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "CanonicalizationMethod"u8))
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlCanonicalizationMethodInfo.TryRead(table, child, out XmlCanonicalizationMethodInfo canonicalizationMethod, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int signatureMethodIndex);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, signatureMethodIndex, "SignatureMethod"u8))
        {
            error = new XmlSignatureReadError(DetermineOrderFailure(table, scan, signatureMethodIndex, "CanonicalizationMethod"u8), 0);

            return false;
        }

        if(!XmlSignatureMethodInfo.TryRead(table, signatureMethodIndex, out XmlSignatureMethodInfo signatureMethod, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, signatureMethodIndex, out int firstReference);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, firstReference, "Reference"u8))
        {
            bool isRepeat = scan == ElementScanResult.Found
                && (XmlSignatureModelGrammar.IsDsElement(table, firstReference, "CanonicalizationMethod"u8) || XmlSignatureModelGrammar.IsDsElement(table, firstReference, "SignatureMethod"u8));
            error = new XmlSignatureReadError(
                isRepeat ? XmlSignatureReadFailure.DuplicateCoreChild
                : scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent
                : XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlReference.TryReadSequence(table, firstReference, pool, owned, out List<XmlReference> references, out error))
        {
            return false;
        }

        signedInfo = new XmlSignedInfo(table, elementIndex, hasId, idOrdinal, canonicalizationMethod, signatureMethod, references);
        error = default;

        return true;
    }


    /// <summary>
    /// Chooses the reason the expected next fixed-order child was not found: a repeat of the element just
    /// consumed is a duplicate, stray non-whitespace text is unexpected content, anything else is a missing
    /// mandatory child.
    /// </summary>
    private static XmlSignatureReadFailure DetermineOrderFailure(XmlNodeTable table, ElementScanResult scan, int foundElementIndex, ReadOnlySpan<byte> previousLocalName)
    {
        if(scan == ElementScanResult.UnexpectedContent)
        {
            return XmlSignatureReadFailure.UnexpectedElementContent;
        }

        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, foundElementIndex, previousLocalName))
        {
            return XmlSignatureReadFailure.DuplicateCoreChild;
        }

        return XmlSignatureReadFailure.MissingRequiredChild;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSignedInfo other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSignedInfo other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSignedInfo left, XmlSignedInfo right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSignedInfo left, XmlSignedInfo right) => !left.Equals(right);
}


/// <summary>
/// The XMLDSIG core structural model of one <c>ds:Signature</c> element: an immutable, pooled reading of
/// every section 4/5 element of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> over an <see cref="XmlNodeTable"/> — indices, spans and decoded octets, no
/// managed-string surfaces.
/// </summary>
/// <remarks>
/// <para>
/// Reading is result-shaped and fail-closed: wrong child order, missing mandatory children, duplicate
/// <c>ds</c>-namespace children and unknown <c>ds</c>-namespace elements or attributes in core positions
/// all refuse with a stable <see cref="XmlSignatureReadFailure"/> reason, never with an exception over
/// input content — the section 4.1 "laxly schema valid" allowance is this specification's OWN generation
/// obligation, not a reading tolerance. What IS tolerated, because real documents are formatted, is
/// insignificant whitespace text between element children (see <see cref="XmlSignatureModelGrammar"/>).
/// </para>
/// <para>
/// This leaf performs no cryptography: <c>DigestMethod</c>/<c>SignatureMethod Algorithm</c>
/// values are exposed as exact-character UTF-8 spans, never mapped to an algorithm enum and never routed
/// through <see cref="System.Uri"/>; digest comparison and signature verification compose above this
/// model. Base64-typed content (<c>SignatureValue</c>, every <c>DigestValue</c>, <c>X509Certificate</c> DER
/// octets, every <c>ds:CryptoBinary</c> key-material field) decodes eagerly during <see cref="TryRead"/>
/// into <see cref="PooledMemory"/> tagged <see cref="BufferTags.XmlDecodedContent"/>, all of it owned by
/// this instance and released together by <see cref="Dispose"/> — including on every refusal path, since
/// the whole read runs inside one <c>try</c>/<c>finally</c> that disposes everything accumulated so far
/// whenever the read does not complete.
/// </para>
/// <para>
/// <c>Object</c> content is deliberately NOT interpreted here: its children are exposed as raw node
/// indices (<see cref="XmlSignatureObject.ContentNodeIndices"/>) a caller who recognizes what they hold —
/// a nested <c>Manifest</c>, a <c>SignatureProperties</c>, or a whole nested <c>ds:Signature</c> — reads
/// itself, over one of those indices, through <see cref="XmlManifest.TryRead"/>,
/// <see cref="XmlSignatureProperties.TryRead"/> or <see cref="TryRead"/> again. Locating every
/// <c>Signature</c> element of a document, nested ones included, is <see cref="XmlSignatureLocator"/>'s
/// job, not this reader's.
/// </para>
/// </remarks>
public sealed class XmlSignature: IDisposable
{
    /// <summary>The document the signature was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>Signature</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>SignedInfo</c> child.</summary>
    public XmlSignedInfo SignedInfo { get; }

    /// <summary>The <c>SignatureValue</c> element's own index.</summary>
    public int SignatureValueElementIndex { get; }

    /// <summary>Whether <c>SignatureValue</c>'s optional <c>Id</c> attribute is present.</summary>
    public bool HasSignatureValueId { get; }

    private int SignatureValueIdAttributeOrdinal { get; }

    /// <summary>The <c>SignatureValue</c> element's <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> SignatureValueId => HasSignatureValueId ? Table.AttributeValueOf(SignatureValueElementIndex, SignatureValueIdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// The decoded <c>SignatureValue</c> octets, tagged <see cref="BufferTags.XmlDecodedContent"/>. Owned
    /// by this instance and released by <see cref="Dispose"/>.
    /// </summary>
    public PooledMemory SignatureValueOctets { get; }

    /// <summary>The <c>KeyInfo</c> child, or <see langword="null"/> when absent (it is optional).</summary>
    public XmlKeyInfo? KeyInfo { get; }

    /// <summary>The <c>Object</c> children, in document order; possibly empty.</summary>
    public IReadOnlyList<XmlSignatureObject> Objects { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XmlSignature(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        XmlSignedInfo signedInfo,
        int signatureValueElementIndex,
        bool hasSignatureValueId,
        int signatureValueIdAttributeOrdinal,
        PooledMemory signatureValueOctets,
        XmlKeyInfo? keyInfo,
        IReadOnlyList<XmlSignatureObject> objects,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        SignedInfo = signedInfo;
        SignatureValueElementIndex = signatureValueElementIndex;
        HasSignatureValueId = hasSignatureValueId;
        SignatureValueIdAttributeOrdinal = signatureValueIdAttributeOrdinal;
        SignatureValueOctets = signatureValueOctets;
        KeyInfo = keyInfo;
        Objects = objects;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads one <c>ds:Signature</c> element's complete structural model: <c>SignedInfo</c>,
    /// <c>SignatureValue</c>, an optional <c>KeyInfo</c> and zero or more <c>Object</c> children, in that
    /// fixed order, per section 4.1.
    /// </summary>
    /// <param name="table">The parsed document.</param>
    /// <param name="signatureElementIndex">The <c>Signature</c> element index, typically one
    /// <see cref="XmlSignatureLocator.FindSignatures"/> returned.</param>
    /// <param name="pool">The pool every decoded base64/<c>CryptoBinary</c> field is rented from.</param>
    /// <param name="signature">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int signatureElementIndex, BaseMemoryPool pool, out XmlSignature? signature, out XmlSignatureReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        signature = null;
        if(!XmlSignatureModelGrammar.IsDsElement(table, signatureElementIndex, "Signature"u8))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, signatureElementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, signatureElementIndex, hasId ? 1 : 0, out error))
        {
            return false;
        }

        var owned = new List<PooledMemory>();
        try
        {
            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, signatureElementIndex, out int child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "SignedInfo"u8))
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingSignedInfo, 0);

                return false;
            }

            if(!XmlSignedInfo.TryRead(table, child, pool, owned, out XmlSignedInfo signedInfo, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int signatureValueIndex);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, signatureValueIndex, "SignatureValue"u8))
            {
                bool isRepeat = scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, signatureValueIndex, "SignedInfo"u8);
                error = new XmlSignatureReadError(
                    isRepeat ? XmlSignatureReadFailure.DuplicateCoreChild
                    : scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent
                    : XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }

            bool hasSignatureValueId = XmlSignatureModelGrammar.TryFindAttribute(table, signatureValueIndex, "Id"u8, out int signatureValueIdOrdinal);
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, signatureValueIndex, hasSignatureValueId ? 1 : 0, out error))
            {
                return false;
            }

            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, signatureValueIndex, pool, owned, out PooledMemory? signatureValueOctets, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, signatureValueIndex, out int next);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            XmlKeyInfo? keyInfo = null;
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, next, "KeyInfo"u8))
            {
                if(!XmlKeyInfo.TryRead(table, next, pool, owned, out XmlKeyInfo readKeyInfo, out error))
                {
                    return false;
                }

                keyInfo = readKeyInfo;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, next, out next);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            var objects = new List<XmlSignatureObject>();
            while(scan == ElementScanResult.Found)
            {
                if(!XmlSignatureModelGrammar.IsDsElement(table, next, "Object"u8))
                {
                    bool isRepeat = XmlSignatureModelGrammar.IsDsElement(table, next, "SignedInfo"u8)
                        || XmlSignatureModelGrammar.IsDsElement(table, next, "SignatureValue"u8)
                        || (keyInfo is not null && XmlSignatureModelGrammar.IsDsElement(table, next, "KeyInfo"u8));
                    bool isOutOfOrder = keyInfo is null && XmlSignatureModelGrammar.IsDsElement(table, next, "KeyInfo"u8);
                    error = new XmlSignatureReadError(
                        isRepeat ? XmlSignatureReadFailure.DuplicateCoreChild
                        : isOutOfOrder ? XmlSignatureReadFailure.InvalidChildOrder
                        : XmlSignatureReadFailure.UnknownCoreElement, 0);

                    return false;
                }

                if(!XmlSignatureObject.TryRead(table, next, out XmlSignatureObject readObject, out error))
                {
                    return false;
                }

                objects.Add(readObject);
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, next, out next);
            }

            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            signature = new XmlSignature(table, signatureElementIndex, hasId, idOrdinal, signedInfo, signatureValueIndex, hasSignatureValueId, signatureValueIdOrdinal, signatureValueOctets!, keyInfo, objects, owned);
            error = default;

            return true;
        }
        finally
        {
            if(signature is null)
            {
                for(int i = 0; i < owned.Count; ++i)
                {
                    owned[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Tells whether this signature was read over the given table instance — the identity guard
    /// <see cref="XmlReferenceProcessing"/>'s entry points require before processing a
    /// <c>table</c> argument against a <c>Signature</c> read from a different document, mirroring the
    /// <see cref="XmlNodeSet.IsOver"/> precedent.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when this signature was read from the same table instance.</returns>
    public bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Releases every decoded base64/<c>CryptoBinary</c> octet buffer this signature and its constituent
    /// elements own. <see cref="Table"/> is not owned and is not disposed here.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        for(int i = 0; i < OwnedContent.Count; ++i)
        {
            OwnedContent[i].Dispose();
        }
    }
}
