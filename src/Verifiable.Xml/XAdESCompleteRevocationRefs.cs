using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Which arm of <c>ResponderIDType</c>'s <c>ByName</c>/<c>ByKey</c> choice (Annex A.1.2) a
/// <see cref="XAdESOcspIdentifier"/> holds.
/// </summary>
public enum XAdESResponderIdKind
{
    /// <summary>The responder is identified by name, in <c>ByName</c> — an XMLDSIG clause 4.5.4.1 Distinguished Name string, carried opaquely.</summary>
    ByName,

    /// <summary>The responder is identified by the digest of its public key, in <c>ByKey</c> — the base-64 DER encoding of RFC 6960's <c>byKey</c> field.</summary>
    ByKey
}


/// <summary>
/// The <c>CRLIdentifierType</c> data type (Annex A.1.2): a mandatory <c>Issuer</c> (<c>xsd:string</c>,
/// XMLDSIG clause 4.5.4.1 Distinguished Name format — carried as an opaque string; this leaf performs no DN
/// parsing, the same uniform-opaque-string posture the leaf takes for every externally-formatted string field),
/// a mandatory <c>IssueTime</c> (<c>xsd:dateTime</c>, via <see cref="XAdESDateTime"/>), an optional <c>Number</c>
/// (<c>xsd:integer</c>, a disambiguating hint per NOTE 3 — strictly lexically parsed via
/// <see cref="XAdESGrammar.TryParseXsdInteger"/>, never combined arithmetically with anything else this leaf
/// computes), and an optional <c>URI</c> attribute (a retrieval hint per NOTE 4, never authoritative — modeled
/// identically to <see cref="XAdESOcspIdentifier"/>'s own <c>URI</c>, which treats
/// the parallel "indicates"/"shall indicate" phrasing asymmetry as non-modal in effect for both).
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every field is a span or a self-contained
/// <see cref="XAdESDateTime"/> — so no <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESCrlIdentifier: IEquatable<XAdESCrlIdentifier>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>CRLIdentifier</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int IssuerTextNodeIndex { get; }

    /// <summary>The <c>Issuer</c> element's <c>string</c> content — an XMLDSIG clause 4.5.4.1 Distinguished Name string, opaque to this leaf.</summary>
    public ReadOnlySpan<byte> Issuer => IssuerTextNodeIndex >= 0 ? Table.ValueOf(IssuerTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>The parsed <c>IssueTime</c> value.</summary>
    public XAdESDateTime IssueTime { get; }

    /// <summary>Whether the optional <c>Number</c> child is present.</summary>
    public bool HasNumber { get; }

    /// <summary>Whether <see cref="Number"/> carried a leading <c>'-'</c>; meaningful only when <see cref="HasNumber"/> is <see langword="true"/>.</summary>
    public bool IsNumberNegative { get; }

    /// <summary>The <c>Number</c> child's parsed magnitude; meaningful only when <see cref="HasNumber"/> is <see langword="true"/>.</summary>
    public long Number { get; }

    /// <summary>Whether the optional <c>URI</c> attribute is present.</summary>
    public bool HasUri { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The <c>URI</c> attribute value — a retrieval hint only (NOTE 4), never authoritative.</summary>
    public ReadOnlySpan<byte> Uri => HasUri ? Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal) : ReadOnlySpan<byte>.Empty;


    private XAdESCrlIdentifier(
        XmlNodeTable table,
        int elementIndex,
        int issuerTextNodeIndex,
        XAdESDateTime issueTime,
        bool hasNumber,
        bool isNumberNegative,
        long number,
        bool hasUri,
        int uriAttributeOrdinal)
    {
        Table = table;
        ElementIndex = elementIndex;
        IssuerTextNodeIndex = issuerTextNodeIndex;
        IssueTime = issueTime;
        HasNumber = hasNumber;
        IsNumberNegative = isNumberNegative;
        Number = number;
        HasUri = hasUri;
        UriAttributeOrdinal = uriAttributeOrdinal;
    }


    /// <summary>
    /// Reads a <c>CRLIdentifier</c> element: its optional <c>URI</c> attribute, then its mandatory
    /// <c>Issuer</c>/<c>IssueTime</c> and optional <c>Number</c> children, in that fixed order.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESCrlIdentifier value, out XAdESReadError error)
    {
        value = default;
        bool hasUri = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasUri ? 1 : 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Issuer"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
            || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int issuerTextNodeIndex, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        int issuerElementIndex = child;
        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, issuerElementIndex, out child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "IssueTime"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
            || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int issueTimeTextNodeIndex, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ReadOnlySpan<byte> issueTimeContent = issueTimeTextNodeIndex >= 0 ? table.ValueOf(issueTimeTextNodeIndex) : ReadOnlySpan<byte>.Empty;
        if(!XAdESDateTime.TryParse(issueTimeContent, out XAdESDateTime issueTime))
        {
            error = new XAdESReadError(XAdESReadFailure.InvalidDateTimeLexicalForm, 0);

            return false;
        }

        int issueTimeElementIndex = child;
        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, issueTimeElementIndex, out child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        bool hasNumber = false;
        bool isNumberNegative = false;
        long number = 0;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Number"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int numberTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            ReadOnlySpan<byte> numberContent = numberTextNodeIndex >= 0 ? table.ValueOf(numberTextNodeIndex) : ReadOnlySpan<byte>.Empty;
            if(!XAdESGrammar.TryParseXsdInteger(numberContent, out isNumberNegative, out number))
            {
                error = new XAdESReadError(XAdESReadFailure.InvalidIntegerLexicalForm, 0);

                return false;
            }

            hasNumber = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Issuer"u8)
                || XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "IssueTime"u8)
                || (hasNumber && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Number"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESCrlIdentifier(table, elementIndex, issuerTextNodeIndex, issueTime, hasNumber, isNumberNegative, number, hasUri, uriOrdinal);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESCrlIdentifier other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESCrlIdentifier other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESCrlIdentifier left, XAdESCrlIdentifier right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESCrlIdentifier left, XAdESCrlIdentifier right) => !left.Equals(right);
}


/// <summary>
/// The <c>OCSPIdentifierType</c> data type (Annex A.1.2): a mandatory <c>ResponderID</c> (the
/// <c>ByName</c>/<c>ByKey</c> choice, see <see cref="XAdESResponderIdKind"/>), a mandatory <c>ProducedAt</c>
/// (<c>xsd:dateTime</c>, via <see cref="XAdESDateTime"/> — "shall indicate the same time as the referenced
/// OCSP response's own <c>ProducedAt</c> field," a cross-document consistency rule this crypto-free leaf
/// cannot check without decoding the referenced OCSP response —
/// <c>Verifiable.Cryptography.Pki.XAdESLevelRules.CheckOcspProducedAtConsistencyAsync</c> performs it above
/// the leaf), and an
/// optional <c>URI</c> attribute (a retrieval hint per NOTE 5 — the clause's own "indicates," non-modal
/// relative to <see cref="XAdESCrlIdentifier"/>'s parallel "shall indicate," is read as no
/// semantic difference: both are modeled as optional hint carriage).
/// </summary>
/// <remarks>
/// <c>ByKey</c>'s decoded octets are threaded through a caller-supplied custody list — the same shape
/// <see cref="XAdESCertIdV2"/> takes for its own optional <c>IssuerSerialV2</c> — rather than owned outright,
/// so this type stays a value struct with no <see cref="IDisposable"/> surface of its own; its owning
/// <see cref="XAdESCompleteRevocationRefs"/> disposes the decoded octets.
/// </remarks>
public readonly struct XAdESOcspIdentifier: IEquatable<XAdESOcspIdentifier>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>OCSPIdentifier</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Which arm of <c>ResponderIDType</c>'s choice this instance holds.</summary>
    public XAdESResponderIdKind ResponderKind { get; }

    private int ByNameTextNodeIndex { get; }

    /// <summary>The <c>ByName</c> element's <c>string</c> content — an XMLDSIG clause 4.5.4.1 Distinguished Name string, opaque to this leaf; meaningful only when <see cref="ResponderKind"/> is <see cref="XAdESResponderIdKind.ByName"/>.</summary>
    public ReadOnlySpan<byte> ByName => ByNameTextNodeIndex >= 0 ? Table.ValueOf(ByNameTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// The decoded <c>ByKey</c> octets — the base-64 DER encoding of RFC 6960's <c>byKey</c> field, undecoded
    /// ASN.1 this leaf never parses — tagged <see cref="BufferTags.XmlDecodedContent"/>; meaningful only when
    /// <see cref="ResponderKind"/> is <see cref="XAdESResponderIdKind.ByKey"/>. Owned by the caller's custody
    /// list.
    /// </summary>
    public PooledMemory? ByKeyOctets { get; }

    /// <summary>The parsed <c>ProducedAt</c> value.</summary>
    public XAdESDateTime ProducedAt { get; }

    /// <summary>Whether the optional <c>URI</c> attribute is present.</summary>
    public bool HasUri { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The <c>URI</c> attribute value — a retrieval hint only (NOTE 5), never authoritative.</summary>
    public ReadOnlySpan<byte> Uri => HasUri ? Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal) : ReadOnlySpan<byte>.Empty;


    private XAdESOcspIdentifier(
        XmlNodeTable table,
        int elementIndex,
        XAdESResponderIdKind responderKind,
        int byNameTextNodeIndex,
        PooledMemory? byKeyOctets,
        XAdESDateTime producedAt,
        bool hasUri,
        int uriAttributeOrdinal)
    {
        Table = table;
        ElementIndex = elementIndex;
        ResponderKind = responderKind;
        ByNameTextNodeIndex = byNameTextNodeIndex;
        ByKeyOctets = byKeyOctets;
        ProducedAt = producedAt;
        HasUri = hasUri;
        UriAttributeOrdinal = uriAttributeOrdinal;
    }


    /// <summary>
    /// Reads an <c>OCSPIdentifier</c> element: its optional <c>URI</c> attribute, then its mandatory
    /// <c>ResponderID</c> (exactly one of <c>ByName</c>/<c>ByKey</c>) and <c>ProducedAt</c> children, in that
    /// fixed order.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESOcspIdentifier value, out XAdESReadError error)
    {
        value = default;
        bool hasUri = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasUri ? 1 : 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ResponderID"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        int responderIdElementIndex = child;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, responderIdElementIndex, 0, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult responderScan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, responderIdElementIndex, out int responderChild);
        if(responderScan != ElementScanResult.Found)
        {
            error = new XAdESReadError(
                responderScan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        XAdESResponderIdKind responderKind;
        int byNameTextNodeIndex = -1;
        PooledMemory? byKeyOctets = null;
        if(XmlSignatureModelGrammar.IsElement(table, responderChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ByName"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, responderChild, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, responderChild, out byNameTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            responderKind = XAdESResponderIdKind.ByName;
        }
        else if(XmlSignatureModelGrammar.IsElement(table, responderChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ByKey"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, responderChild, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, responderChild, pool, owned, out byKeyOctets, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            responderKind = XAdESResponderIdKind.ByKey;
        }
        else
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        int chosenResponderChild = responderChild;
        responderScan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, chosenResponderChild, out responderChild);
        if(responderScan != ElementScanResult.EndOfChildren)
        {
            if(responderScan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            bool isRepeat = responderKind == XAdESResponderIdKind.ByName
                ? XmlSignatureModelGrammar.IsElement(table, responderChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ByName"u8)
                : XmlSignatureModelGrammar.IsElement(table, responderChild, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ByKey"u8);
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, responderIdElementIndex, out child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ProducedAt"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
            || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int producedAtTextNodeIndex, out grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ReadOnlySpan<byte> producedAtContent = producedAtTextNodeIndex >= 0 ? table.ValueOf(producedAtTextNodeIndex) : ReadOnlySpan<byte>.Empty;
        if(!XAdESDateTime.TryParse(producedAtContent, out XAdESDateTime producedAt))
        {
            error = new XAdESReadError(XAdESReadFailure.InvalidDateTimeLexicalForm, 0);

            return false;
        }

        int producedAtElementIndex = child;
        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, producedAtElementIndex, out child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ResponderID"u8)
                || XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "ProducedAt"u8);
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESOcspIdentifier(table, elementIndex, responderKind, byNameTextNodeIndex, byKeyOctets, producedAt, hasUri, uriOrdinal);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESOcspIdentifier other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESOcspIdentifier other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESOcspIdentifier left, XAdESOcspIdentifier right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESOcspIdentifier left, XAdESOcspIdentifier right) => !left.Equals(right);
}


/// <summary>
/// The <c>CRLRefType</c> data type (Annex A.1.2): a mandatory <c>DigestAlgAndValue</c> (the shared
/// <see cref="XAdESDigestAlgAndValue"/> reader — "one reference to one CRL") then an
/// optional <c>CRLIdentifier</c>, in that fixed order. Delta-CRL completeness ("if one or more identified CRLs
/// are a Delta CRL, the qualifying property shall include references to the full set of CRLs") is DER-content-
/// dependent — determining Delta-CRL-ness requires parsing the referenced CRL's own ASN.1, which this
/// crypto-free leaf never does — a recorded, verification-side disposition, the same posture
/// <see cref="XAdESRevocationValues"/>'s own remarks record for the parallel rule on its <c>CRLValues</c> side.
/// </summary>
/// <remarks>
/// Carries no owned pooled content beyond <see cref="DigestAlgAndValue"/>'s own <c>DigestValueOctets</c>, held
/// via the caller-supplied custody list the same way <see cref="XAdESCertIdV2"/>'s <c>CertDigest</c> is — no
/// <see cref="IDisposable"/> surface of its own.
/// </remarks>
public readonly struct XAdESCrlRef: IEquatable<XAdESCrlRef>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>CRLRef</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The mandatory <c>DigestAlgAndValue</c> child.</summary>
    public XAdESDigestAlgAndValue DigestAlgAndValue { get; }

    /// <summary>Whether the optional <c>CRLIdentifier</c> child is present.</summary>
    public bool HasCrlIdentifier { get; }

    /// <summary>The <c>CRLIdentifier</c> child; meaningful only when <see cref="HasCrlIdentifier"/> is <see langword="true"/>.</summary>
    public XAdESCrlIdentifier CrlIdentifier { get; }


    private XAdESCrlRef(XmlNodeTable table, int elementIndex, XAdESDigestAlgAndValue digestAlgAndValue, bool hasCrlIdentifier, XAdESCrlIdentifier crlIdentifier)
    {
        Table = table;
        ElementIndex = elementIndex;
        DigestAlgAndValue = digestAlgAndValue;
        HasCrlIdentifier = hasCrlIdentifier;
        CrlIdentifier = crlIdentifier;
    }


    /// <summary>
    /// Reads a <c>CRLRef</c> element: no attributes of its own, then its mandatory <c>DigestAlgAndValue</c>
    /// and optional <c>CRLIdentifier</c> children, in that fixed order.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESCrlRef value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "DigestAlgAndValue"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XAdESDigestAlgAndValue.TryRead(table, child, pool, owned, out XAdESDigestAlgAndValue digestAlgAndValue, out error))
        {
            return false;
        }

        int digestElementIndex = child;
        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, digestElementIndex, out child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        bool hasCrlIdentifier = false;
        XAdESCrlIdentifier crlIdentifier = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CRLIdentifier"u8))
        {
            if(!XAdESCrlIdentifier.TryRead(table, child, out crlIdentifier, out error))
            {
                return false;
            }

            hasCrlIdentifier = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "DigestAlgAndValue"u8)
                || (hasCrlIdentifier && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CRLIdentifier"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESCrlRef(table, elementIndex, digestAlgAndValue, hasCrlIdentifier, crlIdentifier);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESCrlRef other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESCrlRef other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESCrlRef left, XAdESCrlRef right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESCrlRef left, XAdESCrlRef right) => !left.Equals(right);
}


/// <summary>
/// The <c>OCSPRefType</c> data type (Annex A.1.2): a mandatory <c>OCSPIdentifier</c> then an optional
/// <c>DigestAlgAndValue</c> (the shared <see cref="XAdESDigestAlgAndValue"/> reader — clause's own "should be
/// included," a recommendation this reader models as present-or-absent rather than enforcing, per the
/// contrast with the CRL side's unconditional <c>shall</c> recorded at <see cref="XAdESCrlRef"/>'s own
/// remarks), in that fixed order — note the order is the REVERSE of <see cref="XAdESCrlRef"/>'s own
/// digest-then-identifier sequence.
/// </summary>
/// <remarks>
/// Carries no owned pooled content beyond <see cref="OcspIdentifier"/>'s own possible <c>ByKey</c> octets and
/// <see cref="DigestAlgAndValue"/>'s own <c>DigestValueOctets</c>, both held via the caller-supplied custody
/// list — no <see cref="IDisposable"/> surface of its own.
/// </remarks>
public readonly struct XAdESOcspRef: IEquatable<XAdESOcspRef>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>OCSPRef</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The mandatory <c>OCSPIdentifier</c> child.</summary>
    public XAdESOcspIdentifier OcspIdentifier { get; }

    /// <summary>
    /// Whether the optional <c>DigestAlgAndValue</c> child is present — clause A.1.2's "should be included,"
    /// a recommendation rather than a floor this reader enforces.
    /// </summary>
    public bool HasDigestAlgAndValue { get; }

    /// <summary>The <c>DigestAlgAndValue</c> child; meaningful only when <see cref="HasDigestAlgAndValue"/> is <see langword="true"/>.</summary>
    public XAdESDigestAlgAndValue DigestAlgAndValue { get; }


    private XAdESOcspRef(XmlNodeTable table, int elementIndex, XAdESOcspIdentifier ocspIdentifier, bool hasDigestAlgAndValue, XAdESDigestAlgAndValue digestAlgAndValue)
    {
        Table = table;
        ElementIndex = elementIndex;
        OcspIdentifier = ocspIdentifier;
        HasDigestAlgAndValue = hasDigestAlgAndValue;
        DigestAlgAndValue = digestAlgAndValue;
    }


    /// <summary>
    /// Reads an <c>OCSPRef</c> element: no attributes of its own, then its mandatory <c>OCSPIdentifier</c> and
    /// optional <c>DigestAlgAndValue</c> children, in that fixed order.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESOcspRef value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OCSPIdentifier"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XAdESOcspIdentifier.TryRead(table, child, pool, owned, out XAdESOcspIdentifier ocspIdentifier, out error))
        {
            return false;
        }

        int ocspIdentifierElementIndex = child;
        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, ocspIdentifierElementIndex, out child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        bool hasDigestAlgAndValue = false;
        XAdESDigestAlgAndValue digestAlgAndValue = default;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "DigestAlgAndValue"u8))
        {
            if(!XAdESDigestAlgAndValue.TryRead(table, child, pool, owned, out digestAlgAndValue, out error))
            {
                return false;
            }

            hasDigestAlgAndValue = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OCSPIdentifier"u8)
                || (hasDigestAlgAndValue && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "DigestAlgAndValue"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESOcspRef(table, elementIndex, ocspIdentifier, hasDigestAlgAndValue, digestAlgAndValue);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESOcspRef other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESOcspRef other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESOcspRef left, XAdESOcspRef right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESOcspRef left, XAdESOcspRef right) => !left.Equals(right);
}


/// <summary>
/// The <c>CompleteRevocationRefsType</c> data type (Annex A.1.2, v1.3.2 namespace): three individually-
/// optional lists in fixed sequence order — <c>CRLRefs</c> (one-or-more <c>CRLRef</c> entries), <c>OCSPRefs</c>
/// (one-or-more <c>OCSPRef</c> entries), <c>OtherRefs</c> (one-or-more unmodeled <c>OtherRef</c> entries) —
/// plus an optional <c>Id</c>. This is the ONE shared reader backing BOTH the <c>CompleteRevocationRefs</c>
/// qualifying property (A.1.2, read via <see cref="TryReadCompleteRevocationRefs"/>) and the
/// <c>AttributeRevocationRefs</c> qualifying property (A.1.4, "shall be defined as in XML Schema file ...
/// <c>&lt;xsd:element name="AttributeRevocationRefs" type="CompleteRevocationRefsType"/&gt;</c>" — no new
/// complex type of its own; read via <see cref="TryReadAttributeRevocationRefs"/>): the shared
/// <see cref="TryRead"/> core does not itself check the wrapping element's local name, the same posture
/// <see cref="XAdESCertificateValues"/>/<see cref="XAdESRevocationValues"/> already take. Unlike
/// <see cref="XAdESRevocationValues"/>'s parallel three-list shape, A.1.2's OWN prose imposes a cross-child
/// floor the schema cannot express: "Empty <c>CompleteRevocationRefs</c> qualifying properties shall not be
/// incorporated" — enforced ONLY by <see cref="TryReadCompleteRevocationRefs"/> as
/// <see cref="XAdESReadFailure.EmptyCompleteRevocationRefs"/>. A.1.4 states no equivalent sentence for
/// <c>AttributeRevocationRefs</c> and the schema makes all three children <c>minOccurs="0"</c>, so
/// <see cref="TryReadAttributeRevocationRefs"/> applies no such floor — the same
/// <see cref="XAdESValidationData.TryReadAnyValidationData"/>/<see cref="XAdESValidationData.TryReadTimeStampValidationData"/>
/// shared-core/per-property-narrowing split precedent.
/// </summary>
/// <remarks>
/// <para>
/// A.1.2's closing conditional-<c>shall</c> paragraph (mirrored verbatim by A.1.4 for
/// <c>AttributeRevocationRefs</c>) and the Delta-CRL completeness rule are both DER-content/digest-dependent:
/// this leaf delivers only the structural/input half — see <see cref="XAdESValidationDataTrigger"/> for the
/// former (completed above the leaf by <c>XAdESLevelRules.CheckReferencesResolveToValidationDataAsync</c>),
/// and <see cref="XAdESCrlRef"/>'s own remarks for the latter (a recorded, verification-side disposition).
/// </para>
/// <para>
/// A.1.2's own five-item content-selection list (mirroring A.1.1's own, for revocation data rather than
/// certificates) and A.1.4's own three-item list (the "if not already present within
/// <c>CompleteRevocationRefs</c>" gate plus its three <c>should not</c>-duplicate clauses, mirroring A.1.3's
/// own shape) are both chain-dependent — permanent delegate-seam obligations,
/// the same family as clause 5.4's own content-selection lists and
/// <see cref="XAdESCompleteCertificateRefsV2"/>'s own recorded disposition.
/// </para>
/// <para>
/// The XMLDSIG clause 4.5.4.1 Distinguished Name string-format obligation on <c>Issuer</c>/<c>ByName</c> is
/// carried as an opaque string with the format obligation recorded here rather than validated — this leaf
/// performs no DN parsing anywhere, the same uniform posture it takes for every other externally-formatted
/// string field.
/// </para>
/// <para>
/// This is an Annex A reader that decodes pooled content of its own (any <c>DigestAlgAndValue</c>'s
/// <c>DigestValueOctets</c>, any <c>OCSPIdentifier</c>'s possible <c>ByKey</c> octets), so — like
/// <see cref="XAdESRevocationValues"/> — it is itself <see cref="IDisposable"/>, owning one flat custody list
/// across every decoded field.
/// </para>
/// </remarks>
public sealed class XAdESCompleteRevocationRefs: IDisposable
{
    /// <summary>
    /// The maximum number of <c>CRLRef</c>/<c>OCSPRef</c> entries <see cref="TryReadNonEmptyCrlRefList"/>/
    /// <see cref="TryReadNonEmptyOcspRefList"/> accept under one <c>CRLRefs</c>/<c>OCSPRefs</c> list element
    /// before refusing with <see cref="XAdESReadFailure.EntryCountLimitExceeded"/> — a documented hardening
    /// bound, since each entry decodes a full <c>DigestAlgAndValue</c> (and, for a <c>CRLRef</c>, an optional
    /// <c>CRLIdentifier</c>) and the schema's own <c>maxOccurs="unbounded"</c> content model sets no numeric
    /// limit. Chosen generously above any legitimate validation-data set's own size;
    /// <c>XAdESGrowthBoundsCostTests.CrlRefFloodIsRefusedWithinTheCeiling</c> measures a flood one entry past
    /// this bound refusing well inside its own loose ceiling.
    /// </summary>
    public const int MaximumRevocationRefEntryCount = 4096;

    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>CRLRefs</c> child is present.</summary>
    public bool HasCrlRefs { get; }

    /// <summary>The <c>CRLRef</c> entries, in document order; non-empty when <see cref="HasCrlRefs"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESCrlRef> CrlRefs { get; }

    /// <summary>Whether the optional <c>OCSPRefs</c> child is present.</summary>
    public bool HasOcspRefs { get; }

    /// <summary>The <c>OCSPRef</c> entries, in document order; non-empty when <see cref="HasOcspRefs"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESOcspRef> OcspRefs { get; }

    /// <summary>Whether the optional <c>OtherRefs</c> child is present.</summary>
    public bool HasOtherRefs { get; }

    /// <summary>The <c>OtherRef</c> entries' unmodeled content, in document order; non-empty when <see cref="HasOtherRefs"/> is <see langword="true"/>, empty otherwise.</summary>
    public IReadOnlyList<XAdESUnmodeledContent> OtherRefs { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESCompleteRevocationRefs(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        bool hasCrlRefs,
        IReadOnlyList<XAdESCrlRef> crlRefs,
        bool hasOcspRefs,
        IReadOnlyList<XAdESOcspRef> ocspRefs,
        bool hasOtherRefs,
        IReadOnlyList<XAdESUnmodeledContent> otherRefs,
        List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasCrlRefs = hasCrlRefs;
        CrlRefs = crlRefs;
        HasOcspRefs = hasOcspRefs;
        OcspRefs = ocspRefs;
        HasOtherRefs = hasOtherRefs;
        OtherRefs = otherRefs;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>CompleteRevocationRefsType</c>-shaped element: its optional <c>Id</c> attribute, then its
    /// optional <c>CRLRefs</c>, <c>OCSPRefs</c> and <c>OtherRefs</c> children, in that fixed order. Enforces no
    /// per-property empty-container floor of its own — see this type's remarks and
    /// <see cref="TryReadCompleteRevocationRefs"/>/<see cref="TryReadAttributeRevocationRefs"/>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>CompleteRevocationRefs</c> or <c>AttributeRevocationRefs</c> element
    /// — typically obtained from an <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.CompleteRevocationRefs"/> or
    /// <see cref="XAdESUnsignedSignaturePropertyName.AttributeRevocationRefs"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when a present list carries zero entries.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        var owned = new List<PooledMemory>();
        try
        {
            bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out XmlSignatureReadError grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }

            bool hasCrlRefs = false;
            var crlRefs = new List<XAdESCrlRef>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CRLRefs"u8))
            {
                int listElementIndex = child;
                if(!TryReadNonEmptyCrlRefList(table, listElementIndex, pool, owned, crlRefs, out error))
                {
                    return false;
                }

                hasCrlRefs = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            bool hasOcspRefs = false;
            var ocspRefs = new List<XAdESOcspRef>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OCSPRefs"u8))
            {
                int listElementIndex = child;
                if(!TryReadNonEmptyOcspRefList(table, listElementIndex, pool, owned, ocspRefs, out error))
                {
                    return false;
                }

                hasOcspRefs = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            bool hasOtherRefs = false;
            var otherRefs = new List<XAdESUnmodeledContent>();
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OtherRefs"u8))
            {
                int listElementIndex = child;
                if(!XAdESRevocationValues.TryReadNonEmptyUnmodeledList(table, listElementIndex, "OtherRef"u8, otherRefs, out error))
                {
                    return false;
                }

                hasOtherRefs = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, listElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            if(scan == ElementScanResult.Found)
            {
                bool isRepeat = (hasCrlRefs && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CRLRefs"u8))
                    || (hasOcspRefs && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OCSPRefs"u8))
                    || (hasOtherRefs && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OtherRefs"u8));
                error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            value = new XAdESCompleteRevocationRefs(table, elementIndex, hasId, idOrdinal, hasCrlRefs, crlRefs, hasOcspRefs, ocspRefs, hasOtherRefs, otherRefs, owned);
            error = default;

            return true;
        }
        finally
        {
            if(value is null)
            {
                for(int i = 0; i < owned.Count; ++i)
                {
                    owned[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Reads a <c>CompleteRevocationRefs</c> element (Annex A.1.2): the shared <see cref="TryRead"/> shape,
    /// narrowed by A.1.2's own closing sentence — "Empty <c>CompleteRevocationRefs</c> qualifying properties
    /// shall not be incorporated" — refusing when none of <c>CRLRefs</c>/<c>OCSPRefs</c>/<c>OtherRefs</c> is
    /// present, a floor the schema's individually-optional <c>minOccurs="0"</c> children cannot themselves
    /// express.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>CompleteRevocationRefs</c> element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure: every <see cref="TryRead"/> refusal, plus
    /// <see cref="XAdESReadFailure.EmptyCompleteRevocationRefs"/> when none of the three children is present.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryReadCompleteRevocationRefs(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error)
    {
        if(!TryRead(table, elementIndex, pool, out value, out error))
        {
            return false;
        }

        if(!value!.HasCrlRefs && !value.HasOcspRefs && !value.HasOtherRefs)
        {
            value.Dispose();
            value = null;
            error = new XAdESReadError(XAdESReadFailure.EmptyCompleteRevocationRefs, 0);

            return false;
        }

        return true;
    }


    /// <summary>
    /// Reads an <c>AttributeRevocationRefs</c> element (Annex A.1.4): the shared <see cref="TryRead"/> shape,
    /// WITHOUT <see cref="TryReadCompleteRevocationRefs"/>'s empty-container-forbidding narrowing — A.1.4
    /// states no equivalent "shall not be incorporated" sentence for an empty instance, and the schema (shared
    /// with <c>CompleteRevocationRefs</c>) makes all three children <c>minOccurs="0"</c>, so a spec-legal
    /// <c>AttributeRevocationRefs</c> carrying none of them reads here.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>AttributeRevocationRefs</c> element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure — every <see cref="TryRead"/> refusal.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryReadAttributeRevocationRefs(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESCompleteRevocationRefs? value, out XAdESReadError error)
    {
        return TryRead(table, elementIndex, pool, out value, out error);
    }


    /// <summary>
    /// Reads a <c>CRLRefs</c>-shaped list element: no attributes of its own, then a non-empty sequence of
    /// <c>CRLRef</c> children.
    /// </summary>
    private static bool TryReadNonEmptyCrlRefList(XmlNodeTable table, int listElementIndex, BaseMemoryPool pool, List<PooledMemory> owned, List<XAdESCrlRef> entries, out XAdESReadError error)
    {
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, listElementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, listElementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found)
        {
            if(!XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CRLRef"u8))
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!XAdESCrlRef.TryRead(table, child, pool, owned, out XAdESCrlRef crlRef, out error))
            {
                return false;
            }

            entries.Add(crlRef);
            if(entries.Count > MaximumRevocationRefEntryCount)
            {
                error = new XAdESReadError(XAdESReadFailure.EntryCountLimitExceeded, 0);

                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(entries.Count == 0)
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Reads an <c>OCSPRefs</c>-shaped list element: no attributes of its own, then a non-empty sequence of
    /// <c>OCSPRef</c> children.
    /// </summary>
    private static bool TryReadNonEmptyOcspRefList(XmlNodeTable table, int listElementIndex, BaseMemoryPool pool, List<PooledMemory> owned, List<XAdESOcspRef> entries, out XAdESReadError error)
    {
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, listElementIndex, 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, listElementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found)
        {
            if(!XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "OCSPRef"u8))
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!XAdESOcspRef.TryRead(table, child, pool, owned, out XAdESOcspRef ocspRef, out error))
            {
                return false;
            }

            entries.Add(ocspRef);
            if(entries.Count > MaximumRevocationRefEntryCount)
            {
                error = new XAdESReadError(XAdESReadFailure.EntryCountLimitExceeded, 0);

                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(entries.Count == 0)
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        error = default;

        return true;
    }


    /// <summary>
    /// Tells whether this value was read over the given table instance — the identity guard this library
    /// requires before any processing that combines this value with another table-scoped argument.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when this value was read from the same table instance.</returns>
    public bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Releases every decoded field <see cref="CrlRefs"/>/<see cref="OcspRefs"/> own. <see cref="Table"/> is
    /// not owned and is not disposed here. Idempotent.
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
