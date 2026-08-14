using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>DSAKeyValue</c> shape of section 4.4.2.1 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see>: ordered <c>ds:CryptoBinary</c> fields, each decoded to its octets, with the
/// section's optional-pair constraints on <c>(P,Q)</c> and <c>(Seed,PgenCounter)</c> enforced structurally.
/// </summary>
public readonly struct XmlDsaKeyValue: IEquatable<XmlDsaKeyValue>
{
    /// <summary>The <c>DSAKeyValue</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The optional <c>P</c> field's decoded octets, or <see langword="null"/>.</summary>
    public PooledMemory? P { get; }

    /// <summary>The optional <c>Q</c> field's decoded octets; present exactly when <see cref="P"/> is.</summary>
    public PooledMemory? Q { get; }

    /// <summary>The optional <c>G</c> field's decoded octets, or <see langword="null"/>.</summary>
    public PooledMemory? G { get; }

    /// <summary>The mandatory <c>Y</c> field's decoded octets.</summary>
    public PooledMemory Y { get; }

    /// <summary>The optional <c>J</c> field's decoded octets, or <see langword="null"/>.</summary>
    public PooledMemory? J { get; }

    /// <summary>The optional <c>Seed</c> field's decoded octets, or <see langword="null"/>.</summary>
    public PooledMemory? Seed { get; }

    /// <summary>The optional <c>PgenCounter</c> field's decoded octets; present exactly when <see cref="Seed"/> is.</summary>
    public PooledMemory? PgenCounter { get; }


    internal XmlDsaKeyValue(int elementIndex, PooledMemory? p, PooledMemory? q, PooledMemory? g, PooledMemory y, PooledMemory? j, PooledMemory? seed, PooledMemory? pgenCounter)
    {
        ElementIndex = elementIndex;
        P = p;
        Q = q;
        G = g;
        Y = y;
        J = j;
        Seed = seed;
        PgenCounter = pgenCounter;
    }


    /// <summary>
    /// Reads a <c>DSAKeyValue</c> element's ordered content: <c>(P,Q)?, G?, Y, J?, (Seed,PgenCounter)?</c>.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlDsaKeyValue value, out XmlSignatureReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error))
        {
            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        PooledMemory? p = null;
        PooledMemory? q = null;
        PooledMemory? g = null;
        PooledMemory? j = null;
        PooledMemory? seed = null;
        PooledMemory? pgenCounter = null;

        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, child, "P"u8))
        {
            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out p, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "Q"u8))
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out q, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        }

        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, child, "G"u8))
        {
            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out g, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        }

        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "Y"u8))
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out PooledMemory? y, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);

        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, child, "J"u8))
        {
            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out j, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        }

        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, child, "Seed"u8))
        {
            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out seed, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "PgenCounter"u8))
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out pgenCounter, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        }

        if(scan == ElementScanResult.Found || scan == ElementScanResult.UnexpectedContent)
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XmlDsaKeyValue(elementIndex, p, q, g, y!, j, seed, pgenCounter);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlDsaKeyValue other) => ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlDsaKeyValue other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlDsaKeyValue left, XmlDsaKeyValue right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlDsaKeyValue left, XmlDsaKeyValue right) => !left.Equals(right);
}


/// <summary>
/// The <c>RSAKeyValue</c> shape of section 4.4.2.2: the ordered <c>Modulus</c> then <c>Exponent</c>
/// <c>ds:CryptoBinary</c> fields, each decoded to its octets.
/// </summary>
public readonly struct XmlRsaKeyValue: IEquatable<XmlRsaKeyValue>
{
    /// <summary>The <c>RSAKeyValue</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The <c>Modulus</c> field's decoded octets.</summary>
    public PooledMemory Modulus { get; }

    /// <summary>The <c>Exponent</c> field's decoded octets.</summary>
    public PooledMemory Exponent { get; }


    internal XmlRsaKeyValue(int elementIndex, PooledMemory modulus, PooledMemory exponent)
    {
        ElementIndex = elementIndex;
        Modulus = modulus;
        Exponent = exponent;
    }


    /// <summary>
    /// Reads an <c>RSAKeyValue</c> element's ordered <c>Modulus, Exponent</c> content.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlRsaKeyValue value, out XmlSignatureReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error))
        {
            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "Modulus"u8))
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out PooledMemory? modulus, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "Exponent"u8))
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out PooledMemory? exponent, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out _);
        if(scan != ElementScanResult.EndOfChildren)
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XmlRsaKeyValue(elementIndex, modulus!, exponent!);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlRsaKeyValue other) => ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlRsaKeyValue other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlRsaKeyValue left, XmlRsaKeyValue right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlRsaKeyValue left, XmlRsaKeyValue right) => !left.Equals(right);
}


/// <summary>Which structured form a <c>KeyValue</c> element's single child takes, per section 4.4.2.</summary>
public enum XmlKeyValueKind
{
    /// <summary>A <c>DSAKeyValue</c> child.</summary>
    Dsa,

    /// <summary>An <c>RSAKeyValue</c> child.</summary>
    Rsa,

    /// <summary>A <c>##other</c>-namespace child this leaf does not model further.</summary>
    Foreign
}


/// <summary>
/// One <c>ds:KeyValue</c> element: its single <c>DSAKeyValue</c>, <c>RSAKeyValue</c> or foreign-namespace
/// child, per section 4.4.2.
/// </summary>
public readonly struct XmlKeyValue: IEquatable<XmlKeyValue>
{
    /// <summary>The <c>KeyValue</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Which structured form the child takes.</summary>
    public XmlKeyValueKind Kind { get; }

    /// <summary>The child element's own index.</summary>
    public int ChildElementIndex { get; }

    /// <summary>The <c>DSAKeyValue</c> content, present exactly when <see cref="Kind"/> is <see cref="XmlKeyValueKind.Dsa"/>.</summary>
    public XmlDsaKeyValue? Dsa { get; }

    /// <summary>The <c>RSAKeyValue</c> content, present exactly when <see cref="Kind"/> is <see cref="XmlKeyValueKind.Rsa"/>.</summary>
    public XmlRsaKeyValue? Rsa { get; }


    private XmlKeyValue(int elementIndex, XmlKeyValueKind kind, int childElementIndex, XmlDsaKeyValue? dsa, XmlRsaKeyValue? rsa)
    {
        ElementIndex = elementIndex;
        Kind = kind;
        ChildElementIndex = childElementIndex;
        Dsa = dsa;
        Rsa = rsa;
    }


    /// <summary>
    /// Reads a <c>KeyValue</c> element: exactly one child, dispatched by name into <c>DSAKeyValue</c>,
    /// <c>RSAKeyValue</c> or a tolerated foreign-namespace element.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlKeyValue value, out XmlSignatureReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error))
        {
            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found)
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int trailing);
        if(scan != ElementScanResult.EndOfChildren)
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.DuplicateCoreChild, 0);
            _ = trailing;

            return false;
        }

        bool isDs = table.NamespaceUriOf(child).SequenceEqual(XmlSignatureIdentifiers.XmlSignatureNamespaceUtf8);
        if(isDs && table.LocalNameOf(child).SequenceEqual("DSAKeyValue"u8))
        {
            if(!XmlDsaKeyValue.TryRead(table, child, pool, owned, out XmlDsaKeyValue dsa, out error))
            {
                return false;
            }

            value = new XmlKeyValue(elementIndex, XmlKeyValueKind.Dsa, child, dsa, null);
            error = default;

            return true;
        }

        if(isDs && table.LocalNameOf(child).SequenceEqual("RSAKeyValue"u8))
        {
            if(!XmlRsaKeyValue.TryRead(table, child, pool, owned, out XmlRsaKeyValue rsa, out error))
            {
                return false;
            }

            value = new XmlKeyValue(elementIndex, XmlKeyValueKind.Rsa, child, null, rsa);
            error = default;

            return true;
        }

        if(isDs)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XmlKeyValue(elementIndex, XmlKeyValueKind.Foreign, child, null, null);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlKeyValue other) => ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlKeyValue other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlKeyValue left, XmlKeyValue right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlKeyValue left, XmlKeyValue right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:RetrievalMethod</c> element: its <c>URI</c>/<c>Type</c> attributes and optional
/// <c>Transforms</c> child, per section 4.4.3. The referenced key material is never fetched — the section
/// 4.3.3.2 dereferencing model this element reuses is a caller concern.
/// </summary>
public readonly struct XmlRetrievalMethod: IEquatable<XmlRetrievalMethod>
{
    /// <summary>The table the method's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>RetrievalMethod</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>
    /// Whether the <c>URI</c> attribute is present. Section 4.4.3 states presence is mandatory, but its own
    /// errata records that the published schema omits <c>use="required"</c> and that documents relying on
    /// the lax schema are not to be broken by a stricter reader — so this model exposes absence rather than
    /// refusing it.
    /// </summary>
    public bool HasUri { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The <c>URI</c> attribute value.</summary>
    public ReadOnlySpan<byte> Uri => HasUri ? Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>Type</c> attribute is present.</summary>
    public bool HasType { get; }

    private int TypeAttributeOrdinal { get; }

    /// <summary>The <c>Type</c> attribute value.</summary>
    public ReadOnlySpan<byte> Type => HasType ? Table.AttributeValueOf(ElementIndex, TypeAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The method's transform chain, in document order; empty when no <c>Transforms</c> element is present.</summary>
    public IReadOnlyList<XmlTransform> Transforms { get; }


    private XmlRetrievalMethod(XmlNodeTable table, int elementIndex, bool hasUri, int uriAttributeOrdinal, bool hasType, int typeAttributeOrdinal, IReadOnlyList<XmlTransform> transforms)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasUri = hasUri;
        UriAttributeOrdinal = uriAttributeOrdinal;
        HasType = hasType;
        TypeAttributeOrdinal = typeAttributeOrdinal;
        Transforms = transforms;
    }


    /// <summary>
    /// Reads a <c>RetrievalMethod</c> element: its attributes and its optional <c>Transforms</c> child.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XmlRetrievalMethod method, out XmlSignatureReadError error)
    {
        method = default;
        bool hasUri = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal);
        bool hasType = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Type"u8, out int typeOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, (hasUri ? 1 : 0) + (hasType ? 1 : 0), out error))
        {
            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        List<XmlTransform> transforms = [];
        if(scan == ElementScanResult.Found)
        {
            if(!XmlSignatureModelGrammar.IsDsElement(table, child, "Transforms"u8))
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

                return false;
            }

            if(!XmlTransform.TryReadList(table, child, out transforms, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out int trailing);
            if(scan != ElementScanResult.EndOfChildren)
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.UnknownCoreElement, 0);
                _ = trailing;

                return false;
            }
        }

        method = new XmlRetrievalMethod(table, elementIndex, hasUri, uriOrdinal, hasType, typeOrdinal, transforms);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlRetrievalMethod other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlRetrievalMethod other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlRetrievalMethod left, XmlRetrievalMethod right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlRetrievalMethod left, XmlRetrievalMethod right) => !left.Equals(right);
}


/// <summary>Which member kind one child of an <c>X509Data</c> element is, per section 4.4.4.</summary>
public enum XmlX509DataMemberKind
{
    /// <summary>An <c>X509IssuerSerial</c> member.</summary>
    IssuerSerial,

    /// <summary>An <c>X509SKI</c> member.</summary>
    SubjectKeyIdentifier,

    /// <summary>An <c>X509SubjectName</c> member.</summary>
    SubjectName,

    /// <summary>An <c>X509Certificate</c> member.</summary>
    Certificate,

    /// <summary>An <c>X509CRL</c> member.</summary>
    CertificateRevocationList,

    /// <summary>A <c>##other</c>-namespace member this leaf does not model further.</summary>
    Foreign
}


/// <summary>
/// One child of an <c>X509Data</c> element, per section 4.4.4: an <c>X509IssuerSerial</c> (issuer name and
/// serial number spans), an <c>X509SKI</c>/<c>X509Certificate</c>/<c>X509CRL</c> (each decoded to octets —
/// <c>X509Certificate</c>'s DER bytes among them), an <c>X509SubjectName</c> (a span), or a foreign-namespace
/// element.
/// </summary>
public readonly struct XmlX509DataMember: IEquatable<XmlX509DataMember>
{
    /// <summary>The table the member's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>Which member kind this is.</summary>
    public XmlX509DataMemberKind Kind { get; }

    /// <summary>The member element's own index.</summary>
    public int ElementIndex { get; }

    private int IssuerNameTextNodeIndex { get; }

    /// <summary>The <c>X509IssuerSerial</c>'s <c>X509IssuerName</c> content, valid when <see cref="Kind"/> is <see cref="XmlX509DataMemberKind.IssuerSerial"/>.</summary>
    public ReadOnlySpan<byte> IssuerName => IssuerNameTextNodeIndex >= 0 ? Table.ValueOf(IssuerNameTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    private int SerialNumberTextNodeIndex { get; }

    /// <summary>The <c>X509IssuerSerial</c>'s <c>X509SerialNumber</c> content, valid when <see cref="Kind"/> is <see cref="XmlX509DataMemberKind.IssuerSerial"/>.</summary>
    public ReadOnlySpan<byte> SerialNumber => SerialNumberTextNodeIndex >= 0 ? Table.ValueOf(SerialNumberTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    private int SubjectNameTextNodeIndex { get; }

    /// <summary>The <c>X509SubjectName</c> content, valid when <see cref="Kind"/> is <see cref="XmlX509DataMemberKind.SubjectName"/>.</summary>
    public ReadOnlySpan<byte> SubjectName => SubjectNameTextNodeIndex >= 0 ? Table.ValueOf(SubjectNameTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>The decoded octets, valid when <see cref="Kind"/> is <see cref="XmlX509DataMemberKind.SubjectKeyIdentifier"/>, <see cref="XmlX509DataMemberKind.Certificate"/> or <see cref="XmlX509DataMemberKind.CertificateRevocationList"/>.</summary>
    public PooledMemory? DecodedOctets { get; }


    private XmlX509DataMember(XmlNodeTable table, XmlX509DataMemberKind kind, int elementIndex, int issuerNameTextNodeIndex, int serialNumberTextNodeIndex, int subjectNameTextNodeIndex, PooledMemory? decodedOctets)
    {
        Table = table;
        Kind = kind;
        ElementIndex = elementIndex;
        IssuerNameTextNodeIndex = issuerNameTextNodeIndex;
        SerialNumberTextNodeIndex = serialNumberTextNodeIndex;
        SubjectNameTextNodeIndex = subjectNameTextNodeIndex;
        DecodedOctets = decodedOctets;
    }


    /// <summary>
    /// Reads one <c>X509Data</c> child, dispatching on its <c>ds</c>-namespace local name.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlX509DataMember member, out XmlSignatureReadError error)
    {
        member = default;
        bool isDs = table.NamespaceUriOf(elementIndex).SequenceEqual(XmlSignatureIdentifiers.XmlSignatureNamespaceUtf8);
        if(!isDs)
        {
            member = new XmlX509DataMember(table, XmlX509DataMemberKind.Foreign, elementIndex, -1, -1, -1, null);
            error = default;

            return true;
        }

        ReadOnlySpan<byte> localName = table.LocalNameOf(elementIndex);
        if(localName.SequenceEqual("X509IssuerSerial"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error))
            {
                return false;
            }

            ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "X509IssuerName"u8))
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int issuerNameTextNodeIndex, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsDsElement(table, child, "X509SerialNumber"u8))
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }

            if(!XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out int serialNumberTextNodeIndex, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out _);
            if(scan != ElementScanResult.EndOfChildren)
            {
                error = new XmlSignatureReadError(
                    scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.UnknownCoreElement, 0);

                return false;
            }

            member = new XmlX509DataMember(table, XmlX509DataMemberKind.IssuerSerial, elementIndex, issuerNameTextNodeIndex, serialNumberTextNodeIndex, -1, null);
            error = default;

            return true;
        }

        if(localName.SequenceEqual("X509SubjectName"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, elementIndex, out int subjectNameTextNodeIndex, out error))
            {
                return false;
            }

            member = new XmlX509DataMember(table, XmlX509DataMemberKind.SubjectName, elementIndex, -1, -1, subjectNameTextNodeIndex, null);
            error = default;

            return true;
        }

        XmlX509DataMemberKind? decodedKind = localName switch
        {
            _ when localName.SequenceEqual("X509SKI"u8) => XmlX509DataMemberKind.SubjectKeyIdentifier,
            _ when localName.SequenceEqual("X509Certificate"u8) => XmlX509DataMemberKind.Certificate,
            _ when localName.SequenceEqual("X509CRL"u8) => XmlX509DataMemberKind.CertificateRevocationList,
            _ => null
        };
        if(decodedKind is null)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error)
            || !XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, elementIndex, pool, owned, out PooledMemory? decoded, out error))
        {
            return false;
        }

        member = new XmlX509DataMember(table, decodedKind.Value, elementIndex, -1, -1, -1, decoded);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlX509DataMember other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlX509DataMember other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlX509DataMember left, XmlX509DataMember right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlX509DataMember left, XmlX509DataMember right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:PGPData</c> element: its optional <c>PGPKeyID</c> and <c>PGPKeyPacket</c> fields, each decoded
/// to octets, per section 4.4.5 — at least one of the two is required.
/// </summary>
public readonly struct XmlPgpData: IEquatable<XmlPgpData>
{
    /// <summary>The <c>PGPData</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The decoded <c>PGPKeyID</c> octets, or <see langword="null"/> when absent.</summary>
    public PooledMemory? KeyId { get; }

    /// <summary>The decoded <c>PGPKeyPacket</c> octets, or <see langword="null"/> when absent.</summary>
    public PooledMemory? KeyPacket { get; }


    private XmlPgpData(int elementIndex, PooledMemory? keyId, PooledMemory? keyPacket)
    {
        ElementIndex = elementIndex;
        KeyId = keyId;
        KeyPacket = keyPacket;
    }


    /// <summary>
    /// Reads a <c>PGPData</c> element's <c>(PGPKeyID, PGPKeyPacket?) | PGPKeyPacket</c> content.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlPgpData value, out XmlSignatureReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error))
        {
            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        if(scan != ElementScanResult.Found)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        PooledMemory? keyId = null;
        PooledMemory? keyPacket = null;
        if(XmlSignatureModelGrammar.IsDsElement(table, child, "PGPKeyID"u8))
        {
            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out keyId, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        }

        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsDsElement(table, child, "PGPKeyPacket"u8))
        {
            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out keyPacket, out error))
            {
                return false;
            }

            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out _);
        }

        if(scan == ElementScanResult.Found || scan == ElementScanResult.UnexpectedContent)
        {
            error = new XmlSignatureReadError(
                scan == ElementScanResult.UnexpectedContent ? XmlSignatureReadFailure.UnexpectedElementContent : XmlSignatureReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(keyId is null && keyPacket is null)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        value = new XmlPgpData(elementIndex, keyId, keyPacket);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlPgpData other) => ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlPgpData other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlPgpData left, XmlPgpData right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlPgpData left, XmlPgpData right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:SPKIData</c> element: its one-or-more <c>SPKISexp</c> fields, each decoded to octets, per
/// section 4.4.6.
/// </summary>
public readonly struct XmlSpkiData: IEquatable<XmlSpkiData>
{
    /// <summary>The <c>SPKIData</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The decoded <c>SPKISexp</c> octets, in document order; at least one.</summary>
    public IReadOnlyList<PooledMemory> Sexps { get; }


    private XmlSpkiData(int elementIndex, IReadOnlyList<PooledMemory> sexps)
    {
        ElementIndex = elementIndex;
        Sexps = sexps;
    }


    /// <summary>
    /// Reads a <c>SPKIData</c> element's <c>SPKISexp+</c> content, tolerating interspersed
    /// <c>##other</c>-namespace elements it does not model further.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlSpkiData value, out XmlSignatureReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error)
            || !XmlSignatureModelGrammar.TryReadElementChildren(table, elementIndex, out List<int> children, out error))
        {
            return false;
        }

        var sexps = new List<PooledMemory>();
        foreach(int child in children)
        {
            if(!XmlSignatureModelGrammar.IsDsElement(table, child, "SPKISexp"u8))
            {
                continue;
            }

            if(!XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out PooledMemory? sexp, out error))
            {
                return false;
            }

            sexps.Add(sexp!);
        }

        if(sexps.Count == 0)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        value = new XmlSpkiData(elementIndex, sexps);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlSpkiData other) => ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlSpkiData other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlSpkiData left, XmlSpkiData right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlSpkiData left, XmlSpkiData right) => !left.Equals(right);
}


/// <summary>Which shape one child of a <c>KeyInfo</c> element takes, per section 4.4.</summary>
public enum XmlKeyInfoChildKind
{
    /// <summary>A <c>KeyName</c> child.</summary>
    KeyName,

    /// <summary>A <c>KeyValue</c> child.</summary>
    KeyValue,

    /// <summary>A <c>RetrievalMethod</c> child.</summary>
    RetrievalMethod,

    /// <summary>An <c>X509Data</c> child.</summary>
    X509Data,

    /// <summary>A <c>PGPData</c> child.</summary>
    PGPData,

    /// <summary>A <c>SPKIData</c> child.</summary>
    SPKIData,

    /// <summary>A <c>MgmtData</c> child.</summary>
    MgmtData,

    /// <summary>A <c>##other</c>-namespace child, carried as an opaque node index per section 4.4's extension rule.</summary>
    Foreign
}


/// <summary>
/// One child of a <c>ds:KeyInfo</c> element, per section 4.4: the choice content model of <c>KeyName</c>,
/// <c>KeyValue</c>, <c>RetrievalMethod</c>, <c>X509Data</c>, <c>PGPData</c>, <c>SPKIData</c>,
/// <c>MgmtData</c> or a foreign-namespace element, "handled as a discriminated union — <c>KeyInfo</c>
/// permits any number of any of them in any order ("multiple declarations within <c>KeyInfo</c> refer to
/// the same key"), so nothing here enforces cardinality or order among children of different kinds.
/// </summary>
public readonly struct XmlKeyInfoChild: IEquatable<XmlKeyInfoChild>
{
    /// <summary>The table the child's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>Which shape this child takes.</summary>
    public XmlKeyInfoChildKind Kind { get; }

    /// <summary>The child element's own index.</summary>
    public int ElementIndex { get; }

    private int KeyNameTextNodeIndex { get; }

    /// <summary>The <c>KeyName</c> content, valid when <see cref="Kind"/> is <see cref="XmlKeyInfoChildKind.KeyName"/>.</summary>
    public ReadOnlySpan<byte> KeyNameValue => KeyNameTextNodeIndex >= 0 ? Table.ValueOf(KeyNameTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>The <c>KeyValue</c> content, valid when <see cref="Kind"/> is <see cref="XmlKeyInfoChildKind.KeyValue"/>.</summary>
    public XmlKeyValue? KeyValue { get; }

    /// <summary>The <c>RetrievalMethod</c> content, valid when <see cref="Kind"/> is <see cref="XmlKeyInfoChildKind.RetrievalMethod"/>.</summary>
    public XmlRetrievalMethod? RetrievalMethod { get; }

    /// <summary>The <c>X509Data</c> members, valid when <see cref="Kind"/> is <see cref="XmlKeyInfoChildKind.X509Data"/>.</summary>
    public IReadOnlyList<XmlX509DataMember>? X509DataMembers { get; }

    /// <summary>The <c>PGPData</c> content, valid when <see cref="Kind"/> is <see cref="XmlKeyInfoChildKind.PGPData"/>.</summary>
    public XmlPgpData? PgpData { get; }

    /// <summary>The <c>SPKIData</c> content, valid when <see cref="Kind"/> is <see cref="XmlKeyInfoChildKind.SPKIData"/>.</summary>
    public XmlSpkiData? SpkiData { get; }

    private int MgmtDataTextNodeIndex { get; }

    /// <summary>The <c>MgmtData</c> content, valid when <see cref="Kind"/> is <see cref="XmlKeyInfoChildKind.MgmtData"/>.</summary>
    public ReadOnlySpan<byte> MgmtDataValue => MgmtDataTextNodeIndex >= 0 ? Table.ValueOf(MgmtDataTextNodeIndex) : ReadOnlySpan<byte>.Empty;


    private XmlKeyInfoChild(
        XmlNodeTable table,
        XmlKeyInfoChildKind kind,
        int elementIndex,
        int keyNameTextNodeIndex,
        XmlKeyValue? keyValue,
        XmlRetrievalMethod? retrievalMethod,
        IReadOnlyList<XmlX509DataMember>? x509DataMembers,
        XmlPgpData? pgpData,
        XmlSpkiData? spkiData,
        int mgmtDataTextNodeIndex)
    {
        Table = table;
        Kind = kind;
        ElementIndex = elementIndex;
        KeyNameTextNodeIndex = keyNameTextNodeIndex;
        KeyValue = keyValue;
        RetrievalMethod = retrievalMethod;
        X509DataMembers = x509DataMembers;
        PgpData = pgpData;
        SpkiData = spkiData;
        MgmtDataTextNodeIndex = mgmtDataTextNodeIndex;
    }


    /// <summary>
    /// Reads one <c>KeyInfo</c> child, dispatching on its <c>ds</c>-namespace local name.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlKeyInfoChild child, out XmlSignatureReadError error)
    {
        child = default;
        bool isDs = table.NamespaceUriOf(elementIndex).SequenceEqual(XmlSignatureIdentifiers.XmlSignatureNamespaceUtf8);
        if(!isDs)
        {
            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.Foreign, elementIndex, -1, null, null, null, null, null, -1);
            error = default;

            return true;
        }

        ReadOnlySpan<byte> localName = table.LocalNameOf(elementIndex);
        if(localName.SequenceEqual("KeyName"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, elementIndex, out int textNodeIndex, out error))
            {
                return false;
            }

            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.KeyName, elementIndex, textNodeIndex, null, null, null, null, null, -1);
            error = default;

            return true;
        }

        if(localName.SequenceEqual("MgmtData"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, elementIndex, out int textNodeIndex, out error))
            {
                return false;
            }

            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.MgmtData, elementIndex, -1, null, null, null, null, null, textNodeIndex);
            error = default;

            return true;
        }

        if(localName.SequenceEqual("KeyValue"u8))
        {
            if(!XmlKeyValue.TryRead(table, elementIndex, pool, owned, out XmlKeyValue keyValue, out error))
            {
                return false;
            }

            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.KeyValue, elementIndex, -1, keyValue, null, null, null, null, -1);
            error = default;

            return true;
        }

        if(localName.SequenceEqual("RetrievalMethod"u8))
        {
            if(!XmlRetrievalMethod.TryRead(table, elementIndex, out XmlRetrievalMethod retrievalMethod, out error))
            {
                return false;
            }

            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.RetrievalMethod, elementIndex, -1, null, retrievalMethod, null, null, null, -1);
            error = default;

            return true;
        }

        if(localName.SequenceEqual("X509Data"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out error)
                || !XmlSignatureModelGrammar.TryReadElementChildren(table, elementIndex, out List<int> memberIndices, out error))
            {
                return false;
            }

            if(memberIndices.Count == 0)
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

                return false;
            }

            var members = new List<XmlX509DataMember>(memberIndices.Count);
            foreach(int memberIndex in memberIndices)
            {
                if(!XmlX509DataMember.TryRead(table, memberIndex, pool, owned, out XmlX509DataMember member, out error))
                {
                    return false;
                }

                members.Add(member);
            }

            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.X509Data, elementIndex, -1, null, null, members, null, null, -1);
            error = default;

            return true;
        }

        if(localName.SequenceEqual("PGPData"u8))
        {
            if(!XmlPgpData.TryRead(table, elementIndex, pool, owned, out XmlPgpData pgpData, out error))
            {
                return false;
            }

            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.PGPData, elementIndex, -1, null, null, null, pgpData, null, -1);
            error = default;

            return true;
        }

        if(localName.SequenceEqual("SPKIData"u8))
        {
            if(!XmlSpkiData.TryRead(table, elementIndex, pool, owned, out XmlSpkiData spkiData, out error))
            {
                return false;
            }

            child = new XmlKeyInfoChild(table, XmlKeyInfoChildKind.SPKIData, elementIndex, -1, null, null, null, null, spkiData, -1);
            error = default;

            return true;
        }

        error = new XmlSignatureReadError(XmlSignatureReadFailure.UnknownCoreElement, 0);

        return false;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlKeyInfoChild other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlKeyInfoChild other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlKeyInfoChild left, XmlKeyInfoChild right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlKeyInfoChild left, XmlKeyInfoChild right) => !left.Equals(right);
}


/// <summary>
/// One <c>ds:KeyInfo</c> element: its optional <c>Id</c> attribute and its one-or-more children, per
/// section 4.4.
/// </summary>
public readonly struct XmlKeyInfo: IEquatable<XmlKeyInfo>
{
    /// <summary>The table the info's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>KeyInfo</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The children, in document order; at least one.</summary>
    public IReadOnlyList<XmlKeyInfoChild> Children { get; }


    private XmlKeyInfo(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XmlKeyInfoChild> children)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Children = children;
    }


    /// <summary>
    /// Reads a <c>KeyInfo</c> element: its <c>Id</c> attribute and its choice-content children.
    /// </summary>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XmlKeyInfo keyInfo, out XmlSignatureReadError error)
    {
        keyInfo = default;
        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out error))
        {
            return false;
        }

        if(!XmlSignatureModelGrammar.TryReadElementChildren(table, elementIndex, out List<int> childIndices, out error))
        {
            return false;
        }

        if(childIndices.Count == 0)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.MissingRequiredChild, 0);

            return false;
        }

        var children = new List<XmlKeyInfoChild>(childIndices.Count);
        foreach(int childIndex in childIndices)
        {
            if(!XmlKeyInfoChild.TryRead(table, childIndex, pool, owned, out XmlKeyInfoChild child, out error))
            {
                return false;
            }

            children.Add(child);
        }

        keyInfo = new XmlKeyInfo(table, elementIndex, hasId, idOrdinal, children);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XmlKeyInfo other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XmlKeyInfo other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XmlKeyInfo left, XmlKeyInfo right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XmlKeyInfo left, XmlKeyInfo right) => !left.Equals(right);
}
