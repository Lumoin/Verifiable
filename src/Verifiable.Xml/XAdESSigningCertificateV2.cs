using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// One <c>Cert</c> entry of a <c>SigningCertificateV2</c> qualifying property (clause 5.2.2's
/// <c>CertIDTypeV2</c>): a mandatory <c>CertDigest</c> (the shared <c>DigestAlgAndValueType</c> reader), an
/// optional <c>IssuerSerialV2</c> carried as opaque, pooled, base64-decoded DER
/// bytes — the RFC 5035 <c>IssuerSerial</c> SEQUENCE this leaf never parses, since ASN.1 decoding is Pki
/// territory (this crypto-free leaf's own boundary) — and an optional, advisory <c>URI</c>
/// attribute.
/// </summary>
/// <remarks>
/// <c>IssuerSerialV2</c>'s content is "the base-64 encoding of one DER-encoded instance of type
/// <c>IssuerSerial</c> ... defined in IETF RFC 5035" — an RFC 5035 ESSCertIDv2-family <c>IssuerSerial</c>
/// (<c>issuer GeneralNames</c>, <c>serialNumber CertificateSerialNumber</c>), distinct from RFC 5280's own,
/// differently-shaped <c>IssuerSerial</c> constructs (e.g. inside <c>AuthorityKeyIdentifier</c>). NOTE 2 of
/// clause 5.2.2 states it is only a hint; the binding proof is <see cref="CertDigest"/>, not this pair.
/// </remarks>
public readonly struct XAdESCertIdV2: IEquatable<XAdESCertIdV2>
{
    /// <summary>The table the value's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>Cert</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The <c>CertDigest</c> child: the referenced certificate's digest algorithm and value.</summary>
    public XAdESDigestAlgAndValue CertDigest { get; }

    /// <summary>Whether the optional <c>IssuerSerialV2</c> child is present.</summary>
    public bool HasIssuerSerialV2 { get; }

    /// <summary>
    /// The decoded <c>IssuerSerialV2</c> octets — an opaque, DER-encoded RFC 5035 <c>IssuerSerial</c> SEQUENCE
    /// this leaf does not decode — tagged <see cref="BufferTags.XmlDecodedContent"/>; meaningful only when
    /// <see cref="HasIssuerSerialV2"/> is <see langword="true"/>. Owned by the caller's custody list.
    /// </summary>
    public PooledMemory? IssuerSerialV2Octets { get; }

    /// <summary>Whether the optional, advisory <c>URI</c> attribute is present.</summary>
    public bool HasUri { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The <c>URI</c> attribute value — a retrieval hint only (NOTE 3), never authoritative.</summary>
    public ReadOnlySpan<byte> Uri => HasUri ? Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal) : ReadOnlySpan<byte>.Empty;


    private XAdESCertIdV2(
        XmlNodeTable table,
        int elementIndex,
        XAdESDigestAlgAndValue certDigest,
        bool hasIssuerSerialV2,
        PooledMemory? issuerSerialV2Octets,
        bool hasUri,
        int uriAttributeOrdinal)
    {
        Table = table;
        ElementIndex = elementIndex;
        CertDigest = certDigest;
        HasIssuerSerialV2 = hasIssuerSerialV2;
        IssuerSerialV2Octets = issuerSerialV2Octets;
        HasUri = hasUri;
        UriAttributeOrdinal = uriAttributeOrdinal;
    }


    /// <summary>
    /// Reads a <c>Cert</c> element: its optional <c>URI</c> attribute, then its mandatory <c>CertDigest</c> and
    /// optional <c>IssuerSerialV2</c> children, in that fixed order.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>Cert</c> element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="owned">The caller's custody list. Decoded fields are appended as they are read, including
    /// on paths that subsequently refuse — the caller must dispose the list when this method returns
    /// <see langword="false"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out XAdESCertIdV2 value, out XAdESReadError error)
    {
        value = default;
        bool hasUri = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasUri ? 1 : 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan != ElementScanResult.Found || !XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CertDigest"u8))
        {
            error = new XAdESReadError(
                scan == ElementScanResult.UnexpectedContent ? XAdESReadFailure.UnexpectedElementContent : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(!XAdESDigestAlgAndValue.TryRead(table, child, pool, owned, out XAdESDigestAlgAndValue certDigest, out error))
        {
            return false;
        }

        scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        bool hasIssuerSerialV2 = false;
        PooledMemory? issuerSerialV2Octets = null;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "IssuerSerialV2"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryDecodeSimpleBase64Content(table, child, pool, owned, out issuerSerialV2Octets, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasIssuerSerialV2 = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CertDigest"u8)
                || (hasIssuerSerialV2 && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "IssuerSerialV2"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        value = new XAdESCertIdV2(table, elementIndex, certDigest, hasIssuerSerialV2, issuerSerialV2Octets, hasUri, uriOrdinal);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESCertIdV2 other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESCertIdV2 other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESCertIdV2 left, XAdESCertIdV2 right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESCertIdV2 left, XAdESCertIdV2 right) => !left.Equals(right);
}


/// <summary>
/// The <c>SigningCertificateV2</c> qualifying property of clause 5.2.2: a signed qualifying property that
/// qualifies the signature, containing one-or-more <c>Cert</c> entries (<c>CertIDListV2Type</c>'s
/// <c>Cert+</c>). The first entry is always the signing certificate itself ("The first reference in
/// <c>SigningCertificateV2</c> qualifying property shall be the reference of the signing certificate") — this
/// is positional data <see cref="Certs"/> preserves via document order, not a fact this reader independently
/// verifies (there is nothing in one instance's wire content to check it against): <c>Certs[0]</c> is the
/// signing certificate by construction. Later entries, when present, are additional certificates from the
/// signing certificate's path (clause 5.2.2's <c>may</c>).
/// </summary>
/// <remarks>
/// This is the first clause-5.2 reader that decodes pooled content of its own (via <see cref="XAdESCertIdV2"/>'s
/// <c>CertDigest</c>/<c>IssuerSerialV2</c>), so — unlike <see cref="XAdESSigningTime"/> or the containers above
/// it, which carry none — it is itself <see cref="IDisposable"/>, owning one flat custody list across every
/// <see cref="Certs"/> entry's decoded fields, the same shape <see cref="XmlManifest"/> uses for its own
/// <c>Reference</c> children's decoded digest values.
/// </remarks>
public sealed class XAdESSigningCertificateV2: IDisposable
{
    /// <summary>
    /// The maximum number of <c>Cert</c> entries <see cref="TryReadCertIdListV2"/> accepts under one
    /// <c>CertIDListV2Type</c>-shaped element before refusing with <see cref="XAdESReadFailure.EntryCountLimitExceeded"/>
    /// — a documented hardening bound shared by every site the shared reader backs (<c>SigningCertificateV2</c>
    /// clause 5.2.2, <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> Annex A.1.1/A.1.3), since
    /// each entry decodes a full <c>CertDigest</c> (and, often, a base64 <c>IssuerSerialV2</c>) and the schema's
    /// own <c>maxOccurs="unbounded"</c> content model sets no numeric limit. Chosen generously above any
    /// legitimate certificate chain's own length; <c>XAdESGrowthBoundsCostTests.CertIdListV2FloodIsRefusedWithinTheCeiling</c>
    /// measures a flood one entry past this bound refusing well inside its own loose ceiling.
    /// </summary>
    public const int MaximumCertIdListEntryCount = 4096;

    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>SigningCertificateV2</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The <c>Cert</c> entries, in document order; at least one. <c>Certs[0]</c> is the signing certificate.</summary>
    public IReadOnlyList<XAdESCertIdV2> Certs { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESSigningCertificateV2(XmlNodeTable table, int elementIndex, IReadOnlyList<XAdESCertIdV2> certs, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        Certs = certs;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>SigningCertificateV2</c> element: no attributes of its own, then one-or-more <c>Cert</c>
    /// children.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SigningCertificateV2</c> element — typically obtained from a
    /// <see cref="XAdESSignedSignaturePropertyEntry"/> whose <see cref="XAdESSignedSignaturePropertyEntry.Name"/>
    /// is <see cref="XAdESSignedSignaturePropertyName.SigningCertificateV2"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.MissingRequiredChild"/> when no <c>Cert</c> is present (clause 5.2.2's
    /// "shall contain one reference to the signing certificate").</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESSigningCertificateV2? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        var owned = new List<PooledMemory>();
        try
        {
            if(!TryReadCertIdListV2(table, elementIndex, pool, owned, out List<XAdESCertIdV2> certs, out error))
            {
                return false;
            }

            value = new XAdESSigningCertificateV2(table, elementIndex, certs, owned);
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
    /// Reads a <c>CertIDListV2Type</c>-shaped element: no attributes of its own (the type declares none), then
    /// one-or-more <c>Cert</c> children — the shared core clause 5.2.2's <c>SigningCertificateV2</c> element and
    /// <see cref="XAdESCompleteCertificateRefsV2"/>'s Annex A.1.1/A.1.3 <c>CertRefs</c> child both bind to (the
    /// schema declares <c>CertIDListV2Type</c> exactly once — reused here). Both callers
    /// delegate to this core rather than each re-implementing the <c>Cert+</c> loop, the same additive-
    /// extraction shape <see cref="XAdESDigestAlgAndValue.TryReadDigestMethodAndValue"/> already takes for its
    /// own multiply-reused child sequence. Namespace-agnostic to the wrapping element like that core: the
    /// <c>Cert</c> children it reads are always in the v1.3.2 namespace regardless of whether the wrapping
    /// element itself is <c>SigningCertificateV2</c> (v1.3.2) or <c>CertRefs</c> (v1.4.1, per Annex A's own
    /// namespace binding for that local element) — <c>CertIDListV2Type</c> and the <c>CertIDTypeV2</c> it is
    /// built from are declared once, in the v1.3.2 schema document, irrespective of which schema references
    /// the type.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>CertIDListV2Type</c>-typed element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="owned">The caller's custody list. Decoded fields are appended as they are read, including
    /// on paths that subsequently refuse — the caller must dispose the list when this method returns
    /// <see langword="false"/>.</param>
    /// <param name="certs">The <c>Cert</c> entries, in document order, on success.</param>
    /// <param name="error">The refusal on failure: <see cref="XAdESReadFailure.MissingRequiredChild"/> when no
    /// <c>Cert</c> is present.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryReadCertIdListV2(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, List<PooledMemory> owned, out List<XAdESCertIdV2> certs, out XAdESReadError error)
    {
        certs = [];
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 0, out XmlSignatureReadError grammarError))
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

        while(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "Cert"u8))
        {
            if(!XAdESCertIdV2.TryRead(table, child, pool, owned, out XAdESCertIdV2 cert, out error))
            {
                return false;
            }

            certs.Add(cert);
            if(certs.Count > MaximumCertIdListEntryCount)
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

        if(certs.Count == 0)
        {
            error = new XAdESReadError(scan == ElementScanResult.Found ? XAdESReadFailure.UnknownCoreElement : XAdESReadFailure.MissingRequiredChild, 0);

            return false;
        }

        if(scan == ElementScanResult.Found)
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

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
    /// Releases every decoded field every <see cref="Certs"/> entry owns. <see cref="Table"/> is not owned and
    /// is not disposed here. Idempotent.
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
