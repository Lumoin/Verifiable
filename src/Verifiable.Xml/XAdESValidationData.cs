using Lumoin.Base;

namespace Verifiable.Xml;

/// <summary>
/// The v1.4.1 <c>ValidationDataType</c> data type: an optional <c>xades:CertificateValues</c> then optional
/// <c>xades:RevocationValues</c> child, in that fixed order (both cross-namespace element references into the
/// v1.3.2 schema, reusing <see cref="XAdESCertificateValues"/>/<see cref="XAdESRevocationValues"/> unchanged),
/// plus an optional <c>Id</c> and an optional <c>URI</c>. This is the shared core the schema declares once and
/// two qualifying properties reuse: <c>AnyValidationData</c> (clause 5.4.6, read through
/// <see cref="TryReadAnyValidationData"/>) and <c>TimeStampValidationData</c> (clause 5.5.1, bound to its
/// owning time-stamp container by <see cref="XAdESTimeStampValidationDataPlacement"/> over the same
/// <see cref="TryRead"/> core).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TryRead"/> itself enforces no per-property narrowing — it is the permissive shared shape, the
/// same posture <see cref="XAdESDigestAlgAndValue"/> takes for its own multiply-reused
/// <c>DigestAlgAndValueType</c> core. The <c>URI</c> attribute's per-property narrowing belongs to each
/// binding: clause 5.4.6 states "The <c>AnyValidationData</c> qualifying property shall not have the <c>URI</c>
/// attribute," so <see cref="TryReadAnyValidationData"/> reads the shared shape then refuses when
/// <see cref="HasUri"/> is <see langword="true"/> — the shared type keeps the slot, the binding forbids it,
/// the same DER-narrowing pattern <see cref="XAdESCertificateValues"/>/<see cref="XAdESRevocationValues"/>
/// apply to <c>EncapsulatedPKIDataType</c>'s <c>Encoding</c>. <c>TimeStampValidationData</c>'s own clause
/// 5.5.1.2 narrows <c>URI</c> the opposite direction (conditionally mandatory) — resolved by
/// <see cref="XAdESTimeStampValidationDataPlacement"/> over this same <see cref="TryRead"/> core.
/// </para>
/// <para>
/// Owns the embedded <see cref="CertificateValues"/>/<see cref="RevocationValues"/> readers — each already
/// independently <see cref="IDisposable"/> — and so is itself <see cref="IDisposable"/>, cascading
/// disposal to whichever of the two is present, the same nested-ownership shape
/// <see cref="XAdESCounterSignature"/> already applies to its own embedded <see cref="XmlSignature"/>.
/// </para>
/// </remarks>
public sealed class XAdESValidationData: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>AnyValidationData</c>/<c>TimeStampValidationData</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// Whether the optional <c>URI</c> attribute is present. Always <see langword="false"/> on a value returned
    /// by <see cref="TryReadAnyValidationData"/> — that binding refuses a present <c>URI</c> rather than
    /// surfacing it.
    /// </summary>
    public bool HasUri { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The <c>URI</c> attribute value.</summary>
    public ReadOnlySpan<byte> Uri => HasUri ? Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>CertificateValues</c> child is present.</summary>
    public bool HasCertificateValues { get; }

    /// <summary>The <c>CertificateValues</c> child; not <see langword="null"/> when <see cref="HasCertificateValues"/> is <see langword="true"/>. Owned by this instance.</summary>
    public XAdESCertificateValues? CertificateValues { get; }

    /// <summary>Whether the optional <c>RevocationValues</c> child is present.</summary>
    public bool HasRevocationValues { get; }

    /// <summary>The <c>RevocationValues</c> child; not <see langword="null"/> when <see cref="HasRevocationValues"/> is <see langword="true"/>. Owned by this instance.</summary>
    public XAdESRevocationValues? RevocationValues { get; }

    private bool isDisposed;


    private XAdESValidationData(
        XmlNodeTable table,
        int elementIndex,
        bool hasId,
        int idAttributeOrdinal,
        bool hasUri,
        int uriAttributeOrdinal,
        bool hasCertificateValues,
        XAdESCertificateValues? certificateValues,
        bool hasRevocationValues,
        XAdESRevocationValues? revocationValues)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        HasUri = hasUri;
        UriAttributeOrdinal = uriAttributeOrdinal;
        HasCertificateValues = hasCertificateValues;
        CertificateValues = certificateValues;
        HasRevocationValues = hasRevocationValues;
        RevocationValues = revocationValues;
    }


    /// <summary>
    /// Reads a <c>ValidationDataType</c>-shaped element: its optional <c>Id</c>/<c>URI</c> attributes, then its
    /// optional <c>CertificateValues</c> and <c>RevocationValues</c> children, in that fixed order. Enforces no
    /// per-property narrowing of its own — see this type's remarks.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>ValidationDataType</c>-typed element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESValidationData? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        XAdESCertificateValues? certificateValues = null;
        XAdESRevocationValues? revocationValues = null;
        try
        {
            bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
            bool hasUri = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal);
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, (hasId ? 1 : 0) + (hasUri ? 1 : 0), out XmlSignatureReadError grammarError))
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

            bool hasCertificateValues = false;
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CertificateValues"u8))
            {
                int certificateValuesElementIndex = child;
                if(!XAdESCertificateValues.TryRead(table, certificateValuesElementIndex, pool, out certificateValues, out error))
                {
                    return false;
                }

                hasCertificateValues = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, certificateValuesElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            bool hasRevocationValues = false;
            if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "RevocationValues"u8))
            {
                int revocationValuesElementIndex = child;
                if(!XAdESRevocationValues.TryRead(table, revocationValuesElementIndex, pool, out revocationValues, out error))
                {
                    return false;
                }

                hasRevocationValues = true;
                scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, revocationValuesElementIndex, out child);
                if(scan == ElementScanResult.UnexpectedContent)
                {
                    error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                    return false;
                }
            }

            if(scan == ElementScanResult.Found)
            {
                bool isRepeat = (hasCertificateValues && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CertificateValues"u8))
                    || (hasRevocationValues && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "RevocationValues"u8));
                error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

                return false;
            }

            value = new XAdESValidationData(table, elementIndex, hasId, idOrdinal, hasUri, uriOrdinal, hasCertificateValues, certificateValues, hasRevocationValues, revocationValues);
            certificateValues = null;
            revocationValues = null;
            error = default;

            return true;
        }
        finally
        {
            certificateValues?.Dispose();
            revocationValues?.Dispose();
        }
    }


    /// <summary>
    /// Reads an <c>AnyValidationData</c> element: the shared <see cref="TryRead"/> shape, narrowed by clause
    /// 5.4.6's own binding — "The <c>AnyValidationData</c> qualifying property shall not have the <c>URI</c>
    /// attribute" and "shall contain the certificates identified in 1), or the revocation data identified in
    /// 2), or both of them" (at least one of <see cref="CertificateValues"/>/<see cref="RevocationValues"/>
    /// must be present).
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>AnyValidationData</c> element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.AnyValidationDataUriNotPermitted"/> when the <c>URI</c> attribute is
    /// present; <see cref="XAdESReadFailure.EmptyAnyValidationData"/> when neither child is present.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryReadAnyValidationData(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESValidationData? value, out XAdESReadError error)
    {
        if(!TryRead(table, elementIndex, pool, out value, out error))
        {
            return false;
        }

        if(value!.HasUri)
        {
            value.Dispose();
            value = null;
            error = new XAdESReadError(XAdESReadFailure.AnyValidationDataUriNotPermitted, 0);

            return false;
        }

        if(!value.HasCertificateValues && !value.HasRevocationValues)
        {
            value.Dispose();
            value = null;
            error = new XAdESReadError(XAdESReadFailure.EmptyAnyValidationData, 0);

            return false;
        }

        return true;
    }


    /// <summary>
    /// Reads a <c>TimeStampValidationData</c> element (clause 5.5.1.1): the shared <see cref="TryRead"/> shape,
    /// WITHOUT <see cref="TryReadAnyValidationData"/>'s <c>URI</c>-forbidding narrowing — clause 5.5.1.1's own
    /// "the <c>TimeStampValidationData</c> qualifying property may have the <c>URI</c> attribute" permits it
    /// here, contrasted explicitly by clause 5.4.6's NOTE 3, which states the <c>URI</c> attribute "can be used
    /// within the <c>TimeStampValidationData</c>" instead of <c>AnyValidationData</c>. This reader enforces no
    /// cross-child presence floor either: clause 5.5.1.1 states no "shall contain at least one of
    /// <c>CertificateValues</c>/<c>RevocationValues</c>" sentence the way clause 5.4.6 does for
    /// <c>AnyValidationData</c> — "may contain all [...] or may contain only some, if the rest are present
    /// elsewhere" (clause 5.5.1.1) contemplates a <c>TimeStampValidationData</c> instance whose own children are
    /// both absent because every needed value already lives in ANOTHER instance or the time-stamp's own
    /// embedded certificates, consistent with the shared <see cref="TryRead"/> core's own permissive posture.
    /// The clause 5.5.1.2 placement/<c>URI</c>-binding protocol itself is
    /// <see cref="XAdESTimeStampValidationDataPlacement"/>'s concern, layered above this structural read.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>TimeStampValidationData</c> element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure — every <see cref="TryRead"/> refusal.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryReadTimeStampValidationData(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESValidationData? value, out XAdESReadError error)
    {
        return TryRead(table, elementIndex, pool, out value, out error);
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
    /// Releases the embedded <see cref="CertificateValues"/>/<see cref="RevocationValues"/> readers, when
    /// present. <see cref="Table"/> is not owned and is not disposed here. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        CertificateValues?.Dispose();
        RevocationValues?.Dispose();
    }
}
