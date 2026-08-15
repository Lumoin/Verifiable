using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// Which named child of <c>UnsignedSignatureProperties</c> (clause 4.3.6) a
/// <see cref="XAdESUnsignedSignaturePropertyEntry"/> identifies, or <see cref="Unrecognized"/> for every
/// child this leaf does not classify by name — including the current, v1.4.1-namespace properties Annex A
/// adds through the schema's <c>xsd:any namespace="##other"</c> extension point, and any other foreign
/// content. Unlike <see cref="XAdESSignedSignaturePropertyName"/>'s signed-container counterpart,
/// <see cref="Unrecognized"/> is never a read refusal here: clause 4.3.6's own container is unsigned, and
/// this library tolerates its <c>##other</c> content as unmodeled entries — the <c>ArchiveTimeStamp</c>
/// imprint algorithms must canonicalize ALL unsigned properties in document order, known or not.
/// </summary>
public enum XAdESUnsignedSignaturePropertyName
{
    /// <summary>
    /// Content this leaf does not classify by name; the entry's own (namespace, local name) identity is what
    /// <c>Verifiable.Cryptography.Pki.XAdESQualifyingPropertiesFacts.UnknownPropertyObservations</c> records above the leaf.
    /// </summary>
    Unrecognized = 0,

    /// <summary>The <c>CounterSignature</c> qualifying property (clause 5.2.7).</summary>
    CounterSignature,

    /// <summary>The <c>SignatureTimeStamp</c> qualifying property (clause 5.3).</summary>
    SignatureTimeStamp,

    /// <summary>The <c>CompleteRevocationRefs</c> qualifying property (Annex A.1.2).</summary>
    CompleteRevocationRefs,

    /// <summary>The <c>AttributeRevocationRefs</c> qualifying property (Annex A.1.4).</summary>
    AttributeRevocationRefs,

    /// <summary>The <c>CertificateValues</c> qualifying property (clause 5.4.2), read through <see cref="XAdESCertificateValues"/>.</summary>
    CertificateValues,

    /// <summary>The <c>RevocationValues</c> qualifying property (clause 5.4.3), read through <see cref="XAdESRevocationValues"/>.</summary>
    RevocationValues,

    /// <summary>The <c>AttrAuthoritiesCertValues</c> qualifying property (clause 5.4.4), read through <see cref="XAdESCertificateValues"/>.</summary>
    AttrAuthoritiesCertValues,

    /// <summary>The <c>AttributeRevocationValues</c> qualifying property (clause 5.4.5), read through <see cref="XAdESRevocationValues"/>.</summary>
    AttributeRevocationValues
}


/// <summary>
/// One child of <c>UnsignedSignatureProperties</c>: its element position, in document order, and — when
/// recognized — which named property it is. An entry whose <see cref="Name"/> is
/// <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> carries content this leaf does not interpret
/// (a current v1.4.1-namespace Annex A property, or genuinely foreign content); its identity is still fully
/// recoverable from <see cref="ElementIndex"/> through <see cref="XmlNodeTable"/>.
/// </summary>
public readonly struct XAdESUnsignedSignaturePropertyEntry: IEquatable<XAdESUnsignedSignaturePropertyEntry>
{
    /// <summary>The property element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Which named property this is, or <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/>.</summary>
    public XAdESUnsignedSignaturePropertyName Name { get; }


    internal XAdESUnsignedSignaturePropertyEntry(int elementIndex, XAdESUnsignedSignaturePropertyName name)
    {
        ElementIndex = elementIndex;
        Name = name;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESUnsignedSignaturePropertyEntry other) => ElementIndex == other.ElementIndex && Name == other.Name;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESUnsignedSignaturePropertyEntry other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(ElementIndex, Name);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESUnsignedSignaturePropertyEntry left, XAdESUnsignedSignaturePropertyEntry right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESUnsignedSignaturePropertyEntry left, XAdESUnsignedSignaturePropertyEntry right) => !left.Equals(right);
}


/// <summary>
/// The <c>UnsignedSignatureProperties</c> container of clause 4.3.6: unsigned qualifying properties that
/// qualify the XML signature itself or the signer, per the acquired v132 XSD's
/// <c>xsd:choice maxOccurs="unbounded"</c> content model (XA-4.3.6-3) — unlike every
/// other container in clause 4.3 (all <c>xsd:sequence</c>), children may repeat and interleave in any order.
/// Five of the thirteen named choice members are obsoleted V1 names (XA-4.3.6-7/-8:
/// <c>CompleteCertificateRefs</c>, <c>AttributeCertificateRefs</c>, <c>SigAndRefsTimeStamp</c>,
/// <c>RefsOnlyTimeStamp</c>, and the <c>http://uri.etsi.org/01903/v1.3.2#</c>-namespace <c>ArchiveTimeStamp</c>)
/// and refuse the read wherever they appear; the current v1.4.1-namespace
/// <c>ArchiveTimeStamp</c> and every Annex A V2 property live in a DIFFERENT namespace and so fall through
/// the schema's own <c>xsd:any namespace="##other"</c> slot, carried as <see cref="XAdESUnsignedSignaturePropertyEntry"/>
/// entries whose <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
/// <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> — never refused, since this container's
/// content is unsigned. A SIXTH deprecated name is refused outside the thirteen-member choice: clause A.2.2's
/// <c>RenewedDigests</c> (as defined in ETSI EN 319 132-1 V1.1.1) sits, unlike the five above, in the SAME
/// <c>http://uri.etsi.org/01903/v1.4.1#</c> namespace as its own replacement <c>RenewedDigestsV2</c> — the v141
/// XSD declares both as distinct top-level elements (neither a member of this schema's own choice, confirmed
/// against the acquired v141 file) — so namespace alone cannot distinguish deprecated from current here, unlike
/// <c>ArchiveTimeStamp</c>'s namespace-borne split; this reader instead matches <c>RenewedDigests</c>'s exact
/// local name, distinct from (never a prefix match against) <c>RenewedDigestsV2</c>'s.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every entry is a plain (element index, name) pair over
/// <see cref="Table"/> — so no <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESUnsignedSignatureProperties: IEquatable<XAdESUnsignedSignatureProperties>
{
    /// <summary>
    /// The maximum number of children <see cref="TryRead"/> accepts under one <c>UnsignedSignatureProperties</c>
    /// element before refusing with <see cref="XAdESReadFailure.EntryCountLimitExceeded"/> — a documented
    /// hardening bound against a hostile flood of entries (e.g. tens of thousands of <c>CounterSignature</c> or
    /// unrecognized <c>##other</c> occurrences), since the schema's own <c>xsd:choice maxOccurs="unbounded"</c>
    /// content model (XA-4.3.6-3) sets no numeric limit and every entry — recognized or not — is retained.
    /// Chosen generously above any legitimate signature's own property count;
    /// <c>XAdESGrowthBoundsCostTests.UnsignedSignaturePropertiesFloodIsRefusedWithinTheCeiling</c> measures a
    /// flood one entry past this bound refusing well inside its own loose ceiling.
    /// </summary>
    public const int MaximumPropertyCount = 8192;

    private static readonly (byte[] LocalName, bool IsDeprecated, XAdESUnsignedSignaturePropertyName Name)[] Names =
    [
        ("CounterSignature"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.CounterSignature),
        ("SignatureTimeStamp"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.SignatureTimeStamp),
        ("CompleteCertificateRefs"u8.ToArray(), true, default),
        ("CompleteRevocationRefs"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.CompleteRevocationRefs),
        ("AttributeCertificateRefs"u8.ToArray(), true, default),
        ("AttributeRevocationRefs"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.AttributeRevocationRefs),
        ("SigAndRefsTimeStamp"u8.ToArray(), true, default),
        ("RefsOnlyTimeStamp"u8.ToArray(), true, default),
        ("CertificateValues"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.CertificateValues),
        ("RevocationValues"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.RevocationValues),
        ("AttrAuthoritiesCertValues"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.AttrAuthoritiesCertValues),
        ("AttributeRevocationValues"u8.ToArray(), false, XAdESUnsignedSignaturePropertyName.AttributeRevocationValues),
        ("ArchiveTimeStamp"u8.ToArray(), true, default),
    ];

    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>UnsignedSignatureProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>Every child, in document order; at least one.</summary>
    public IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> Properties { get; }


    private XAdESUnsignedSignatureProperties(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XAdESUnsignedSignaturePropertyEntry> properties)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Properties = properties;
    }


    /// <summary>
    /// Reads an <c>UnsignedSignatureProperties</c> element: its optional <c>Id</c> attribute, then every
    /// child in document order — a deprecated v1.3.2-namespace name refuses the whole read
    /// (<see cref="XAdESReadFailure.DeprecatedQualifyingProperty"/>), any other name is recorded as an entry
    /// (recognized or <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/>), and zero children
    /// refuses as empty (XA-4.3.6-10).
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>UnsignedSignatureProperties</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESUnsignedSignatureProperties value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "UnsignedSignatureProperties"u8))
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, hasId ? 1 : 0, out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        var entries = new List<XAdESUnsignedSignaturePropertyEntry>();
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found)
        {
            //Every entry in Names requires the v132 namespace (IsElement checks both namespace and local
            //name), so the deprecated "ArchiveTimeStamp" entry here only ever matches the obsoleted
            //v1.3.2-namespace form — the current v1.4.1-namespace ArchiveTimeStamp is a distinct global
            //element in a different namespace and never matches any entry, falling through to Unrecognized
            //exactly like every other Annex A V2 property and genuinely foreign content.
            XAdESUnsignedSignaturePropertyName name = XAdESUnsignedSignaturePropertyName.Unrecognized;
            bool isDeprecatedMatch = false;
            for(int i = 0; i < Names.Length; ++i)
            {
                if(XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, Names[i].LocalName))
                {
                    isDeprecatedMatch = Names[i].IsDeprecated;
                    name = Names[i].Name;

                    break;
                }
            }

            //Clause A.2.2's deprecated RenewedDigests: the SAME v1.4.1 namespace as current RenewedDigestsV2
            //(unlike ArchiveTimeStamp's namespace-borne split), so distinguished by exact local name only —
            //IsElement's SequenceEqual match never confuses this with the "RenewedDigestsV2" suffix.
            if(!isDeprecatedMatch && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV141Utf8, "RenewedDigests"u8))
            {
                isDeprecatedMatch = true;
            }

            if(isDeprecatedMatch)
            {
                error = new XAdESReadError(XAdESReadFailure.DeprecatedQualifyingProperty, 0);

                return false;
            }

            entries.Add(new XAdESUnsignedSignaturePropertyEntry(child, name));
            if(entries.Count > MaximumPropertyCount)
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
            error = new XAdESReadError(XAdESReadFailure.EmptyQualifyingPropertiesContainer, 0);

            return false;
        }

        value = new XAdESUnsignedSignatureProperties(table, elementIndex, hasId, idOrdinal, entries);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESUnsignedSignatureProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESUnsignedSignatureProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESUnsignedSignatureProperties left, XAdESUnsignedSignatureProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESUnsignedSignatureProperties left, XAdESUnsignedSignatureProperties right) => !left.Equals(right);
}
