using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// Which non-deprecated named child of <c>SignedSignatureProperties</c> (clause 4.3.4) a
/// <see cref="XAdESSignedSignaturePropertyEntry"/> identifies. The three obsoleted V1 names the same schema
/// sequence also declares — <c>SigningCertificate</c>, <c>SignatureProductionPlace</c>, <c>SignerRole</c> —
/// never produce an entry: encountering one refuses the whole read with
/// <see cref="XAdESReadFailure.DeprecatedQualifyingProperty"/>.
/// </summary>
public enum XAdESSignedSignaturePropertyName
{
    /// <summary>The <c>SigningTime</c> qualifying property (clause 5.2.1).</summary>
    SigningTime,

    /// <summary>The <c>SigningCertificateV2</c> qualifying property (clause 5.2.2).</summary>
    SigningCertificateV2,

    /// <summary>The <c>SignaturePolicyIdentifier</c> qualifying property (clause 5.2.9).</summary>
    SignaturePolicyIdentifier,

    /// <summary>The <c>SignatureProductionPlaceV2</c> qualifying property (clause 5.2.5).</summary>
    SignatureProductionPlaceV2,

    /// <summary>The <c>SignerRoleV2</c> qualifying property (clause 5.2.6).</summary>
    SignerRoleV2
}


/// <summary>
/// One recognized child of <c>SignedSignatureProperties</c>: its element position and which named property it
/// is, per <see cref="XAdESSignedSignaturePropertyName"/>. Carries no further content — reading the property's
/// own body is each named reader's own concern (<see cref="XAdESSigningTime"/>, <see cref="XAdESSigningCertificateV2"/>,
/// <see cref="XAdESSignaturePolicyIdentifier"/>, <see cref="XAdESSignatureProductionPlaceV2"/>,
/// <see cref="XAdESSignerRoleV2"/>); this container exposes identity and position only, per its own
/// "containers expose their child properties as ordered recognized-name entries" design.
/// </summary>
public readonly struct XAdESSignedSignaturePropertyEntry: IEquatable<XAdESSignedSignaturePropertyEntry>
{
    /// <summary>The property element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Which named property this is.</summary>
    public XAdESSignedSignaturePropertyName Name { get; }


    internal XAdESSignedSignaturePropertyEntry(int elementIndex, XAdESSignedSignaturePropertyName name)
    {
        ElementIndex = elementIndex;
        Name = name;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSignedSignaturePropertyEntry other) => ElementIndex == other.ElementIndex && Name == other.Name;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSignedSignaturePropertyEntry other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(ElementIndex, Name);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSignedSignaturePropertyEntry left, XAdESSignedSignaturePropertyEntry right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSignedSignaturePropertyEntry left, XAdESSignedSignaturePropertyEntry right) => !left.Equals(right);
}


/// <summary>
/// The <c>SignedSignatureProperties</c> container of clause 4.3.4: signed qualifying properties that qualify
/// the XML signature itself or the signer, per the acquired v132 XSD's fixed
/// <c>SigningTime?, SigningCertificate?, SigningCertificateV2?, SignaturePolicyIdentifier?,
/// SignatureProductionPlace?, SignatureProductionPlaceV2?, SignerRole?, SignerRoleV2?, xsd:any##other*</c>
/// sequence (XA-4.3.4-2). Each of the eight named slots occurs at most once, in that
/// exact order; the trailing <c>##other</c> extension point is prose-closed (XA-4.3.4-4: "shall not
/// incorporate any elements ... not specified within any version of this multi-part deliverable") — no
/// Annex A addition ever fills it (every Annex A property is an unsigned-signature
/// property), so ANY child that is neither a slot in its correct position nor a recognized obsoleted name
/// refuses.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every entry is a plain (element index, name) pair over
/// <see cref="Table"/> — so no <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESSignedSignatureProperties: IEquatable<XAdESSignedSignatureProperties>
{
    private static (byte[] LocalName, bool IsDeprecated, XAdESSignedSignaturePropertyName Name)[] Slots { get; } =
    [
        ("SigningTime"u8.ToArray(), false, XAdESSignedSignaturePropertyName.SigningTime),
        ("SigningCertificate"u8.ToArray(), true, default),
        ("SigningCertificateV2"u8.ToArray(), false, XAdESSignedSignaturePropertyName.SigningCertificateV2),
        ("SignaturePolicyIdentifier"u8.ToArray(), false, XAdESSignedSignaturePropertyName.SignaturePolicyIdentifier),
        ("SignatureProductionPlace"u8.ToArray(), true, default),
        ("SignatureProductionPlaceV2"u8.ToArray(), false, XAdESSignedSignaturePropertyName.SignatureProductionPlaceV2),
        ("SignerRole"u8.ToArray(), true, default),
        ("SignerRoleV2"u8.ToArray(), false, XAdESSignedSignaturePropertyName.SignerRoleV2),
    ];

    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignedSignatureProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The recognized named children present, in document (and so schema sequence) order; at least one.</summary>
    public IReadOnlyList<XAdESSignedSignaturePropertyEntry> Properties { get; }


    private XAdESSignedSignatureProperties(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XAdESSignedSignaturePropertyEntry> properties)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Properties = properties;
    }


    /// <summary>
    /// Reads a <c>SignedSignatureProperties</c> element: its optional <c>Id</c> attribute, then its children
    /// against the fixed eight-slot allowlist, refusing a deprecated name, an unrecognized/mispositioned
    /// name, or an empty element (XA-4.3.4-7).
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignedSignatureProperties</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESSignedSignatureProperties value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedSignatureProperties"u8))
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

        var entries = new List<XAdESSignedSignaturePropertyEntry>();
        var consumed = new bool[Slots.Length];
        int nextSlot = 0;
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found)
        {
            int matchedSlot = -1;
            for(int i = 0; i < Slots.Length; ++i)
            {
                if(XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, Slots[i].LocalName))
                {
                    matchedSlot = i;

                    break;
                }
            }

            if(matchedSlot < 0)
            {
                error = new XAdESReadError(XAdESReadFailure.UnknownQualifyingProperty, 0);

                return false;
            }

            if(consumed[matchedSlot])
            {
                error = new XAdESReadError(XAdESReadFailure.DuplicateCoreChild, 0);

                return false;
            }

            if(matchedSlot < nextSlot)
            {
                //A legitimate name whose sequence position was already passed by a later slot — out of
                //order, distinct from an exact repeat.
                error = new XAdESReadError(XAdESReadFailure.UnknownQualifyingProperty, 0);

                return false;
            }

            if(Slots[matchedSlot].IsDeprecated)
            {
                error = new XAdESReadError(XAdESReadFailure.DeprecatedQualifyingProperty, 0);

                return false;
            }

            entries.Add(new XAdESSignedSignaturePropertyEntry(child, Slots[matchedSlot].Name));
            consumed[matchedSlot] = true;
            nextSlot = matchedSlot + 1;

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

        value = new XAdESSignedSignatureProperties(table, elementIndex, hasId, idOrdinal, entries);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSignedSignatureProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSignedSignatureProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSignedSignatureProperties left, XAdESSignedSignatureProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSignedSignatureProperties left, XAdESSignedSignatureProperties right) => !left.Equals(right);
}
