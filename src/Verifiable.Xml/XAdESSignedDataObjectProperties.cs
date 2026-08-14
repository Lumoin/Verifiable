using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// Which named child group of <c>SignedDataObjectProperties</c> (clause 4.3.5) a
/// <see cref="XAdESSignedDataObjectPropertyEntry"/> belongs to.
/// </summary>
public enum XAdESSignedDataObjectPropertyName
{
    /// <summary>The <c>DataObjectFormat</c> qualifying property (clause 5.2.3).</summary>
    DataObjectFormat,

    /// <summary>The <c>CommitmentTypeIndication</c> qualifying property (clause 5.2.4).</summary>
    CommitmentTypeIndication,

    /// <summary>The <c>AllDataObjectsTimeStamp</c> qualifying property (clause 5.2.8.1).</summary>
    AllDataObjectsTimeStamp,

    /// <summary>The <c>IndividualDataObjectsTimeStamp</c> qualifying property (clause 5.2.8.2).</summary>
    IndividualDataObjectsTimeStamp
}


/// <summary>
/// One recognized child of <c>SignedDataObjectProperties</c>: its element position and which named group it
/// belongs to, per <see cref="XAdESSignedDataObjectPropertyName"/>. Carries no further content — reading the
/// property's own body is each named reader's own concern (<see cref="XAdESDataObjectFormat"/>,
/// <see cref="XAdESCommitmentTypeIndication"/>, <see cref="XAdESAllDataObjectsTimeStamp"/>,
/// <see cref="XAdESIndividualDataObjectsTimeStamp"/>).
/// </summary>
public readonly struct XAdESSignedDataObjectPropertyEntry: IEquatable<XAdESSignedDataObjectPropertyEntry>
{
    /// <summary>The property element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Which named group this entry belongs to.</summary>
    public XAdESSignedDataObjectPropertyName Name { get; }


    internal XAdESSignedDataObjectPropertyEntry(int elementIndex, XAdESSignedDataObjectPropertyName name)
    {
        ElementIndex = elementIndex;
        Name = name;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSignedDataObjectPropertyEntry other) => ElementIndex == other.ElementIndex && Name == other.Name;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSignedDataObjectPropertyEntry other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(ElementIndex, Name);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSignedDataObjectPropertyEntry left, XAdESSignedDataObjectPropertyEntry right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSignedDataObjectPropertyEntry left, XAdESSignedDataObjectPropertyEntry right) => !left.Equals(right);
}


/// <summary>
/// The <c>SignedDataObjectProperties</c> container of clause 4.3.5: signed qualifying properties that qualify
/// some of the signed data objects, per the acquired v132 XSD's fixed <c>DataObjectFormat*,
/// CommitmentTypeIndication*, AllDataObjectsTimeStamp*, IndividualDataObjectsTimeStamp*, xsd:any##other*</c>
/// sequence (XA-4.3.5-2): unlike <see cref="XAdESSignedSignatureProperties"/>'s eight
/// at-most-once slots, each of these four groups may repeat any number of times, but the groups themselves
/// stay in that fixed relative order — once a later group's instance appears, an earlier group's instance can
/// no longer follow. The trailing <c>##other</c> extension point is prose-closed the same way
/// <see cref="XAdESSignedSignatureProperties"/>'s is (XA-4.3.5-4), and this container has no obsoleted V1
/// names of its own (clause 4.3.5 states no obsoletion rule) — every non-conforming
/// child is <see cref="XAdESReadFailure.UnknownQualifyingProperty"/>.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every entry is a plain (element index, name) pair over
/// <see cref="Table"/> — so no <see cref="IDisposable"/> surface is needed.
/// </remarks>
public readonly struct XAdESSignedDataObjectProperties: IEquatable<XAdESSignedDataObjectProperties>
{
    private static readonly (byte[] LocalName, XAdESSignedDataObjectPropertyName Name)[] Groups =
    [
        ("DataObjectFormat"u8.ToArray(), XAdESSignedDataObjectPropertyName.DataObjectFormat),
        ("CommitmentTypeIndication"u8.ToArray(), XAdESSignedDataObjectPropertyName.CommitmentTypeIndication),
        ("AllDataObjectsTimeStamp"u8.ToArray(), XAdESSignedDataObjectPropertyName.AllDataObjectsTimeStamp),
        ("IndividualDataObjectsTimeStamp"u8.ToArray(), XAdESSignedDataObjectPropertyName.IndividualDataObjectsTimeStamp),
    ];

    /// <summary>The table the properties' spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignedDataObjectProperties</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;

    /// <summary>The recognized children present, in document (and so schema group) order; at least one.</summary>
    public IReadOnlyList<XAdESSignedDataObjectPropertyEntry> Properties { get; }


    private XAdESSignedDataObjectProperties(XmlNodeTable table, int elementIndex, bool hasId, int idAttributeOrdinal, IReadOnlyList<XAdESSignedDataObjectPropertyEntry> properties)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
        Properties = properties;
    }


    /// <summary>
    /// Reads a <c>SignedDataObjectProperties</c> element: its optional <c>Id</c> attribute, then its children
    /// against the fixed four-group allowlist, refusing an unrecognized name, a group repeated after a later
    /// group already started, or an empty element (XA-4.3.5-6).
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignedDataObjectProperties</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESSignedDataObjectProperties value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "SignedDataObjectProperties"u8))
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

        var entries = new List<XAdESSignedDataObjectPropertyEntry>();
        int currentGroup = 0;
        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out int child);
        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        while(scan == ElementScanResult.Found)
        {
            int matchedGroup = -1;
            for(int i = 0; i < Groups.Length; ++i)
            {
                if(XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, Groups[i].LocalName))
                {
                    matchedGroup = i;

                    break;
                }
            }

            if(matchedGroup < 0 || matchedGroup < currentGroup)
            {
                //Either genuinely unrecognized content, or a legitimate group name that appears after a
                //later group already started — both are refused identically, since the schema's fixed
                //group order forbids interleaving.
                error = new XAdESReadError(XAdESReadFailure.UnknownQualifyingProperty, 0);

                return false;
            }

            entries.Add(new XAdESSignedDataObjectPropertyEntry(child, Groups[matchedGroup].Name));
            currentGroup = matchedGroup;

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

        value = new XAdESSignedDataObjectProperties(table, elementIndex, hasId, idOrdinal, entries);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSignedDataObjectProperties other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSignedDataObjectProperties other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSignedDataObjectProperties left, XAdESSignedDataObjectProperties right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSignedDataObjectProperties left, XAdESSignedDataObjectProperties right) => !left.Equals(right);
}
