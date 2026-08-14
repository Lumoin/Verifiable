using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>QualifyingPropertiesReference</c> element of clause 4.4.3: the indirect-incorporation carrier — a
/// mandatory <c>URI</c> (XA-4.4.3-2's attribute-only <c>QualifyingPropertiesReferenceType</c>) naming a
/// <c>QualifyingProperties</c> element that is NOT a descendant of the <c>ds:Signature</c> root element, plus
/// an optional <c>Id</c>. Modeled structurally here — the raw <c>URI</c> span is captured with no shape
/// validation, mirroring <see cref="XAdESInclude"/>'s own posture — but never resolved: see
/// <see cref="RefuseVerification"/>.
/// </summary>
public readonly struct XAdESQualifyingPropertiesReference: IEquatable<XAdESQualifyingPropertiesReference>
{
    /// <summary>The table the reference's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>QualifyingPropertiesReference</c> element's own index.</summary>
    public int ElementIndex { get; }

    private int UriAttributeOrdinal { get; }

    /// <summary>The mandatory <c>URI</c> attribute value, exact-character, unvalidated.</summary>
    public ReadOnlySpan<byte> Uri => Table.AttributeValueOf(ElementIndex, UriAttributeOrdinal);

    /// <summary>Whether the optional <c>Id</c> attribute is present.</summary>
    public bool HasId { get; }

    private int IdAttributeOrdinal { get; }

    /// <summary>The <c>Id</c> attribute value.</summary>
    public ReadOnlySpan<byte> Id => HasId ? Table.AttributeValueOf(ElementIndex, IdAttributeOrdinal) : ReadOnlySpan<byte>.Empty;


    private XAdESQualifyingPropertiesReference(XmlNodeTable table, int elementIndex, int uriAttributeOrdinal, bool hasId, int idAttributeOrdinal)
    {
        Table = table;
        ElementIndex = elementIndex;
        UriAttributeOrdinal = uriAttributeOrdinal;
        HasId = hasId;
        IdAttributeOrdinal = idAttributeOrdinal;
    }


    /// <summary>
    /// Reads a <c>QualifyingPropertiesReference</c> element: its mandatory <c>URI</c> and optional <c>Id</c>
    /// attributes, refusing any element or non-whitespace text content — <c>QualifyingPropertiesReferenceType</c>
    /// declares none.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>QualifyingPropertiesReference</c> element.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    internal static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESQualifyingPropertiesReference value, out XAdESReadError error)
    {
        value = default;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV132Utf8, "QualifyingPropertiesReference"u8))
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "URI"u8, out int uriOrdinal))
        {
            error = new XAdESReadError(XAdESReadFailure.MissingRequiredAttribute, 0);

            return false;
        }

        bool hasId = XmlSignatureModelGrammar.TryFindAttribute(table, elementIndex, "Id"u8, out int idOrdinal);
        if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, elementIndex, 1 + (hasId ? 1 : 0), out XmlSignatureReadError grammarError))
        {
            error = XAdESGrammar.FromGrammarFailure(grammarError);

            return false;
        }

        ElementScanResult scan = XmlSignatureModelGrammar.TryFindFirstElementChild(table, elementIndex, out _);
        if(scan == ElementScanResult.Found)
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(scan == ElementScanResult.UnexpectedContent)
        {
            error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

            return false;
        }

        value = new XAdESQualifyingPropertiesReference(table, elementIndex, uriOrdinal, hasId, idOrdinal);
        error = default;

        return true;
    }


    /// <summary>
    /// Always refuses: clause 4.4.1's indirect incorporation names a <c>QualifyingProperties</c> element that
    /// lives outside the current document, retrieving it needs network or filesystem access this
    /// transport-agnostic library never performs, and clause 6.3 forbids indirect incorporation in every
    /// XAdES baseline level regardless — a recorded scope refusal. A caller
    /// reaching this method already holds a structurally valid <see cref="XAdESQualifyingPropertiesReference"/>;
    /// the named refusal documents the boundary explicitly rather than the reference silently going unused.
    /// </summary>
    /// <returns>The fixed <see cref="XAdESProcessingFailure.IndirectIncorporationNotSupported"/> refusal.</returns>
    [SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "Deliberately an instance method despite touching no instance state: the whole point is that a caller calls it ON the structurally valid reference it already holds (reference.RefuseVerification()), tying the refusal visibly to that specific value in code, rather than a free-standing static call that could be reached without ever having read a reference at all.")]
    public XAdESProcessingError RefuseVerification() => new(XAdESProcessingFailure.IndirectIncorporationNotSupported, 0);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESQualifyingPropertiesReference other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESQualifyingPropertiesReference other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESQualifyingPropertiesReference left, XAdESQualifyingPropertiesReference right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESQualifyingPropertiesReference left, XAdESQualifyingPropertiesReference right) => !left.Equals(right);
}
