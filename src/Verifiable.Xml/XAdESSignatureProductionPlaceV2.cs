using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Xml;

/// <summary>
/// The <c>SignatureProductionPlaceV2</c> qualifying property of clause 5.2.5: a signed qualifying property
/// that qualifies the signer, specifying an address associated with the signer at a particular geographical
/// location through five individually optional <c>xsd:string</c> children — <c>City</c>, <c>StreetAddress</c>,
/// <c>StateOrProvince</c>, <c>PostalCode</c>, <c>CountryName</c> — in that fixed schema order (the acquired
/// v132 XSD's <c>SignatureProductionPlaceV2Type</c> sequence, cross-checked against the schema file directly:
/// no attribute of its own). Clause 5.2.5 narrows the schema's "each independently optional" shape with its
/// own floor the schema itself cannot express: "Empty <c>SignatureProductionPlaceV2</c> qualifying properties
/// shall not be generated" — <see cref="TryRead"/> enforces it explicitly, the same schema-permits/prose-
/// forbids pattern <see cref="XAdESDataObjectFormat"/>'s cross-child floor and <see cref="XAdESSignerRoleV2"/>'s
/// own empty-property rule both apply.
/// </summary>
/// <remarks>
/// Carries no owned pooled content of its own — every field is a span computed from <see cref="Table"/> — so
/// no <see cref="IDisposable"/> surface is needed. The V1 sibling property <c>SignatureProductionPlace</c> is
/// one of the three obsoleted names <see cref="XAdESSignedSignatureProperties"/> recognizes and refuses
/// (<see cref="XAdESReadFailure.DeprecatedQualifyingProperty"/>); V2 supersedes it
/// project-wide, the same V1→V2 pattern <see cref="XAdESSigningCertificateV2"/> and <see cref="XAdESSignerRoleV2"/>
/// each follow for their own clauses.
/// </remarks>
public readonly struct XAdESSignatureProductionPlaceV2: IEquatable<XAdESSignatureProductionPlaceV2>
{
    /// <summary>The table the property's spans read from.</summary>
    internal XmlNodeTable Table { get; }

    /// <summary>The <c>SignatureProductionPlaceV2</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>Whether the optional <c>City</c> child is present.</summary>
    public bool HasCity { get; }

    private int CityTextNodeIndex { get; }

    /// <summary>The <c>City</c> element's <c>string</c> content, valid when <see cref="HasCity"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> City => HasCity && CityTextNodeIndex >= 0 ? Table.ValueOf(CityTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>StreetAddress</c> child is present.</summary>
    public bool HasStreetAddress { get; }

    private int StreetAddressTextNodeIndex { get; }

    /// <summary>The <c>StreetAddress</c> element's <c>string</c> content, valid when <see cref="HasStreetAddress"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> StreetAddress => HasStreetAddress && StreetAddressTextNodeIndex >= 0 ? Table.ValueOf(StreetAddressTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>StateOrProvince</c> child is present.</summary>
    public bool HasStateOrProvince { get; }

    private int StateOrProvinceTextNodeIndex { get; }

    /// <summary>The <c>StateOrProvince</c> element's <c>string</c> content, valid when <see cref="HasStateOrProvince"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> StateOrProvince => HasStateOrProvince && StateOrProvinceTextNodeIndex >= 0 ? Table.ValueOf(StateOrProvinceTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>PostalCode</c> child is present.</summary>
    public bool HasPostalCode { get; }

    private int PostalCodeTextNodeIndex { get; }

    /// <summary>The <c>PostalCode</c> element's <c>string</c> content, valid when <see cref="HasPostalCode"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> PostalCode => HasPostalCode && PostalCodeTextNodeIndex >= 0 ? Table.ValueOf(PostalCodeTextNodeIndex) : ReadOnlySpan<byte>.Empty;

    /// <summary>Whether the optional <c>CountryName</c> child is present.</summary>
    public bool HasCountryName { get; }

    private int CountryNameTextNodeIndex { get; }

    /// <summary>The <c>CountryName</c> element's <c>string</c> content, valid when <see cref="HasCountryName"/> is <see langword="true"/>.</summary>
    public ReadOnlySpan<byte> CountryName => HasCountryName && CountryNameTextNodeIndex >= 0 ? Table.ValueOf(CountryNameTextNodeIndex) : ReadOnlySpan<byte>.Empty;


    private XAdESSignatureProductionPlaceV2(
        XmlNodeTable table,
        int elementIndex,
        bool hasCity,
        int cityTextNodeIndex,
        bool hasStreetAddress,
        int streetAddressTextNodeIndex,
        bool hasStateOrProvince,
        int stateOrProvinceTextNodeIndex,
        bool hasPostalCode,
        int postalCodeTextNodeIndex,
        bool hasCountryName,
        int countryNameTextNodeIndex)
    {
        Table = table;
        ElementIndex = elementIndex;
        HasCity = hasCity;
        CityTextNodeIndex = cityTextNodeIndex;
        HasStreetAddress = hasStreetAddress;
        StreetAddressTextNodeIndex = streetAddressTextNodeIndex;
        HasStateOrProvince = hasStateOrProvince;
        StateOrProvinceTextNodeIndex = stateOrProvinceTextNodeIndex;
        HasPostalCode = hasPostalCode;
        PostalCodeTextNodeIndex = postalCodeTextNodeIndex;
        HasCountryName = hasCountryName;
        CountryNameTextNodeIndex = countryNameTextNodeIndex;
    }


    /// <summary>
    /// Reads a <c>SignatureProductionPlaceV2</c> element: no attributes of its own, then its five optional
    /// <c>City</c>/<c>StreetAddress</c>/<c>StateOrProvince</c>/<c>PostalCode</c>/<c>CountryName</c> children,
    /// in that fixed order, refusing an element with none of the five present.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignatureProductionPlaceV2</c> element — typically obtained from a
    /// <see cref="XAdESSignedSignaturePropertyEntry"/> whose <see cref="XAdESSignedSignaturePropertyEntry.Name"/>
    /// is <see cref="XAdESSignedSignaturePropertyName.SignatureProductionPlaceV2"/>.</param>
    /// <param name="value">The read model on success.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.EmptySignatureProductionPlaceV2"/> when none of the five children is present
    /// (clause 5.2.5's "Empty ... shall not be generated").</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, out XAdESSignatureProductionPlaceV2 value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        value = default;
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

        bool hasCity = false;
        int cityTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "City"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out cityTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasCity = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasStreetAddress = false;
        int streetAddressTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "StreetAddress"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out streetAddressTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasStreetAddress = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasStateOrProvince = false;
        int stateOrProvinceTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "StateOrProvince"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out stateOrProvinceTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasStateOrProvince = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasPostalCode = false;
        int postalCodeTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "PostalCode"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out postalCodeTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasPostalCode = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        bool hasCountryName = false;
        int countryNameTextNodeIndex = -1;
        if(scan == ElementScanResult.Found && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CountryName"u8))
        {
            if(!XmlSignatureModelGrammar.TryValidateAttributeCount(table, child, 0, out grammarError)
                || !XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex(table, child, out countryNameTextNodeIndex, out grammarError))
            {
                error = XAdESGrammar.FromGrammarFailure(grammarError);

                return false;
            }

            hasCountryName = true;
            scan = XmlSignatureModelGrammar.TryFindNextElementSibling(table, child, out child);
            if(scan == ElementScanResult.UnexpectedContent)
            {
                error = new XAdESReadError(XAdESReadFailure.UnexpectedElementContent, 0);

                return false;
            }
        }

        if(scan == ElementScanResult.Found)
        {
            bool isRepeat = (hasCity && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "City"u8))
                || (hasStreetAddress && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "StreetAddress"u8))
                || (hasStateOrProvince && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "StateOrProvince"u8))
                || (hasPostalCode && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "PostalCode"u8))
                || (hasCountryName && XmlSignatureModelGrammar.IsElement(table, child, XAdESIdentifiers.XAdESNamespaceV132Utf8, "CountryName"u8));
            error = new XAdESReadError(isRepeat ? XAdESReadFailure.DuplicateCoreChild : XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        if(!hasCity && !hasStreetAddress && !hasStateOrProvince && !hasPostalCode && !hasCountryName)
        {
            error = new XAdESReadError(XAdESReadFailure.EmptySignatureProductionPlaceV2, 0);

            return false;
        }

        value = new XAdESSignatureProductionPlaceV2(
            table, elementIndex,
            hasCity, cityTextNodeIndex,
            hasStreetAddress, streetAddressTextNodeIndex,
            hasStateOrProvince, stateOrProvinceTextNodeIndex,
            hasPostalCode, postalCodeTextNodeIndex,
            hasCountryName, countryNameTextNodeIndex);
        error = default;

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(XAdESSignatureProductionPlaceV2 other) => ReferenceEquals(Table, other.Table) && ElementIndex == other.ElementIndex;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is XAdESSignatureProductionPlaceV2 other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => XmlModelEquality.CombineHash(Table, ElementIndex);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(XAdESSignatureProductionPlaceV2 left, XAdESSignatureProductionPlaceV2 right) => left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(XAdESSignatureProductionPlaceV2 left, XAdESSignatureProductionPlaceV2 right) => !left.Equals(right);
}
