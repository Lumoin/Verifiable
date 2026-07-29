using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Renders an X.500 <c>Name</c> (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4">RFC 5280
/// §4.1.2.4</see>) as text, so two names read from different structures — a certificate's <c>issuer</c> field
/// and the <c>IssuerSerial</c> of an ESS signing certificate reference, for example — can be compared and
/// reported without either side carrying raw DER through a public surface.
/// </summary>
/// <remarks>
/// <para>
/// The rendering is deterministic and canonical for comparison purposes only: attributes appear in encoding
/// order as <c>type=value</c> pairs joined by <c>", "</c>, with the four attribute types this library already
/// names in <see cref="WellKnownOids"/> rendered by their short names and every other type by its
/// dotted-decimal object identifier. It is not an
/// <see href="https://www.rfc-editor.org/rfc/rfc4514">RFC 4514</see> distinguished name: no escaping or
/// reordering is applied, because nothing here parses the result back.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> A name arrives inside a certificate or a signature attribute, so
/// the DER is read through <see cref="AsnReader"/>'s bounds-checked cursors under
/// <see cref="AsnEncodingRules.DER"/>, iteratively, with the reader closed at every level. An attribute value in
/// an encoding this reader does not decode contributes nothing rather than aborting the walk.
/// </para>
/// </remarks>
internal static class PkiDistinguishedNameText
{
    /// <summary>The <c>commonName</c> attribute's short name.</summary>
    private const string CommonNameShortName = "CN";

    /// <summary>The <c>organizationName</c> attribute's short name.</summary>
    private const string OrganizationNameShortName = "O";

    /// <summary>The <c>organizationalUnitName</c> attribute's short name.</summary>
    private const string OrganizationalUnitNameShortName = "OU";

    /// <summary>The <c>countryName</c> attribute's short name.</summary>
    private const string CountryNameShortName = "C";


    /// <summary>
    /// Renders a <c>Name</c> from its DER encoding.
    /// </summary>
    /// <param name="nameDer">The DER-encoded <c>Name</c>, tag and length included.</param>
    /// <returns>The rendered name.</returns>
    /// <exception cref="AsnContentException">Thrown when the bytes are not a well-formed <c>Name</c>.</exception>
    public static string FromDer(ReadOnlyMemory<byte> nameDer)
    {
        var reader = new AsnReader(nameDer, AsnEncodingRules.DER);
        string rendered = Read(reader);
        reader.ThrowIfNotEmpty();

        return rendered;
    }


    /// <summary>
    /// Renders the <c>Name</c> a reader is positioned at, consuming it.
    /// </summary>
    /// <param name="name">The reader positioned at the <c>Name</c>.</param>
    /// <returns>The rendered name; empty when the name carries no relative distinguished names.</returns>
    /// <exception cref="AsnContentException">Thrown when the structure is not a well-formed <c>Name</c>.</exception>
    public static string Read(AsnReader name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var rendered = new StringBuilder();
        AsnReader relativeNames = name.ReadSequence();
        while(relativeNames.HasData)
        {
            //A deployed multi-valued relative name violating the DER SET OF sort order must not abort the walk:
            //encoding strictness of a name is the signature verification step's concern, not this rendering's.
            AsnReader relativeName = relativeNames.ReadSetOf(skipSortOrderValidation: true);
            while(relativeName.HasData)
            {
                AsnReader attribute = relativeName.ReadSequence();
                string attributeType = attribute.ReadObjectIdentifier();
                string? value = TryReadDirectoryString(attribute);
                attribute.ThrowIfNotEmpty();
                if(value is null)
                {
                    continue;
                }

                if(rendered.Length > 0)
                {
                    _ = rendered.Append(", ");
                }

                _ = rendered.Append(ShortName(attributeType)).Append('=').Append(value);
            }
        }

        return rendered.ToString();
    }


    /// <summary>
    /// Maps an attribute type to the short name it is rendered under.
    /// </summary>
    /// <param name="attributeType">The dotted-decimal attribute type object identifier.</param>
    /// <returns>The short name, or the object identifier itself for a type without one here.</returns>
    private static string ShortName(string attributeType) => attributeType switch
    {
        WellKnownOids.CommonName => CommonNameShortName,
        WellKnownOids.OrganizationName => OrganizationNameShortName,
        WellKnownOids.OrganizationalUnitName => OrganizationalUnitNameShortName,
        WellKnownOids.CountryName => CountryNameShortName,
        _ => attributeType
    };


    /// <summary>
    /// Reads an attribute value as text when it is one of the <c>DirectoryString</c>-style forms, consuming it
    /// either way so the caller's emptiness check stays exact.
    /// </summary>
    /// <param name="attribute">The reader positioned at the attribute's value.</param>
    /// <returns>The text, or <see langword="null"/> for an encoding this reader does not decode.</returns>
    public static string? TryReadDirectoryString(AsnReader attribute)
    {
        ArgumentNullException.ThrowIfNull(attribute);

        Asn1Tag tag = attribute.PeekTag();
        if(tag.TagClass != TagClass.Universal)
        {
            _ = attribute.ReadEncodedValue();

            return null;
        }

        var tagNumber = (UniversalTagNumber)tag.TagValue;
        bool isDirectoryString = tagNumber is UniversalTagNumber.UTF8String
            or UniversalTagNumber.PrintableString
            or UniversalTagNumber.IA5String
            or UniversalTagNumber.T61String
            or UniversalTagNumber.BMPString;
        if(isDirectoryString)
        {
            return attribute.ReadCharacterString(tagNumber);
        }

        _ = attribute.ReadEncodedValue();

        return null;
    }
}
