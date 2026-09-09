using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Renders an X.500 <c>Name</c> (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4">RFC 5280
/// section 4.1.2.4</see>) as an
/// <see href="https://www.rfc-editor.org/rfc/rfc4514">RFC 4514</see> distinguished name string — the form
/// <see cref="ReadCertificateSubjectNameDelegate"/> returns and
/// <see cref="TrustedListMembership.Evaluate(IReadOnlyList{PkiCertificateMemory}, IReadOnlyList{TrustedList}, ReadCertificateSubjectKeyIdentifierDelegate, ReadCertificateSubjectNameDelegate)"/>
/// compares an <see cref="X509SubjectNameIdentity"/> entry against.
/// </summary>
/// <remarks>
/// <para>
/// RFC 4514 section 2.1 states each RDN of the string encoding "from the first to the last" corresponds to the
/// RDNSequence "from the last to the first" — the rendering below therefore emits the DER-encoded relative
/// names in reverse order. Each relative name's AttributeTypeAndValue pairs are joined by <c>+</c> and rendered
/// as <c>type=value</c> with <c>type</c> the RFC 4514 section 3 short descriptor when one is defined for the
/// attribute's object identifier, and the dotted-decimal object identifier otherwise (the grammar's
/// <c>numericoid</c> alternative). Each value is escaped per section 2.4: a leading space or <c>#</c>, a
/// trailing space, any of <c>"+,;&lt;&gt;\</c>, and the null character are backslash-escaped.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> A certificate's Subject is attacker-influenced, so the DER is
/// read through <see cref="AsnReader"/>'s bounds-checked cursors under <see cref="AsnEncodingRules.DER"/>. An
/// attribute value in an encoding this reader does not decode as a <c>DirectoryString</c> contributes nothing
/// to the rendering, mirroring <see cref="PkiDistinguishedNameText"/>'s walk rather than aborting it — the
/// same choice that comparison-only rendering already makes, since a fail-open decoder that stops on the
/// first unrecognised value would let an attacker suppress attributes a comparison relies on.
/// </para>
/// </remarks>
public static class Rfc4514SubjectNameText
{
    /// <summary>The <c>commonName</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string CommonNameDescriptor = "CN";

    /// <summary>The <c>organizationName</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string OrganizationNameDescriptor = "O";

    /// <summary>The <c>organizationalUnitName</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string OrganizationalUnitNameDescriptor = "OU";

    /// <summary>The <c>countryName</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string CountryNameDescriptor = "C";

    /// <summary>The <c>localityName</c> attribute's object identifier (RFC 4514 section 3).</summary>
    private const string LocalityNameOid = "2.5.4.7";

    /// <summary>The <c>localityName</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string LocalityNameDescriptor = "L";

    /// <summary>The <c>stateOrProvinceName</c> attribute's object identifier (RFC 4514 section 3).</summary>
    private const string StateOrProvinceNameOid = "2.5.4.8";

    /// <summary>The <c>stateOrProvinceName</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string StateOrProvinceNameDescriptor = "ST";

    /// <summary>The <c>streetAddress</c> attribute's object identifier (RFC 4514 section 3).</summary>
    private const string StreetAddressOid = "2.5.4.9";

    /// <summary>The <c>streetAddress</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string StreetAddressDescriptor = "STREET";

    /// <summary>The <c>domainComponent</c> attribute's object identifier (RFC 4514 section 3).</summary>
    private const string DomainComponentOid = "0.9.2342.19200300.100.1.25";

    /// <summary>The <c>domainComponent</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string DomainComponentDescriptor = "DC";

    /// <summary>The <c>userid</c> attribute's object identifier (RFC 4514 section 3).</summary>
    private const string UserIdOid = "0.9.2342.19200300.100.1.1";

    /// <summary>The <c>userid</c> attribute's RFC 4514 section 3 short descriptor.</summary>
    private const string UserIdDescriptor = "UID";


    /// <summary>
    /// Renders a <c>Name</c> from its DER encoding as an RFC 4514 distinguished name string.
    /// </summary>
    /// <param name="nameDer">The DER-encoded <c>Name</c>, tag and length included.</param>
    /// <returns>The RFC 4514 distinguished name string; empty when the name carries no relative distinguished names.</returns>
    /// <exception cref="AsnContentException">Thrown when the bytes are not a well-formed <c>Name</c>.</exception>
    public static string FromDer(ReadOnlyMemory<byte> nameDer)
    {
        AsnReader reader = new(nameDer, AsnEncodingRules.DER);
        AsnReader relativeNames = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        List<string> renderedRelativeNames = [];
        while(relativeNames.HasData)
        {
            //A deployed multi-valued relative name violating the DER SET OF sort order must not abort the
            //walk: encoding strictness of a name is the signature verification step's concern, not this
            //rendering's.
            AsnReader relativeName = relativeNames.ReadSetOf(skipSortOrderValidation: true);
            List<string> attributeTypeAndValues = [];
            while(relativeName.HasData)
            {
                AsnReader attribute = relativeName.ReadSequence();
                string attributeType = attribute.ReadObjectIdentifier();
                string? value = PkiDistinguishedNameText.TryReadDirectoryString(attribute);
                attribute.ThrowIfNotEmpty();
                if(value is not null)
                {
                    attributeTypeAndValues.Add($"{Descriptor(attributeType)}={EscapeValue(value)}");
                }
            }

            if(attributeTypeAndValues.Count > 0)
            {
                renderedRelativeNames.Add(string.Join("+", attributeTypeAndValues));
            }
        }

        //RFC 4514 section 2.1: the string's relative names run from the RDNSequence's last to its first.
        renderedRelativeNames.Reverse();

        return string.Join(",", renderedRelativeNames);
    }


    /// <summary>
    /// Maps an attribute type to its RFC 4514 section 3 short descriptor, or to its dotted-decimal object
    /// identifier (the grammar's <c>numericoid</c> alternative) when the section defines no descriptor for it.
    /// </summary>
    /// <param name="attributeType">The dotted-decimal attribute type object identifier.</param>
    /// <returns>The short descriptor, or <paramref name="attributeType"/> itself.</returns>
    private static string Descriptor(string attributeType) => attributeType switch
    {
        WellKnownOids.CommonName => CommonNameDescriptor,
        WellKnownOids.OrganizationName => OrganizationNameDescriptor,
        WellKnownOids.OrganizationalUnitName => OrganizationalUnitNameDescriptor,
        WellKnownOids.CountryName => CountryNameDescriptor,
        LocalityNameOid => LocalityNameDescriptor,
        StateOrProvinceNameOid => StateOrProvinceNameDescriptor,
        StreetAddressOid => StreetAddressDescriptor,
        DomainComponentOid => DomainComponentDescriptor,
        UserIdOid => UserIdDescriptor,
        _ => attributeType
    };


    /// <summary>
    /// Escapes an attribute value per RFC 4514 section 2.4: a leading space or <c>#</c>, a trailing space, any
    /// of <c>"+,;&lt;&gt;\</c>, and the null character are backslash-escaped (the null character as the
    /// two-hex-digit form <c>\00</c>).
    /// </summary>
    /// <param name="value">The attribute value text to escape.</param>
    /// <returns>The escaped value.</returns>
    private static string EscapeValue(string value)
    {
        if(value.Length == 0)
        {
            return value;
        }

        StringBuilder escaped = new(value.Length);
        for(int index = 0; index < value.Length; index++)
        {
            char character = value[index];
            if(character == '\0')
            {
                _ = escaped.Append("\\00");

                continue;
            }

            bool isAlwaysEscaped = character is '"' or '+' or ',' or ';' or '<' or '>' or '\\';
            bool isLeadingSpaceOrHash = index == 0 && character is ' ' or '#';
            bool isTrailingSpace = index == value.Length - 1 && character == ' ';
            if(isAlwaysEscaped || isLeadingSpaceOrHash || isTrailingSpace)
            {
                _ = escaped.Append('\\');
            }

            _ = escaped.Append(character);
        }

        return escaped.ToString();
    }
}
