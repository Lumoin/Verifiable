using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigPl</c> (label 263, clause 5.2.1 Table 1) signed header parameter: an address
/// associated with the signer at a particular geographical (e.g. city) location, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.2.4. Modelled after schema.org's
/// <see href="https://schema.org/PostalAddress">PostalAddress</see> (clause 5.2.4 NOTE — informative only, not a
/// normative dependency).
/// </summary>
/// <remarks>
/// <para>
/// CDDL (clause 5.2.4): <c>sigPl = { ?1 =&gt; tstr, ?2 =&gt; tstr, ?3 =&gt; tstr, ?4 =&gt; tstr, ?5 =&gt; tstr,
/// ?6 =&gt; tstr }</c> — every member is individually optional, but the map as a whole "shall have at least one
/// of its members" (clause 5.2.4). Mirroring
/// <see cref="Verifiable.Cryptography.Pki.CAdESSignerLocation"/>'s "at least one field present" convention, that invariant
/// is documented here rather than runtime-enforced by this record; the codec/builder layer that produces
/// <c>sigPl</c> is the enforcement point. Table 3 (clause 5.2.4) assigns the map key values: <c>addressCountry</c>
/// = <c>1</c>, <c>addressLocality</c> = <c>2</c>, <c>addressRegion</c> = <c>3</c>, <c>postOfficeBoxNumber</c> =
/// <c>4</c>, <c>postalCode</c> = <c>5</c>, <c>streetAddress</c> = <c>6</c>.
/// </para>
/// <para>
/// <c>sigPl</c> is a signer-qualifying header parameter (clause 5.2.4, "The <c>sigPl</c> header parameter shall
/// be a signed header parameter that qualifies the signer"). Placing it in the protected headers map at the
/// signer layer of a <c>COSE_Sign</c> structure (clause 5.2.4) is the signature builder's responsibility — this
/// type models only the parameter's own content.
/// </para>
/// <para>
/// <strong><see cref="AddressCountry"/> reading (contract R-6, D7):</strong> clause 5.2.4's own sentence is
/// garbled in the source — "The <c>addressCountry</c> member shall contain may contain either the name of the
/// country or its two-letter ISO 3166-1 [i.14] alpha-2 country code" duplicates "shall contain"/"may contain".
/// Every other <c>sigPl</c> member is CDDL-optional and clause 5.2.4 never says "shall contain" elsewhere, so
/// this is read permissively ("may contain") — <see cref="AddressCountry"/> stays optional like every other
/// member, accepting either a free-text country name or an ISO 3166-1 alpha-2 code in the same string field
/// (union-shaped content, not two separate fields or a closed enum).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record CBAdESSignatureProductionPlace
{
    /// <summary>The <c>addressCountry</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int AddressCountryKey = 1;

    /// <summary>The <c>addressLocality</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int AddressLocalityKey = 2;

    /// <summary>The <c>addressRegion</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int AddressRegionKey = 3;

    /// <summary>The <c>postOfficeBoxNumber</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int PostOfficeBoxNumberKey = 4;

    /// <summary>The <c>postalCode</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int PostalCodeKey = 5;

    /// <summary>The <c>streetAddress</c> member's map key (Table 3, clause 5.2.4).</summary>
    public const int StreetAddressKey = 6;

    /// <summary>
    /// Gets the country — either its name or its two-letter ISO 3166-1 alpha-2 code (clause 5.2.4; see the
    /// <see cref="CBAdESSignatureProductionPlace"/> remarks for the D7 reading), or <see langword="null"/> to
    /// omit it.
    /// </summary>
    public string? AddressCountry { get; init; }

    /// <summary>Gets the locality (e.g. city), or <see langword="null"/> to omit it.</summary>
    public string? AddressLocality { get; init; }

    /// <summary>Gets the region, or <see langword="null"/> to omit it.</summary>
    public string? AddressRegion { get; init; }

    /// <summary>Gets the post office box number, or <see langword="null"/> to omit it.</summary>
    public string? PostOfficeBoxNumber { get; init; }

    /// <summary>Gets the postal code, or <see langword="null"/> to omit it.</summary>
    public string? PostalCode { get; init; }

    /// <summary>Gets the street address, or <see langword="null"/> to omit it.</summary>
    public string? StreetAddress { get; init; }


    /// <summary>
    /// Builds a compact, human-readable summary of whichever members are present, for the debugger display.
    /// </summary>
    private string DebuggerDisplay
    {
        get
        {
            List<string> parts = [];
            if(StreetAddress is not null)
            {
                parts.Add(StreetAddress);
            }

            if(PostOfficeBoxNumber is not null)
            {
                parts.Add(PostOfficeBoxNumber);
            }

            if(AddressLocality is not null)
            {
                parts.Add(AddressLocality);
            }

            if(AddressRegion is not null)
            {
                parts.Add(AddressRegion);
            }

            if(PostalCode is not null)
            {
                parts.Add(PostalCode);
            }

            if(AddressCountry is not null)
            {
                parts.Add(AddressCountry);
            }

            return parts.Count > 0
                ? $"CBAdESSignatureProductionPlace: {string.Join(", ", parts)}"
                : "CBAdESSignatureProductionPlace: (empty)";
        }
    }
}
