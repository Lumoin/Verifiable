using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>sigPl</c> signed header parameter, unifying
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.4</see> (CB-AdES, label 263, clause 5.2.1 Table 1) and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.2.4</see> (JAdES, JA-5.2.4-01/-02) — an address associated with the
/// signer at a particular geographical (e.g. city) location. Modelled after schema.org's
/// <see href="https://schema.org/PostalAddress">PostalAddress</see> (clause 5.2.4 NOTE in both specifications —
/// informative only, not a normative dependency).
/// </summary>
/// <remarks>
/// <para>
/// CB-AdES CDDL (clause 5.2.4): <c>sigPl = { ?1 =&gt; tstr, ?2 =&gt; tstr, ?3 =&gt; tstr, ?4 =&gt; tstr, ?5 =&gt;
/// tstr, ?6 =&gt; tstr }</c>. Table 3 (clause 5.2.4) assigns the map key values: <c>addressCountry</c> = <c>1</c>,
/// <c>addressLocality</c> = <c>2</c>, <c>addressRegion</c> = <c>3</c>, <c>postOfficeBoxNumber</c> = <c>4</c>,
/// <c>postalCode</c> = <c>5</c>, <c>streetAddress</c> = <c>6</c>.
/// </para>
/// <para>JAdES JSON Schema (clause 5.2.4, copied from Annex B.1): the same six members, each individually
/// optional under the same names as CB-AdES's map keys.</para>
/// <para>
/// <strong>At-least-one-member.</strong> In both specifications every member is individually optional, but the
/// container as a whole requires at least one to be present: CB-AdES's CDDL states the map "shall have at least
/// one of its members" (clause 5.2.4); JAdES's schema carries <c>"minProperties": 1</c>. Mirroring
/// <see cref="Verifiable.Cryptography.Pki.CAdESSignerLocation"/>'s "at least one field present" convention, that
/// invariant is documented here rather than runtime-enforced by this record; the codec/builder layer that
/// produces <c>sigPl</c> is the enforcement point in both formats.
/// </para>
/// <para>
/// <c>sigPl</c> is a signer-qualifying header parameter in both specifications: CB-AdES states "The
/// <c>sigPl</c> header parameter shall be a signed header parameter that qualifies the signer" (clause 5.2.4);
/// JAdES states the equivalent (JA-5.2.4-01) and carries it in the JWS Protected Header (JA-5.2.4-03/-06).
/// Placing it in the protected/signed headers at the signer layer is the signature builder's responsibility —
/// this type models only the parameter's own content.
/// </para>
/// <para>
/// <strong><see cref="AddressCountry"/> reading:</strong> CB-AdES clause 5.2.4's own
/// sentence is garbled in the source — "The <c>addressCountry</c> member shall contain may contain either the
/// name of the country or its two-letter ISO 3166-1 [i.14] alpha-2 country code" duplicates "shall
/// contain"/"may contain". Every other <c>sigPl</c> member is CDDL-optional and clause 5.2.4 never says "shall
/// contain" elsewhere, so this is read permissively ("may contain") — <see cref="AddressCountry"/> stays
/// optional like every other member, accepting either a free-text country name or an ISO 3166-1 alpha-2 code in
/// the same string field (union-shaped content, not two separate fields or a closed enum). JAdES states the
/// same permissive rule directly and without the garbling (JA-5.2.4-05): <see cref="AddressCountry"/> may
/// contain either the country's name or its two-letter ISO 3166-1 alpha-2 country code.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record AdESSignatureProductionPlace
{
    /// <summary>
    /// Gets the country — either its name or its two-letter ISO 3166-1 alpha-2 code (ETSI TS 119 152-1 clause
    /// 5.2.4, see the <see cref="AdESSignatureProductionPlace"/> remarks for the reading; ETSI TS 119 182-1
    /// clause 5.2.4, JA-5.2.4-05) — or <see langword="null"/> to omit it.
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
                ? $"AdESSignatureProductionPlace: {string.Join(", ", parts)}"
                : "AdESSignatureProductionPlace: (empty)";
        }
    }
}
