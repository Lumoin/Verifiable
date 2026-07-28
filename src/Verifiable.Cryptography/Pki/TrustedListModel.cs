using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One language-tagged text value from a Trusted List's many multilingual (<c>InternationalNamesType</c> /
/// <c>MultiLangStringType</c> / <c>MultiLangNormStringType</c>) fields, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.1.4</see> (Language support). Every such field in this model is an
/// <see cref="IReadOnlyList{T}"/> of this one shape, so a caller reads scheme names, service names, TSP
/// names, and legal notices the same way regardless of which field they came from.
/// </summary>
/// <param name="Language">The <c>xml:lang</c> tag (for example <c>"en"</c>).</param>
/// <param name="Value">The text in that language.</param>
public sealed record LocalizedText(string Language, string Value);


/// <summary>
/// A postal address, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.3.5.1</see> (scheme operator) / clause 5.4.3 (TSP) — both use the same
/// <c>PostalAddressType</c>.
/// </summary>
public sealed record TrustedListPostalAddress
{
    /// <summary>The <c>xml:lang</c> tag this address is given in.</summary>
    public required string Language { get; init; }

    /// <summary>The street address line.</summary>
    public required string StreetAddress { get; init; }

    /// <summary>The locality (city/town).</summary>
    public required string Locality { get; init; }

    /// <summary>The state or province, when the document supplied one.</summary>
    public string? StateOrProvince { get; init; }

    /// <summary>The postal code, when the document supplied one.</summary>
    public string? PostalCode { get; init; }

    /// <summary>The ISO 3166 country code.</summary>
    public required string CountryName { get; init; }
}


/// <summary>
/// The <c>SchemeInformation</c> block of a <see cref="TrustedList"/> — the scheme operator's identity and
/// the rules governing the list itself, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.3</see>.
/// </summary>
public sealed record TrustedListSchemeInformation
{
    /// <summary>The version of the TSLType/version-specific schema the document was written to (clause 5.3.1).</summary>
    public required int TslVersionIdentifier { get; init; }

    /// <summary>The monotonically increasing sequence number of this list (clause 5.3.2).</summary>
    public required int TslSequenceNumber { get; init; }

    /// <summary>Whether this document is a Trusted List or the List Of the Trusted Lists (clause 5.3.3).</summary>
    public required TrustedListKind TslType { get; init; }

    /// <summary>The scheme operator's name, one entry per language (clause 5.3.4).</summary>
    public required IReadOnlyList<LocalizedText> SchemeOperatorNames { get; init; }

    /// <summary>The scheme operator's postal addresses, one entry per language (clause 5.3.5.1).</summary>
    public required IReadOnlyList<TrustedListPostalAddress> SchemeOperatorPostalAddresses { get; init; }

    /// <summary>The scheme operator's electronic addresses (URIs), one entry per language (clause 5.3.5.2).</summary>
    public required IReadOnlyList<LocalizedText> SchemeOperatorElectronicAddresses { get; init; }

    /// <summary>The scheme's own name, one entry per language (clause 5.3.6).</summary>
    public required IReadOnlyList<LocalizedText> SchemeNames { get; init; }

    /// <summary>URIs of human-readable information about the scheme, one entry per language (clause 5.3.7).</summary>
    public required IReadOnlyList<LocalizedText> SchemeInformationUris { get; init; }

    /// <summary>The URI identifying how a service's status is determined (clause 5.3.8).</summary>
    public required string StatusDeterminationApproach { get; init; }

    /// <summary>The scheme's community rules URIs, one entry per language (clause 5.3.9).</summary>
    public IReadOnlyList<LocalizedText> SchemeTypeCommunityRules { get; init; } = [];

    /// <summary>The ISO 3166 territory code the scheme covers — <c>"EU"</c> for the List Of the Trusted Lists (clause 5.3.10).</summary>
    public string? SchemeTerritory { get; init; }

    /// <summary>The scheme's policy or legal notice URIs, one entry per language (clause 5.3.11).</summary>
    public IReadOnlyList<LocalizedText> PolicyOrLegalNotices { get; init; } = [];

    /// <summary>The number of years historical service information must be retained for (clause 5.3.12).</summary>
    public required int HistoricalInformationPeriodYears { get; init; }

    /// <summary>Pointers to other Trusted Lists (clause 5.3.13) — the LOTL/pivot mechanism's data.</summary>
    public IReadOnlyList<OtherTrustedListPointer> PointersToOtherTrustedLists { get; init; } = [];

    /// <summary>The instant this list was issued (clause 5.3.14).</summary>
    public required DateTimeOffset ListIssueDateTime { get; init; }

    /// <summary>The instant the next update is expected, when the document supplied one (clause 5.3.15).</summary>
    public DateTimeOffset? NextUpdate { get; init; }

    /// <summary>URIs at which this list is published (clause 5.3.16).</summary>
    public IReadOnlyList<string> DistributionPoints { get; init; } = [];
}


/// <summary>
/// A pointer from a <see cref="TrustedList"/> to another Trusted List, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.3.13</see>. On the EU List Of the Trusted Lists this is how every member
/// state list — and every historical pivot LOTL — is reached; <see cref="ServiceDigitalIdentities"/> carries
/// the trust anchors the pointed-to list's own signature must be verified against, letting the LOTL bootstrap
/// trust in each list it points to rather than relying on PKIX discovery.
/// </summary>
public sealed record OtherTrustedListPointer : IDisposable
{
    /// <summary>The location (URI) the pointed-to list is published at (clause 5.3.13 item a).</summary>
    public required Uri TslLocation { get; init; }

    /// <summary>The trust anchors for the pointed-to list's signature (clause 5.3.13 item b), when the document supplied any.</summary>
    public required ServiceDigitalIdentity ServiceDigitalIdentities { get; init; }

    /// <summary>The additional information describing the pointed-to list (clause 5.3.13 item c).</summary>
    public required OtherTrustedListPointerAdditionalInformation AdditionalInformation { get; init; }


    /// <summary>Disposes <see cref="ServiceDigitalIdentities"/>.</summary>
    public void Dispose() => ServiceDigitalIdentities.Dispose();
}


/// <summary>
/// The additional information carried by an <see cref="OtherTrustedListPointer"/> — the fields a caller
/// needs to select the EU LOTL pointer itself versus a member-state Trusted List pointer, and to route a
/// pivot walk, without fetching the pointed-to document first.
/// </summary>
public sealed record OtherTrustedListPointerAdditionalInformation
{
    /// <summary>The pointed-to list's scheme territory (ISO 3166 country code, or <c>"EU"</c> for a LOTL pointer), when the document supplied one.</summary>
    public string? SchemeTerritory { get; init; }

    /// <summary>The MIME type of the pointed-to document, when the document supplied one (for example distinguishing an XML list from a machine-convertible other format).</summary>
    public string? MimeType { get; init; }

    /// <summary>The pointed-to scheme operator's name, one entry per language, when the document supplied any.</summary>
    public IReadOnlyList<LocalizedText> SchemeOperatorNames { get; init; } = [];

    /// <summary>The pointed-to scheme's community rules URIs, when the document supplied any.</summary>
    public IReadOnlyList<string> SchemeTypeCommunityRules { get; init; } = [];

    /// <summary>Free-text information about the pointed-to list, one entry per language, when the document supplied any.</summary>
    public IReadOnlyList<LocalizedText> TextualInformation { get; init; } = [];
}


/// <summary>
/// A Trust Service Provider — an entity operating one or more <see cref="TrustService"/>s — per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.4</see>.
/// </summary>
public sealed record TrustServiceProvider : IDisposable
{
    /// <summary>The TSP's legal name, one entry per language (clause 5.4.1).</summary>
    public required IReadOnlyList<LocalizedText> Names { get; init; }

    /// <summary>The TSP's trade name, one entry per language, when the document supplied one (clause 5.4.2).</summary>
    public IReadOnlyList<LocalizedText> TradeNames { get; init; } = [];

    /// <summary>The TSP's postal addresses, one entry per language (clause 5.4.3).</summary>
    public required IReadOnlyList<TrustedListPostalAddress> PostalAddresses { get; init; }

    /// <summary>The TSP's electronic addresses (URIs), one entry per language (clause 5.4.3).</summary>
    public required IReadOnlyList<LocalizedText> ElectronicAddresses { get; init; }

    /// <summary>URIs of human-readable information about the TSP, one entry per language (clause 5.4.4).</summary>
    public required IReadOnlyList<LocalizedText> InformationUris { get; init; }

    /// <summary>The services this TSP operates (clause 5.4.6).</summary>
    public required IReadOnlyList<TrustService> Services { get; init; }


    /// <summary>Disposes every <see cref="Services"/>' owned digital identity material.</summary>
    public void Dispose()
    {
        foreach(TrustService service in Services)
        {
            service.Dispose();
        }
    }
}


/// <summary>
/// One trust service currently offered by a <see cref="TrustServiceProvider"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5</see>. <see cref="History"/> carries the same shape's predecessor
/// states (clause 5.5.10 / 5.6) — a certificate valid under an earlier status must be evaluated against the
/// history entry whose validity window covers the certificate's relevant time, never against the current
/// status alone.
/// </summary>
public sealed record TrustService : IDisposable
{
    /// <summary>What kind of service this is (clause 5.5.1).</summary>
    public required TrustServiceTypeIdentifier ServiceTypeIdentifier { get; init; }

    /// <summary>The service's name, one entry per language (clause 5.5.2).</summary>
    public required IReadOnlyList<LocalizedText> ServiceNames { get; init; }

    /// <summary>The material the service is recognised by (clause 5.5.3).</summary>
    public required ServiceDigitalIdentity DigitalIdentity { get; init; }

    /// <summary>The service's current status (clause 5.5.4).</summary>
    public required TrustServiceStatus Status { get; init; }

    /// <summary>The instant <see cref="Status"/> took effect (clause 5.5.5).</summary>
    public required DateTimeOffset StatusStartingTime { get; init; }

    /// <summary>Additional-service-information types asserted on the service (clause 5.5.9.1).</summary>
    public IReadOnlyList<TrustServiceAdditionalInformationType> AdditionalServiceInformation { get; init; } = [];

    /// <summary>The service's qualification elements (clause 5.5.9.2) — the input to TS 119 615 certificate qualification.</summary>
    public IReadOnlyList<QualificationElement> Qualifications { get; init; } = [];

    /// <summary>The service's prior states, oldest last per the document's own ordering (clause 5.5.10).</summary>
    public IReadOnlyList<TrustServiceHistoryEntry> History { get; init; } = [];


    /// <summary>Disposes <see cref="DigitalIdentity"/> and every <see cref="History"/> entry's owned material.</summary>
    public void Dispose()
    {
        DigitalIdentity.Dispose();
        foreach(TrustServiceHistoryEntry entry in History)
        {
            entry.Dispose();
        }
    }
}


/// <summary>
/// One prior state of a <see cref="TrustService"/>, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.6</see>. A strict subset of <see cref="TrustService"/>'s fields — the
/// schema's <c>ServiceHistoryInstanceType</c> carries no scheme/TSP service-definition URIs or supply
/// points, only what identifies the prior state and how long it held.
/// </summary>
public sealed record TrustServiceHistoryEntry : IDisposable
{
    /// <summary>The service type identifier as it was in this prior state (clause 5.6.1).</summary>
    public required TrustServiceTypeIdentifier ServiceTypeIdentifier { get; init; }

    /// <summary>The service's name as it was in this prior state, one entry per language (clause 5.6.2).</summary>
    public required IReadOnlyList<LocalizedText> ServiceNames { get; init; }

    /// <summary>The digital identity as it was in this prior state (clause 5.6.3).</summary>
    public required ServiceDigitalIdentity DigitalIdentity { get; init; }

    /// <summary>The status that held during this prior state (clause 5.6.4).</summary>
    public required TrustServiceStatus PreviousStatus { get; init; }

    /// <summary>The instant <see cref="PreviousStatus"/> took effect (clause 5.6.5).</summary>
    public required DateTimeOffset StatusStartingTime { get; init; }

    /// <summary>Additional-service-information types asserted during this prior state (clause 5.6.6 / 5.5.9.1).</summary>
    public IReadOnlyList<TrustServiceAdditionalInformationType> AdditionalServiceInformation { get; init; } = [];

    /// <summary>The qualification elements that applied during this prior state (clause 5.6.6 / 5.5.9.2).</summary>
    public IReadOnlyList<QualificationElement> Qualifications { get; init; } = [];


    /// <summary>Disposes <see cref="DigitalIdentity"/>.</summary>
    public void Dispose() => DigitalIdentity.Dispose();
}


/// <summary>
/// A parsed Trusted List (or List Of the Trusted Lists) document, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5</see>. This is the pure, XML-agnostic semantic model:
/// <see cref="ParseTrustedListDelegate"/> produces it from raw document bytes and
/// <see cref="VerifyTrustedListSignatureDelegate"/> separately verifies the document's signature — parsing
/// and trust are independent, exactly as for the CMS/CAdES pair in this namespace. Owns every certificate its
/// tree carries; the caller disposes it.
/// </summary>
public sealed record TrustedList : IDisposable
{
    /// <summary>The list's scheme information (clause 5.3).</summary>
    public required TrustedListSchemeInformation SchemeInformation { get; init; }

    /// <summary>
    /// The Trust Service Providers this list carries directly. Empty for a List Of the Trusted Lists that
    /// carries only <see cref="TrustedListSchemeInformation.PointersToOtherTrustedLists"/> and no services of
    /// its own — the common shape, though the schema does not forbid a LOTL from also listing providers.
    /// </summary>
    public IReadOnlyList<TrustServiceProvider> TrustServiceProviders { get; init; } = [];


    /// <summary>Disposes every owned certificate this list's provider/pointer tree carries.</summary>
    public void Dispose()
    {
        foreach(TrustServiceProvider provider in TrustServiceProviders)
        {
            provider.Dispose();
        }

        foreach(OtherTrustedListPointer pointer in SchemeInformation.PointersToOtherTrustedLists)
        {
            pointer.Dispose();
        }
    }
}
