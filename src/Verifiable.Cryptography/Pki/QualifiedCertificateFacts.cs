using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The facts about an X.509 certificate that the
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4</see> qualification procedures read: issuer and subject identification
/// for trusted-list selection and provider-name consistency, the
/// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
/// ETSI EN 319 412-5 V2.6.1</see> QC statements (compliance and type, the legislation-country statements of
/// clauses 4.2.4 and 4.2.5, and the generic statements of clause 4.3 — limit value, retention period, PDS
/// locations, and identification method) and the ETSI certificate policy identifiers the determination
/// tables select rows by, and the extension contents the TS 119 612 clause 5.5.9.2.2 criteria trees assert
/// against. A pure-data record: the caller extracts these from the certificate with whatever X.509 machinery
/// it composes (the certificate bytes themselves travel separately as <see cref="PkiCertificateMemory"/> for
/// the service-matching seam), keeping the procedures free of any certificate-library dependency, in the
/// same way <see cref="X509CertificateProfile"/> keeps profile enforcement backend-neutral.
/// <see cref="QualifiedCertificateFactsExtractor"/> is the in-library population, reading the facts straight
/// off the certificate DER.
/// </summary>
[DebuggerDisplay("QualifiedCertificateFacts: issuer C={IssuerCountryCode}, QcCompliance={HasQcCompliance}, QcSscd={HasQcSscdStatement}, QcTypes={QcTypes.Count}, policies={CertificatePolicyOids.Count}")]
public sealed record QualifiedCertificateFacts
{
    /// <summary>
    /// The <c>countryName</c> attribute value of the certificate's issuer field, or <see langword="null"/>
    /// when the issuer carries none. PRO-4.4.4-01 derives the trusted-list country code from this value via
    /// <see cref="TrustedListQualification.ResolveTrustedListTerritory(string)"/>.
    /// </summary>
    public required string? IssuerCountryCode { get; init; }

    /// <summary>The <c>organizationName</c> attribute values of the certificate's issuer field, in certificate order (PRO-4.4.4-06 matches these against the provider's names).</summary>
    public required IReadOnlyList<string> IssuerOrganizationNames { get; init; }

    /// <summary>The <c>commonName</c> attribute values of the certificate's issuer field, in certificate order (the PRO-4.4.4-06 (b) fallback identification strategy).</summary>
    public required IReadOnlyList<string> IssuerCommonNames { get; init; }

    /// <summary>The certificate issuer's distinguished name as a string, when the caller supplies one for the PRO-4.4.4-06 (b) fallback comparison against a <see cref="X509SubjectNameIdentity"/>; otherwise <see langword="null"/>.</summary>
    public string? IssuerDistinguishedName { get; init; }

    /// <summary>The <c>countryName</c> attribute value of the certificate's subject field, or <see langword="null"/> when the subject carries none (PRO-4.6.4-02 derives the token issuer's trusted-list country code from this value).</summary>
    public required string? SubjectCountryCode { get; init; }

    /// <summary>The <c>organizationName</c> attribute values of the certificate's subject field, in certificate order (PRO-4.6.4-08 matches these against the provider's names).</summary>
    public required IReadOnlyList<string> SubjectOrganizationNames { get; init; }

    /// <summary>The certificate's <c>notBefore</c> validity instant (PRO-4.4.4-07 and PRO-4.4.4-34 evaluate the determination at this instant too).</summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>Whether the certificate carries the EN 319 412-5 <c>id-etsi-qcs-QcCompliance</c> statement.</summary>
    public required bool HasQcCompliance { get; init; }

    /// <summary>The EN 319 412-5 <c>id-etsi-qcs-QcType</c> values the certificate declares, in certificate order; empty when the statement is absent.</summary>
    public required IReadOnlyList<EuQualifiedCertificateType> QcTypes { get; init; }

    /// <summary>Whether the certificate carries the EN 319 412-5 <c>id-etsi-qcs-QcSSCD</c> statement (the Tables 6 and 7 row selector).</summary>
    public required bool HasQcSscdStatement { get; init; }

    /// <summary>The EN 319 412-5 clause 4.3.2 <c>id-etsi-qcs-QcLimitValue</c> statement's transaction-value limit, or <see langword="null"/> when the statement is absent.</summary>
    public required QcMonetaryValue? QcLimitValue { get; init; }

    /// <summary>The EN 319 412-5 clause 4.3.3 <c>id-etsi-qcs-QcRetentionPeriod</c> statement's retention period, expressed as a number of years after certificate expiry, or <see langword="null"/> when the statement is absent.</summary>
    public required BigInteger? QcRetentionPeriodYears { get; init; }

    /// <summary>The EN 319 412-5 clause 4.3.4 <c>id-etsi-qcs-QcPDS</c> statement's PKI Disclosure Statement locations, in certificate order; empty when the statement is absent.</summary>
    public required IReadOnlyList<PdsLocation> QcPdsLocations { get; init; }

    /// <summary>The EN 319 412-5 clause 4.2.4 <c>id-etsi-qcs-QcCClegislation</c> statement's country codes under whose legislation the certificate is issued as a qualified certificate, in certificate order; empty when the statement is absent.</summary>
    public required IReadOnlyList<string> QcCcLegislationCountryCodes { get; init; }

    /// <summary>The EN 319 412-5 clause 4.3.5 <c>id-etsi-qcs-QcIdentMethod</c> statement's eIDAS/eIDAS2 Article 24 identification methods, in certificate order; empty when the statement is absent, and identifiers this library does not recognise are omitted.</summary>
    public required IReadOnlyList<EuIdentityVerificationMethod> QcIdentityVerificationMethods { get; init; }

    /// <summary>The EN 319 412-5 clause 4.2.5 <c>id-etsi-qcs-QcQSCDlegislation</c> statement's country codes under whose legislation the QSCD was certified, in certificate order; empty when the statement is absent.</summary>
    public required IReadOnlyList<string> QcQscdLegislationCountryCodes { get; init; }

    /// <summary>Whether the certificate carries a CertificatePolicies extension at all — a TS 119 612 clause 5.5.9.2.2.2 <c>PolicySet</c> assertion requires the extension to be present, not merely its identifiers to be vacuously matched.</summary>
    public required bool HasCertificatePoliciesExtension { get; init; }

    /// <summary>The dotted-decimal certificate policy object identifiers the certificate's CertificatePolicies extension carries, in certificate order.</summary>
    public required IReadOnlyList<string> CertificatePolicyOids { get; init; }

    /// <summary>Whether the certificate carries a KeyUsage extension at all — a TS 119 612 clause 5.5.9.2.2.1 <c>KeyUsage</c> assertion requires the extension to be present.</summary>
    public required bool HasKeyUsageExtension { get; init; }

    /// <summary>The Key Usage bits the certificate asserts (set to one); a bit not listed reads as zero.</summary>
    public required IReadOnlyList<KeyUsageBitName> SetKeyUsageBits { get; init; }

    /// <summary>Whether the certificate carries an ExtendedKeyUsage extension at all — a TS 119 612 clause 5.5.9.2.2.3 <c>ExtendedKeyUsage</c> assertion requires the extension to be present.</summary>
    public required bool HasExtendedKeyUsageExtension { get; init; }

    /// <summary>The dotted-decimal key purpose object identifiers the certificate's ExtendedKeyUsage extension carries, in certificate order.</summary>
    public required IReadOnlyList<string> ExtendedKeyUsageOids { get; init; }

    /// <summary>The dotted-decimal attribute type object identifiers present in the certificate's subject distinguished name, in certificate order (the TS 119 612 clause 5.5.9.2.2.3 <c>CertSubjectDNAttribute</c> assertion input).</summary>
    public required IReadOnlyList<string> SubjectAttributeTypeOids { get; init; }
}


/// <summary>
/// The EN 319 412-5 clause 4.3.2 <c>MonetaryValue</c> a <c>QcLimitValue</c> statement carries: a transaction
/// value limit of <see cref="Amount"/> × 10^<see cref="Exponent"/> in the currency the <c>Iso4217CurrencyCode</c>
/// CHOICE identifies — exactly one of <see cref="AlphabeticCurrencyCode"/> or <see cref="NumericCurrencyCode"/>
/// is non-null, as read off the wire.
/// </summary>
/// <param name="AlphabeticCurrencyCode">The ISO 4217 alphabetic currency code, or <see langword="null"/> when the statement used the numeric alternative.</param>
/// <param name="NumericCurrencyCode">The ISO 4217 numeric currency code, or <see langword="null"/> when the statement used the alphabetic alternative.</param>
/// <param name="Amount">The <c>MonetaryValue.amount</c> integer.</param>
/// <param name="Exponent">The <c>MonetaryValue.exponent</c> integer; the represented value is <see cref="Amount"/> × 10^<see cref="Exponent"/>.</param>
[DebuggerDisplay("QcMonetaryValue: {Amount}E{Exponent}, alpha={AlphabeticCurrencyCode}, num={NumericCurrencyCode}")]
public sealed record QcMonetaryValue(string? AlphabeticCurrencyCode, BigInteger? NumericCurrencyCode, BigInteger Amount, BigInteger Exponent);


/// <summary>
/// One EN 319 412-5 clause 4.3.4 <c>PdsLocation</c> from a <c>QcPDS</c> statement: a PKI Disclosure
/// Statement's URL and the language it is written in.
/// </summary>
/// <param name="Url">The PDS location, an IA5String off the wire (QCS-4.3.4-03 expects an <c>https</c> URL).</param>
/// <param name="Language">The two-character ISO 639 Set 1 language code (QCS-4.3.4-01).</param>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "The value is a fact recorded as the certificate wrote it: the extractor treats the bytes as hostile and must surface a location that is not a parseable URI rather than throw, and System.Uri normalises case, escaping and default ports, which would make the fact differ from the wire. QCS-4.3.4-03's https requirement is an issuance-profile rule the read side observes, not enforces.")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The property carries the constructor parameter verbatim; see the CA1054 justification.")]
[DebuggerDisplay("PdsLocation: {Language} {Url}")]
public sealed record PdsLocation(string Url, string Language);


/// <summary>
/// The EN 319 412-5 clause 4.3.5 <c>QcIdentMethod</c> statement's eIDAS/eIDAS2 Article 24 identification
/// methods — the four identifiers Annex B assigns, for the <c>id-etsi-qcs-QcIdentMethod</c> statement whose
/// syntax clause 4.3.5.1 defines, with the eIDAS2 pair also defined in clause 4.3.5.3. Mirrors
/// <see cref="EuQualifiedCertificateType"/>: member values match the object identifier arc's last number.
/// </summary>
public enum EuIdentityVerificationMethod
{
    /// <summary>Not a specification value: the CLR default for an uninitialized value. A certificate's declared method list never contains it.</summary>
    None = 0,

    /// <summary>Identification according to eIDAS1 Article 24 paragraph 1 a) or b) (<c>id-etsi-qct-eIDAS1-ab</c>, OID 0.4.0.1862.1.8.1).</summary>
    Eidas1Ab = 1,

    /// <summary>Identification according to eIDAS1 Article 24 paragraph 1 c) or d) (<c>id-etsi-qct-eIDAS1-cd</c>, OID 0.4.0.1862.1.8.2).</summary>
    Eidas1Cd = 2,

    /// <summary>Identification according to eIDAS2 Article 24 paragraph 1a a), c) or d) (<c>id-etsi-qct-eIDAS2-acd</c>, OID 0.4.0.1862.1.8.3).</summary>
    Eidas2Acd = 3,

    /// <summary>Identification according to eIDAS2 Article 24 paragraph 1a b) (<c>id-etsi-qct-eIDAS2-b</c>, OID 0.4.0.1862.1.8.4).</summary>
    Eidas2B = 4
}


/// <summary>
/// Maps <see cref="EuIdentityVerificationMethod"/> to and from the EN 319 412-5 <c>QcIdentMethod</c> object
/// identifiers Annex B assigns under clause 4.3.5.1, with the eIDAS2 pair also defined in clause 4.3.5.3, that
/// a certificate's <c>id-etsi-qcs-QcIdentMethod</c> statement carries.
/// </summary>
public static class EuIdentityVerificationMethodMapping
{
    /// <summary>Maps a QcIdentMethod object identifier to an <see cref="EuIdentityVerificationMethod"/>.</summary>
    /// <param name="oid">The dotted-decimal object identifier.</param>
    /// <returns>The matching method, or <see langword="null"/> when the identifier is not a known QcIdentMethod.</returns>
    public static EuIdentityVerificationMethod? FromOid(string oid) => oid switch
    {
        WellKnownOids.QcIdentMethodEidas1Ab => EuIdentityVerificationMethod.Eidas1Ab,
        WellKnownOids.QcIdentMethodEidas1Cd => EuIdentityVerificationMethod.Eidas1Cd,
        WellKnownOids.QcIdentMethodEidas2Acd => EuIdentityVerificationMethod.Eidas2Acd,
        WellKnownOids.QcIdentMethodEidas2B => EuIdentityVerificationMethod.Eidas2B,
        _ => null
    };

    /// <summary>Maps an <see cref="EuIdentityVerificationMethod"/> to its QcIdentMethod object identifier.</summary>
    /// <param name="method">The method to map.</param>
    /// <returns>The dotted-decimal object identifier of one of the four EN 319 412-5 identification methods.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="method"/> is not one of the four EN 319 412-5 identification methods.</exception>
    public static string ToOid(EuIdentityVerificationMethod method) => method switch
    {
        EuIdentityVerificationMethod.Eidas1Ab => WellKnownOids.QcIdentMethodEidas1Ab,
        EuIdentityVerificationMethod.Eidas1Cd => WellKnownOids.QcIdentMethodEidas1Cd,
        EuIdentityVerificationMethod.Eidas2Acd => WellKnownOids.QcIdentMethodEidas2Acd,
        EuIdentityVerificationMethod.Eidas2B => WellKnownOids.QcIdentMethodEidas2B,
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Only the four EN 319 412-5 identification methods have an object identifier.")
    };
}


/// <summary>
/// Decides whether a certificate is recognised by a trust service's digital identity — the check (ii) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 PRO-4.3.4-03</see>: either an RFC 5280 section 6.1 certification path from the
/// service's digital identity (as trust anchor) to the certificate validates successfully at the evaluation
/// time, or the digital identity's public key and subject name are identical to the certificate's own.
/// </summary>
/// <remarks>
/// This library ships the seam, not a path builder: an implementation typically composes
/// <see cref="ValidateCertificateChainAsyncDelegate"/> (and, when intermediates must be fetched,
/// <see cref="CompleteCertificateChainAsyncDelegate"/>) with each
/// <see cref="X509CertificateIdentity"/> entry of <paramref name="serviceDigitalIdentity"/> as the sole
/// trust anchor, and falls back to the direct public-key-and-subject-name comparison for the path-length-zero
/// case. PRO-4.3.4-03 fixes the RFC 5280 section 6.1.1 inputs: (b) is <paramref name="validationTime"/> and
/// (c) to (i) take the default values of the <c>PathConstraints</c> type of Common PKI v2.0 part 5 Table 1.
/// </remarks>
/// <param name="certificate">The certificate being qualified. The caller retains ownership.</param>
/// <param name="serviceDigitalIdentity">The service's digital identity to match against; its entries are alternatives, any one of which suffices.</param>
/// <param name="validationTime">The instant the certification path must be valid at.</param>
/// <param name="pool">The memory pool the implementation rents any scratch buffers from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns><see langword="true"/> when the service's digital identity recognises the certificate.</returns>
public delegate ValueTask<bool> MatchCertificateToTrustServiceAsyncDelegate(
    PkiCertificateMemory certificate,
    ServiceDigitalIdentity serviceDigitalIdentity,
    DateTimeOffset validationTime,
    BaseMemoryPool pool,
    CancellationToken cancellationToken);
