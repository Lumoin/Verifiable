using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The facts about an X.509 certificate that the
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4</see> qualification procedures read: issuer and subject identification
/// for trusted-list selection and provider-name consistency, the EN 319 412-5 QC statements and the ETSI
/// certificate policy identifiers the determination tables select rows by, and the extension contents the
/// TS 119 612 clause 5.5.9.2.2 criteria trees assert against. A pure-data record: the caller extracts these
/// from the certificate with whatever X.509 machinery it composes (the certificate bytes themselves travel
/// separately as <see cref="PkiCertificateMemory"/> for the service-matching seam), keeping the procedures
/// free of any certificate-library dependency, in the same way <see cref="X509CertificateProfile"/> keeps
/// profile enforcement backend-neutral. <see cref="QualifiedCertificateFactsExtractor"/> is the in-library
/// population, reading the facts straight off the certificate DER.
/// </summary>
[DebuggerDisplay("QualifiedCertificateFacts: issuer C={IssuerCountryCode}, QcCompliance={HasQcCompliance}, QcTypes={QcTypes.Count}")]
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
