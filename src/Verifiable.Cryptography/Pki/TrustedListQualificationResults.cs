using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The state a <see cref="TrustService"/> was in at a specific instant — the <c>SI-at-Date-time</c> element
/// of an
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4.3.3</see> result tuple: either a projection of the service's current
/// information (excluding its history), or the applicable
/// <see cref="TrustServiceHistoryEntry"/>, both reduced to the common shape the qualification procedures
/// read. Holds references into the owning <see cref="TrustedList"/>; it owns nothing and must not outlive
/// the list.
/// </summary>
public sealed record TrustServiceStateAtTime
{
    /// <summary>The service type identifier in effect in this state.</summary>
    public required TrustServiceTypeIdentifier ServiceTypeIdentifier { get; init; }

    /// <summary>The service status in effect in this state (the current status, or the history instance's previous status).</summary>
    public required TrustServiceStatus Status { get; init; }

    /// <summary>The instant <see cref="Status"/> took effect.</summary>
    public required DateTimeOffset StatusStartingTime { get; init; }

    /// <summary>The additional-service-information types asserted in this state.</summary>
    public required IReadOnlyList<TrustServiceAdditionalInformationType> AdditionalServiceInformation { get; init; }

    /// <summary>The qualification elements that applied in this state.</summary>
    public required IReadOnlyList<QualificationElement> Qualifications { get; init; }

    /// <summary>Whether this state came from a <see cref="TrustServiceHistoryEntry"/> rather than the service's current information.</summary>
    public required bool IsFromHistory { get; init; }


    /// <summary>Projects a service's current information into the common state shape.</summary>
    /// <param name="service">The service whose current information to project.</param>
    /// <returns>The current state.</returns>
    public static TrustServiceStateAtTime FromCurrent(TrustService service)
    {
        ArgumentNullException.ThrowIfNull(service);

        return new()
        {
            ServiceTypeIdentifier = service.ServiceTypeIdentifier,
            Status = service.Status,
            StatusStartingTime = service.StatusStartingTime,
            AdditionalServiceInformation = service.AdditionalServiceInformation,
            Qualifications = service.Qualifications,
            IsFromHistory = false
        };
    }

    /// <summary>Projects a history instance into the common state shape.</summary>
    /// <param name="entry">The history instance to project.</param>
    /// <returns>The historical state.</returns>
    public static TrustServiceStateAtTime FromHistory(TrustServiceHistoryEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return new()
        {
            ServiceTypeIdentifier = entry.ServiceTypeIdentifier,
            Status = entry.PreviousStatus,
            StatusStartingTime = entry.StatusStartingTime,
            AdditionalServiceInformation = entry.AdditionalServiceInformation,
            Qualifications = entry.Qualifications,
            IsFromHistory = true
        };
    }
}


/// <summary>
/// One tuple of the <c>SI-Results</c> output of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4.3.3</see>: the matched service (<c>SI-full</c>), its state at the
/// evaluation time (<c>SI-at-Date-time</c>), and the operating provider's names (<c>TSP-Name</c> /
/// <c>TSP-Trade-Name</c>). Holds references into the owning <see cref="TrustedList"/>; it owns nothing and
/// must not outlive the list.
/// </summary>
public sealed record MatchedServiceInformation
{
    /// <summary>The matched service, complete with its history (<c>SI-full</c>).</summary>
    public required TrustService Service { get; init; }

    /// <summary>The service's state applicable at the evaluation time (<c>SI-at-Date-time</c>).</summary>
    public required TrustServiceStateAtTime StateAtTime { get; init; }

    /// <summary>The operating provider's legal names, one entry per language (<c>TSP-Name</c>).</summary>
    public required IReadOnlyList<LocalizedText> ProviderNames { get; init; }

    /// <summary>The operating provider's trade names, one entry per language (<c>TSP-Trade-Name</c>).</summary>
    public required IReadOnlyList<LocalizedText> ProviderTradeNames { get; init; }

    /// <summary>The matched service's digital identity — the anchor material the match was made against.</summary>
    public required ServiceDigitalIdentity DigitalIdentity { get; init; }
}


/// <summary>
/// The outcome of the clause 4.3 procedure (obtaining listed services matching a certificate) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1</see>: the <c>SI-Status</c>, <c>SI-Sub-Status</c> and <c>SI-Results</c> outputs.
/// </summary>
[DebuggerDisplay("ListedServicesMatchResult: {Status}, {Matches.Count} matches")]
public sealed record ListedServicesMatchResult
{
    /// <summary>The procedure's main status indication (<c>SI-Status</c>).</summary>
    public required TrustedListProcessStatus Status { get; init; }

    /// <summary>The supplementary indications (<c>SI-Sub-Status</c>).</summary>
    public required IReadOnlyList<TrustedListQualificationSubStatus> SubStatuses { get; init; }

    /// <summary>The matched service tuples (<c>SI-Results</c>); empty when nothing matched or the procedure failed.</summary>
    public required IReadOnlyList<MatchedServiceInformation> Matches { get; init; }
}


/// <summary>
/// The outcome of the clause 4.4 procedure (EU qualified certificate determination) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1</see>: the <c>QC-Status</c>, <c>QC-Sub-Status</c> and <c>QC-Results</c> outputs,
/// plus the three <c>CHECK_*_SET-OF_QE</c> intermediate outputs the clause 4.5 QSCD determination consumes.
/// </summary>
[DebuggerDisplay("EuQualifiedCertificateDeterminationResult: {Status}, {Indications.Count} indications")]
public sealed record EuQualifiedCertificateDeterminationResult
{
    /// <summary>The procedure's main status indication (<c>QC-Status</c>).</summary>
    public required TrustedListProcessStatus Status { get; init; }

    /// <summary>The supplementary indications (<c>QC-Sub-Status</c>).</summary>
    public required IReadOnlyList<TrustedListQualificationSubStatus> SubStatuses { get; init; }

    /// <summary>The determined indications (<c>QC-Results</c>); empty when the procedure failed before producing any.</summary>
    public required IReadOnlyList<EuQualifiedCertificateIndication> Indications { get; init; }

    /// <summary>The qualification elements whose criteria identified the certificate on for-eSignatures states (<c>CHECK_1_SET-OF_QE</c>).</summary>
    public required IReadOnlyList<QualificationElement> ESignatureQualificationElements { get; init; }

    /// <summary>The qualification elements whose criteria identified the certificate on for-eSeals states (<c>CHECK_2_SET-OF_QE</c>).</summary>
    public required IReadOnlyList<QualificationElement> ESealQualificationElements { get; init; }

    /// <summary>The qualification elements whose criteria identified the certificate on for-website-authentication states (<c>CHECK_3_SET-OF_QE</c>).</summary>
    public required IReadOnlyList<QualificationElement> WebsiteAuthenticationQualificationElements { get; init; }
}


/// <summary>
/// The outcome of the clause 4.5 procedure (QSCD determination) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1</see>: the <c>QSCD-Status</c>, <c>QSCD-Sub-Status</c> and <c>QSCD-Results</c>
/// outputs.
/// </summary>
[DebuggerDisplay("QualifiedSignatureCreationDeviceDeterminationResult: {Status}, {Indication}")]
public sealed record QualifiedSignatureCreationDeviceDeterminationResult
{
    /// <summary>The procedure's main status indication (<c>QSCD-Status</c>).</summary>
    public required TrustedListProcessStatus Status { get; init; }

    /// <summary>The supplementary indications (<c>QSCD-Sub-Status</c>).</summary>
    public required IReadOnlyList<TrustedListQualificationSubStatus> SubStatuses { get; init; }

    /// <summary>The determined device indication (<c>QSCD-Results</c>); <see langword="null"/> when the procedure failed before producing one.</summary>
    public required QualifiedSignatureCreationDeviceIndication? Indication { get; init; }
}


/// <summary>
/// The outcome of the clause 4.6 procedure (EU trust service token issuer qualification determination) of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1</see>: the <c>QTSTo-Status</c>, <c>QTSTo-Sub-Status</c>, <c>QTSTo-Results</c>
/// and <c>TSP-Name</c> outputs. The clause 4.7 time stamp determination reports the same shape through
/// composition.
/// </summary>
[DebuggerDisplay("TrustServiceTokenIssuerQualificationResult: {Status}, {Indication}")]
public sealed record TrustServiceTokenIssuerQualificationResult
{
    /// <summary>The procedure's main status indication (<c>QTSTo-Status</c>).</summary>
    public required TrustedListProcessStatus Status { get; init; }

    /// <summary>The supplementary indications (<c>QTSTo-Sub-Status</c>).</summary>
    public required IReadOnlyList<TrustedListQualificationSubStatus> SubStatuses { get; init; }

    /// <summary>The determined qualification indication (<c>QTSTo-Results</c>); <see langword="null"/> when the procedure failed before producing one.</summary>
    public required TrustServiceTokenIssuerIndication? Indication { get; init; }

    /// <summary>The matched provider's legal names (<c>TSP-Name</c>); empty when the procedure produced none.</summary>
    public required IReadOnlyList<LocalizedText> ProviderNames { get; init; }
}
