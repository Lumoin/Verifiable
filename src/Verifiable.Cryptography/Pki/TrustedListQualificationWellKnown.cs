using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The specification-defined constants of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1</see>'s qualification procedures that are neither statuses, indications, nor
/// object identifiers (those live in <see cref="WellKnownOids"/>).
/// </summary>
public static class TrustedListQualificationWellKnown
{
    /// <summary>
    /// The instant Regulation (EU) No 910/2014 applied and Directive 1999/93/EC was repealed
    /// (2016-06-30T22:00:00Z) — the boundary PRO-4.4.4-07 and PRO-4.6.4-01 branch the determination
    /// regimes on.
    /// </summary>
    public static DateTimeOffset EidasRegulationApplicationInstant { get; } = new(2016, 6, 30, 22, 0, 0, TimeSpan.Zero);
}


/// <summary>
/// The main status indication every procedure of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4</see> reports (the <c>*-Status</c> output each processing clause sets to
/// <c>"PROCESS_PASSED"</c>, <c>"PROCESS_PASSED_WITH_WARNING"</c>, or <c>"PROCESS_FAILED"</c>).
/// </summary>
public enum TrustedListProcessStatus
{
    /// <summary>The procedure completed and its result is usable (<c>"PROCESS_PASSED"</c>).</summary>
    Passed = 0,

    /// <summary>The procedure completed but recorded one or more warnings (<c>"PROCESS_PASSED_WITH_WARNING"</c>).</summary>
    PassedWithWarning = 1,

    /// <summary>The procedure could not complete; its result must not be relied on (<c>"PROCESS_FAILED"</c>).</summary>
    Failed = 2
}


/// <summary>
/// Maps <see cref="TrustedListProcessStatus"/> to and from the status strings the specification's output
/// variables carry.
/// </summary>
public static class TrustedListProcessStatusMapping
{
    /// <summary>Maps a <see cref="TrustedListProcessStatus"/> to its specification string.</summary>
    /// <param name="status">The status to map.</param>
    /// <returns>The specification's status string.</returns>
    public static string ToWireValue(TrustedListProcessStatus status) => status switch
    {
        TrustedListProcessStatus.Passed => "PROCESS_PASSED",
        TrustedListProcessStatus.PassedWithWarning => "PROCESS_PASSED_WITH_WARNING",
        TrustedListProcessStatus.Failed => "PROCESS_FAILED",
        _ => "PROCESS_FAILED"
    };
}


/// <summary>
/// One sub-status indication supplementing a procedure's <see cref="TrustedListProcessStatus"/>, per the
/// <c>*-Sub-Status</c> outputs of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4</see>. The named values the specification spells out are provided as
/// statics; where the specification only requires "appropriate values" (for example the pairwise
/// comparison of PRO-4.4.4-32), this library defines its own descriptive strings, which
/// GPR-4.0-01 permits — conformance binds the outputs and the main status indication, not the wording of
/// supplementary indications the specification leaves open.
/// </summary>
[DebuggerDisplay("TrustedListQualificationSubStatus: {Value}")]
public readonly record struct TrustedListQualificationSubStatus(string Value)
{
    /// <summary>No confirmation for the certificate was found in the member state's trusted list (PRO-4.4.4-05).</summary>
    public static TrustedListQualificationSubStatus NoConfirmationFound { get; } = new("No_confirmation_found_in_EUMSTL_CC");

    /// <summary>The certificate names no country from which a member state trusted list could be selected (PRO-4.3.4-01 (b)).</summary>
    public static TrustedListQualificationSubStatus CountryCodeNotRepresentingEuMemberState { get; } = new("Provided_country_code_not_representing_an_EU_MS");

    /// <summary>
    /// Library-defined (see the type remarks): the time stamp qualification indications determined at the
    /// evaluation time and at the token's generation time differ (PRO-4.7.4-06 (a) requires "appropriate
    /// values reflecting the problematic comparison(s)" but names none).
    /// </summary>
    public static TrustedListQualificationSubStatus ErrorTimeStampIndicationsDifferBetweenEvaluationAndGenerationTime { get; } = new("ERROR_QTST_Results_differ_between_Date-time_and_generation_time");

    /// <summary>Two or more for-eSignatures matches at the evaluation time carry identical statuses (PRO-4.3.4-05).</summary>
    public static TrustedListQualificationSubStatus WarningType1Duplication { get; } = new("WARNING_T1_DUPLICATION");

    /// <summary>Two or more for-eSignatures matches at the evaluation time carry different statuses (PRO-4.3.4-06).</summary>
    public static TrustedListQualificationSubStatus ErrorType1Duplication { get; } = new("ERROR_T1_DUPLICATION");

    /// <summary>Two or more for-eSeals matches at the evaluation time carry identical statuses (PRO-4.3.4-07).</summary>
    public static TrustedListQualificationSubStatus WarningType2Duplication { get; } = new("WARNING_T2_DUPLICATION");

    /// <summary>Two or more for-eSeals matches at the evaluation time carry different statuses (PRO-4.3.4-08).</summary>
    public static TrustedListQualificationSubStatus ErrorType2Duplication { get; } = new("ERROR_T2_DUPLICATION");

    /// <summary>Two or more for-website-authentication matches at the evaluation time carry identical statuses (PRO-4.3.4-09).</summary>
    public static TrustedListQualificationSubStatus WarningType3Duplication { get; } = new("WARNING_T3_DUPLICATION");

    /// <summary>Two or more for-website-authentication matches at the evaluation time carry different statuses (PRO-4.3.4-10).</summary>
    public static TrustedListQualificationSubStatus ErrorType3Duplication { get; } = new("ERROR_T3_DUPLICATION");

    /// <summary>Matched services belong to different Trust Service Providers (PRO-4.3.4-11).</summary>
    public static TrustedListQualificationSubStatus ErrorTrustServiceProviderConflict { get; } = new("ERROR_TSP_CONFLICT");

    /// <summary>The certificate's issuer name does not identify the matched Trust Service Provider (PRO-4.4.4-06).</summary>
    public static TrustedListQualificationSubStatus ErrorTrustServiceProviderNameInconsistency { get; } = new("ERROR_TSP_NAME_INCONSISTENCY_BETWEEN_CERT_AND_TL");

    /// <summary>A matched service state carries a status other than granted or withdrawn under the Regulation regime (PRO-4.4.4-10A / -18A / -26A).</summary>
    public static TrustedListQualificationSubStatus ErrorServiceStatusNoncompliance { get; } = new("ERROR_Service_Status_Noncompliance_with_TS119612");

    /// <summary>The for-eSignatures qualifiers applied to the certificate are mutually inconsistent (PRO-4.4.4-12).</summary>
    public static TrustedListQualificationSubStatus WarningType1QualifierInconsistency { get; } = new("WARNING_T1_TL_Inconsistency_in_applying_qualifiers");

    /// <summary>The for-eSeals qualifiers applied to the certificate are mutually inconsistent (PRO-4.4.4-20).</summary>
    public static TrustedListQualificationSubStatus WarningType2QualifierInconsistency { get; } = new("WARNING_T2_TL_Inconsistency_in_applying_qualifiers");

    /// <summary>The for-website-authentication qualifiers applied to the certificate are mutually inconsistent (PRO-4.4.4-28).</summary>
    public static TrustedListQualificationSubStatus WarningType3QualifierInconsistency { get; } = new("WARNING_T3_TL_Inconsistency_in_applying_qualifiers");

    /// <summary>The qualifiers applied under the Directive regime are mutually inconsistent (PRO-4.4.4-33 (h)).</summary>
    public static TrustedListQualificationSubStatus ErrorType1QualifierInconsistency { get; } = new("ERROR_T1_TL_Inconsistency_in_applying_qualifiers");

    /// <summary>The certificate carries more than one QcType identifier, non-compliant with EN 319 412-5 (PRO-4.4.4-14 / -22 / -30).</summary>
    public static TrustedListQualificationSubStatus WarningCertificateQcTypeInconsistency { get; } = new("WARNING_CERT_Inconsistency_in_QcType_qualifiers_Non-compliance_with_EN319412-5");

    /// <summary>The trusted list and the certificate together do not carry enough information to determine the qualified certificate type for eSignatures (Table 1 row8/column3, PRO-4.4.4-15 (d)).</summary>
    public static TrustedListQualificationSubStatus WarningType1NotEnoughInformationOnQcType { get; } = new("WARNING_T1_Not_Enough_Info_on_QC_Type");

    /// <summary>The trusted list and the certificate together do not carry enough information to determine the qualified certificate type for eSeals (Table 2 row8/column3, PRO-4.4.4-23 (d)).</summary>
    public static TrustedListQualificationSubStatus WarningType2NotEnoughInformationOnQcType { get; } = new("WARNING_T2_Not_Enough_Info_on_QC_Type");

    /// <summary>The trusted list and the certificate together do not carry enough information to determine the qualified certificate type for website authentication (Table 3 row8/column3, PRO-4.4.4-31 (d)).</summary>
    public static TrustedListQualificationSubStatus WarningType3NotEnoughInformationOnQcType { get; } = new("WARNING_T3_Not_Enough_Info_on_QC_Type");

    /// <summary>Two or more Directive-regime matches carry identical statuses (PRO-4.4.4-33 (c)).</summary>
    public static TrustedListQualificationSubStatus WarningServiceEntryDuplication { get; } = new("WARNING_TL-SERVICE-ENTRY-SDI_DUPLICATION");

    /// <summary>Two or more Directive-regime matches carry conflicting statuses (PRO-4.4.4-33 (d)).</summary>
    public static TrustedListQualificationSubStatus ErrorServiceEntryDuplicationStatusConflict { get; } = new("ERROR_TL-SERVICE-ENTRY-SDI_DUPLICATION_STATUS_CONFLICT");

    /// <summary>The SSCD qualifiers applied under the Directive regime are mutually inconsistent (PRO-4.5.4-03 (a)).</summary>
    public static TrustedListQualificationSubStatus WarningSscdQualifierInconsistency { get; } = new("WARNING_Inconsistency_in_applying_qualifiers_for_SSCD_status");

    /// <summary>An unknown qualifier was found in a Qualifications extension marked critical (PRO-4.5.4-04 (b)).</summary>
    public static TrustedListQualificationSubStatus ErrorUnknownCriticalQualifiers { get; } = new("ERROR_Unknown_critical_qualifiers_for_QSCD_status");

    /// <summary>An unknown qualifier was found in a non-critical Qualifications extension (PRO-4.5.4-04 (b)).</summary>
    public static TrustedListQualificationSubStatus WarningUnknownQualifiers { get; } = new("WARNING_Unknown_qualifiers_for_QSCD_status");

    /// <summary>The QSCD qualifiers applied to the certificate are mutually inconsistent (PRO-4.5.4-04 (c)).</summary>
    public static TrustedListQualificationSubStatus WarningQscdQualifierInconsistency { get; } = new("WARNING_Inconsistency_in_applying_qualifiers_for_QSCD_status");

    /// <summary>Matched services report conflicting statuses for the trust service token issuer's certificate (PRO-4.6.4-06).</summary>
    public static TrustedListQualificationSubStatus ErrorTokenIssuerStatusInconsistency { get; } = new("ERROR_INCONSISTENCY_IN_TL_ON_TSTO-CERT_STATUS");

    /// <summary>Matched services duplicate the trust service token issuer's service information with different keys (PRO-4.6.4-07).</summary>
    public static TrustedListQualificationSubStatus WarningTokenIssuerServiceInformationDuplication { get; } = new("WARNING_DUPLICATION_OF_SERVICE_INFORMATION_IN_TL_REGARDING_TSTO-CERT");

    /// <summary>The token issuer certificate's subject name does not identify the matched Trust Service Provider (PRO-4.6.4-08).</summary>
    public static TrustedListQualificationSubStatus ErrorTokenIssuerNameInconsistency { get; } = new("ERROR_TSP_NAME_INCONSISTENCY_BETWEEN_TSTO-CERT_AND_TL");

    /// <summary>
    /// Library-defined (see the type remarks): a matched service's history instances are not in strictly
    /// descending status-starting-time order, or two instances share the exact same starting time
    /// (PRO-4.3.4-03A requires stopping with an error but names no value).
    /// </summary>
    public static TrustedListQualificationSubStatus ErrorServiceHistoryOrder { get; } = new("ERROR_Service_history_instances_not_in_strictly_descending_order");

    /// <summary>
    /// Library-defined (see the type remarks): the qualified-certificate indications determined at the
    /// evaluation time and at the certificate's NotBefore time differ (PRO-4.4.4-36 (a) requires
    /// "appropriate values reflecting the problematic comparison(s)" but names none).
    /// </summary>
    public static TrustedListQualificationSubStatus ErrorIndicationsDifferBetweenEvaluationTimeAndNotBefore { get; } = new("ERROR_QC_Results_differ_between_Date-time_and_NotBeforeDate");

    /// <summary>
    /// Library-defined (see the type remarks): a qualification element's criteria tree could not be soundly
    /// evaluated against the certificate (an unrecognised criterion, or a non-conformant empty criteria
    /// list), so the element was treated as not identifying the certificate. Surfacing the condition keeps
    /// the fail-closed treatment visible instead of silent.
    /// </summary>
    public static TrustedListQualificationSubStatus WarningCriteriaNotEvaluable { get; } = new("WARNING_QualificationElement_criteria_not_evaluable");


    /// <summary>
    /// Creates the library-defined sub-status naming one problematic two-by-two indication combination of
    /// PRO-4.4.4-32 (the specification requires "appropriate values reflecting the problematic two by two
    /// combinations" but names none).
    /// </summary>
    /// <param name="isError">Whether Table 4 classifies the pair as an error (<see langword="true"/>) or a warning.</param>
    /// <param name="first">One indication of the pair.</param>
    /// <param name="second">The other indication of the pair.</param>
    /// <returns>The pair-conflict sub-status.</returns>
    public static TrustedListQualificationSubStatus ForIndicationPair(bool isError, EuQualifiedCertificateIndication first, EuQualifiedCertificateIndication second) =>
        new($"{(isError ? "ERROR" : "WARNING")}_QC_status_check_{EuQualifiedCertificateIndicationMapping.ToWireValue(first)}_with_{EuQualifiedCertificateIndicationMapping.ToWireValue(second)}");

    /// <summary>Wraps a propagated status or sub-status value from an inner procedure run (for example PRO-4.4.4-04 (b) propagating <c>SI-Status</c> and <c>SI-Sub-Status</c> values).</summary>
    /// <param name="value">The propagated value.</param>
    /// <returns>The sub-status carrying the propagated value.</returns>
    public static TrustedListQualificationSubStatus Propagated(string value) => new(value);
}


/// <summary>
/// One indication of a certificate's EU qualified status, per the <c>QC-Results</c> output of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4.4.3</see>. A determination reports a SET of these — one per certificate
/// type dimension (eSignature, eSeal, website authentication), or the single
/// <see cref="NotQualified"/> / <see cref="Indeterminate"/> collapse cases.
/// </summary>
public enum EuQualifiedCertificateIndication
{
    /// <summary>The certificate is not an EU qualified certificate (<c>"Not_Qualified"</c>).</summary>
    NotQualified = 0,

    /// <summary>The certificate is not an EU qualified certificate for electronic signatures (<c>"Not_Qualified_For_eSig"</c>).</summary>
    NotQualifiedForESignature = 1,

    /// <summary>The certificate is not an EU qualified certificate for electronic seals (<c>"Not_Qualified_For_eSeal"</c>).</summary>
    NotQualifiedForESeal = 2,

    /// <summary>The certificate is not an EU qualified certificate for website authentication (<c>"Not_QWAC"</c>).</summary>
    NotQualifiedForWebsiteAuthentication = 3,

    /// <summary>The certificate is an EU qualified certificate for electronic signatures (<c>"QC_For_eSig"</c>).</summary>
    QualifiedForESignature = 4,

    /// <summary>The certificate is an EU qualified certificate for electronic seals (<c>"QC_For_eSeal"</c>).</summary>
    QualifiedForESeal = 5,

    /// <summary>The certificate is an EU qualified certificate for website authentication (<c>"QWAC"</c>).</summary>
    QualifiedForWebsiteAuthentication = 6,

    /// <summary>The trusted list cannot confirm whether the certificate is qualified for electronic signatures (<c>"INDET_QC_For_eSig"</c>).</summary>
    IndeterminateForESignature = 7,

    /// <summary>The trusted list cannot confirm whether the certificate is qualified for electronic seals (<c>"INDET_QC_For_eSeal"</c>).</summary>
    IndeterminateForESeal = 8,

    /// <summary>The trusted list cannot confirm whether the certificate is qualified for website authentication (<c>"INDET_QWAC"</c>).</summary>
    IndeterminateForWebsiteAuthentication = 9,

    /// <summary>The trusted list cannot be used for any qualified-status confirmation for this certificate (<c>"INDETERMINATE"</c>).</summary>
    Indeterminate = 10
}


/// <summary>
/// Maps <see cref="EuQualifiedCertificateIndication"/> to the indication strings the specification's
/// <c>QC-Results</c> output carries.
/// </summary>
public static class EuQualifiedCertificateIndicationMapping
{
    /// <summary>Maps an <see cref="EuQualifiedCertificateIndication"/> to its specification string.</summary>
    /// <param name="indication">The indication to map.</param>
    /// <returns>The specification's indication string.</returns>
    public static string ToWireValue(EuQualifiedCertificateIndication indication) => indication switch
    {
        EuQualifiedCertificateIndication.NotQualified => "Not_Qualified",
        EuQualifiedCertificateIndication.NotQualifiedForESignature => "Not_Qualified_For_eSig",
        EuQualifiedCertificateIndication.NotQualifiedForESeal => "Not_Qualified_For_eSeal",
        EuQualifiedCertificateIndication.NotQualifiedForWebsiteAuthentication => "Not_QWAC",
        EuQualifiedCertificateIndication.QualifiedForESignature => "QC_For_eSig",
        EuQualifiedCertificateIndication.QualifiedForESeal => "QC_For_eSeal",
        EuQualifiedCertificateIndication.QualifiedForWebsiteAuthentication => "QWAC",
        EuQualifiedCertificateIndication.IndeterminateForESignature => "INDET_QC_For_eSig",
        EuQualifiedCertificateIndication.IndeterminateForESeal => "INDET_QC_For_eSeal",
        EuQualifiedCertificateIndication.IndeterminateForWebsiteAuthentication => "INDET_QWAC",
        EuQualifiedCertificateIndication.Indeterminate => "INDETERMINATE",
        _ => "INDETERMINATE"
    };
}


/// <summary>
/// The indication of whether a certificate's private key resided in a qualified electronic signature/seal
/// creation device, per the <c>QSCD-Results</c> output of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4.5.3</see>.
/// </summary>
public enum QualifiedSignatureCreationDeviceIndication
{
    /// <summary>The private key resided in a qualified creation device at the evaluation time (<c>"QSCD_YES"</c>).</summary>
    PrivateKeyOnDevice = 0,

    /// <summary>The private key did not reside in a qualified creation device at the evaluation time (<c>"QSCD_NO"</c>).</summary>
    PrivateKeyNotOnDevice = 1,

    /// <summary>The trusted lists cannot confirm whether the private key resided in a qualified creation device (<c>"QSCD_INDETERMINATE"</c>).</summary>
    Indeterminate = 2
}


/// <summary>
/// Maps <see cref="QualifiedSignatureCreationDeviceIndication"/> to the indication strings the
/// specification's <c>QSCD-Results</c> output carries.
/// </summary>
public static class QualifiedSignatureCreationDeviceIndicationMapping
{
    /// <summary>Maps a <see cref="QualifiedSignatureCreationDeviceIndication"/> to its specification string.</summary>
    /// <param name="indication">The indication to map.</param>
    /// <returns>The specification's indication string.</returns>
    public static string ToWireValue(QualifiedSignatureCreationDeviceIndication indication) => indication switch
    {
        QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice => "QSCD_YES",
        QualifiedSignatureCreationDeviceIndication.PrivateKeyNotOnDevice => "QSCD_NO",
        QualifiedSignatureCreationDeviceIndication.Indeterminate => "QSCD_INDETERMINATE",
        _ => "QSCD_INDETERMINATE"
    };
}


/// <summary>
/// The indication of a trust service token issuer's EU qualified status, per the <c>QTSTo-Results</c>
/// output of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4.6.3</see>, and by composition the <c>QTST-Results</c> output of
/// clause 4.7.3.
/// </summary>
public enum TrustServiceTokenIssuerIndication
{
    /// <summary>The issuer was not an EU qualified trust service provider for the service type at the evaluation time (<c>"Not_Qualified"</c>).</summary>
    NotQualified = 0,

    /// <summary>The issuer was an EU qualified trust service provider for the service type at the evaluation time (<c>"Qualified"</c>).</summary>
    Qualified = 1,

    /// <summary>The trusted list cannot confirm the issuer's qualified status for the service type (<c>"Indeterminate"</c>).</summary>
    Indeterminate = 2
}


/// <summary>
/// The EU qualified certificate types EN 319 412-5's <c>id-etsi-qcs-QcType</c> statement declares, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119615/01.04.01_60/ts_119615v010401p.pdf">
/// ETSI TS 119 615 V1.4.1 clause 4.4.4</see>'s Tables 1-3 row selection (which reads the statement's
/// QcType 1/2/3 values from the certificate).
/// </summary>
public enum EuQualifiedCertificateType
{
    /// <summary>Not a specification value: the CLR default for an uninitialized value. A certificate's declared type list never contains it.</summary>
    None = 0,

    /// <summary>QcType 1: a certificate for electronic signatures (<c>id-etsi-qct-esign</c>, OID 0.4.0.1862.1.6.1).</summary>
    ElectronicSignature = 1,

    /// <summary>QcType 2: a certificate for electronic seals (<c>id-etsi-qct-eseal</c>, OID 0.4.0.1862.1.6.2).</summary>
    ElectronicSeal = 2,

    /// <summary>QcType 3: a certificate for website authentication (<c>id-etsi-qct-web</c>, OID 0.4.0.1862.1.6.3).</summary>
    WebsiteAuthentication = 3
}


/// <summary>
/// Maps <see cref="EuQualifiedCertificateType"/> to and from the EN 319 412-5 QcType object identifiers a
/// certificate's <c>id-etsi-qcs-QcType</c> statement carries.
/// </summary>
public static class EuQualifiedCertificateTypeMapping
{
    /// <summary>Maps a QcType object identifier to an <see cref="EuQualifiedCertificateType"/>.</summary>
    /// <param name="oid">The dotted-decimal object identifier.</param>
    /// <returns>The matching type, or <see langword="null"/> when the identifier is not a known QcType.</returns>
    public static EuQualifiedCertificateType? FromOid(string oid) => oid switch
    {
        WellKnownOids.QcTypeElectronicSignature => EuQualifiedCertificateType.ElectronicSignature,
        WellKnownOids.QcTypeElectronicSeal => EuQualifiedCertificateType.ElectronicSeal,
        WellKnownOids.QcTypeWebsiteAuthentication => EuQualifiedCertificateType.WebsiteAuthentication,
        _ => null
    };

    /// <summary>Maps an <see cref="EuQualifiedCertificateType"/> to its QcType object identifier.</summary>
    /// <param name="type">The type to map.</param>
    /// <returns>The dotted-decimal object identifier.</returns>
    public static string ToOid(EuQualifiedCertificateType type) => type switch
    {
        EuQualifiedCertificateType.ElectronicSignature => WellKnownOids.QcTypeElectronicSignature,
        EuQualifiedCertificateType.ElectronicSeal => WellKnownOids.QcTypeElectronicSeal,
        EuQualifiedCertificateType.WebsiteAuthentication => WellKnownOids.QcTypeWebsiteAuthentication,
        _ => WellKnownOids.QcTypeElectronicSignature
    };
}
