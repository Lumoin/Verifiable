using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One item of the <em>associated validation report data</em> a signature validation process or building
/// block reports alongside its indication and sub-indication, per the middle column of Table 6 (and the
/// corresponding "Additional Information" columns of Tables 13, 15, 17 and 22) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// A DU-ready closed sum: every sibling record is declared alongside this base, and a consumer reads a
/// conclusion's report data with an exhaustive switch expression rather than a type test against an open
/// hierarchy. There is one sibling per <em>distinct mandated data shape</em> rather than one per Table 6 row,
/// because several rows mandate exactly the same shape — <c>REVOKED</c>, <c>REVOKED_NO_POE</c> and
/// <c>REVOKED_CA_NO_POE</c> all mandate "the certificate chain used in the validation process" plus "the time
/// and the reason of revocation", and <c>CRYPTO_CONSTRAINTS_FAILURE</c> and
/// <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c> both mandate "identification of the material" plus "the time up to
/// which the algorithm or key size were considered secure". Each sibling's documentation names the rows it
/// serves.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every carrier a sibling holds — a <see cref="PkiCertificateMemory"/> chain, a
/// revocation-data item — is a non-owning reference to memory the validation run owns. A report data item must
/// not outlive the carriers it points at, and disposing it disposes nothing.
/// </para>
/// </remarks>
public abstract record SignatureValidationReportData
{
    /// <summary>
    /// Prevents this closed sum from being extended outside the sibling records declared alongside it.
    /// </summary>
    private protected SignatureValidationReportData()
    {
    }
}


/// <summary>
/// Whether a reported certificate chain is one the validation succeeded in validating or merely the last one
/// it managed to build — the distinction Table 13 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.6.3</see> draws between "the validated certificate chain" and "the last
/// certificate chain built".
/// </summary>
public enum CertificateChainReportKind
{
    /// <summary>
    /// "The last certificate chain built" — the chain exists but its validation did not complete
    /// successfully. The weaker of the two claims, and therefore the value of an unset field.
    /// </summary>
    LastBuilt = 0,

    /// <summary>
    /// "The validated certificate chain" — path validation over the chain completed successfully, even where
    /// a later step of the block then produced an <c>INDETERMINATE</c> outcome.
    /// </summary>
    Validated = 1
}


/// <summary>
/// The report data Table 6 mandates for <c>FORMAT_FAILURE</c>: "any information available why parsing of the
/// signature failed".
/// </summary>
/// <param name="Reason">What the format checking building block (clause 5.2.2) could state about the parse failure.</param>
[DebuggerDisplay("FormatFailureReportData: {Reason}")]
public sealed record FormatFailureReportData(string Reason): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>HASH_FAILURE</c>, and Table 15 of clause 5.2.7.3 repeats for the
/// cryptographic verification building block: identifiers (for example a URI or an OID) uniquely identifying
/// the elements within the Signed Data Object — signature attributes, or the signed data itself — that caused
/// the failure.
/// </summary>
/// <param name="FailingObjectIdentifiers">The identifiers of the elements whose hashes did not match; never empty when the sub-indication is reported.</param>
[DebuggerDisplay("HashFailureReportData: {FailingObjectIdentifiers.Count} failing objects")]
public sealed record HashFailureReportData(IReadOnlyList<string> FailingObjectIdentifiers): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>SIG_CRYPTO_FAILURE</c>: "the signing certificate used in the
/// validation process".
/// </summary>
/// <param name="SigningCertificate">A non-owning reference to the DER-encoded signing certificate the cryptographic verification used.</param>
[DebuggerDisplay("SigningCertificateReportData: {SigningCertificate}")]
public sealed record SigningCertificateReportData(PkiCertificateMemory SigningCertificate): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for the revocation rows — <c>REVOKED</c>, <c>REVOKED_NO_POE</c> and
/// <c>REVOKED_CA_NO_POE</c>: "the certificate chain used in the validation process" (for
/// <c>REVOKED_CA_NO_POE</c>, "the certificate chain which includes the revoked CA certificate") together with
/// "the time and, if available, the reason of revocation".
/// </summary>
/// <param name="CertificateChain">A non-owning reference to the chain used in the validation, signing certificate first.</param>
/// <param name="RevokedCertificate">A non-owning reference to the member of <paramref name="CertificateChain"/> that was found revoked — the signing certificate for <c>REVOKED</c> / <c>REVOKED_NO_POE</c>, an intermediate CA certificate for <c>REVOKED_CA_NO_POE</c>.</param>
/// <param name="RevocationTime">The instant the revocation took effect, as the revocation data states it; <see langword="null"/> when the source that reported the revocation stated no date. No instant is substituted for an absent one: step 4)a)a of clause 5.5.4 compares this value with best-signature-time, and a revocation date that is not known cannot be shown to be posterior to it.</param>
/// <param name="RevocationReason">The RFC 5280 §5.3.1 <c>CRLReason</c> enumerated value when the revocation data carried one; <see langword="null"/> when it did not (Table 6 makes the reason conditional on availability for <c>REVOKED</c>).</param>
[DebuggerDisplay("CertificateRevocationReportData: revoked at {RevocationTime}, reason {RevocationReason}")]
public sealed record CertificateRevocationReportData(
    IReadOnlyList<PkiCertificateMemory> CertificateChain,
    PkiCertificateMemory RevokedCertificate,
    DateTimeOffset? RevocationTime,
    int? RevocationReason): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>EXPIRED</c> ("the validated certificate chain") and Table 13 of
/// clause 5.2.6.3 mandates for the X.509 certificate validation rows whose only additional information is a
/// chain — <c>NO_CERTIFICATE_CHAIN_FOUND_NO_POE</c>, <c>OUT_OF_BOUNDS_NO_POE</c> and
/// <c>OUT_OF_BOUNDS_NOT_REVOKED</c> — and for the <c>PASSED</c> row ("the certificate chain used in the
/// successful validation").
/// </summary>
/// <param name="CertificateChain">A non-owning reference to the chain, signing certificate first.</param>
/// <param name="Kind">Whether the chain is a validated one or merely the last one built.</param>
[DebuggerDisplay("CertificateChainReportData: {Kind}, {CertificateChain.Count} certificates")]
public sealed record CertificateChainReportData(
    IReadOnlyList<PkiCertificateMemory> CertificateChain,
    CertificateChainReportKind Kind): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>CHAIN_CONSTRAINTS_FAILURE</c>: "the certificate chain used in the
/// validation process" together with "the set of constraints that have not been met by the chain".
/// </summary>
/// <param name="CertificateChain">A non-owning reference to the chain the constraints were applied to.</param>
/// <param name="UnsatisfiedConstraints">The per-constraint outcomes for the X.509 validation constraints the chain did not meet.</param>
[DebuggerDisplay("ChainConstraintsFailureReportData: {UnsatisfiedConstraints.Count} unmet constraints")]
public sealed record ChainConstraintsFailureReportData(
    IReadOnlyList<PkiCertificateMemory> CertificateChain,
    IReadOnlyList<ValidationConstraintEvaluation> UnsatisfiedConstraints): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>CERTIFICATE_CHAIN_GENERAL_FAILURE</c> ("additional information
/// regarding the reason") together with the last chain built that Table 13 of clause 5.2.6.3 adds.
/// </summary>
/// <param name="CertificateChain">A non-owning reference to the last chain built; empty when no chain was built at all.</param>
/// <param name="Reason">What the block could state about the unspecified chain-validation error.</param>
[DebuggerDisplay("CertificateChainGeneralFailureReportData: {Reason}")]
public sealed record CertificateChainGeneralFailureReportData(
    IReadOnlyList<PkiCertificateMemory> CertificateChain,
    string Reason): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>SIG_CONSTRAINTS_FAILURE</c>, and Table 17 of clause 5.2.8.3
/// repeats for the signature acceptance validation building block: "the set of constraints that have not been
/// met by the signature".
/// </summary>
/// <param name="UnsatisfiedConstraints">The per-constraint outcomes for the signature elements constraints the signature did not meet.</param>
[DebuggerDisplay("UnsatisfiedSignatureConstraintsReportData: {UnsatisfiedConstraints.Count} unmet constraints")]
public sealed record UnsatisfiedSignatureConstraintsReportData(
    IReadOnlyList<ValidationConstraintEvaluation> UnsatisfiedConstraints): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>CRYPTO_CONSTRAINTS_FAILURE</c> and
/// <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c>, and Table 17 of clause 5.2.8.3 repeats for the signature
/// acceptance validation building block: "identification of the material (signature, certificate) that is
/// produced using an algorithm or key size below the required cryptographic security level" together with, "if
/// known, the time up to which the algorithm or key size were considered secure".
/// </summary>
/// <param name="UnreliableAlgorithms">One entry per offending piece of material, naming the material, the algorithm and key size it used, and the instant up to which the cryptographic constraints considered that algorithm reliable. Every entry's <see cref="AlgorithmReliabilityAssessment.IsReliable"/> is <see langword="false"/>.</param>
[DebuggerDisplay("CryptographicConstraintsFailureReportData: {UnreliableAlgorithms.Count} offending materials")]
public sealed record CryptographicConstraintsFailureReportData(
    IReadOnlyList<AlgorithmReliabilityAssessment> UnreliableAlgorithms): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>POLICY_PROCESSING_ERROR</c>: "additional information on the
/// problem" that prevented the formal policy file from being processed.
/// </summary>
/// <param name="Problem">What the validation context initialization building block (clause 5.2.4) could state about the policy-processing failure.</param>
[DebuggerDisplay("PolicyProcessingErrorReportData: {Problem}")]
public sealed record PolicyProcessingErrorReportData(string Problem): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>TIMESTAMP_ORDER_FAILURE</c>: "the list of time-stamps that do not
/// respect the ordering constraints" checked in step 4)e) of clause 5.5.4.
/// </summary>
/// <param name="TimestampTokens">Non-owning references to the DER-encoded RFC 3161 time-stamp tokens whose generation times violate the ordering constraints.</param>
[DebuggerDisplay("TimestampOrderFailureReportData: {TimestampTokens.Count} tokens")]
public sealed record TimestampOrderFailureReportData(
    IReadOnlyList<PkiCertificateMemory> TimestampTokens): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>REVOCATION_OUT_OF_BOUNDS_NO_POE</c>: "the certificate chain used
/// in the validation process" together with "the revocation data that is concerned by the failure".
/// </summary>
/// <param name="CertificateChain">A non-owning reference to the chain used in the validation.</param>
/// <param name="RevocationData">Non-owning references to the DER-encoded CRLs or OCSP responses whose issuer certificate was outside its validity interval at the validation time.</param>
[DebuggerDisplay("RevocationOutOfBoundsReportData: {RevocationData.Count} revocation data items")]
public sealed record RevocationOutOfBoundsReportData(
    IReadOnlyList<PkiCertificateMemory> CertificateChain,
    IReadOnlyList<PkiCertificateMemory> RevocationData): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>NO_POE</c>: "at least the signed objects for which the POEs are
/// missing", with additional information on the problem where the process can supply it.
/// </summary>
/// <param name="ObjectsMissingProofs">The identities of the objects for which the set of proofs of existence holds nothing at or before the required instant.</param>
/// <param name="AdditionalInformation">What the process could state about the problem; <see langword="null"/> when it had nothing to add (Table 6 makes this a "should", not a "shall").</param>
[DebuggerDisplay("MissingProofOfExistenceReportData: {ObjectsMissingProofs.Count} objects")]
public sealed record MissingProofOfExistenceReportData(
    IReadOnlyList<ValidationObjectIdentity> ObjectsMissingProofs,
    string? AdditionalInformation): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>TRY_LATER</c> ("the point of time where the necessary revocation
/// status information is expected to become available") together with the last chain built that Table 13 of
/// clause 5.2.6.3 adds.
/// </summary>
/// <param name="SuggestedRetryTime">The instant at or after which fresher revocation status information is expected — typically the <c>nextUpdate</c> field of the CRL or OCSP response consulted, per Table 13; <see langword="null"/> when no such instant was available.</param>
/// <param name="CertificateChain">A non-owning reference to the last chain built.</param>
/// <param name="RevocationData">Non-owning references to the DER-encoded revocation data whose status information was not fresh enough, which step 6 of clause 5.5.4 re-checks against best-signature-time.</param>
[DebuggerDisplay("TryLaterReportData: retry at {SuggestedRetryTime}")]
public sealed record TryLaterReportData(
    DateTimeOffset? SuggestedRetryTime,
    IReadOnlyList<PkiCertificateMemory> CertificateChain,
    IReadOnlyList<PkiCertificateMemory> RevocationData): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 asks for on <c>SIGNED_DATA_NOT_FOUND</c>, and Table 15 of clause 5.2.7.3 repeats
/// for the cryptographic verification building block: "the identifier(s) (e.g. an URI) of the signed data that
/// caused the failure", when available.
/// </summary>
/// <param name="SignedDataIdentifiers">The identifiers of the signed data items that could not be obtained; empty when the process had none to report.</param>
[DebuggerDisplay("SignedDataNotFoundReportData: {SignedDataIdentifiers.Count} identifiers")]
public sealed record SignedDataNotFoundReportData(
    IReadOnlyList<string> SignedDataIdentifiers): SignatureValidationReportData;


/// <summary>
/// The report data Table 6 mandates for <c>CUSTOM</c>: "information allowing identification of the reason for
/// the custom diagnostic result" — the escape hatch clause 5.1.3 requires when no Table 6 sub-indication maps
/// to the reason the process returned <c>INDETERMINATE</c>.
/// </summary>
/// <param name="Diagnostic">The reason, in terms a Driving Application can present to a verifier.</param>
[DebuggerDisplay("CustomDiagnosticReportData: {Diagnostic}")]
public sealed record CustomDiagnosticReportData(string Diagnostic): SignatureValidationReportData;
