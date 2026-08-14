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
/// A DU-ready closed sum: every sibling type is declared alongside this base, and a consumer reads a
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
public abstract class SignatureValidationReportData
{
    /// <summary>
    /// Prevents this closed sum from being extended outside the sibling types declared alongside it.
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
/// <remarks>
/// The report datum is the sentence it carries, so equality is an ordinal comparison of <see cref="Reason"/>.
/// A report assembled twice over the same signature states the same reason and compares equal, which is what
/// lets a test or a de-duplicating consumer treat two such findings as one.
/// </remarks>
[DebuggerDisplay("FormatFailureReportData: {Reason}")]
public sealed class FormatFailureReportData : SignatureValidationReportData, IEquatable<FormatFailureReportData>
{
    /// <summary>Initializes a new <see cref="FormatFailureReportData"/>.</summary>
    /// <param name="reason">What the format checking building block (clause 5.2.2) could state about the parse failure.</param>
    public FormatFailureReportData(string reason)
    {
        Reason = reason;
    }

    /// <summary>What the format checking building block (clause 5.2.2) could state about the parse failure.</summary>
    public string Reason { get; }

    /// <inheritdoc/>
    public bool Equals(FormatFailureReportData? other)
    {
        return other is not null && string.Equals(Reason, other.Reason, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as FormatFailureReportData);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Reason);
    }

    /// <summary>Reports whether two format-failure reports state the same reason.</summary>
    public static bool operator ==(FormatFailureReportData? left, FormatFailureReportData? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two format-failure reports state a different reason.</summary>
    public static bool operator !=(FormatFailureReportData? left, FormatFailureReportData? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The report data Table 6 mandates for <c>HASH_FAILURE</c>, and Table 15 of clause 5.2.7.3 repeats for the
/// cryptographic verification building block: identifiers (for example a URI or an OID) uniquely identifying
/// the elements within the Signed Data Object — signature attributes, or the signed data itself — that caused
/// the failure.
/// </summary>
[DebuggerDisplay("HashFailureReportData: {FailingObjectIdentifiers.Count} failing objects")]
public sealed class HashFailureReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="HashFailureReportData"/>.</summary>
    /// <param name="failingObjectIdentifiers">The identifiers of the elements whose hashes did not match; never empty when the sub-indication is reported.</param>
    public HashFailureReportData(IReadOnlyList<string> failingObjectIdentifiers)
    {
        FailingObjectIdentifiers = failingObjectIdentifiers;
    }

    /// <summary>The identifiers of the elements whose hashes did not match; never empty when the sub-indication is reported.</summary>
    public IReadOnlyList<string> FailingObjectIdentifiers { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>SIG_CRYPTO_FAILURE</c>: "the signing certificate used in the
/// validation process".
/// </summary>
[DebuggerDisplay("SigningCertificateReportData: {SigningCertificate}")]
public sealed class SigningCertificateReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="SigningCertificateReportData"/>.</summary>
    /// <param name="signingCertificate">A non-owning reference to the DER-encoded signing certificate the cryptographic verification used.</param>
    public SigningCertificateReportData(PkiCertificateMemory signingCertificate)
    {
        SigningCertificate = signingCertificate;
    }

    /// <summary>A non-owning reference to the DER-encoded signing certificate the cryptographic verification used.</summary>
    public PkiCertificateMemory SigningCertificate { get; }
}


/// <summary>
/// The report data Table 6 mandates for the revocation rows — <c>REVOKED</c>, <c>REVOKED_NO_POE</c> and
/// <c>REVOKED_CA_NO_POE</c>: "the certificate chain used in the validation process" (for
/// <c>REVOKED_CA_NO_POE</c>, "the certificate chain which includes the revoked CA certificate") together with
/// "the time and, if available, the reason of revocation".
/// </summary>
[DebuggerDisplay("CertificateRevocationReportData: revoked at {RevocationTime}, reason {RevocationReason}")]
public sealed class CertificateRevocationReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="CertificateRevocationReportData"/>.</summary>
    /// <param name="certificateChain">A non-owning reference to the chain used in the validation, signing certificate first.</param>
    /// <param name="revokedCertificate">A non-owning reference to the member of <paramref name="certificateChain"/> that was found revoked — the signing certificate for <c>REVOKED</c> / <c>REVOKED_NO_POE</c>, an intermediate CA certificate for <c>REVOKED_CA_NO_POE</c>.</param>
    /// <param name="revocationTime">The instant the revocation took effect, as the revocation data states it; <see langword="null"/> when the source that reported the revocation stated no date. No instant is substituted for an absent one: step 4)a)a of clause 5.5.4 compares this value with best-signature-time, and a revocation date that is not known cannot be shown to be posterior to it.</param>
    /// <param name="revocationReason">The RFC 5280 §5.3.1 <c>CRLReason</c> enumerated value when the revocation data carried one; <see langword="null"/> when it did not (Table 6 makes the reason conditional on availability for <c>REVOKED</c>).</param>
    public CertificateRevocationReportData(IReadOnlyList<PkiCertificateMemory> certificateChain, PkiCertificateMemory revokedCertificate, DateTimeOffset? revocationTime, int? revocationReason)
    {
        CertificateChain = certificateChain;
        RevokedCertificate = revokedCertificate;
        RevocationTime = revocationTime;
        RevocationReason = revocationReason;
    }

    /// <summary>A non-owning reference to the chain used in the validation, signing certificate first.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; }

    /// <summary>A non-owning reference to the member of <see cref="CertificateChain"/> that was found revoked — the signing certificate for <c>REVOKED</c> / <c>REVOKED_NO_POE</c>, an intermediate CA certificate for <c>REVOKED_CA_NO_POE</c>.</summary>
    public PkiCertificateMemory RevokedCertificate { get; }

    /// <summary>The instant the revocation took effect, as the revocation data states it; <see langword="null"/> when the source that reported the revocation stated no date. No instant is substituted for an absent one: step 4)a)a of clause 5.5.4 compares this value with best-signature-time, and a revocation date that is not known cannot be shown to be posterior to it.</summary>
    public DateTimeOffset? RevocationTime { get; }

    /// <summary>The RFC 5280 §5.3.1 <c>CRLReason</c> enumerated value when the revocation data carried one; <see langword="null"/> when it did not (Table 6 makes the reason conditional on availability for <c>REVOKED</c>).</summary>
    public int? RevocationReason { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>EXPIRED</c> ("the validated certificate chain") and Table 13 of
/// clause 5.2.6.3 mandates for the X.509 certificate validation rows whose only additional information is a
/// chain — <c>NO_CERTIFICATE_CHAIN_FOUND_NO_POE</c>, <c>OUT_OF_BOUNDS_NO_POE</c> and
/// <c>OUT_OF_BOUNDS_NOT_REVOKED</c> — and for the <c>PASSED</c> row ("the certificate chain used in the
/// successful validation").
/// </summary>
[DebuggerDisplay("CertificateChainReportData: {Kind}, {CertificateChain.Count} certificates")]
public sealed class CertificateChainReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="CertificateChainReportData"/>.</summary>
    /// <param name="certificateChain">A non-owning reference to the chain, signing certificate first.</param>
    /// <param name="kind">Whether the chain is a validated one or merely the last one built.</param>
    public CertificateChainReportData(IReadOnlyList<PkiCertificateMemory> certificateChain, CertificateChainReportKind kind)
    {
        CertificateChain = certificateChain;
        Kind = kind;
    }

    /// <summary>A non-owning reference to the chain, signing certificate first.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; }

    /// <summary>Whether the chain is a validated one or merely the last one built.</summary>
    public CertificateChainReportKind Kind { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>CHAIN_CONSTRAINTS_FAILURE</c>: "the certificate chain used in the
/// validation process" together with "the set of constraints that have not been met by the chain".
/// </summary>
[DebuggerDisplay("ChainConstraintsFailureReportData: {UnsatisfiedConstraints.Count} unmet constraints")]
public sealed class ChainConstraintsFailureReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="ChainConstraintsFailureReportData"/>.</summary>
    /// <param name="certificateChain">A non-owning reference to the chain the constraints were applied to.</param>
    /// <param name="unsatisfiedConstraints">The per-constraint outcomes for the X.509 validation constraints the chain did not meet.</param>
    public ChainConstraintsFailureReportData(IReadOnlyList<PkiCertificateMemory> certificateChain, IReadOnlyList<ValidationConstraintEvaluation> unsatisfiedConstraints)
    {
        CertificateChain = certificateChain;
        UnsatisfiedConstraints = unsatisfiedConstraints;
    }

    /// <summary>A non-owning reference to the chain the constraints were applied to.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; }

    /// <summary>The per-constraint outcomes for the X.509 validation constraints the chain did not meet.</summary>
    public IReadOnlyList<ValidationConstraintEvaluation> UnsatisfiedConstraints { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>CERTIFICATE_CHAIN_GENERAL_FAILURE</c> ("additional information
/// regarding the reason") together with the last chain built that Table 13 of clause 5.2.6.3 adds.
/// </summary>
[DebuggerDisplay("CertificateChainGeneralFailureReportData: {Reason}")]
public sealed class CertificateChainGeneralFailureReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="CertificateChainGeneralFailureReportData"/>.</summary>
    /// <param name="certificateChain">A non-owning reference to the last chain built; empty when no chain was built at all.</param>
    /// <param name="reason">What the block could state about the unspecified chain-validation error.</param>
    public CertificateChainGeneralFailureReportData(IReadOnlyList<PkiCertificateMemory> certificateChain, string reason)
    {
        CertificateChain = certificateChain;
        Reason = reason;
    }

    /// <summary>A non-owning reference to the last chain built; empty when no chain was built at all.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; }

    /// <summary>What the block could state about the unspecified chain-validation error.</summary>
    public string Reason { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>SIG_CONSTRAINTS_FAILURE</c>, and Table 17 of clause 5.2.8.3
/// repeats for the signature acceptance validation building block: "the set of constraints that have not been
/// met by the signature".
/// </summary>
[DebuggerDisplay("UnsatisfiedSignatureConstraintsReportData: {UnsatisfiedConstraints.Count} unmet constraints")]
public sealed class UnsatisfiedSignatureConstraintsReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="UnsatisfiedSignatureConstraintsReportData"/>.</summary>
    /// <param name="unsatisfiedConstraints">The per-constraint outcomes for the signature elements constraints the signature did not meet.</param>
    public UnsatisfiedSignatureConstraintsReportData(IReadOnlyList<ValidationConstraintEvaluation> unsatisfiedConstraints)
    {
        UnsatisfiedConstraints = unsatisfiedConstraints;
    }

    /// <summary>The per-constraint outcomes for the signature elements constraints the signature did not meet.</summary>
    public IReadOnlyList<ValidationConstraintEvaluation> UnsatisfiedConstraints { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>CRYPTO_CONSTRAINTS_FAILURE</c> and
/// <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c>, and Table 17 of clause 5.2.8.3 repeats for the signature
/// acceptance validation building block: "identification of the material (signature, certificate) that is
/// produced using an algorithm or key size below the required cryptographic security level" together with, "if
/// known, the time up to which the algorithm or key size were considered secure".
/// </summary>
[DebuggerDisplay("CryptographicConstraintsFailureReportData: {UnreliableAlgorithms.Count} offending materials")]
public sealed class CryptographicConstraintsFailureReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="CryptographicConstraintsFailureReportData"/>.</summary>
    /// <param name="unreliableAlgorithms">One entry per offending piece of material, naming the material, the algorithm and key size it used, and the instant up to which the cryptographic constraints considered that algorithm reliable. Every entry's <see cref="AlgorithmReliabilityAssessment.IsReliable"/> is <see langword="false"/>.</param>
    public CryptographicConstraintsFailureReportData(IReadOnlyList<AlgorithmReliabilityAssessment> unreliableAlgorithms)
    {
        UnreliableAlgorithms = unreliableAlgorithms;
    }

    /// <summary>One entry per offending piece of material, naming the material, the algorithm and key size it used, and the instant up to which the cryptographic constraints considered that algorithm reliable. Every entry's <see cref="AlgorithmReliabilityAssessment.IsReliable"/> is <see langword="false"/>.</summary>
    public IReadOnlyList<AlgorithmReliabilityAssessment> UnreliableAlgorithms { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>POLICY_PROCESSING_ERROR</c>: "additional information on the
/// problem" that prevented the formal policy file from being processed.
/// </summary>
/// <remarks>
/// Two of these describe the same policy-processing failure exactly when they state the same problem, so
/// equality is an ordinal comparison of <see cref="Problem"/> and nothing about which run produced the datum
/// enters into it.
/// </remarks>
[DebuggerDisplay("PolicyProcessingErrorReportData: {Problem}")]
public sealed class PolicyProcessingErrorReportData : SignatureValidationReportData, IEquatable<PolicyProcessingErrorReportData>
{
    /// <summary>Initializes a new <see cref="PolicyProcessingErrorReportData"/>.</summary>
    /// <param name="problem">What the validation context initialization building block (clause 5.2.4) could state about the policy-processing failure.</param>
    public PolicyProcessingErrorReportData(string problem)
    {
        Problem = problem;
    }

    /// <summary>What the validation context initialization building block (clause 5.2.4) could state about the policy-processing failure.</summary>
    public string Problem { get; }

    /// <inheritdoc/>
    public bool Equals(PolicyProcessingErrorReportData? other)
    {
        return other is not null && string.Equals(Problem, other.Problem, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as PolicyProcessingErrorReportData);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Problem);
    }

    /// <summary>Reports whether two policy-processing-error reports state the same problem.</summary>
    public static bool operator ==(PolicyProcessingErrorReportData? left, PolicyProcessingErrorReportData? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two policy-processing-error reports state a different problem.</summary>
    public static bool operator !=(PolicyProcessingErrorReportData? left, PolicyProcessingErrorReportData? right)
    {
        return !(left == right);
    }
}


/// <summary>
/// The report data Table 6 mandates for <c>TIMESTAMP_ORDER_FAILURE</c>: "the list of time-stamps that do not
/// respect the ordering constraints" checked in step 4)e) of clause 5.5.4.
/// </summary>
[DebuggerDisplay("TimestampOrderFailureReportData: {TimestampTokens.Count} tokens")]
public sealed class TimestampOrderFailureReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="TimestampOrderFailureReportData"/>.</summary>
    /// <param name="timestampTokens">Non-owning references to the DER-encoded RFC 3161 time-stamp tokens whose generation times violate the ordering constraints.</param>
    public TimestampOrderFailureReportData(IReadOnlyList<PkiCertificateMemory> timestampTokens)
    {
        TimestampTokens = timestampTokens;
    }

    /// <summary>Non-owning references to the DER-encoded RFC 3161 time-stamp tokens whose generation times violate the ordering constraints.</summary>
    public IReadOnlyList<PkiCertificateMemory> TimestampTokens { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>REVOCATION_OUT_OF_BOUNDS_NO_POE</c>: "the certificate chain used
/// in the validation process" together with "the revocation data that is concerned by the failure".
/// </summary>
[DebuggerDisplay("RevocationOutOfBoundsReportData: {RevocationData.Count} revocation data items")]
public sealed class RevocationOutOfBoundsReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="RevocationOutOfBoundsReportData"/>.</summary>
    /// <param name="certificateChain">A non-owning reference to the chain used in the validation.</param>
    /// <param name="revocationData">Non-owning references to the DER-encoded CRLs or OCSP responses whose issuer certificate was outside its validity interval at the validation time.</param>
    public RevocationOutOfBoundsReportData(IReadOnlyList<PkiCertificateMemory> certificateChain, IReadOnlyList<PkiCertificateMemory> revocationData)
    {
        CertificateChain = certificateChain;
        RevocationData = revocationData;
    }

    /// <summary>A non-owning reference to the chain used in the validation.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; }

    /// <summary>Non-owning references to the DER-encoded CRLs or OCSP responses whose issuer certificate was outside its validity interval at the validation time.</summary>
    public IReadOnlyList<PkiCertificateMemory> RevocationData { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>NO_POE</c>: "at least the signed objects for which the POEs are
/// missing", with additional information on the problem where the process can supply it.
/// </summary>
[DebuggerDisplay("MissingProofOfExistenceReportData: {ObjectsMissingProofs.Count} objects")]
public sealed class MissingProofOfExistenceReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="MissingProofOfExistenceReportData"/>.</summary>
    /// <param name="objectsMissingProofs">The identities of the objects for which the set of proofs of existence holds nothing at or before the required instant.</param>
    /// <param name="additionalInformation">What the process could state about the problem; <see langword="null"/> when it had nothing to add (Table 6 makes this a "should", not a "shall").</param>
    public MissingProofOfExistenceReportData(IReadOnlyList<ValidationObjectIdentity> objectsMissingProofs, string? additionalInformation)
    {
        ObjectsMissingProofs = objectsMissingProofs;
        AdditionalInformation = additionalInformation;
    }

    /// <summary>The identities of the objects for which the set of proofs of existence holds nothing at or before the required instant.</summary>
    public IReadOnlyList<ValidationObjectIdentity> ObjectsMissingProofs { get; }

    /// <summary>What the process could state about the problem; <see langword="null"/> when it had nothing to add (Table 6 makes this a "should", not a "shall").</summary>
    public string? AdditionalInformation { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>TRY_LATER</c> ("the point of time where the necessary revocation
/// status information is expected to become available") together with the last chain built that Table 13 of
/// clause 5.2.6.3 adds.
/// </summary>
[DebuggerDisplay("TryLaterReportData: retry at {SuggestedRetryTime}")]
public sealed class TryLaterReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="TryLaterReportData"/>.</summary>
    /// <param name="suggestedRetryTime">The instant at or after which fresher revocation status information is expected — typically the <c>nextUpdate</c> field of the CRL or OCSP response consulted, per Table 13; <see langword="null"/> when no such instant was available.</param>
    /// <param name="certificateChain">A non-owning reference to the last chain built.</param>
    /// <param name="revocationData">Non-owning references to the DER-encoded revocation data whose status information was not fresh enough, which step 6 of clause 5.5.4 re-checks against best-signature-time.</param>
    public TryLaterReportData(DateTimeOffset? suggestedRetryTime, IReadOnlyList<PkiCertificateMemory> certificateChain, IReadOnlyList<PkiCertificateMemory> revocationData)
    {
        SuggestedRetryTime = suggestedRetryTime;
        CertificateChain = certificateChain;
        RevocationData = revocationData;
    }

    /// <summary>The instant at or after which fresher revocation status information is expected — typically the <c>nextUpdate</c> field of the CRL or OCSP response consulted, per Table 13; <see langword="null"/> when no such instant was available.</summary>
    public DateTimeOffset? SuggestedRetryTime { get; }

    /// <summary>A non-owning reference to the last chain built.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; }

    /// <summary>Non-owning references to the DER-encoded revocation data whose status information was not fresh enough, which step 6 of clause 5.5.4 re-checks against best-signature-time.</summary>
    public IReadOnlyList<PkiCertificateMemory> RevocationData { get; }
}


/// <summary>
/// The report data Table 6 asks for on <c>SIGNED_DATA_NOT_FOUND</c>, and Table 15 of clause 5.2.7.3 repeats
/// for the cryptographic verification building block: "the identifier(s) (e.g. an URI) of the signed data that
/// caused the failure", when available.
/// </summary>
[DebuggerDisplay("SignedDataNotFoundReportData: {SignedDataIdentifiers.Count} identifiers")]
public sealed class SignedDataNotFoundReportData : SignatureValidationReportData
{
    /// <summary>Initializes a new <see cref="SignedDataNotFoundReportData"/>.</summary>
    /// <param name="signedDataIdentifiers">The identifiers of the signed data items that could not be obtained; empty when the process had none to report.</param>
    public SignedDataNotFoundReportData(IReadOnlyList<string> signedDataIdentifiers)
    {
        SignedDataIdentifiers = signedDataIdentifiers;
    }

    /// <summary>The identifiers of the signed data items that could not be obtained; empty when the process had none to report.</summary>
    public IReadOnlyList<string> SignedDataIdentifiers { get; }
}


/// <summary>
/// The report data Table 6 mandates for <c>CUSTOM</c>: "information allowing identification of the reason for
/// the custom diagnostic result" — the escape hatch clause 5.1.3 requires when no Table 6 sub-indication maps
/// to the reason the process returned <c>INDETERMINATE</c>.
/// </summary>
/// <remarks>
/// Being an escape hatch, the datum's whole content is the diagnostic text, so that text — compared ordinally
/// — is its identity: two custom diagnostics reading the same are the same finding.
/// </remarks>
[DebuggerDisplay("CustomDiagnosticReportData: {Diagnostic}")]
public sealed class CustomDiagnosticReportData : SignatureValidationReportData, IEquatable<CustomDiagnosticReportData>
{
    /// <summary>Initializes a new <see cref="CustomDiagnosticReportData"/>.</summary>
    /// <param name="diagnostic">The reason, in terms a Driving Application can present to a verifier.</param>
    public CustomDiagnosticReportData(string diagnostic)
    {
        Diagnostic = diagnostic;
    }

    /// <summary>The reason, in terms a Driving Application can present to a verifier.</summary>
    public string Diagnostic { get; }

    /// <inheritdoc/>
    public bool Equals(CustomDiagnosticReportData? other)
    {
        return other is not null && string.Equals(Diagnostic, other.Diagnostic, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as CustomDiagnosticReportData);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Diagnostic);
    }

    /// <summary>Reports whether two custom diagnostics state the same text.</summary>
    public static bool operator ==(CustomDiagnosticReportData? left, CustomDiagnosticReportData? right)
    {
        return left is null ? right is null : left.Equals(right);
    }

    /// <summary>Reports whether two custom diagnostics state different text.</summary>
    public static bool operator !=(CustomDiagnosticReportData? left, CustomDiagnosticReportData? right)
    {
        return !(left == right);
    }
}
