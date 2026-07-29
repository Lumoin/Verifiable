using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The main status indication a signature validation <em>process</em> reports, per Table 5 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>. The processes that report it are the validation process for
/// Basic Signatures (clause 5.3), the validation process for Signatures with Time and Signatures with
/// Long-Term Validation Material (clause 5.5), and the validation process for Signatures providing Long Term
/// Availability and Integrity of Validation Material (clause 5.6.3).
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately a different type from <see cref="BuildingBlockIndication"/>. Clause 5.1.3 spells the
/// two vocabularies differently — a process reports <c>TOTAL-PASSED</c> / <c>TOTAL-FAILED</c> /
/// <c>INDETERMINATE</c> while a building block reports <c>PASSED</c> / <c>FAILED</c> /
/// <c>INDETERMINATE</c> — and
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.4.2</see> assigns the two vocabularies <em>different</em> URN sets for
/// the same element name, so a single enumeration could not be mapped to the wire unambiguously. Use
/// <see cref="BuildingBlockIndicationMapping.ToProcessIndication"/> to promote a block result to a process
/// result under clause 5.1.3's three promotion rules.
/// </para>
/// <para>
/// <see cref="Indeterminate"/> occupies zero so that an uninitialized value is never a passing one; clause
/// 5.1.3 defines <c>INDETERMINATE</c> as "the available information is insufficient to ascertain the
/// signature to be <c>TOTAL-PASSED</c> or <c>TOTAL-FAILED</c>", which is exactly the correct reading of a
/// value nothing has yet set.
/// </para>
/// </remarks>
public enum SignatureValidationIndication
{
    /// <summary>
    /// <c>INDETERMINATE</c> — the available information is insufficient to ascertain the signature to be
    /// <c>TOTAL-PASSED</c> or <c>TOTAL-FAILED</c> (Table 5). Also the value of an unset field, by design.
    /// </summary>
    Indeterminate = 0,

    /// <summary>
    /// <c>TOTAL-PASSED</c> — the format check succeeded, the cryptographic checks succeeded, the constraints
    /// applicable to the signer's certificate validated positively, and the signature validated positively
    /// against the validation constraints (Table 5).
    /// </summary>
    TotalPassed = 1,

    /// <summary>
    /// <c>TOTAL-FAILED</c> — the format check failed, the cryptographic checks failed, or it has been proven
    /// that the signing certificate was invalid at the time of generation of the signature (Table 5).
    /// </summary>
    TotalFailed = 2
}


/// <summary>
/// The status indication one basic building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2</see> reports — the <c>PASSED</c> / <c>FAILED</c> /
/// <c>INDETERMINATE</c> vocabulary of the per-block output tables (Table 11, Table 11B, Table 13, Table 15,
/// Table 17, Table 22 and Table 24), as opposed to the process-level <c>TOTAL-*</c> vocabulary of
/// <see cref="SignatureValidationIndication"/>.
/// </summary>
/// <remarks>
/// <see cref="Indeterminate"/> occupies zero for the same fail-closed reason as
/// <see cref="SignatureValidationIndication.Indeterminate"/>: a block output nothing has set must never read
/// as a passing one.
/// </remarks>
public enum BuildingBlockIndication
{
    /// <summary>
    /// <c>INDETERMINATE</c> — the block could not decide; a sub-indication states why. Also the value of an
    /// unset field, by design.
    /// </summary>
    Indeterminate = 0,

    /// <summary>
    /// <c>PASSED</c> — the block's check succeeded.
    /// </summary>
    Passed = 1,

    /// <summary>
    /// <c>FAILED</c> — the block's check failed determinately.
    /// </summary>
    Failed = 2
}


/// <summary>
/// One status sub-indication supplementing a main status indication, per Table 6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see>. The Table 6 values are provided as statics; the type stays an
/// open wire-value wrapper rather than a closed enumeration because clause 5.1.3 itself keeps the set open —
/// when no Table 6 sub-indication maps to the reason, "the SVA shall return a custom diagnostic of the reason
/// for <c>INDETERMINATE</c>", reported under <see cref="Custom"/> with the reason carried in a
/// <see cref="CustomDiagnosticReportData"/>.
/// </summary>
/// <remarks>
/// Each value's <see cref="Value"/> is the specification's own token, so
/// <see cref="SignatureValidationSubIndicationMapping.ToWireValue"/> can build the
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1 clause 4.3.4.3</see> URN by prefixing it, and a value minted by a caller for a
/// custom diagnostic maps the same way.
/// </remarks>
[DebuggerDisplay("SignatureValidationSubIndication: {Value}")]
public readonly record struct SignatureValidationSubIndication(string Value)
{
    /// <summary>
    /// <c>FORMAT_FAILURE</c> (<c>TOTAL-FAILED</c>): the signature is not conformant to one of the base
    /// standards to the extent that the cryptographic verification building block is unable to process it.
    /// </summary>
    public static SignatureValidationSubIndication FormatFailure { get; } = new("FORMAT_FAILURE");

    /// <summary>
    /// <c>HASH_FAILURE</c> (<c>TOTAL-FAILED</c>): at least one hash of a Signed Data Object included in the
    /// signing process does not match the corresponding hash value in the signature.
    /// </summary>
    public static SignatureValidationSubIndication HashFailure { get; } = new("HASH_FAILURE");

    /// <summary>
    /// <c>SIG_CRYPTO_FAILURE</c> (<c>TOTAL-FAILED</c>): the signature value could not be verified using the
    /// signer's public key in the signing certificate.
    /// </summary>
    public static SignatureValidationSubIndication SignatureCryptographicFailure { get; } = new("SIG_CRYPTO_FAILURE");

    /// <summary>
    /// <c>REVOKED</c> (<c>TOTAL-FAILED</c>): the signing certificate has been revoked and there is proof that
    /// the signature has been created after the revocation time.
    /// </summary>
    public static SignatureValidationSubIndication Revoked { get; } = new("REVOKED");

    /// <summary>
    /// <c>EXPIRED</c> (<c>TOTAL-FAILED</c>): there is proof that the signature has been created after the
    /// <c>notAfter</c> date of the signing certificate.
    /// </summary>
    public static SignatureValidationSubIndication Expired { get; } = new("EXPIRED");

    /// <summary>
    /// <c>NOT_YET_VALID</c> (<c>TOTAL-FAILED</c>): there is proof that the signature was created before the
    /// <c>notBefore</c> date of the signing certificate.
    /// </summary>
    public static SignatureValidationSubIndication NotYetValid { get; } = new("NOT_YET_VALID");

    /// <summary>
    /// <c>SIG_CONSTRAINTS_FAILURE</c> (<c>INDETERMINATE</c>): one or more attributes of the signature do not
    /// match the validation constraints.
    /// </summary>
    public static SignatureValidationSubIndication SignatureConstraintsFailure { get; } = new("SIG_CONSTRAINTS_FAILURE");

    /// <summary>
    /// <c>CHAIN_CONSTRAINTS_FAILURE</c> (<c>INDETERMINATE</c>): the certificate chain used does not match the
    /// validation constraints related to the certificate.
    /// </summary>
    public static SignatureValidationSubIndication ChainConstraintsFailure { get; } = new("CHAIN_CONSTRAINTS_FAILURE");

    /// <summary>
    /// <c>CERTIFICATE_CHAIN_GENERAL_FAILURE</c> (<c>INDETERMINATE</c>): the set of certificates available for
    /// chain validation produced an error for an unspecified reason.
    /// </summary>
    public static SignatureValidationSubIndication CertificateChainGeneralFailure { get; } = new("CERTIFICATE_CHAIN_GENERAL_FAILURE");

    /// <summary>
    /// <c>CRYPTO_CONSTRAINTS_FAILURE</c> (<c>INDETERMINATE</c>): material involved in validating the signature
    /// uses an algorithm or key size below the required cryptographic security level, the material was produced
    /// after the time up to which that algorithm or key was considered secure, and the material is not
    /// protected by a sufficiently strong time-stamp applied before that time.
    /// </summary>
    public static SignatureValidationSubIndication CryptographicConstraintsFailure { get; } = new("CRYPTO_CONSTRAINTS_FAILURE");

    /// <summary>
    /// <c>POLICY_PROCESSING_ERROR</c> (<c>INDETERMINATE</c>): a given formal policy file could not be
    /// processed for any reason (not accessible, not parseable, digest mismatch, and so on).
    /// </summary>
    public static SignatureValidationSubIndication PolicyProcessingError { get; } = new("POLICY_PROCESSING_ERROR");

    /// <summary>
    /// <c>SIGNATURE_POLICY_NOT_AVAILABLE</c> (<c>INDETERMINATE</c>): the electronic document containing the
    /// details of the policy is not available.
    /// </summary>
    public static SignatureValidationSubIndication SignaturePolicyNotAvailable { get; } = new("SIGNATURE_POLICY_NOT_AVAILABLE");

    /// <summary>
    /// <c>TIMESTAMP_ORDER_FAILURE</c> (<c>INDETERMINATE</c>): constraints on the order of signature
    /// time-stamps and/or Signed Data Object time-stamps are not respected.
    /// </summary>
    public static SignatureValidationSubIndication TimestampOrderFailure { get; } = new("TIMESTAMP_ORDER_FAILURE");

    /// <summary>
    /// <c>NO_SIGNING_CERTIFICATE_FOUND</c> (<c>INDETERMINATE</c>): the signing certificate cannot be
    /// identified.
    /// </summary>
    public static SignatureValidationSubIndication NoSigningCertificateFound { get; } = new("NO_SIGNING_CERTIFICATE_FOUND");

    /// <summary>
    /// <c>NO_CERTIFICATE_CHAIN_FOUND</c> (<c>INDETERMINATE</c>): no certificate chain has been found for the
    /// identified signing certificate.
    /// </summary>
    public static SignatureValidationSubIndication NoCertificateChainFound { get; } = new("NO_CERTIFICATE_CHAIN_FOUND");

    /// <summary>
    /// <c>NO_CERTIFICATE_CHAIN_FOUND_NO_POE</c> (<c>INDETERMINATE</c>): no certificate chain has been found
    /// because the trust anchor was not trusted at the validation date/time by the validation policy in use
    /// (its sunset date had passed), and the algorithm cannot ascertain whether the signing time lies before
    /// or after the time the trust anchor was trusted.
    /// </summary>
    public static SignatureValidationSubIndication NoCertificateChainFoundNoProofOfExistence { get; } = new("NO_CERTIFICATE_CHAIN_FOUND_NO_POE");

    /// <summary>
    /// <c>REVOKED_NO_POE</c> (<c>INDETERMINATE</c>): the signing certificate was revoked at the validation
    /// date/time, but the algorithm cannot ascertain whether the signing time lies before or after the
    /// revocation time.
    /// </summary>
    public static SignatureValidationSubIndication RevokedNoProofOfExistence { get; } = new("REVOKED_NO_POE");

    /// <summary>
    /// <c>REVOKED_CA_NO_POE</c> (<c>INDETERMINATE</c>): at least one certificate chain was found but an
    /// intermediate CA certificate is revoked.
    /// </summary>
    public static SignatureValidationSubIndication RevokedCertificationAuthorityNoProofOfExistence { get; } = new("REVOKED_CA_NO_POE");

    /// <summary>
    /// <c>OUT_OF_BOUNDS_NOT_REVOKED</c> (<c>INDETERMINATE</c>): the signing certificate is expired or not yet
    /// valid at the validation date/time and the algorithm cannot ascertain that the signing time lies within
    /// the certificate's validity interval; the certificate is known not to be revoked.
    /// </summary>
    public static SignatureValidationSubIndication OutOfBoundsNotRevoked { get; } = new("OUT_OF_BOUNDS_NOT_REVOKED");

    /// <summary>
    /// <c>OUT_OF_BOUNDS_NO_POE</c> (<c>INDETERMINATE</c>): the signing certificate is expired or not yet valid
    /// at the validation date/time and the algorithm cannot ascertain that the signing time lies within the
    /// certificate's validity interval.
    /// </summary>
    public static SignatureValidationSubIndication OutOfBoundsNoProofOfExistence { get; } = new("OUT_OF_BOUNDS_NO_POE");

    /// <summary>
    /// <c>REVOCATION_OUT_OF_BOUNDS_NO_POE</c> (<c>INDETERMINATE</c>): the signing certificate of the
    /// revocation data carrying the revocation status information of the signature's signing certificate is
    /// expired or not yet valid at the validation date/time, and the algorithm cannot ascertain that the
    /// revocation data is proven to have existed within that issuer certificate's validity interval.
    /// </summary>
    public static SignatureValidationSubIndication RevocationOutOfBoundsNoProofOfExistence { get; } = new("REVOCATION_OUT_OF_BOUNDS_NO_POE");

    /// <summary>
    /// <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c> (<c>INDETERMINATE</c>): material involved in validating the
    /// signature uses an algorithm or key size below the required cryptographic security level and there is no
    /// proof that this material was produced before the time up to which that algorithm or key was considered
    /// secure.
    /// </summary>
    public static SignatureValidationSubIndication CryptographicConstraintsFailureNoProofOfExistence { get; } = new("CRYPTO_CONSTRAINTS_FAILURE_NO_POE");

    /// <summary>
    /// <c>NO_POE</c> (<c>INDETERMINATE</c>): a proof of existence is missing to ascertain that a signed object
    /// was produced before some compromising event (for example a broken algorithm).
    /// </summary>
    public static SignatureValidationSubIndication NoProofOfExistence { get; } = new("NO_POE");

    /// <summary>
    /// <c>TRY_LATER</c> (<c>INDETERMINATE</c>): not all constraints can be fulfilled using available
    /// information, but it may be possible using additional revocation status information available later.
    /// </summary>
    public static SignatureValidationSubIndication TryLater { get; } = new("TRY_LATER");

    /// <summary>
    /// <c>SIGNED_DATA_NOT_FOUND</c> (<c>INDETERMINATE</c>): signed data cannot be obtained.
    /// </summary>
    public static SignatureValidationSubIndication SignedDataNotFound { get; } = new("SIGNED_DATA_NOT_FOUND");

    /// <summary>
    /// <c>CUSTOM</c> (<c>INDETERMINATE</c>): a custom diagnostic not specified in EN 319 102-1. The reason is
    /// carried alongside in a <see cref="CustomDiagnosticReportData"/>, which Table 6 makes mandatory for this
    /// value ("the process shall output information allowing identification of the reason").
    /// </summary>
    public static SignatureValidationSubIndication Custom { get; } = new("CUSTOM");


    /// <summary>
    /// Gets whether Table 7 of clause 5.1.3 lists this sub-indication among those for which the Driving
    /// Application may rerun the validation process and obtain a different result once the stated condition
    /// holds (a different chain can be constructed, the policy file becomes available, the signing certificate
    /// or CA certificates become available, additional proofs of existence become available, or fresher
    /// revocation status information becomes available).
    /// </summary>
    /// <remarks>
    /// Sub-indications outside Table 7 — including any caller-minted custom value — report
    /// <see langword="false"/>: retrying is only advertised where the specification itself lists a condition
    /// under which the outcome can change.
    /// </remarks>
    public bool IsRetryable =>
        string.Equals(Value, ChainConstraintsFailure.Value, StringComparison.Ordinal)
        || string.Equals(Value, CertificateChainGeneralFailure.Value, StringComparison.Ordinal)
        || string.Equals(Value, PolicyProcessingError.Value, StringComparison.Ordinal)
        || string.Equals(Value, SignaturePolicyNotAvailable.Value, StringComparison.Ordinal)
        || string.Equals(Value, NoSigningCertificateFound.Value, StringComparison.Ordinal)
        || string.Equals(Value, NoCertificateChainFound.Value, StringComparison.Ordinal)
        || string.Equals(Value, RevokedNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, RevokedCertificationAuthorityNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, OutOfBoundsNotRevoked.Value, StringComparison.Ordinal)
        || string.Equals(Value, OutOfBoundsNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, CryptographicConstraintsFailureNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, NoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, TryLater.Value, StringComparison.Ordinal);

    /// <summary>
    /// Gets whether retrying this sub-indication requires additional proofs of existence, which Table 7
    /// qualifies as "only relevant for the validation process for Signatures providing Long Term Availability
    /// and Integrity of Validation Material" (clause 5.6.3).
    /// </summary>
    public bool RequiresAdditionalProofsOfExistenceToRetry =>
        string.Equals(Value, RevokedNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, RevokedCertificationAuthorityNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, OutOfBoundsNotRevoked.Value, StringComparison.Ordinal)
        || string.Equals(Value, OutOfBoundsNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, CryptographicConstraintsFailureNoProofOfExistence.Value, StringComparison.Ordinal)
        || string.Equals(Value, NoProofOfExistence.Value, StringComparison.Ordinal);
}
