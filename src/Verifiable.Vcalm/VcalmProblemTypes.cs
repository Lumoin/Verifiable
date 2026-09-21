using Verifiable.Core.StatusLists;

namespace Verifiable.Vcalm;

/// <summary>
/// The RFC 9457 ProblemDetails <c>type</c> URLs the W3C VCALM 1.0 verifier service emits.
/// </summary>
/// <remarks>
/// <para>
/// §3.8 mandates that the ProblemDetails <c>type</c> "MUST be present and its value MUST be a
/// URL identifying the type of problem." VCALM 1.0 itself defines one type
/// (<see cref="UnknownOptionProvided"/>); the verification ProblemDetails reuse the
/// VC Data Model 2.0 / VC Data Integrity 1.0 / Bitstring Status List 1.0 catalogues §3.8 points
/// implementers at. The dated-URL note in §3.8 (Issue 3) is honoured by anchoring against the
/// <c>vc-data-model-2.0</c> path while VCDM 2.0 finishes becoming a global standard.
/// </para>
/// <para>
/// §3.8 lists, among the ProblemDetails an implementation might report, "Section 3.5: Processing
/// Errors in the Bitstring Status List v1.0 specification": <see cref="StatusRetrievalError"/>,
/// <see cref="StatusVerificationError"/>, and <see cref="StatusListLengthError"/> reuse
/// <see cref="BitstringStatusListConstants.ErrorTypeUrlPrefix"/>, the prefix the Bitstring Status
/// List 1.0 catalogue itself defines; <see cref="RangeError"/> is the RANGE_ERROR the Bitstring
/// Status List 1.0 Validate Algorithm raises, anchored against the VC Data Model 2.0 catalogue like
/// this catalogue's other VC Data Model rows.
/// </para>
/// </remarks>
public static class VcalmProblemTypes
{
    /// <summary>
    /// §3.8: "An option that is unknown to the implementation was provided to the API call."
    /// The single problem type VCALM 1.0 itself defines, paired with the §2.4 MUST that an
    /// endpoint reject options it does not understand.
    /// </summary>
    public static string UnknownOptionProvided { get; } =
        "https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED";

    /// <summary>
    /// The cryptographic-security ERROR (§3.8.1: a proof / cryptography failure is unrecoverable
    /// and MUST set <c>verified</c> to false). Anchored against the VCDM 2.0 §7.2 problem-details
    /// catalogue per the §3.8 Issue-3 dated-URL guidance.
    /// </summary>
    public static string CryptographicSecurityError { get; } =
        "https://www.w3.org/TR/vc-data-model-2.0#CRYPTOGRAPHIC_SECURITY_ERROR";

    /// <summary>
    /// The malformed / data-model ERROR (§3.8.1: a data-model or malformed-context failure is
    /// unrecoverable and MUST set <c>verified</c> to false).
    /// </summary>
    public static string MalformedValueError { get; } =
        "https://www.w3.org/TR/vc-data-model-2.0#MALFORMED_VALUE_ERROR";

    /// <summary>
    /// The validity-period WARNING (§3.8.1: a validity-period ProblemDetails is recoverable and
    /// does NOT flip <c>verified</c>) — emitted when <c>validFrom</c> is in the future or
    /// <c>validUntil</c> is in the past relative to the verification instant.
    /// </summary>
    public static string ValidityPeriodWarning { get; } =
        "https://www.w3.org/TR/vc-data-model-2.0#VALIDITY_PERIOD_WARNING";

    /// <summary>
    /// The status WARNING (§3.8.1: a status ProblemDetails is recoverable and does NOT flip
    /// <c>verified</c>) — emitted when the credential's status resolves to revoked or suspended.
    /// </summary>
    public static string StatusWarning { get; } =
        "https://www.w3.org/TR/vc-data-model-2.0#STATUS_WARNING";

    /// <summary>
    /// The Bitstring Status List 1.0 §3.5 <c>STATUS_RETRIEVAL_ERROR</c>: reported as a §3.8.1
    /// status WARNING when the application's <see cref="ResolveVcalmStatusListDelegate"/> cannot
    /// retrieve the referenced status list — it returns <see langword="null"/>, throws a
    /// <see cref="BitstringStatusListException"/> of kind
    /// <see cref="BitstringStatusListErrorType.StatusRetrieval"/>, or throws any other exception.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring
    /// Status List 1.0 §3.5 Processing Errors</see>: "Retrieval of the status list failed."
    /// </remarks>
    public static string StatusRetrievalError { get; } =
        BitstringStatusListConstants.ErrorTypeUrlPrefix + "STATUS_RETRIEVAL_ERROR";

    /// <summary>
    /// The Bitstring Status List 1.0 §3.5 <c>STATUS_VERIFICATION_ERROR</c>: reported as a §3.8.1
    /// status WARNING when a <c>BitstringStatusListEntry</c>'s <c>statusListIndex</c>,
    /// <c>statusListCredential</c>, or <c>statusPurpose</c> is missing or unparseable, or when
    /// <see cref="BitstringStatusListValidation.GetStatus"/> throws a
    /// <see cref="BitstringStatusListException"/> of kind
    /// <see cref="BitstringStatusListErrorType.StatusVerification"/> (a failed proof or purpose
    /// mismatch).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring
    /// Status List 1.0 §3.5 Processing Errors</see>: "Validation of the status entry failed."
    /// </remarks>
    public static string StatusVerificationError { get; } =
        BitstringStatusListConstants.ErrorTypeUrlPrefix + "STATUS_VERIFICATION_ERROR";

    /// <summary>
    /// The Bitstring Status List 1.0 §3.5 <c>STATUS_LIST_LENGTH_ERROR</c>: reported as a §3.8.1
    /// status WARNING when the referenced status list is shorter than the herd-privacy minimum.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring
    /// Status List 1.0 §3.5 Processing Errors</see>: "The status list length does not satisfy the
    /// minimum length required for herd privacy."
    /// </remarks>
    public static string StatusListLengthError { get; } =
        BitstringStatusListConstants.ErrorTypeUrlPrefix + "STATUS_LIST_LENGTH_ERROR";

    /// <summary>
    /// The VC Data Model 2.0 <c>RANGE_ERROR</c> the Bitstring Status List 1.0 Validate Algorithm
    /// raises when a <c>statusListIndex</c> lies outside the bitstring; reported as a §3.8.1 status
    /// WARNING.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#validate-algorithm">Bitstring
    /// Status List 1.0 §3.2 Validate Algorithm</see>: "a RANGE_ERROR MUST be raised."
    /// </remarks>
    public static string RangeError { get; } =
        "https://www.w3.org/TR/vc-data-model-2.0#RANGE_ERROR";
}
