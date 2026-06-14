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
/// </remarks>
public static class VcalmProblemTypes
{
    /// <summary>
    /// §3.8: "An option that is unknown to the implementation was provided to the API call."
    /// The single problem type VCALM 1.0 itself defines, paired with the §2.4 MUST that an
    /// endpoint reject options it does not understand.
    /// </summary>
    public static readonly string UnknownOptionProvided =
        "https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED";

    /// <summary>
    /// The cryptographic-security ERROR (§3.8.1: a proof / cryptography failure is unrecoverable
    /// and MUST set <c>verified</c> to false). Anchored against the VCDM 2.0 §7.2 problem-details
    /// catalogue per the §3.8 Issue-3 dated-URL guidance.
    /// </summary>
    public static readonly string CryptographicSecurityError =
        "https://www.w3.org/TR/vc-data-model-2.0#CRYPTOGRAPHIC_SECURITY_ERROR";

    /// <summary>
    /// The malformed / data-model ERROR (§3.8.1: a data-model or malformed-context failure is
    /// unrecoverable and MUST set <c>verified</c> to false).
    /// </summary>
    public static readonly string MalformedValueError =
        "https://www.w3.org/TR/vc-data-model-2.0#MALFORMED_VALUE_ERROR";

    /// <summary>
    /// The validity-period WARNING (§3.8.1: a validity-period ProblemDetails is recoverable and
    /// does NOT flip <c>verified</c>) — emitted when <c>validFrom</c> is in the future or
    /// <c>validUntil</c> is in the past relative to the verification instant.
    /// </summary>
    public static readonly string ValidityPeriodWarning =
        "https://www.w3.org/TR/vc-data-model-2.0#VALIDITY_PERIOD_WARNING";

    /// <summary>
    /// The status WARNING (§3.8.1: a status ProblemDetails is recoverable and does NOT flip
    /// <c>verified</c>) — emitted when the credential's status resolves to revoked or suspended.
    /// </summary>
    public static readonly string StatusWarning =
        "https://www.w3.org/TR/vc-data-model-2.0#STATUS_WARNING";
}
