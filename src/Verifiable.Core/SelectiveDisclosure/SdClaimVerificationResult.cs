using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.SelectiveDisclosure;

/// <summary>
/// Enumerates the possible reasons for selective disclosure claim verification failure.
/// </summary>
public enum SdClaimVerificationFailureReason
{
    /// <summary>
    /// No failure; claim verification succeeded.
    /// </summary>
    None = 0,

    /// <summary>
    /// The disclosure digest does not match the computed hash.
    /// </summary>
    DigestMismatch,

    /// <summary>
    /// The claim signature is cryptographically invalid.
    /// </summary>
    SignatureInvalid,

    /// <summary>
    /// A mandatory claim was not disclosed.
    /// </summary>
    MandatoryClaimMissing,

    /// <summary>
    /// The disclosure format is malformed or cannot be parsed.
    /// </summary>
    MalformedDisclosure
}


/// <summary>
/// Result of verifying a single selectively disclosed claim.
/// </summary>
[DebuggerDisplay("{Path}: {IsValid ? \"Valid\" : FailureReason}")]
public readonly record struct SdClaimVerificationResult
{
    /// <summary>
    /// Path to the claim in the credential structure.
    /// </summary>
    public CredentialPath Path { get; init; }

    /// <summary>
    /// Whether this claim's signature or digest verified successfully.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// Reason for failure, if any.
    /// </summary>
    public SdClaimVerificationFailureReason FailureReason { get; init; }


    /// <summary>
    /// Creates a successful claim verification result.
    /// </summary>
    /// <param name="path">The path to the verified claim.</param>
    /// <returns>A successful claim verification result.</returns>
    public static SdClaimVerificationResult Success(CredentialPath path) => new()
    {
        Path = path,
        IsValid = true,
        FailureReason = SdClaimVerificationFailureReason.None
    };


    /// <summary>
    /// Creates a failed claim verification result.
    /// </summary>
    /// <param name="path">The path to the claim that failed verification.</param>
    /// <param name="reason">The reason for verification failure.</param>
    /// <returns>A failed claim verification result.</returns>
    public static SdClaimVerificationResult Failed(CredentialPath path, SdClaimVerificationFailureReason reason) => new()
    {
        Path = path,
        IsValid = false,
        FailureReason = reason
    };
}


/// <summary>
/// Enumerates the possible reasons for overall selective disclosure verification failure.
/// </summary>
public enum SdVerificationFailureReason
{
    /// <summary>
    /// No failure; verification succeeded.
    /// </summary>
    None = 0,

    /// <summary>
    /// The issuer signature is cryptographically invalid.
    /// </summary>
    IssuerSignatureInvalid,

    /// <summary>
    /// The base proof structure is malformed or cannot be parsed.
    /// </summary>
    MalformedBaseProof,

    /// <summary>
    /// The derived proof structure is malformed or cannot be parsed.
    /// </summary>
    MalformedDerivedProof,

    /// <summary>
    /// One or more disclosed claims failed verification.
    /// </summary>
    ClaimVerificationFailed,

    /// <summary>
    /// One or more mandatory claims are missing from the disclosure.
    /// </summary>
    MandatoryClaimsMissing,

    /// <summary>
    /// The verification method was not found in the issuer's DID document.
    /// </summary>
    VerificationMethodNotFound,

    /// <summary>
    /// The token structure is invalid (e.g., missing required fields).
    /// </summary>
    InvalidTokenStructure
}


/// <summary>
/// Result of verifying a selective disclosure credential.
/// </summary>
/// <remarks>
/// <para>
/// This result provides both overall verification status and per-claim results,
/// allowing the verifier to determine exactly which claims were successfully
/// verified and which failed.
/// </para>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public readonly record struct SdVerificationResult
{
    /// <summary>
    /// Gets a value indicating whether the overall verification succeeded.
    /// </summary>
    /// <remarks>
    /// This is true only if the issuer signature is valid and all disclosed claims verify successfully.
    /// </remarks>
    public bool IsValid { get; init; }

    /// <summary>
    /// Gets the reason for overall verification failure, if any.
    /// </summary>
    public SdVerificationFailureReason FailureReason { get; init; }

    /// <summary>
    /// Gets the verification results for each disclosed claim.
    /// </summary>
    /// <remarks>
    /// This collection contains results for all claims that were disclosed and verified,
    /// allowing the verifier to see exactly what was presented.
    /// </remarks>
    public IReadOnlyList<SdClaimVerificationResult> ClaimResults { get; init; }


    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <param name="claimResults">The verification results for each disclosed claim.</param>
    /// <returns>A successful verification result.</returns>
    public static SdVerificationResult Success(IReadOnlyList<SdClaimVerificationResult> claimResults) => new()
    {
        IsValid = true,
        FailureReason = SdVerificationFailureReason.None,
        ClaimResults = claimResults
    };


    /// <summary>
    /// Creates a failed verification result.
    /// </summary>
    /// <param name="reason">The reason for verification failure.</param>
    /// <param name="claimResults">Optional claim results if partial verification was attempted.</param>
    /// <returns>A failed verification result.</returns>
    public static SdVerificationResult Failed(
        SdVerificationFailureReason reason,
        IReadOnlyList<SdClaimVerificationResult>? claimResults = null) => new()
        {
            IsValid = false,
            FailureReason = reason,
            ClaimResults = claimResults ?? []
        };


    /// <summary>
    /// Returns a string representation of the verification result.
    /// </summary>
    /// <returns>A string describing the verification result.</returns>
    public override string ToString()
    {
        if(IsValid)
        {
            return $"Valid ({ClaimResults.Count} claims verified)";
        }

        int failedCount = 0;
        foreach(var claim in ClaimResults)
        {
            if(!claim.IsValid)
            {
                failedCount++;
            }
        }

        return failedCount > 0
            ? $"Invalid ({FailureReason}, {failedCount} claims failed)"
            : $"Invalid ({FailureReason})";
    }
}