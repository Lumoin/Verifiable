using System.Diagnostics;

namespace Verifiable.Core.Model.DataIntegrity;


/// <summary>
/// Enumerates the possible reasons for credential verification failure.
/// </summary>
public enum VerificationFailureReason
{
    /// <summary>
    /// No failure; verification succeeded.
    /// </summary>
    None = 0,

    /// <summary>
    /// The credential has no proof attached.
    /// </summary>
    NoProof,

    /// <summary>
    /// The proof is missing the cryptosuite specification.
    /// </summary>
    MissingCryptosuite,

    /// <summary>
    /// The proof is missing the verification method reference.
    /// </summary>
    MissingVerificationMethod,

    /// <summary>
    /// The verification method referenced by the proof was not found in the issuer's DID document.
    /// </summary>
    VerificationMethodNotFound,

    /// <summary>
    /// The cryptographic signature is invalid.
    /// </summary>
    SignatureInvalid
}


/// <summary>
/// Represents the result of verifying a Verifiable Credential's proof.
/// </summary>
/// <remarks>
/// <para>
/// This result indicates whether the cryptographic signature verified successfully.
/// Temporal policy decisions (e.g., "is this credential expired") are the caller's
/// responsibility - they can read <c>ValidFrom</c>, <c>ValidUntil</c>, and proof
/// timestamps directly from the credential they already have.
/// </para>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public readonly record struct CredentialVerificationResult
{
    /// <summary>
    /// Gets a value indicating whether the credential's cryptographic signature is valid.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// Gets the reason for verification failure, if any.
    /// </summary>
    public VerificationFailureReason FailureReason { get; init; }


    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <returns>A successful verification result.</returns>
    public static CredentialVerificationResult Success() => new()
    {
        IsValid = true,
        FailureReason = VerificationFailureReason.None
    };


    /// <summary>
    /// Creates a failed verification result with the specified reason.
    /// </summary>
    /// <param name="reason">The reason for verification failure.</param>
    /// <returns>A failed verification result.</returns>
    public static CredentialVerificationResult Failed(VerificationFailureReason reason) => new()
    {
        IsValid = false,
        FailureReason = reason
    };


    /// <summary>
    /// Returns a string representation of the verification result.
    /// </summary>
    /// <returns>A string describing the verification result.</returns>
    public override string ToString() => IsValid ? "Valid" : $"Invalid ({FailureReason})";
}