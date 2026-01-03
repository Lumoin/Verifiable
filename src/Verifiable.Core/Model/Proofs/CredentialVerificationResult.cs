using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Proofs;

/// <summary>
/// Represents the result of a credential verification operation.
/// </summary>
/// <remarks>
/// <para>
/// This type provides a structured way to communicate verification outcomes,
/// distinguishing between successful verification and various failure modes.
/// </para>
/// <para>
/// The verification process encompasses multiple checks including:
/// </para>
/// <list type="bullet">
/// <item><description>Credential validity period (not expired, not yet valid).</description></item>
/// <item><description>Proof presence and structure.</description></item>
/// <item><description>Verification method resolution from the issuer's DID document.</description></item>
/// <item><description>Cryptographic signature validation.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public readonly struct CredentialVerificationResult: IEquatable<CredentialVerificationResult>
{
    /// <summary>
    /// Gets a value indicating whether the verification was successful.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the reason for verification failure, or <c>null</c> if verification succeeded.
    /// </summary>
    public VerificationFailureReason? FailureReason { get; }


    private CredentialVerificationResult(bool isValid, VerificationFailureReason? failureReason)
    {
        IsValid = isValid;
        FailureReason = failureReason;
    }


    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <returns>A result indicating successful verification.</returns>
    public static CredentialVerificationResult Success() => new(true, null);


    /// <summary>
    /// Creates a failed verification result with the specified reason.
    /// </summary>
    /// <param name="reason">The reason for verification failure.</param>
    /// <returns>A result indicating failed verification.</returns>
    public static CredentialVerificationResult Failed(VerificationFailureReason reason) => new(false, reason);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CredentialVerificationResult other)
    {
        return IsValid == other.IsValid && FailureReason == other.FailureReason;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is CredentialVerificationResult other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return HashCode.Combine(IsValid, FailureReason);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(CredentialVerificationResult left, CredentialVerificationResult right)
    {
        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(CredentialVerificationResult left, CredentialVerificationResult right)
    {
        return !left.Equals(right);
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        return IsValid ? "Success" : $"Failed: {FailureReason}";
    }
}


/// <summary>
/// Specifies reasons why credential verification might fail.
/// </summary>
/// <remarks>
/// <para>
/// These reasons cover the various stages of verification, from structural
/// checks through cryptographic validation.
/// </para>
/// </remarks>
public enum VerificationFailureReason
{
    /// <summary>
    /// The credential does not contain a proof.
    /// </summary>
    /// <remarks>
    /// This indicates a credential secured with Data Integrity was expected but
    /// the <c>proof</c> property is null or empty.
    /// </remarks>
    NoProof,

    /// <summary>
    /// The proof does not contain a verification method reference.
    /// </summary>
    /// <remarks>
    /// The <c>verificationMethod</c> property in the proof is required to identify
    /// which key was used for signing.
    /// </remarks>
    MissingVerificationMethod,

    /// <summary>
    /// The proof does not contain cryptosuite information.
    /// </summary>
    /// <remarks>
    /// The <c>cryptosuite</c> property is required to determine the hash and signature
    /// algorithms used for verification.
    /// </remarks>
    MissingCryptosuite,

    /// <summary>
    /// The verification method referenced in the proof was not found in the issuer's DID document.
    /// </summary>
    /// <remarks>
    /// The verification method ID must resolve to a method in the issuer's DID document
    /// that is authorized for the proof's purpose (e.g., <c>assertionMethod</c>).
    /// </remarks>
    VerificationMethodNotFound,

    /// <summary>
    /// The cryptographic signature is invalid.
    /// </summary>
    /// <remarks>
    /// The signature verification failed, which could indicate tampering with the
    /// credential or proof, or use of an incorrect key.
    /// </remarks>
    SignatureInvalid,

    /// <summary>
    /// The credential has expired (current time is after <c>validUntil</c>).
    /// </summary>
    CredentialExpired,

    /// <summary>
    /// The credential is not yet valid (current time is before <c>validFrom</c>).
    /// </summary>
    CredentialNotYetValid,

    /// <summary>
    /// Failed to resolve the issuer's DID document.
    /// </summary>
    /// <remarks>
    /// The issuer's DID could not be resolved to obtain the DID document containing
    /// the verification methods.
    /// </remarks>
    IssuerDidResolutionFailed
}