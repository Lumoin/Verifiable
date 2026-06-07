using System.Diagnostics;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// The result of verifying a credential or presentation, carrying the minted
/// <see cref="Verified{T}"/> on success.
/// </summary>
/// <remarks>
/// <para>
/// This is the verified-typed counterpart of <see cref="CredentialVerificationResult"/>: it
/// reports the same validity and <see cref="VerificationFailureReason"/>, but on success it also
/// hands back the <see cref="Verified{T}"/> the verification minted. A caller that wants the
/// trusted value reads <see cref="Verified"/> (non-null exactly when <see cref="IsValid"/>);
/// possessing that value is proof the verification succeeded.
/// </para>
/// </remarks>
/// <typeparam name="T">The verified value's type (for example a credential or a presentation).</typeparam>
[DebuggerDisplay("{ToString(),nq}")]
public readonly record struct CredentialVerificationResult<T> where T : notnull
{
    /// <summary>
    /// Whether verification succeeded.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// The reason verification failed, or <see cref="VerificationFailureReason.None"/> on success.
    /// </summary>
    public VerificationFailureReason FailureReason { get; init; }

    /// <summary>
    /// The verified value, non-null exactly when <see cref="IsValid"/> is <see langword="true"/>.
    /// </summary>
    public Verified<T>? Verified { get; init; }


    /// <summary>
    /// Creates a successful result carrying the minted verified value.
    /// </summary>
    /// <param name="verified">The verified value.</param>
    public static CredentialVerificationResult<T> Success(Verified<T> verified) => new()
    {
        IsValid = true,
        FailureReason = VerificationFailureReason.None,
        Verified = verified
    };


    /// <summary>
    /// Creates a failed result with the specified reason.
    /// </summary>
    /// <param name="reason">The reason for verification failure.</param>
    public static CredentialVerificationResult<T> Failed(VerificationFailureReason reason) => new()
    {
        IsValid = false,
        FailureReason = reason,
        Verified = null
    };


    /// <summary>
    /// Returns a string representation of the verification result.
    /// </summary>
    public override string ToString() => IsValid ? "Valid" : $"Invalid ({FailureReason})";
}
