namespace Verifiable.JCose;

/// <summary>
/// Result of verifying a COSE_Sign1 structure.
/// </summary>
/// <remarks>
/// <para>
/// This is a low-level result containing raw bytes. For credential-specific
/// verification that decodes the payload, use
/// <c>CoseCredentialVerificationResult</c> in <c>Verifiable.Core.Model.Credentials</c>.
/// </para>
/// </remarks>
/// <param name="IsValid">Whether the signature is valid.</param>
/// <param name="Payload">The payload bytes if verification succeeded, otherwise empty.</param>
/// <param name="ProtectedHeader">The protected header bytes.</param>
/// <param name="Algorithm">The algorithm from protected header, or null if not present.</param>
/// <param name="KeyId">The key ID from protected header, or null if not present.</param>
public readonly record struct CoseVerificationResult(
    bool IsValid,
    ReadOnlyMemory<byte> Payload,
    ReadOnlyMemory<byte> ProtectedHeader,
    int? Algorithm,
    string? KeyId)
{
    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <param name="payload">The verified payload bytes.</param>
    /// <param name="protectedHeader">The protected header bytes.</param>
    /// <param name="algorithm">The algorithm identifier.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <returns>A successful verification result.</returns>
    public static CoseVerificationResult Success(
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> protectedHeader,
        int? algorithm = null,
        string? keyId = null) => new(true, payload, protectedHeader, algorithm, keyId);


    /// <summary>
    /// Creates a failed verification result.
    /// </summary>
    /// <param name="protectedHeader">The protected header bytes, if available.</param>
    /// <param name="algorithm">The algorithm identifier, if available.</param>
    /// <param name="keyId">The key identifier, if available.</param>
    /// <returns>A failed verification result.</returns>
    public static CoseVerificationResult Failed(
        ReadOnlyMemory<byte> protectedHeader = default,
        int? algorithm = null,
        string? keyId = null) => new(false, default, protectedHeader, algorithm, keyId);
}