using System.Collections.Generic;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Result of verifying a COSE-secured Verifiable Credential.
/// </summary>
/// <param name="IsValid">Whether the signature is valid.</param>
/// <param name="ProtectedHeader">The decoded protected header with integer keys.</param>
/// <param name="Credential">The decoded credential.</param>
/// <param name="Algorithm">The COSE algorithm identifier from the header.</param>
/// <param name="KeyId">The key ID from the header, if present.</param>
public readonly record struct CoseCredentialVerificationResult(
    bool IsValid,
    IReadOnlyDictionary<int, object>? ProtectedHeader,
    VerifiableCredential? Credential,
    int? Algorithm = null,
    string? KeyId = null)
{
    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <param name="protectedHeader">The decoded protected header.</param>
    /// <param name="credential">The decoded credential.</param>
    /// <param name="algorithm">The COSE algorithm identifier.</param>
    /// <param name="keyId">The key ID, if present.</param>
    /// <returns>A successful verification result.</returns>
    public static CoseCredentialVerificationResult Success(
        IReadOnlyDictionary<int, object> protectedHeader,
        VerifiableCredential credential,
        int? algorithm = null,
        string? keyId = null)
    {
        return new CoseCredentialVerificationResult(true, protectedHeader, credential, algorithm, keyId);
    }


    /// <summary>
    /// Creates a failed verification result.
    /// </summary>
    /// <returns>A failed verification result.</returns>
    public static CoseCredentialVerificationResult Failed()
    {
        return new CoseCredentialVerificationResult(false, null, null, null, null);
    }
}