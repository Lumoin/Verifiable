using System.Collections.Generic;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Result of verifying a JWS-secured Verifiable Credential.
/// </summary>
/// <param name="IsValid">Whether the signature is valid.</param>
/// <param name="Header">The decoded JWT header.</param>
/// <param name="Credential">
/// The verified credential, or <see langword="null"/> when verification failed. A non-null value
/// is a <see cref="Verified{T}"/> minted by the verify path, so it cannot be a credential that was
/// merely deserialized without its signature being checked.
/// </param>
public readonly record struct JwsCredentialVerificationResult(
    bool IsValid,
    Dictionary<string, object>? Header,
    Verified<VerifiableCredential>? Credential);
