using System.Collections.Generic;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Result of verifying a JWS-secured Verifiable Credential.
/// </summary>
/// <param name="IsValid">Whether the signature is valid.</param>
/// <param name="Header">The decoded JWT header.</param>
/// <param name="Credential">The decoded credential.</param>
public readonly record struct JwsCredentialVerificationResult(
    bool IsValid,
    Dictionary<string, object>? Header,
    VerifiableCredential? Credential);