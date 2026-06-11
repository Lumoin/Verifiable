using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The decoded body of an OID4VCI 1.0 Appendix D.1 key attestation (<c>key-attestation+jwt</c>),
/// as read by <see cref="KeyAttestationParser"/>. Array-valued members are surfaced as their
/// VERBATIM JSON text (the serialization firewall keeps <c>System.Text.Json</c> out of the
/// library); the application parses <see cref="AttestedKeysJson"/> into JWKs with its own JSON
/// layer and verifies the attestation's signature and trust against its Wallet-Provider anchors.
/// </summary>
[DebuggerDisplay("KeyAttestation Nonce={Nonce} ExpiresAt={ExpiresAt}")]
public sealed record KeyAttestation
{
    /// <summary>
    /// The verbatim <c>attested_keys</c> JSON array (REQUIRED) — a non-empty array of attested
    /// public keys in JWK syntax, exactly as signed.
    /// </summary>
    public required string AttestedKeysJson { get; init; }

    /// <summary>The verbatim <c>key_storage</c> JSON array, or <see langword="null"/> when absent.</summary>
    public string? KeyStorageJson { get; init; }

    /// <summary>The verbatim <c>user_authentication</c> JSON array, or <see langword="null"/> when absent.</summary>
    public string? UserAuthenticationJson { get; init; }

    /// <summary>The <c>nonce</c> the Issuer provided to prove freshness, or <see langword="null"/> when absent.</summary>
    public string? Nonce { get; init; }

    /// <summary>The <c>certification</c> URL of the key storage component, or <see langword="null"/> when absent.</summary>
    public string? Certification { get; init; }

    /// <summary>The <c>iat</c> the attestation was issued at, or <see langword="null"/> when unreadable.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>The <c>exp</c> the attestation (and its keys) expire at, or <see langword="null"/> when absent.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }
}
