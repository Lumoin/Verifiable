using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The result of validating an OID4VCI 1.0 <c>jwt</c> key proof (Appendix F.1 / F.4). On
/// success it carries the RFC 7638 thumbprint of the holder key the proof bound to — the key
/// the issued Credential MUST be bound to — and the validated <c>aud</c>/<c>iat</c>/<c>nonce</c>;
/// on failure it carries the single <see cref="CredentialProofValidationFailureReason"/> the
/// Credential Endpoint maps to a §8.3.1.2 error.
/// </summary>
[DebuggerDisplay("CredentialProofValidationResult Success={IsSuccess} Reason={FailureReason}")]
public sealed record CredentialProofValidationResult
{
    /// <summary>
    /// The base64url-encoded RFC 7638 thumbprint of the holder key the proof bound to, when
    /// validation succeeded. The Credential Issuer binds the issued Credential to this key.
    /// <see langword="null"/> on failure.
    /// </summary>
    public string? BoundKeyThumbprint { get; init; }

    /// <summary>The validated <c>aud</c> claim (the Credential Issuer Identifier) on success; otherwise <see langword="null"/>.</summary>
    public string? Audience { get; init; }

    /// <summary>The validated <c>iat</c> claim on success; otherwise <see langword="null"/>.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>The validated <c>nonce</c> (the echoed <c>c_nonce</c>) on success when one was required; otherwise <see langword="null"/>.</summary>
    public string? Nonce { get; init; }

    /// <summary>The failure reason if the proof was rejected. <see langword="null"/> on success.</summary>
    public CredentialProofValidationFailureReason? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the proof is valid.</summary>
    public bool IsValid => FailureReason is null;

    /// <summary>Builds a success result.</summary>
    public static CredentialProofValidationResult Success(
        string boundKeyThumbprint, string audience, DateTimeOffset issuedAt, string? nonce) =>
        new()
        {
            BoundKeyThumbprint = boundKeyThumbprint,
            Audience = audience,
            IssuedAt = issuedAt,
            Nonce = nonce
        };

    /// <summary>Builds a failure result.</summary>
    public static CredentialProofValidationResult Failure(CredentialProofValidationFailureReason reason) =>
        new() { FailureReason = reason };
}
