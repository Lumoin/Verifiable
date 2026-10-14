using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The result of validating a DPoP proof.
/// </summary>
[DebuggerDisplay("DpopProofValidationResult Success={IsSuccess} Reason={FailureReason}")]
public sealed record DpopProofValidationResult
{
    /// <summary>The validated claims if the proof is valid; otherwise <see langword="null"/>.</summary>
    public DpopProofClaims? Claims { get; init; }

    /// <summary>
    /// The base64url-encoded RFC 7638 thumbprint of the proof's embedded
    /// JWK, if validation succeeded. This is the value the receiver
    /// compares against an access token's <c>cnf.jkt</c> binding.
    /// </summary>
    /// <remarks>
    /// Set on every success to the base64url JWK SHA-256 Thumbprint of the proof's public key, the
    /// value of the <c>jkt</c> member
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>:
    /// "The value of the jkt member MUST be the base64url encoding (as defined in [RFC7515]) of the
    /// JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key";
    /// <see href="https://www.rfc-editor.org/rfc/rfc7638#section-3">RFC 7638 Section 3</see>): a
    /// validated proof names the public key a code or a token is bound to
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>:
    /// "It MUST further behave as if the contained public key's thumbprint was provided using
    /// dpop_jkt"). An application's <see cref="ValidateDpopProofDelegate"/> that answers success
    /// otherwise (no value, the empty string, or text of another spelling) breaks that promise; the
    /// authorization server answers such a request <c>server_error</c>, never an unbound or a
    /// misbound issuance.
    /// </remarks>
    public string? JwkThumbprint { get; init; }

    /// <summary>
    /// The failure reason if the proof was rejected. <see langword="null"/>
    /// on success.
    /// </summary>
    public DpopProofValidationFailureReason? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the proof is valid.</summary>
    public bool IsSuccess => FailureReason is null;

    /// <summary>Builds a success result.</summary>
    public static DpopProofValidationResult Success(DpopProofClaims claims, string jwkThumbprint) =>
        new() { Claims = claims, JwkThumbprint = jwkThumbprint };

    /// <summary>Builds a failure result.</summary>
    public static DpopProofValidationResult Failure(DpopProofValidationFailureReason reason) =>
        new() { FailureReason = reason };
}
