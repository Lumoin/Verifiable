using System.Diagnostics;

namespace Verifiable.OAuth.Dpop;

/// <summary>
/// The result of validating a DPoP proof.
/// </summary>
[DebuggerDisplay("DpopValidationResult Success={IsSuccess} Reason={FailureReason}")]
public sealed record DpopValidationResult
{
    /// <summary>The validated claims if the proof is valid; otherwise <see langword="null"/>.</summary>
    public DpopProofClaims? Claims { get; init; }

    /// <summary>
    /// The base64url-encoded RFC 7638 thumbprint of the proof's embedded
    /// JWK, if validation succeeded. This is the value the receiver
    /// compares against an access token's <c>cnf.jkt</c> binding.
    /// </summary>
    public string? JwkThumbprint { get; init; }

    /// <summary>
    /// The failure reason if the proof was rejected. <see langword="null"/>
    /// on success.
    /// </summary>
    public DpopValidationFailureReason? FailureReason { get; init; }

    /// <summary><see langword="true"/> when the proof is valid.</summary>
    public bool IsSuccess => FailureReason is null;

    /// <summary>Builds a success result.</summary>
    public static DpopValidationResult Success(DpopProofClaims claims, string jwkThumbprint) =>
        new() { Claims = claims, JwkThumbprint = jwkThumbprint };

    /// <summary>Builds a failure result.</summary>
    public static DpopValidationResult Failure(DpopValidationFailureReason reason) =>
        new() { FailureReason = reason };
}
