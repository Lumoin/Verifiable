using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Outcome of <see cref="JwsAccessTokenValidator.ValidateAsync"/>. Carries
/// either the extracted <see cref="JwsAccessTokenClaims"/> on success, or
/// a typed <see cref="JwsAccessTokenValidationFailureReason"/> with an
/// optional human-readable description on failure.
/// </summary>
/// <remarks>
/// Mirrors the success/failure shape of
/// <see cref="Verifiable.OAuth.Dpop.DpopProofValidationResult"/> from the
/// DPoP validator family — both validators compose at the call site, both
/// return typed outcomes the resource-server handler dispatches on.
/// </remarks>
[DebuggerDisplay("JwsAccessTokenValidationResult Success={IsSuccess} Reason={FailureReason}")]
public sealed record JwsAccessTokenValidationResult
{
    /// <summary>The validated claims when validation succeeded; otherwise <see langword="null"/>.</summary>
    public JwsAccessTokenClaims? Claims { get; init; }

    /// <summary>The failure reason when validation failed; otherwise <see langword="null"/>.</summary>
    public JwsAccessTokenValidationFailureReason? FailureReason { get; init; }

    /// <summary>Optional free-text description, useful for <c>WWW-Authenticate</c> error_description fields.</summary>
    public string? FailureDescription { get; init; }

    /// <summary><see langword="true"/> when validation succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result.</summary>
    public static JwsAccessTokenValidationResult Success(JwsAccessTokenClaims claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        return new() { Claims = claims };
    }


    /// <summary>Builds a failure result.</summary>
    public static JwsAccessTokenValidationResult Failure(
        JwsAccessTokenValidationFailureReason reason,
        string? description = null) =>
        new() { FailureReason = reason, FailureDescription = description };
}
