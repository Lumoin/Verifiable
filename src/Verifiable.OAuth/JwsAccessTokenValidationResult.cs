using System.Diagnostics;
using Verifiable.JCose;

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

    /// <summary>
    /// The reading's own refusal of the token's header or payload, with the segment it concerns
    /// (<see cref="JwsPartDocumentRefusal"/>), carried whole beside <see cref="FailureReason"/>, so a resource server records the
    /// reason without reading the token again; the shape <see cref="Verifiable.OAuth.Dpop.DpopProofValidationResult.PartRefusal"/>
    /// carries a DPoP proof's in. <see langword="null"/> on success and for a failure no reading refused.
    /// </summary>
    public JwsPartRefusal? PartRefusal { get; init; }

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


    /// <summary>Builds the failure of a token whose header or payload its reading refused, carrying the reading's refusal.</summary>
    /// <param name="reason">The coarse category the refusal is answered under.</param>
    /// <param name="description">The description of the failure.</param>
    /// <param name="partRefusal">The reading's refusal, with the segment it concerns.</param>
    /// <returns>The failure.</returns>
    public static JwsAccessTokenValidationResult PartRefused(
        JwsAccessTokenValidationFailureReason reason,
        string? description,
        JwsPartRefusal partRefusal)
    {
        ArgumentNullException.ThrowIfNull(partRefusal);

        return new() { FailureReason = reason, FailureDescription = description, PartRefusal = partRefusal };
    }
}
