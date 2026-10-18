using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// Outcome of <see cref="Oidc10IdTokenValidator.ValidateAsync"/>. Carries either the extracted
/// <see cref="Oidc10IdTokenClaims"/> on success, or a typed
/// <see cref="JwsAccessTokenValidationFailureReason"/> with an optional human-readable description
/// on failure.
/// </summary>
/// <remarks>
/// Mirrors the success/failure shape of <see cref="JwsAccessTokenValidationResult"/> — the
/// RFC 9068 access-token counterpart — while carrying <see cref="Oidc10IdTokenClaims"/> instead of
/// <see cref="JwsAccessTokenClaims"/>, since an ID Token and an access token surface different
/// optional claims even though both validators share the same underlying signed-JWT validation core
/// and the same closed failure-reason vocabulary.
/// </remarks>
[DebuggerDisplay("Oidc10IdTokenValidationResult Success={IsSuccess} Reason={FailureReason}")]
public sealed record Oidc10IdTokenValidationResult
{
    /// <summary>The validated claims when validation succeeded; otherwise <see langword="null"/>.</summary>
    public Oidc10IdTokenClaims? Claims { get; init; }

    /// <summary>The failure reason when validation failed; otherwise <see langword="null"/>.</summary>
    public JwsAccessTokenValidationFailureReason? FailureReason { get; init; }

    /// <summary>Optional free-text description, useful for <c>WWW-Authenticate</c> error_description fields.</summary>
    public string? FailureDescription { get; init; }

    /// <summary>
    /// The reading's own refusal of the ID Token's header or payload, with the segment it concerns
    /// (<see cref="JwsPartDocumentRefusal"/>), carried whole beside <see cref="FailureReason"/>, as
    /// <see cref="JwsAccessTokenValidationResult.PartRefusal"/> carries an access token's. <see langword="null"/> on success and
    /// for a failure no reading refused.
    /// </summary>
    public JwsPartRefusal? PartRefusal { get; init; }

    /// <summary><see langword="true"/> when validation succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success result.</summary>
    public static Oidc10IdTokenValidationResult Success(Oidc10IdTokenClaims claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        return new() { Claims = claims };
    }


    /// <summary>Builds a failure result.</summary>
    public static Oidc10IdTokenValidationResult Failure(
        JwsAccessTokenValidationFailureReason reason,
        string? description = null) =>
        new() { FailureReason = reason, FailureDescription = description };


    /// <summary>Builds the failure of an ID Token whose header or payload its reading refused, carrying the reading's refusal.</summary>
    /// <param name="reason">The coarse category the refusal is answered under.</param>
    /// <param name="description">The description of the failure.</param>
    /// <param name="partRefusal">The reading's refusal, with the segment it concerns.</param>
    /// <returns>The failure.</returns>
    public static Oidc10IdTokenValidationResult PartRefused(
        JwsAccessTokenValidationFailureReason reason,
        string? description,
        JwsPartRefusal partRefusal)
    {
        ArgumentNullException.ThrowIfNull(partRefusal);

        return new() { FailureReason = reason, FailureDescription = description, PartRefusal = partRefusal };
    }
}
