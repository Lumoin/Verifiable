using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// The neutral outcome of <see cref="JwsAccessTokenValidator.ValidateSignedJwtCoreAsync"/> — the
/// shared parse / signature / <c>iss</c> / <c>aud</c> / <c>azp</c> / <c>exp</c> / <c>iat</c> /
/// <c>nbf</c> / <c>sub</c> validation core behind both <see cref="JwsAccessTokenValidator.ValidateAsync"/>
/// and <see cref="Oidc10IdTokenValidator.ValidateAsync"/>.
/// </summary>
/// <remarks>
/// Each caller maps this into its own profile-specific result and claims type
/// (<see cref="JwsAccessTokenValidationResult"/> / <see cref="JwsAccessTokenClaims"/> for the RFC 9068
/// access-token profile, <see cref="Oidc10IdTokenValidationResult"/> / <see cref="Oidc10IdTokenClaims"/>
/// for the OIDC Core §3.1.3.7 ID Token profile), reading any profile-specific optional claims
/// (<c>client_id</c>/<c>scope</c>/<c>jti</c> for the access-token profile; <c>nonce</c>/<c>auth_time</c>/
/// <c>acr</c>/<c>amr</c>/<c>sid</c> for the ID Token profile) from <see cref="Payload"/>. On success every
/// member except <see cref="NotBefore"/> is populated; on failure only <see cref="FailureReason"/> and
/// <see cref="FailureDescription"/> are.
/// </remarks>
[DebuggerDisplay("SignedJwtValidationOutcome Success={IsSuccess} Reason={FailureReason}")]
internal sealed record SignedJwtValidationOutcome
{
    /// <summary>The verified payload when validation succeeded; otherwise <see langword="null"/>.</summary>
    public JwtPayload? Payload { get; init; }

    /// <summary>The <c>sub</c> claim when validation succeeded; otherwise <see langword="null"/>.</summary>
    public string? Subject { get; init; }

    /// <summary>The <c>iss</c> claim when validation succeeded; otherwise <see langword="null"/>.</summary>
    public string? Issuer { get; init; }

    /// <summary>The normalised <c>aud</c> claim when validation succeeded; otherwise <see langword="null"/>.</summary>
    public IReadOnlyList<string>? Audience { get; init; }

    /// <summary>
    /// The <c>azp</c> claim when validation succeeded and the claim was present; <see langword="null"/>
    /// when validation succeeded but no <c>azp</c> was carried, or when validation failed.
    /// </summary>
    public string? AuthorizedParty { get; init; }

    /// <summary>The <c>iat</c> claim as written when validation succeeded; otherwise <see langword="null"/>.</summary>
    public NumericDate? IssuedAt { get; init; }

    /// <summary>The <c>exp</c> claim as written when validation succeeded; otherwise <see langword="null"/>.</summary>
    public NumericDate? Expiration { get; init; }

    /// <summary>The <c>nbf</c> claim as written when validation succeeded and present; otherwise <see langword="null"/>.</summary>
    public NumericDate? NotBefore { get; init; }

    /// <summary>The failure reason when validation failed; otherwise <see langword="null"/>.</summary>
    public JwsAccessTokenValidationFailureReason? FailureReason { get; init; }

    /// <summary>Optional free-text description of the failure.</summary>
    public string? FailureDescription { get; init; }

    /// <summary>
    /// The reading's own refusal of the token's header or payload (<see cref="JwtPartRefused{TPart}"/>), with the segment it
    /// concerns, carried whole beside <see cref="FailureReason"/>; <see langword="null"/> on success and for a failure no reading
    /// refused.
    /// </summary>
    public JwsPartRefusal? PartRefusal { get; init; }

    /// <summary><see langword="true"/> when validation succeeded.</summary>
    public bool IsSuccess => FailureReason is null;


    /// <summary>Builds a success outcome.</summary>
    public static SignedJwtValidationOutcome Success(
        JwtPayload payload,
        string subject,
        string issuer,
        IReadOnlyList<string> audience,
        string? authorizedParty,
        NumericDate issuedAt,
        NumericDate expiration,
        NumericDate? notBefore)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(audience);

        return new()
        {
            Payload = payload,
            Subject = subject,
            Issuer = issuer,
            Audience = audience,
            AuthorizedParty = authorizedParty,
            IssuedAt = issuedAt,
            Expiration = expiration,
            NotBefore = notBefore
        };
    }


    /// <summary>Builds a failure outcome.</summary>
    public static SignedJwtValidationOutcome Failure(
        JwsAccessTokenValidationFailureReason reason,
        string? description = null) =>
        new() { FailureReason = reason, FailureDescription = description };


    /// <summary>Builds the failure of a token whose header or payload its reading refused, carrying the reading's refusal.</summary>
    /// <param name="reason">The coarse category the refusal is answered under.</param>
    /// <param name="description">The description of the failure.</param>
    /// <param name="partRefusal">The reading's refusal, with the segment it concerns.</param>
    /// <returns>The failure.</returns>
    public static SignedJwtValidationOutcome PartRefused(
        JwsAccessTokenValidationFailureReason reason,
        string description,
        JwsPartRefusal partRefusal)
    {
        ArgumentNullException.ThrowIfNull(partRefusal);

        return new() { FailureReason = reason, FailureDescription = description, PartRefusal = partRefusal };
    }
}
