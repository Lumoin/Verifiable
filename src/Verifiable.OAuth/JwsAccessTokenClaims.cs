using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Typed view of the claims extracted from a successfully-validated
/// JWS-signed access token per RFC 7519 and RFC 9068. Returned in
/// <see cref="JwsAccessTokenValidationResult.Claims"/> on success; the
/// resource server reads these instead of re-parsing the JWT payload
/// directly.
/// </summary>
/// <remarks>
/// Absent optional claims are surfaced as <see langword="null"/>. The
/// validator populates <see cref="Confirmation"/> from the <c>cnf</c>
/// claim per RFC 7800 §3 / RFC 9449 §6.1; consumers compare its
/// <see cref="ConfirmationMethod.JwkThumbprint"/> against the proof
/// thumbprint returned by
/// <see cref="Verifiable.OAuth.Dpop.DpopProofValidator.ValidateAsync"/>
/// to enforce DPoP binding.
/// </remarks>
[DebuggerDisplay("JwsAccessTokenClaims Sub={Subject,nq} Iss={Issuer,nq}")]
public sealed record JwsAccessTokenClaims
{
    /// <summary>RFC 7519 §4.1.2 <c>sub</c> — the subject identifier.</summary>
    public required string Subject { get; init; }

    /// <summary>RFC 7519 §4.1.1 <c>iss</c> — the issuer identifier. Compared by ordinal equality.</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// RFC 7519 §4.1.3 <c>aud</c> — the audience values. RFC 9068 §4 permits
    /// either a single string or array; the validator normalises both shapes
    /// into this list.
    /// </summary>
    public required IReadOnlyList<string> Audience { get; init; }

    /// <summary>RFC 7519 §4.1.6 <c>iat</c> — issuance instant.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>RFC 7519 §4.1.4 <c>exp</c> — expiry instant.</summary>
    public required DateTimeOffset Expiration { get; init; }

    /// <summary>RFC 7519 §4.1.5 <c>nbf</c> — not-before instant. <see langword="null"/> when absent.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>RFC 9068 §2.2 <c>client_id</c> — the client identifier.</summary>
    public string? ClientId { get; init; }

    /// <summary>RFC 9068 §2.2 <c>scope</c> — space-separated granted scopes.</summary>
    public string? Scope { get; init; }

    /// <summary>RFC 7519 §4.1.7 <c>jti</c> — the token's unique identifier.</summary>
    public string? JwtId { get; init; }

    /// <summary>
    /// RFC 7800 §3 <c>cnf</c> — the confirmation method binding the token to
    /// a proof of possession key. <see langword="null"/> when the token is
    /// not sender-constrained.
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }
}
