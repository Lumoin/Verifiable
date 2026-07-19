using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Typed view of the claims extracted from a successfully-validated OpenID Connect Core 1.0 ID
/// Token per OIDC Core §3.1.3.7. Returned in <see cref="Oidc10IdTokenValidationResult.Claims"/> on
/// success; the relying party reads these instead of re-parsing the JWT payload directly.
/// </summary>
/// <remarks>
/// Mirrors <see cref="JwsAccessTokenClaims"/>'s standard signed-JWT members (<c>sub</c>/<c>iss</c>/
/// <c>aud</c>/<c>azp</c>/<c>iat</c>/<c>exp</c>/<c>nbf</c>), replacing the access-token-specific
/// <c>client_id</c>/<c>scope</c>/<c>jti</c> with the ID-Token-specific OIDC Core §2 authentication
/// claims: <c>nonce</c>, <c>auth_time</c>, <c>acr</c>, <c>amr</c>, <c>sid</c>. Absent optional claims
/// are surfaced as <see langword="null"/>. <see cref="Nonce"/>, <see cref="AuthTime"/>,
/// <see cref="Acr"/>, and <see cref="Sid"/> are surfaced regardless of whether
/// <see cref="Oidc10IdTokenValidator.ValidateAsync"/> was asked to enforce them, so a caller that
/// requested <c>acr_values</c>/<c>max_age</c> can itself compare <see cref="Acr"/>/<see cref="AuthTime"/>
/// against the request (the OIDC Core §3.1.3.7 SHOULDs the validator does not enforce).
/// </remarks>
[DebuggerDisplay("Oidc10IdTokenClaims Sub={Subject,nq} Iss={Issuer,nq}")]
public sealed record Oidc10IdTokenClaims
{
    /// <summary>RFC 7519 §4.1.2 <c>sub</c> — the End-User identifier.</summary>
    public required string Subject { get; init; }

    /// <summary>RFC 7519 §4.1.1 <c>iss</c> — the issuer identifier. Compared by ordinal equality.</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// RFC 7519 §4.1.3 <c>aud</c> — the audience values. OIDC Core §2 permits either a single
    /// string or an array; the validator normalises both shapes into this list.
    /// </summary>
    public required IReadOnlyList<string> Audience { get; init; }

    /// <summary>RFC 7519 §4.1.6 <c>iat</c> — issuance instant.</summary>
    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>RFC 7519 §4.1.4 <c>exp</c> — expiry instant.</summary>
    public required DateTimeOffset Expiration { get; init; }

    /// <summary>RFC 7519 §4.1.5 <c>nbf</c> — not-before instant. <see langword="null"/> when absent.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>
    /// OIDC Core §2 <c>azp</c> — the authorized party the ID Token was issued to.
    /// <see langword="null"/> when absent. When present it must equal the relying party's own
    /// client identifier (OIDC Core §3.1.3.7); the validator enforces that when the caller supplies
    /// an expected authorized party.
    /// </summary>
    public string? AuthorizedParty { get; init; }

    /// <summary>
    /// OIDC Core §2 <c>nonce</c> — the value that binds this ID Token to the authentication request
    /// that produced it, mitigating replay. <see langword="null"/> when absent. When the caller
    /// supplied an expected nonce to <see cref="Oidc10IdTokenValidator.ValidateAsync"/>, this equals
    /// it (OIDC Core §3.1.3.7's conditional-MUST); otherwise it is surfaced unchecked.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// OIDC Core §2 <c>auth_time</c> — the instant the End-User authentication occurred.
    /// <see langword="null"/> when absent.
    /// </summary>
    public DateTimeOffset? AuthTime { get; init; }

    /// <summary>
    /// OIDC Core §2 <c>acr</c> — the Authentication Context Class Reference. <see langword="null"/>
    /// when absent.
    /// </summary>
    public string? Acr { get; init; }

    /// <summary>
    /// OIDC Core §2 <c>amr</c> — the Authentication Methods References. <see langword="null"/> when
    /// absent.
    /// </summary>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>
    /// OIDC Core / OIDC Back-Channel Logout §2 <c>sid</c> — the End-User's authentication session
    /// identifier at the OP. <see langword="null"/> when absent.
    /// </summary>
    public string? Sid { get; init; }

    /// <summary>
    /// RFC 7800 §3 <c>cnf</c> — the confirmation method binding the token to a proof of possession
    /// key. <see langword="null"/> when the token is not sender-constrained.
    /// </summary>
    public ConfirmationMethod? Confirmation { get; init; }
}
