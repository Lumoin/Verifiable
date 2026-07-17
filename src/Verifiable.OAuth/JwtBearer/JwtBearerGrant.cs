using System.Diagnostics;

namespace Verifiable.OAuth.JwtBearer;

/// <summary>
/// The token shape an authorization server issues for a validated JWT Bearer authorization-grant
/// assertion per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-2.1">RFC 7523 §2.1</see>. Returned by
/// the application's <see cref="Server.ValidateJwtBearerAssertionDelegate"/> after it has validated
/// the presented <c>assertion</c> JWT against the §3 processing rules, or <see langword="null"/>
/// when the assertion is not acceptable (the grant is then refused with <c>invalid_grant</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.1">RFC 7523 §3.1</see>).
/// </summary>
/// <remarks>
/// <para>
/// The library never validates the assertion JWT itself: which issuers and keys to accept, the
/// signature check (rule 9), the <c>aud</c>-names-this-AS check (rule 3), and the time window (rules
/// 4–5) are the application's concern — it is the trust authority. This record carries only the
/// parameters the issued access token is shaped from once the application has accepted the assertion.
/// </para>
/// <para>
/// <see cref="Subject"/> becomes the issued access token's <c>sub</c> — the principal the assertion's
/// own <c>sub</c> (rule 2.A) authorizes access for. <see cref="Scope"/> is the granted scope echoed
/// in the §5.1 token response. <see cref="Audience"/>, when non-empty, confines the issued access
/// token to the named target(s) (its <c>aud</c> claim), bypassing the registration's scope→audience
/// resolver; an empty list leaves the resolver to shape the audience.
/// </para>
/// </remarks>
[DebuggerDisplay("JwtBearerGrant Subject={Subject}, Scope={Scope}")]
public sealed record JwtBearerGrant
{
    /// <summary>
    /// The subject (<c>sub</c>) of the issued access token — the principal the assertion's <c>sub</c>
    /// claim (RFC 7523 §3 rule 2.A) authorizes access for. Becomes the issued token's <c>sub</c>.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The granted scope echoed in the RFC 6749 §5.1 token response. The application decides the
    /// effective scope from the assertion and its own policy (RFC 7523 §2.1 / RFC 7521 §4.1).
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The target audience(s) that confine the issued access token (its <c>aud</c> claim). When
    /// non-empty the value becomes the access token's audience verbatim, bypassing the scope→audience
    /// resolver; MAY be empty, in which case the resolver shapes the audience.
    /// </summary>
    public IReadOnlyList<string> Audience { get; init; } = [];

    /// <summary>
    /// The granted RFC 9396 authorization details embedded as the issued access token's
    /// <c>authorization_details</c> claim, or <see langword="null"/> to emit no claim. Each element is
    /// the object form of one authorization detail (a dictionary of <c>type</c> and its fields). For
    /// an ID-JAG redemption these are the details the Resource Authorization Server granted after
    /// processing the grant's <c>authorization_details</c> per
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.4.1; the same structured value the RFC 9068
    /// access-token producer reads from <see cref="Server.ExchangeContextServerExtensions.GrantedAuthorizationDetailsClaim"/>.
    /// </summary>
    public IReadOnlyList<object>? AuthorizationDetailsClaim { get; init; }

    /// <summary>
    /// The granted authorization details as a JSON array string echoed in the §4.4.2 token response
    /// (RFC 9396 §2.2 response format), or <see langword="null"/> to omit the field. Pre-serialised so
    /// the library emits it verbatim and never serialises JSON itself.
    /// </summary>
    public string? AuthorizationDetailsResponseJson { get; init; }

    /// <summary>
    /// The JWK SHA-256 thumbprint the grant is bound to — the redeemed ID-JAG's <c>cnf.jkt</c> claim —
    /// or <see langword="null"/> when the grant is not key-bound. When non-null the redeem MUST be
    /// accompanied by a DPoP proof whose key thumbprint equals this value, and the issued access token
    /// is bound to it (draft-ietf-oauth-identity-assertion-authz-grant-04 §9.8.1.2.1/§9.8.1.2.2); the
    /// jwt-bearer endpoint runs the §9.8.1.2 matrix over this and the presented proof. Sourced from
    /// <see cref="IdJag.IdJagAssertionValidationResult.ConfirmationKeyThumbprint"/>.
    /// </summary>
    public string? RequiredKeyThumbprint { get; init; }

    /// <summary>
    /// Whether the Resource Server requires sender-constrained access tokens for this redemption
    /// (§9.8.1.2.4). When <see langword="true"/> and the grant is not key-bound and no DPoP proof is
    /// presented, the request is rejected with <c>invalid_grant</c> rather than issuing a Bearer token.
    /// </summary>
    public bool RequiresSenderConstrainedToken { get; init; }

    /// <summary>
    /// The validated assertion's <c>iss</c> (the IdP that issued an ID-JAG), or <see langword="null"/>
    /// when the seam does not supply it. With <see cref="Jti"/> and <see cref="Expiration"/> it lets the
    /// jwt-bearer endpoint apply the shared RFC 7523 §3 (rule 7) replay defense
    /// (<see cref="Server.JtiReplayGuard"/>) on the same <c>(issuer, jti)</c> store the JAR and DPoP
    /// paths use; keying on the assertion's own issuer isolates independent IdPs so they never collide.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// The validated assertion's <c>jti</c> (RFC 7519 §4.1.7; REQUIRED on an ID-JAG per §3.1), or
    /// <see langword="null"/>. When the seam supplies it together with <see cref="Issuer"/> and
    /// <see cref="Expiration"/>, the jwt-bearer endpoint consults <see cref="Server.JtiReplayGuard"/> and
    /// refuses a replayed assertion with <c>invalid_grant</c> (governed by
    /// <see cref="Server.JtiReplayPolicy"/>); a <see langword="null"/> value skips the check.
    /// </summary>
    public string? Jti { get; init; }

    /// <summary>
    /// The validated assertion's <c>exp</c> — the replay-store entry's expiry window — or
    /// <see langword="null"/>. Supplied with <see cref="Jti"/> so the recorded <c>jti</c> expires no
    /// later than the assertion it guards.
    /// </summary>
    public DateTimeOffset? Expiration { get; init; }
}
