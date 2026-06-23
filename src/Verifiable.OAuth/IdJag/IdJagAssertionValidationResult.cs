using System.Diagnostics;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The outcome of validating an Identity Assertion JWT Authorization Grant (ID-JAG) assertion against
/// the draft-ietf-oauth-identity-assertion-authz-grant §4.4.1 / §9.3 claim rules via
/// <see cref="IdJagAssertionValidation.Validate"/>. A success carries the claims a Resource
/// Authorization Server shapes its access token from; a failure carries the
/// <see cref="IdJagValidationFailureReason"/> the caller maps to <c>invalid_grant</c>.
/// </summary>
/// <remarks>
/// The crypto layer (signature verification, key resolution) is the caller's concern — the result
/// describes only the claim-rule outcome over an already signature-verified, decoded assertion. The
/// caller wires this into its <see cref="Server.ValidateJwtBearerAssertionDelegate"/> and, on success,
/// builds a <see cref="JwtBearer.JwtBearerGrant"/> from <see cref="Subject"/> and <see cref="Scope"/>.
/// </remarks>
[DebuggerDisplay("IdJagAssertionValidationResult IsValid={IsValid} Reason={FailureReason}")]
public sealed record IdJagAssertionValidationResult
{
    /// <summary>Whether the assertion satisfied every claim rule.</summary>
    public bool IsValid => FailureReason is null;

    /// <summary>The reason validation failed, or <see langword="null"/> on success.</summary>
    public IdJagValidationFailureReason? FailureReason { get; init; }

    /// <summary>A human-readable description of the failure, or <see langword="null"/> on success.</summary>
    public string? FailureDescription { get; init; }

    /// <summary>
    /// The <c>sub</c> claim — the End-User the access token is issued for. Present on success.
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>The <c>iss</c> claim — the IdP Authorization Server that issued the grant.</summary>
    public string? Issuer { get; init; }

    /// <summary>The validated <c>aud</c> claim value(s).</summary>
    public IReadOnlyList<string> Audience { get; init; } = [];

    /// <summary>
    /// The <c>tenant</c> claim — the IdP (issuer) tenant for a multi-tenant issuer, when present
    /// (draft-ietf-oauth-identity-assertion-authz-grant §3.1 / §6). Surfaced for the Resource
    /// Authorization Server's subject-identifier scoping (<c>iss + tenant + sub</c>);
    /// <see langword="null"/> for a single-tenant issuer.
    /// </summary>
    public string? Tenant { get; init; }

    /// <summary>
    /// The <c>aud_tenant</c> claim — the Resource Authorization Server tenant the grant is scoped to,
    /// when present (§3.1). When non-null, <see cref="AudienceSubject"/> identifies the account within
    /// that tenant; the Resource Authorization Server treats <c>aud + aud_tenant + aud_sub</c> as unique.
    /// </summary>
    public string? AudienceTenant { get; init; }

    /// <summary>
    /// The <c>aud_sub</c> claim — the Resource Authorization Server's own identifier for the End-User,
    /// when present (§3.1). The Resource Authorization Server MAY use it for subject resolution
    /// (including JIT provisioning); <see langword="null"/> when the grant carries no <c>aud_sub</c>.
    /// </summary>
    public string? AudienceSubject { get; init; }

    /// <summary>
    /// The <c>sub_id</c> claim parsed as a SAML NameID Subject Identifier (§3.2), when the grant carries
    /// a well-formed one; otherwise <see langword="null"/> (absent, not an object, a different Subject
    /// Identifier Format, or missing a REQUIRED member). Surfaced for the Resource Authorization Server's
    /// §3.2.2 subject resolution; per §9.5 its <see cref="SamlNameIdSubjectIdentifier.Issuer"/> MUST NOT
    /// be used to establish trust in the ID-JAG issuer (the grant is validated by its own <c>iss</c>).
    /// </summary>
    public SamlNameIdSubjectIdentifier? SubjectIdentifier { get; init; }

    /// <summary>
    /// The <c>resource</c> claim value(s) (RFC 8707) carried by the grant, when present — the
    /// Resource Server target(s) the Resource Authorization Server processes per §4.4.1. Empty when
    /// the grant carries no <c>resource</c> claim.
    /// </summary>
    public IReadOnlyList<string> Resource { get; init; } = [];

    /// <summary>
    /// The decoded <c>authorization_details</c> claim (a JSON array of authorization detail objects)
    /// carried by the grant, when present — the RFC 9396 structured authorization the Resource
    /// Authorization Server processes per §4.4.1 to decide what to grant in the access token.
    /// <see langword="null"/> when the grant carries no <c>authorization_details</c> claim.
    /// </summary>
    public IReadOnlyList<object>? AuthorizationDetails { get; init; }

    /// <summary>The <c>client_id</c> claim — equal to the authenticated client on success.</summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// The JWK SHA-256 thumbprint from the grant's <c>cnf.jkt</c> claim (RFC 7800 / RFC 9449), when
    /// present — the key the redeem MUST demonstrate proof of possession of per §9.8.1. Drives the
    /// §9.8.1.2 matrix via <see cref="JwtBearer.JwtBearerGrant.RequiredKeyThumbprint"/>;
    /// <see langword="null"/> when the grant carries no <c>cnf</c> claim (the grant is not key-bound).
    /// </summary>
    public string? ConfirmationKeyThumbprint { get; init; }

    /// <summary>The <c>scope</c> claim, when present.</summary>
    public string? Scope { get; init; }

    /// <summary>The <c>iat</c> claim, when present.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>The <c>exp</c> claim.</summary>
    public DateTimeOffset? Expiration { get; init; }

    /// <summary>
    /// The <c>jti</c> claim — the grant's unique identifier (§3.1 REQUIRED on the issued ID-JAG;
    /// RFC 7519 §4.1.7), when present; otherwise <see langword="null"/>. Surfaced so a Resource
    /// Authorization Server can apply the RFC 7523 §3 (rule 7) replay defense — recording redeemed
    /// <c>jti</c> values in its own store and refusing reuse — which the library leaves app-side because
    /// it holds no token store. This is not a §4.4.1 validation MUST, so a grant without <c>jti</c> still
    /// validates here; an app requiring replay protection refuses an absent or already-seen <c>jti</c> in
    /// its <see cref="Server.ValidateJwtBearerAssertionDelegate"/>.
    /// </summary>
    public string? Jti { get; init; }


    /// <summary>
    /// Builds a failed result with the given <paramref name="reason"/> and optional
    /// <paramref name="description"/>.
    /// </summary>
    /// <param name="reason">The failure reason.</param>
    /// <param name="description">An optional human-readable description.</param>
    /// <returns>A failed <see cref="IdJagAssertionValidationResult"/>.</returns>
    public static IdJagAssertionValidationResult Failure(
        IdJagValidationFailureReason reason,
        string? description = null) =>
        new()
        {
            FailureReason = reason,
            FailureDescription = description
        };
}
