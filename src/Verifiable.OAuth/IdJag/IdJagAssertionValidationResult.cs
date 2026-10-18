using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The outcome of validating an Identity Assertion JWT Authorization Grant (ID-JAG) assertion against
/// the draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.4.1 / §9.3 claim rules via
/// <see cref="IdJagAssertionValidation.Validate"/> or <see cref="IdJagAssertionValidation.ValidateAsync"/>. A
/// success carries the claims a Resource
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
    /// (draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1 / §6). Surfaced for the Resource
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
    /// The <c>sub_id</c> claim as read: a JSON object whose <c>format</c> member names a format, a string that
    /// is not blank (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>;
    /// <see cref="Verifiable.Core.SecurityEvents.SubjectIdentifier.IsWellFormed"/>), whose members
    /// hold the rules of its format when the format is one the library knows
    /// (<see cref="Verifiable.Core.SecurityEvents.SubjectIdentifierFormats.IsKnown"/>,
    /// <see cref="Verifiable.Core.SecurityEvents.SubjectIdentifier.IsValidForKnownFormat"/>), or of a format the
    /// library does not know, carried opaque. <see langword="null"/> when the claim is absent, is not such an
    /// object, or names a known format whose rules it breaks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Surfaced for the Resource Authorization Server's subject resolution
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>).
    /// The claim is judged only under an <see cref="IdJagSubjectIdentifierRule"/> that requires or compares it;
    /// <see cref="SubjectIdentifierComparison"/> records that judgement.
    /// </para>
    /// <para>
    /// Under <see cref="IdJagSubjectIdentifierRule.Default"/> the claim is surfaced and judged by nothing, and
    /// <see cref="SubjectIdentifierComparison"/> is <see langword="null"/>. An application that resolves a
    /// subject by it takes on what the texts ask of the party that does: the same End-User as <see cref="Subject"/>
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>),
    /// the refusals of a server that requires the claim
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>),
    /// the association of the validated issuer with a SAML issuer
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>),
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9493#section-4.1">RFC 9493 Section 4.1</see>: "When
    /// processing a JWT with both JWT "sub" and "sub_id" Claims, implementations MUST NOT rely on both claims to
    /// determine the JWT Subject." Or it validates with a rule that compares the claim.
    /// </para>
    /// </remarks>
    public Verifiable.Core.SecurityEvents.SubjectIdentifier? SubjectIdentifier { get; init; }

    /// <summary>
    /// The <c>sub_id</c> claim read as a SAML NameID Subject Identifier
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>):
    /// the projection of <see cref="SubjectIdentifier"/> through
    /// <see cref="Verifiable.OAuth.IdJag.SamlNameIdSubjectIdentifier.TryFrom"/>; <see langword="null"/> when
    /// <see cref="SubjectIdentifier"/> is <see langword="null"/> or of another format.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">Section 9.5</see>:
    /// "When the ID-JAG includes a sub_id claim, the Resource Authorization Server MUST NOT use the
    /// sub_id.issuer value to establish trust in the ID-JAG issuer." The grant is validated by its own
    /// <c>iss</c>, so <see cref="Verifiable.OAuth.IdJag.SamlNameIdSubjectIdentifier.Issuer"/> is surfaced as data and never as
    /// the grant's issuer.
    /// </remarks>
    public SamlNameIdSubjectIdentifier? SamlNameIdSubjectIdentifier { get; init; }

    /// <summary>
    /// The record of the comparison of <see cref="SubjectIdentifier"/> with the grant's validated subject under
    /// the redeem's <see cref="IdJagSubjectIdentifierRule"/>: the relation, the outcome, whose rule decided it,
    /// the decision, and the two values compared. <see langword="null"/> when nothing was compared: a
    /// <see langword="null"/> record means nothing judged the claim.
    /// </summary>
    /// <remarks>
    /// The record rides a successful result and the two refusals the comparison decides,
    /// <see cref="IdJagValidationFailureReason.SubjectIdentifierMismatch"/> and
    /// <see cref="IdJagValidationFailureReason.SubjectIdentifierUndetermined"/>, so an audit keeps the attempt
    /// whichever way it was decided.
    /// </remarks>
    public Verifiable.Core.Relations.ComparisonRecord<Verifiable.Core.SecurityEvents.SubjectIdentifier, IdJagSubjectContext>? SubjectIdentifierComparison { get; init; }

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

    /// <summary>
    /// The <c>act</c> (actor) claim carried by the grant — the delegation chain recorded on it per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>, the outermost
    /// object naming the current actor and any nested <c>act</c> members the prior actors, least recent
    /// deepest. <see langword="null"/> when the grant records no delegation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Surfaced so a Resource Authorization Server can continue the chain on the access token it issues
    /// (<see cref="JwtBearer.JwtBearerGrant.Act"/> → <see cref="IdJagActorDecision"/>). Carrying the
    /// actor across the redemption is this authorization server's profile decision, exercising the
    /// discretion RFC 8693 §1.1 grants ("When and if a composite token is issued is at the discretion of
    /// the authorization server"): §4.3 / §9.7 of this specification define no <c>actor_token</c>
    /// processing and no rule about an <c>act</c> claim on the grant, and
    /// draft-ietf-oauth-identity-chaining-16 §2.4 — the redemption leg — never mentions <c>act</c>.
    /// </para>
    /// <para>
    /// Per §4.1 the chain is delegation, never impersonation: <see cref="Subject"/> stays the principal
    /// access is requested for while these actors are the parties acting for it. Only the outermost
    /// actor is the current one — "Prior actors identified by any nested <c>act</c> claims are
    /// informational only and are not to be considered in access control decisions."
    /// </para>
    /// </remarks>
    public IReadOnlyDictionary<string, object>? Act { get; init; }

    /// <summary>
    /// The <c>may_act</c> (authorized actor) claim carried by the grant — the party its issuer asserts
    /// is "eligible to act" for <see cref="Subject"/> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>, identified by
    /// a <c>sub</c> optionally combined with an <c>iss</c>. <see langword="null"/> when the grant
    /// constrains the acting party in no way.
    /// </summary>
    /// <remarks>
    /// Surfaced so the redemption can enforce it (<see cref="JwtBearer.JwtBearerGrant.MayAct"/> →
    /// <see cref="IdJagActorDecision"/>): §4.4 states the claim "can be used by the authorization server
    /// to determine whether the client ... is authorized to engage in the requested delegation or
    /// impersonation", which at this leg is the client redeeming the grant. A grant carrying a
    /// <c>may_act</c> that identifies no party is refused by
    /// <see cref="IdJagValidationFailureReason.MalformedAuthorizedActor"/> rather than surfaced as
    /// unconstrained.
    /// </remarks>
    public IReadOnlyDictionary<string, object>? MayAct { get; init; }

    /// <summary>The <c>scope</c> claim, when present.</summary>
    public string? Scope { get; init; }

    /// <summary>The <c>iat</c> claim as written, when present.</summary>
    public NumericDate? IssuedAt { get; init; }

    /// <summary>The <c>exp</c> claim as written.</summary>
    public NumericDate? Expiration { get; init; }

    /// <summary>
    /// The <c>jti</c> claim, the grant's unique identifier (REQUIRED on the ID-JAG by
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 Section 4.1.7</see>), when
    /// present; otherwise <see langword="null"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Surfaced so a Resource Authorization Server's <see cref="Server.ValidateJwtBearerAssertionDelegate"/> can
    /// carry it onto <see cref="JwtBearer.JwtBearerGrant.Jti"/>. The token endpoint's jwt-bearer grant applies
    /// the replay defense of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> (rule 7) through
    /// <see cref="Server.JtiReplayGuard.ConsultAsync"/> only when the grant the delegate returns carries
    /// <see cref="JwtBearer.JwtBearerGrant.Jti"/>, <see cref="JwtBearer.JwtBearerGrant.Issuer"/> and
    /// <see cref="JwtBearer.JwtBearerGrant.Expiration"/> together, the last two of which the delegate can set
    /// from <see cref="Issuer"/> and <see cref="Expiration"/>. The guard keys the <c>jti</c> on that issuer under
    /// <see cref="Server.JtiReplayPurpose.AuthorizationGrantAssertion"/> and applies the exchange's
    /// <see cref="Server.JtiReplayPolicy"/>: under <see cref="Server.JtiReplayPolicy.Disabled"/> nothing is
    /// checked; under the other two a <c>jti</c> longer than <see cref="Server.JtiReplayGuard.MaxJtiLength"/>
    /// or one the store has seen is refused with <c>invalid_grant</c>; with no store wired,
    /// <see cref="Server.JtiReplayPolicy.OptionalIfStorePresent"/> checks nothing further and
    /// <see cref="Server.JtiReplayPolicy.Required"/> answers <c>server_error</c>, as does a wired store that
    /// cannot prove what it records.
    /// </para>
    /// <para>
    /// A <c>jti</c> is not a
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// validation MUST, so this validation accepts a grant without <c>jti</c>; an application requiring replay
    /// protection refuses an absent <c>jti</c> in its <see cref="Server.ValidateJwtBearerAssertionDelegate"/>.
    /// </para>
    /// </remarks>
    public string? Jti { get; init; }


    /// <summary>
    /// Renders whether the result is valid, its failure reason, the grant's issuer, and whether a tenant, a
    /// subject identifier and a comparison are present, and none of <see cref="Subject"/>, the value of
    /// <see cref="Tenant"/>, <see cref="AudienceSubject"/> or the NameID of
    /// <see cref="SamlNameIdSubjectIdentifier"/>.
    /// </summary>
    /// <remarks>
    /// A record's generated text prints every property, and the subject, the tenants, the audience subject, the
    /// actors and a subject identifier can identify a person; a result that reaches a log, a trace or an
    /// exception message through its text carries none of those values. The debugger display renders the
    /// validity and the failure reason, neither of which identifies a person. The rule is this library's.
    /// </remarks>
    /// <returns>
    /// The text <c>IdJagAssertionValidationResult(IsValid=..., Reason=..., Issuer=..., HasTenant=...,
    /// HasSubjectIdentifier=..., HasComparison=...)</c>.
    /// </returns>
    public override string ToString() =>
        $"IdJagAssertionValidationResult(IsValid={IsValid}, Reason={FailureReason}, Issuer={Issuer}, HasTenant={Tenant is not null}, HasSubjectIdentifier={SubjectIdentifier is not null}, HasComparison={SubjectIdentifierComparison is not null})";


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
