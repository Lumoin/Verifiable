using System.Diagnostics;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.TokenExchange;

/// <summary>
/// The authorization-server policy verdict for a Token Exchange request — the effective parameters
/// of the token to issue, per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.1">RFC 8693 §2.1</see> and
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">§2.2.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// Returned by the application's <see cref="Server.AuthorizeTokenExchangeDelegate"/> — the semantic
/// permit/deny plus the issued-token shaping. The application decides which client may exchange a
/// validated <c>subject_token</c> for whom, at which target (the request's <c>resource</c> /
/// <c>audience</c> / <c>scope</c>), and what the issued token's effective <see cref="Subject"/>,
/// <see cref="Scope"/>, <see cref="Audience"/>, and <see cref="IssuedTokenType"/> are.
/// </para>
/// <para>
/// A <see langword="null"/> return from the authorizing delegate means the exchange is denied (the
/// library answers <c>invalid_target</c> per RFC 8693 §2.2.2). With impersonation semantics the
/// <see cref="Subject"/> is typically the validated subject token's <c>sub</c> — the client becomes
/// indistinguishable from that subject at the target (RFC 8693 §1.1).
/// </para>
/// </remarks>
[DebuggerDisplay("TokenExchangeAuthorization Subject={Subject}, Scope={Scope}")]
public sealed record TokenExchangeAuthorization
{
    /// <summary>
    /// The subject (<c>sub</c>) of the issued token. For impersonation this is the validated
    /// <c>subject_token</c>'s subject per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#appendix-A.1.4">RFC 8693 Appendix A.1.4</see>.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The effective scope of the issued token (space-delimited). Returned in the response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 §2.2.1</see>.
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The audience(s) the issued token is shaped for — the target service(s) the request's
    /// <c>resource</c> / <c>audience</c> named (RFC 8693 §2.1.1). MAY be empty.
    /// </summary>
    public IReadOnlyList<string> Audience { get; init; } = [];

    /// <summary>
    /// The type of the issued token, reported as the response's <c>issued_token_type</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 §2.2.1</see>.
    /// Defaults to <see cref="TokenType.AccessToken"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="TokenType.AccessToken"/> mints an RFC 9068 access-token JWT (response
    /// <c>token_type</c> Bearer). <see cref="TokenType.IdJag"/> mints an Identity Assertion JWT
    /// Authorization Grant (<c>typ</c> <c>oauth-id-jag+jwt</c>, response <c>token_type</c>
    /// <c>N_A</c>) per draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3. Any other value is
    /// rejected as a <c>server_error</c> (an AS misconfiguration), keeping <c>issued_token_type</c>
    /// consistent with the returned token per RFC 8693 §2.2.1.
    /// </remarks>
    public TokenType IssuedTokenType { get; init; } = TokenType.AccessToken;

    /// <summary>
    /// The <c>client_id</c> claim of an issued ID-JAG — the identifier of the OAuth client at the
    /// Resource Authorization Server that will act on behalf of the <see cref="Subject"/>, per
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1. MAY differ from the client requesting
    /// the exchange (it represents an independent client relationship in the resource trust domain).
    /// When <see langword="null"/>, the requesting client's identifier is used. Applies only when
    /// <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public string? ResourceClientId { get; init; }

    /// <summary>
    /// The <c>tenant</c> claim of an issued ID-JAG — the tenant identifier for a multi-tenant IdP
    /// (issuer), per draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1 / §6.1. The IdP MUST include
    /// it when the issuer is multi-tenant and the tenant context is relevant, so the subject identifier
    /// scopes as <c>iss + tenant + sub</c> (§6.3). <see langword="null"/> omits the claim (single-tenant
    /// issuer). Applies only when <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public string? Tenant { get; init; }

    /// <summary>
    /// The <c>aud_tenant</c> claim of an issued ID-JAG — a Resource Authorization Server tenant
    /// identifier, included only when that server is multi-tenant and the IdP knows the tenant, per
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1. When present, <see cref="AudienceSubject"/>
    /// is the account identifier within that tenant and the combination <c>aud + aud_tenant + aud_sub</c>
    /// MUST be unique within the Resource Authorization Server. <see langword="null"/> omits the claim.
    /// Applies only when <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public string? AudienceTenant { get; init; }

    /// <summary>
    /// The <c>aud_sub</c> claim of an issued ID-JAG — the Resource Authorization Server's own identifier
    /// for the End-User (scoped to <see cref="AudienceTenant"/> when present), per
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1. The Resource Authorization Server MAY use it
    /// for subject resolution (including JIT provisioning). <see langword="null"/> omits the claim.
    /// Applies only when <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public string? AudienceSubject { get; init; }

    /// <summary>
    /// The <c>sub_id</c> claim of an issued ID-JAG — a SAML NameID Subject Identifier (§3.2) that
    /// identifies the same End-User as <see cref="Subject"/> in the Resource Authorization Server's SAML
    /// SSO subject namespace, for deployments that resolve users by SAML &lt;NameID&gt; rather than by
    /// <c>iss</c> + <c>sub</c>. The IdP derives it from the &lt;NameID&gt; it would use for SSO to that
    /// server (§3.2.2). <see langword="null"/> omits the claim. Applies only when
    /// <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public IdJag.SamlNameIdSubjectIdentifier? SubjectIdentifier { get; init; }

    /// <summary>
    /// Additional claims to include in the issued ID-JAG beyond the §3.1 core set — the optional ID Token
    /// identity claims an ID-JAG MAY also carry (<c>auth_time</c>, <c>acr</c>, <c>amr</c>, <c>email</c>,
    /// and any other claim valid for an ID Token per §3.1; <c>email</c> is RECOMMENDED). Reserved,
    /// grant-controlled claim names (<c>iss</c>, <c>sub</c>, <c>aud</c>, <c>client_id</c>, <c>jti</c>,
    /// <c>iat</c>, <c>exp</c>, <c>scope</c>, <c>resource</c>, <c>authorization_details</c>, <c>cnf</c>,
    /// <c>tenant</c>, <c>aud_tenant</c>, <c>aud_sub</c>, <c>sub_id</c>) are ignored — the mint controls
    /// those. <see langword="null"/> or empty adds nothing. Applies only when
    /// <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }

    /// <summary>
    /// The granted Resource Identifier(s) (<see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>)
    /// an issued ID-JAG carries as its <c>resource</c> claim — the protected resource(s) the access
    /// token ultimately obtained at the Resource Authorization Server is for
    /// (draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1 / §4.3.3). A single identifier
    /// serialises as a JSON string and multiple as a JSON array; an empty list omits the claim. MAY
    /// narrow the <see cref="TokenExchangeRequest.Resource"/> the client requested. Read back from the
    /// grant on the redeem leg via <see cref="IdJag.IdJagAssertionValidationResult.Resource"/>.
    /// Applies only when <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public IReadOnlyList<string> Resource { get; init; } = [];

    /// <summary>
    /// The granted RFC 9396 authorization details an issued ID-JAG carries as its
    /// <c>authorization_details</c> claim — the structured authorization the access token ultimately
    /// obtained at the Resource Authorization Server is scoped by
    /// (draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1 / §4.3.3). Each element is the object
    /// form of one authorization detail (a dictionary of <c>type</c> and its fields) the JWT payload
    /// serialiser emits as a JSON object. MAY narrow the
    /// <see cref="TokenExchangeRequest.AuthorizationDetails"/> the client requested;
    /// <see langword="null"/> omits the claim. Read back on the redeem leg via
    /// <see cref="IdJag.IdJagAssertionValidationResult.AuthorizationDetails"/>. Applies only when
    /// <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public IReadOnlyList<object>? AuthorizationDetailsClaim { get; init; }

    /// <summary>
    /// The <c>act</c> (actor) claim an issued ID-JAG carries — the JSON object naming the current actor
    /// (its <c>sub</c>) with any prior actors under its own nested <c>act</c> member, least recent
    /// deepest, per <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>.
    /// <see langword="null"/> lets the library carry the chain it already built from the validated
    /// <c>actor_token</c> (delegation) and the subject token's own prior <c>act</c>, and emits no claim
    /// when the exchange was an impersonation. Applies only when <see cref="IssuedTokenType"/> is
    /// <see cref="TokenType.IdJag"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the IdP's §9.7 derivation point — "Such profiles or extensions should define how
    /// <c>actor_token</c> is validated, how the relationship between the authenticated client, subject,
    /// and actor is authorized, how any resulting <c>act</c> claim is derived, and how unnecessary
    /// disclosure of actor identity or attributes is minimized across trust domains" — since
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3 / §9.7 define no
    /// <c>actor_token</c> processing themselves. Emitting the claim at all is discretionary: RFC 8693
    /// §1.1 leaves "When and if a composite token is issued ... at the discretion of the authorization
    /// server and applicable policy and configuration."
    /// </para>
    /// <para>
    /// The claim is delegation, never impersonation (§1.1): <see cref="Subject"/> stays the resource
    /// owner while this names the party acting for it — the distinction §9.7 asks profiles to preserve,
    /// noting also that "The authenticated client identity is also not a substitute for actor identity."
    /// A value supplied here replaces the library's chain wholesale, so a deployment that shapes it
    /// owns the §9.7 risk that a chain could "overstate the actor's authority"; the library's own chain
    /// has already passed the §4.4 <c>may_act</c> check against the presented <c>actor_token</c>.
    /// </para>
    /// </remarks>
    public IReadOnlyDictionary<string, object>? Actor { get; init; }

    /// <summary>
    /// The <c>may_act</c> (authorized actor) claim an issued ID-JAG carries — the JSON object
    /// identifying the party authorized "to become the actor and act on behalf of another party" per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>, by a
    /// <c>sub</c> optionally combined with an <c>iss</c>. <see langword="null"/> omits the claim, which
    /// leaves the grant's redemption unconstrained by an authorized-actor statement. Applies only when
    /// <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    /// <remarks>
    /// A grant minted with this claim is refused at redemption unless the redeeming client is the party
    /// it names — §4.4's own purpose, "determine whether the client ... is authorized to engage in the
    /// requested delegation or impersonation", applied at the boundary where that client becomes the
    /// actor. The party is identified in the Resource Authorization Server's namespace: its <c>sub</c>
    /// is a <c>client_id</c> there, and an <c>iss</c>, when included, is that server's issuer. Read back
    /// on the redeem leg via <see cref="IdJag.IdJagAssertionValidationResult.MayAct"/>.
    /// </remarks>
    public IReadOnlyDictionary<string, object>? AuthorizedActor { get; init; }

    /// <summary>
    /// The granted authorization details as a JSON array string for the §4.3.4 token-exchange
    /// response, or <see langword="null"/> to omit the response field. Populated only when the IdP
    /// granted authorization details that differ from the request or modified them (§4.3.4 makes the
    /// field REQUIRED then and unnecessary otherwise, since the client already holds the requested
    /// value). Pre-serialised here so the library emits it verbatim and never serialises JSON itself.
    /// </summary>
    public string? AuthorizationDetailsResponseJson { get; init; }
}
