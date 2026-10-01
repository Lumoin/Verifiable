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
/// A <see langword="null"/> return from the authorizing delegate means the exchange is denied. The token endpoint
/// answers 400 <c>invalid_target</c> when the request named a <c>resource</c> or an <c>audience</c>, under
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2">RFC 8693 Section 2.2.2</see>: "If the
/// authorization server is unwilling or unable to issue a token for any target service indicated by the
/// "resource" or "audience" parameters, the "invalid_target" error code SHOULD be used in the error response."
/// It answers 400 <c>invalid_request</c> when the request named neither, the code of the same section's MUST:
/// "The value of the "error" parameter MUST be the "invalid_request" error code." The description is
/// <c>The token exchange was not authorized.</c> in either case. An ID-JAG request names its Resource
/// Authorization Server as the <c>audience</c>, so its denial is <c>invalid_target</c>. The library cannot tell
/// why the delegate denied, so it reads a denial of a request that names a target as unwillingness to issue for
/// that target, a rule of this library. With impersonation semantics the
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
    /// A subject that is null, empty or white space only names no subject: it is the authorization seam's own defect,
    /// which the token exchange answers <c>server_error</c> before anything is obtained, stored or minted. That rule is
    /// this library's. A <c>subject_token</c> whose validated subject is blank never reaches this seam: the token
    /// exchange answers it as a token that is not valid (<see cref="ValidatedSecurityToken.Subject"/>).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The effective scope of the issued token (space-delimited). Returned in the response per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 §2.2.1</see>.
    /// </summary>
    public required string Scope { get; init; }

    /// <summary>
    /// The audience(s) the issued token is shaped for — the target service(s) the request's
    /// <c>resource</c> / <c>audience</c> named (RFC 8693 Section 2.1.1). MAY be empty. For an issued ID-JAG
    /// (<see cref="IssuedTokenType"/> <see cref="TokenType.IdJag"/>) the list names at most one Resource
    /// Authorization Server, the one the grant's <c>aud</c> claim holds
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3</see>:
    /// "audience: REQUIRED - The identifier of the Resource Authorization Server in another trust domain as the
    /// intended audience for the ID-JAG."). A list of several values, or one whose first value is null, empty or white
    /// space only, is the authorization seam's own defect, which the token exchange answers <c>server_error</c> before
    /// any grant identifier is obtained; an empty list leaves the audience to the request's one <c>audience</c>. That
    /// rule is this library's.
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
    /// <c>N_A</c>) per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.3">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.3</see>.
    /// <see cref="TokenType.RefreshToken"/> mints an opaque Refresh Token, returned in the
    /// <c>access_token</c> field with <c>issued_token_type</c> the refresh_token URN and
    /// <c>token_type</c> <c>N_A</c>: the protocol transition of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.5">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.5</see>,
    /// where a client exchanges a SAML 2.0 assertion for a Refresh Token and later presents that Refresh
    /// Token as a <c>subject_token</c> for an ID-JAG.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.3">Section 4.4.3</see>
    /// states that later step: "If the IdP
    /// Authorization Server supports Refresh Tokens as a subject_token in Token Exchange, the client can
    /// skip renewing the Identity Assertion and directly request a new ID-JAG by presenting the Refresh
    /// Token (see Section 4.3.2)." Any other value is rejected as a <c>server_error</c> (an AS
    /// misconfiguration), keeping <c>issued_token_type</c> consistent with the returned token per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1">RFC 8693 Section 2.2.1</see>.
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
    /// The <c>tenant</c> claim of an issued ID-JAG, which
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// defines as "tenant: OPTIONAL - JSON string that represents the tenant identifier for a multi-tenant
    /// issuer" (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6.1">Section 6.1</see>
    /// relates the issuer and the tenant).
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6.3">Section 6.3</see>
    /// states when the IdP includes it: "When the Resource Authorization Server is multi-tenant, the IdP MUST
    /// include the tenant claim in the ID-JAG to ensure proper subject identifier scoping." The subject
    /// identifier then scopes as <c>iss + tenant + sub</c>. <see langword="null"/> or empty omits the claim. A
    /// value of white space only is the authorization seam's own defect: the ID-JAG mint answers it
    /// <c>server_error</c> and mints nothing. That rule is this library's.
    /// Applies only when <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public string? Tenant { get; init; }

    /// <summary>
    /// The <c>aud_tenant</c> claim of an issued ID-JAG — a Resource Authorization Server tenant
    /// identifier, included only when that server is multi-tenant and the IdP knows the tenant, per
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1. When present, <see cref="AudienceSubject"/>
    /// is the account identifier within that tenant and the combination <c>aud + aud_tenant + aud_sub</c>
    /// MUST be unique within the Resource Authorization Server. <see langword="null"/> or empty omits the claim.
    /// A value of white space only is the authorization seam's own defect: the ID-JAG mint answers it
    /// <c>server_error</c> and mints nothing. That rule is this library's.
    /// Applies only when <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public string? AudienceTenant { get; init; }

    /// <summary>
    /// The <c>aud_sub</c> claim of an issued ID-JAG — the Resource Authorization Server's own identifier
    /// for the End-User (scoped to <see cref="AudienceTenant"/> when present), per
    /// draft-ietf-oauth-identity-assertion-authz-grant-04 §3.1. The Resource Authorization Server MAY use it
    /// for subject resolution (including JIT provisioning). <see langword="null"/> or empty omits the claim. A
    /// value of white space only is the authorization seam's own defect: the ID-JAG mint answers it
    /// <c>server_error</c> and mints nothing. That rule is this library's.
    /// Applies only when <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    public string? AudienceSubject { get; init; }

    /// <summary>
    /// The <c>sub_id</c> claim of an issued ID-JAG: any
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see> Subject Identifier the
    /// authorization seam chooses for the End-User named by <see cref="Subject"/>, written as
    /// <see cref="Verifiable.Core.SecurityEvents.SubjectIdentifier.ToWireObject"/> renders it.
    /// <see langword="null"/>, the default, omits the claim. Applies only when
    /// <see cref="IssuedTokenType"/> is <see cref="TokenType.IdJag"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "sub_id: OPTIONAL - Subject Identifier as defined in [RFC9493]. The sub_id claim MAY be used to
    /// identify the same End-User as the sub claim using a different identifier namespace from the ID-JAG
    /// iss and sub." Whether a grant carries it is the seam's choice, which
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.6">Section 9.6</see>
    /// guides: "The IdP Authorization Server SHOULD include sub_id only when needed by the target Resource
    /// Authorization Server for subject resolution."
    /// </para>
    /// <para>
    /// The library writes the identifier the seam returns and chooses nothing in it, so what the texts ask of
    /// the party that chooses the identifier is the seam's.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>:
    /// "When constructing a SAML NameID Subject Identifier, the IdP Authorization Server MUST derive its members
    /// from the SAML Assertion Subject &lt;NameID&gt; value it would use for SSO to the target Resource
    /// Authorization Server, or from an equivalent configured mapping that records the SAML &lt;NameID&gt; value
    /// and attributes the IdP Authorization Server would issue for that subject and Resource Authorization
    /// Server. Each optional field MUST be included exactly when the corresponding attribute is present on that
    /// &lt;NameID&gt; or in the configured mapping."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.6">Section 9.6</see>:
    /// "The IdP Authorization Server SHOULD minimize the subject identifiers included in the ID-JAG to those
    /// required by the Resource Authorization Server."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-6.1">RFC 9493 Section 6.1</see>: "When
    /// transmitting Subject Identifiers, the transmitter SHOULD take care that they are only transmitting
    /// multiple identifiers together when it is known that the recipient already knows that the identifiers
    /// are related" or "when correlation is essential to the use case."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2">RFC 9493 Section 3.2</see>: "Since the
    /// Subject Identifier Format conveys semantic information, applications SHOULD choose the most specific
    /// possible format for the identifier in question."
    /// </para>
    /// <para>
    /// An identifier that is not well formed
    /// (<see cref="Verifiable.Core.SecurityEvents.SubjectIdentifier.IsWellFormed"/>: its format name is blank,
    /// or its format is one this library recognizes and its members break that format's rules) is the seam's
    /// own defect: the token exchange answers <c>server_error</c> with
    /// <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/> and mints nothing. An identifier of a
    /// format this library does not recognize is written as given, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see> lets a format
    /// be a registered name or a Collision-Resistant Name. A SAML NameID Subject Identifier comes from
    /// <see cref="IdJag.SamlNameIdSubjectIdentifier.ToSubjectIdentifier"/>.
    /// </para>
    /// </remarks>
    public Verifiable.Core.SecurityEvents.SubjectIdentifier? SubjectIdentifier { get; init; }

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
    /// <see cref="TokenType.IdJag"/>. An actor whose <c>sub</c> member is present and is not a string with a
    /// character that is not white space (null, a value that is not a string, the empty string, or white space
    /// only) names no actor: it is the authorization seam's own defect, which the token exchange answers
    /// <c>server_error</c> with <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/>, as it answers a blank
    /// <see cref="Subject"/>, before anything is obtained, stored or minted. The check runs whatever the
    /// <see cref="IssuedTokenType"/>, so an access or refresh token exchange whose authorization shapes such an actor
    /// is refused too. That rule is this library's. An actor without a <c>sub</c> member is written as given, and the
    /// prior actors nested under its own <c>act</c> member are written as given.
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
