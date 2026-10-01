namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The reason an Identity Assertion JWT Authorization Grant (ID-JAG) assertion failed the
/// <see cref="IdJagAssertionValidation"/> claim rules of
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.4.1 (and the §9.3 same-trust-domain rule).
/// Every value maps a Resource Authorization Server to the <c>invalid_grant</c> rejection the
/// processing rules mandate.
/// </summary>
public enum IdJagValidationFailureReason
{
    /// <summary>The JWT <c>typ</c> header is not <c>oauth-id-jag+jwt</c> (§4.4.1 / RFC 8725 §3.11).</summary>
    InvalidType,

    /// <summary>The <c>iss</c> claim is absent.</summary>
    MissingIssuer,

    /// <summary>
    /// The <c>iss</c> claim equals the Resource Authorization Server's own issuer identifier — the
    /// grant was issued in the same trust domain, which §9.3 forbids redeeming for an access token.
    /// </summary>
    SameTrustDomain,

    /// <summary>The <c>aud</c> claim is absent.</summary>
    MissingAudience,

    /// <summary>
    /// The <c>aud</c> claim does not name the Resource Authorization Server's issuer identifier, or is
    /// an array that does not contain exactly one element equal to it (§4.4.1 — audience injection).
    /// </summary>
    AudienceMismatch,

    /// <summary>The <c>client_id</c> claim is absent.</summary>
    MissingClientId,

    /// <summary>The <c>client_id</c> claim does not match the authenticated client (§4.4.1 client continuity).</summary>
    ClientMismatch,

    /// <summary>
    /// The <c>sub</c> claim is absent or white space only
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7521#section-5.2">RFC 7521 Section 5.2</see>).
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 2: "The JWT
    /// MUST contain a "sub" (subject) claim identifying the principal that is the subject of the JWT." Reading a
    /// value of white space only as identifying no principal is this library's reading.
    /// </summary>
    MissingSubject,

    /// <summary>
    /// The <c>cnf</c> claim is present but carries no usable <c>jkt</c> thumbprint (§9.8.1). A grant
    /// asserting a confirmation the Resource Authorization Server cannot honor is rejected rather than
    /// silently downgraded to an unbound Bearer token.
    /// </summary>
    MalformedConfirmation,

    /// <summary>
    /// The <c>act</c> claim is present but is not an
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> actor object —
    /// not a JSON object, naming no <c>sub</c>, nesting a prior actor that is itself not an actor
    /// object, or nesting deeper than a delegation chain can reach. A grant asserting a delegation the
    /// Resource Authorization Server cannot read is rejected rather than redeemed as if no delegation
    /// had occurred, which would silently drop the acting party from the issued access token.
    /// </summary>
    MalformedActor,

    /// <summary>
    /// The <c>may_act</c> claim is present but is not an
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>
    /// authorized-actor object — not a JSON object, or naming neither a <c>sub</c> nor an <c>iss</c> to
    /// identify the party eligible to act. A grant whose actor constraint cannot be read is rejected
    /// rather than redeemed unconstrained, which would let a malformed claim bypass the constraint
    /// entirely.
    /// </summary>
    MalformedAuthorizedActor,

    /// <summary>The <c>exp</c> claim is absent (RFC 7521 §5.2).</summary>
    MissingExpiration,

    /// <summary>The grant has expired (<c>exp</c> at or before now, within skew).</summary>
    Expired,

    /// <summary>The grant is not yet valid (<c>nbf</c> after now, beyond skew).</summary>
    NotYetValid,

    /// <summary>
    /// The temporal claims are internally inconsistent — <c>exp</c> at or before <c>iat</c> or
    /// <c>nbf</c> (the validity window never opens, independent of the current clock), or an
    /// <c>exp</c>/<c>iat</c>/<c>nbf</c> claim that is present but not a numeric timestamp.
    /// </summary>
    InconsistentTemporalClaims,

    /// <summary>
    /// The rule's <see cref="IdJagSubjectIdentifierRule.Presence"/> is
    /// <see cref="IdJagSubjectIdentifierPresence.Required"/> and the grant carries no <c>sub_id</c> claim.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// refuses a grant when "the ID-JAG does not contain a sub_id claim using the SAML NameID Subject
    /// Identifier Format"
    /// </summary>
    SubjectIdentifierRequired,

    /// <summary>
    /// The <c>sub_id</c> claim is not a Subject Identifier, or its format is one this library knows and its
    /// members break that format's rules, while the rule requires or compares the claim.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// refuses a grant when "the sub_id claim is malformed", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see> says what well
    /// formed is: "A Subject Identifier MUST conform to a specific Identifier Format and MUST contain a "format"
    /// member whose value is the name of that Identifier Format." and "Every member within a Subject Identifier
    /// MUST match the rules specified for that member by this specification or by a Subject Identifier's
    /// Identifier Format. A Subject Identifier MUST NOT contain any members prohibited or not described by its
    /// Identifier Format and MUST contain all members required by its Identifier Format." The check covers the
    /// members present, their JSON types, the members a format does not describe and the reserved <c>format</c>
    /// member; the rules on a member's value are the caller's, which
    /// <see cref="Verifiable.Core.SecurityEvents.SubjectIdentifier.IsValidForKnownFormat"/> names.
    /// </summary>
    MalformedSubjectIdentifier,

    /// <summary>
    /// The rule's <see cref="IdJagSubjectIdentifierRule.Presence"/> is
    /// <see cref="IdJagSubjectIdentifierPresence.Required"/> and the <c>sub_id</c> claim names a format outside
    /// the rule's non-empty <see cref="IdJagSubjectIdentifierRule.AcceptedFormats"/>.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>
    /// refuses a grant when "the sub_id claim is malformed or uses a Subject Identifier Format that the
    /// Resource Authorization Server does not support"
    /// </summary>
    UnsupportedSubjectIdentifierFormat,

    /// <summary>
    /// The comparison of the <c>sub_id</c> claim with the validated subject decided
    /// <see cref="Verifiable.Core.Relations.ComparisonDecision.Deny"/>: the claim does not name the End-User
    /// the grant's <c>iss</c> and <c>sub</c> name, or the application's association refused it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "When both sub and sub_id are present, they MUST identify the same End-User."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>
    /// refuses a grant when "the sub_id claim is not authorized by local policy for the validated ID-JAG
    /// issuer."
    /// </summary>
    SubjectIdentifierMismatch,

    /// <summary>
    /// The comparison of the <c>sub_id</c> claim with the validated subject decided
    /// <see cref="Verifiable.Core.Relations.ComparisonDecision.IndeterminateDeny"/>: the rule requires the claim
    /// and nothing could decide whether it names the grant's subject, so the grant is refused.
    /// <see href="https://github.com/pic-protocol/pic-spec/blob/35b1d904aebf9438b0f25d7465d1d0b965d6656b/draft/0.2/rfc/pic-lineage-guardrail-spec.txt">PIC Sandboxed Execution (pic-sandboxed-execution-02) Section 2.6</see>:
    /// "An input required by policy that is unauthenticated, ambiguously bound, semantically unmapped,
    /// inconsistent with the presented continuity state, unavailable, or controlled only by the proposing
    /// executor MUST produce deny or indeterminate-deny." The rule that requires the claim is the one of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.2</see>:
    /// "If the Resource Authorization Server requires a SAML NameID Subject Identifier for subject resolution,
    /// it MUST reject the token request with an invalid_grant error as defined in Section 5.2 of [RFC6749] if
    /// any of the following is true"
    /// </summary>
    SubjectIdentifierUndetermined,

    /// <summary>
    /// The <c>tenant</c> claim is present and is not a JSON string with at least one character that is not
    /// white space.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// defines the claim as "tenant: OPTIONAL - JSON string that represents the tenant identifier for a
    /// multi-tenant issuer" and scopes the grant's subject by it: "A public subject identifier MUST be unique
    /// when scoped with issuer (iss+sub) for a single-tenant issuer and MUST be unique when scoped with issuer
    /// and tenant (iss+tenant+sub) for multi-tenant issuer." The tenant decides which namespace the subject is
    /// unique in, so a present value that is not such a string, the empty string and a string of white space
    /// only included, refuses the grant and is not read as a grant that carries no tenant. That refusal is
    /// this library's fail-closed reading: no sentence of Section 3.1,
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// or <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6.3">Section 6.3</see>
    /// states it.
    /// </summary>
    MalformedTenant,

    /// <summary>
    /// The <c>aud_tenant</c> claim is present and is not a JSON string with at least one character that is not
    /// white space.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// defines the claim as "aud_tenant: OPTIONAL - A JSON string that represents a Resource Authorization
    /// Server tenant identifier" and states "The combination of aud + aud_tenant and aud_sub MUST be unique
    /// within the Resource Authorization Server." A present value that is not such a string, the empty string
    /// and a string of white space only included, refuses the grant and is not read as absent, so the account
    /// is never resolved outside the tenant the grant names. That refusal is this library's fail-closed
    /// reading: no sentence of Section 3.1,
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// or <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6.3">Section 6.3</see>
    /// states it.
    /// </summary>
    MalformedAudienceTenant,

    /// <summary>
    /// The <c>aud_sub</c> claim is present and is not a JSON string with at least one character that is not
    /// white space.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// defines the claim as "aud_sub: OPTIONAL - The Resource Authorization Server's identifier for the
    /// End-User as defined in [OpenID.Enterprise]." and names no JSON type for it; reading the identifier as such
    /// a string, as the <c>tenant</c> and <c>aud_tenant</c> claims beside it are, and refusing any other value
    /// is this library's reading.
    /// </summary>
    MalformedAudienceSubject,

    /// <summary>
    /// The <c>resource</c> claim is present and is not a JSON string the resource indicator grammar accepts, nor
    /// a non-empty JSON array of such strings.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// defines the claim as "resource: OPTIONAL - The Resource Identifier (Section 2 of [RFC8707]) of the
    /// Resource Server (either a single URI or an array of URIs)." and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// states "If the resource claim is present, the Resource Authorization Server MUST process it according to
    /// Section 2 of [RFC8707]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see>: "Its value MUST be
    /// an absolute URI, as specified by Section 4.3 of [RFC3986]. The URI MUST NOT include a fragment component."
    /// An empty string, an empty array and an element that is not a JSON string are refused with the values the
    /// grammar refuses; refusing the empty string and the empty array is this library's fail-closed reading: no
    /// sentence of Section 3.1 or Section 4.4.1 states it. A grant carrying such a claim is not a valid JWT for
    /// this server, so the answer is the one of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.1">RFC 7523 Section 3.1</see>: "If the
    /// JWT is not valid, or the current time is not within the token's valid time window for use, the
    /// authorization server constructs an error response as defined in OAuth 2.0 [RFC6749]. The value of the
    /// "error" parameter MUST be the "invalid_grant" error code." Reading a malformed <c>resource</c> claim as
    /// a JWT that is not valid, rather than as RFC 8707's <c>invalid_target</c> for a request parameter, is this
    /// library's reading.
    /// </summary>
    MalformedResource,

    /// <summary>
    /// The <c>authorization_details</c> claim is present and is not a JSON array.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.4.1</see>:
    /// "If the authorization_details claim is present, the Resource Authorization Server MUST parse it as a
    /// JSON array and process each authorization detail object according to [RFC9396]." The shape of each
    /// element is the application's to process.
    /// </summary>
    MalformedAuthorizationDetails,

    /// <summary>
    /// The <c>jti</c> claim is absent, or is not a JSON string with at least one character that is not white
    /// space.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "jti: REQUIRED - Unique ID of this JWT as defined in Section 4.1.7 of [RFC7519]."
    /// Refusing a <c>jti</c> of white space only is this library's fail-closed reading: no sentence of Section 3.1
    /// or <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// states it.
    /// </summary>
    MissingJti,

    /// <summary>
    /// The <c>iat</c> claim is absent.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "iat: REQUIRED - as defined in Section 4.1.6 of [RFC7519]." A present <c>iat</c> that is not a numeric
    /// timestamp is <see cref="InconsistentTemporalClaims"/>.
    /// </summary>
    MissingIssuedAt,

    /// <summary>
    /// The <c>scope</c> claim is present and is not a JSON string whose value is a space-delimited list of scope
    /// tokens.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// defines the claim as "scope: OPTIONAL - a JSON string containing a space-separated list of scopes
    /// associated with the token, in the format described in Section 3.3 of [RFC6749]." and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// states "If the scope claim is present, the Resource Authorization Server MUST process it according to
    /// Section 3.3 of [RFC6749]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 Section 3.3</see> gives the
    /// grammar "scope = scope-token *( SP scope-token )" and "scope-token = 1*( %x21 / %x23-5B / %x5D-7E )", so an
    /// empty string, a leading, trailing or doubled space, a tab and a character outside that set each break it.
    /// Refusing such a grant, rather than reading the claim as absent or carrying it unchecked, is decided by
    /// this library: a grant carrying the claim is not a valid JWT for this server, and the answer is the
    /// <c>invalid_grant</c> of <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.1">RFC 7523 Section 3.1</see>.
    /// </summary>
    MalformedScope
}
