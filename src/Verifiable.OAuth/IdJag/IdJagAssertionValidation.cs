
using Verifiable.Core;
using Verifiable.Core.Relations;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.OAuth.JwtBearer;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// Validates the claim rules an Identity Assertion JWT Authorization Grant (ID-JAG) assertion must
/// satisfy when redeemed at a Resource Authorization Server's JWT Bearer (RFC 7523) token endpoint,
/// per draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.4.1 and the §9.3 same-trust-domain rule.
/// </summary>
/// <remarks>
/// <para>
/// This helper is transport- and crypto-agnostic: it operates on the already signature-verified,
/// decoded <see cref="JwtHeader"/> and <see cref="JwtPayload"/>. The caller — its
/// <see cref="Server.ValidateJwtBearerAssertionDelegate"/> wiring — owns the §4.4.1 "All of
/// Section 5.2 of [RFC7521] applies" signature step: it resolves the verification key for the
/// grant's <c>iss</c> (only a trusted IdP's key resolves, which is how issuer trust is established —
/// §9.5 forbids deriving trust from <c>sub_id.issuer</c>), verifies the signature (for example via
/// <see cref="Jws.VerifyAndDecodeAsync(string, Verifiable.Cryptography.DecodeDelegate, JwtPartDecoder, BaseMemoryPool, Verifiable.Cryptography.PublicKeyMemory, CancellationToken)"/>), and then calls <see cref="Validate"/> or
/// <see cref="ValidateAsync"/> to enforce the ID-JAG-specific claim rules. On success the caller shapes a
/// <see cref="JwtBearer.JwtBearerGrant"/> from <see cref="IdJagAssertionValidationResult.Subject"/>
/// and <see cref="IdJagAssertionValidationResult.Scope"/>; on failure it returns <see langword="null"/>
/// so the grant is refused with <c>invalid_grant</c>.
/// </para>
/// <para>
/// The rules enforced (each a §4.4.1 MUST unless noted):
/// </para>
/// <list type="bullet">
///   <item><description><c>typ</c> header is <c>oauth-id-jag+jwt</c>.</description></item>
///   <item><description><c>iss</c> is present and is not the Resource Authorization Server's own issuer (§9.3).</description></item>
///   <item><description><c>aud</c> is the Resource Authorization Server's issuer as a string, or a single-element array of it; any other shape (multi-element array, mismatch) is rejected.</description></item>
///   <item><description><c>client_id</c> equals the authenticated client.</description></item>
///   <item><description><c>sub</c> is present and not white space only, <c>exp</c> is present, the temporal claims are consistent, and the grant is neither expired nor not-yet-valid (<see href="https://www.rfc-editor.org/rfc/rfc7521#section-5.2">RFC 7521 Section 5.2</see>); a grant whose <c>nbf</c> or <c>iat</c> lies after the current instant plus the skew is not yet valid, the <c>iat</c> case this library's policy under <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>: "Application of additional restrictions and policy are at the discretion of the authorization server." The age of a grant's <c>iat</c> is the application's to judge; no maximum age is applied.</description></item>
///   <item><description>
///     an <c>act</c> or <c>may_act</c> claim, when present, is a well-formed
///     <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> /
///     <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">§4.4</see> object — not a §4.4.1
///     rule (ID-JAG §4.3/§9.7 defines no actor processing), but a fail-closed read: a delegation this
///     server cannot parse is refused rather than dropped from the token it would issue.
///   </description></item>
///   <item><description>
///     a <c>tenant</c>, <c>aud_tenant</c> or <c>aud_sub</c> claim, when present, is a JSON string with at
///     least one character that is not white space. The JSON string of <c>tenant</c> and <c>aud_tenant</c> is
///     the draft's
///     (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>
///     defines each as a JSON string and names no JSON type for <c>aud_sub</c>; the quotations stand in
///     <see cref="IdJagValidationFailureReason.MalformedTenant"/>,
///     <see cref="IdJagValidationFailureReason.MalformedAudienceTenant"/> and
///     <see cref="IdJagValidationFailureReason.MalformedAudienceSubject"/>). Refusing a present value of any of
///     the three that is not a string with at least one character that is not white space, the empty string
///     included, is this library's fail-closed reading: no sentence of Section 3.1,
///     <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
///     or
///     <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-6.3">Section 6.3</see>
///     states that refusal. A tenant relationship this server cannot read is refused rather than read as
///     absent.
///   </description></item>
///   <item><description>
///     <c>iat</c> and <c>jti</c> are present, the <c>jti</c> a JSON string with at least one character that is
///     not white space (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>
///     makes both REQUIRED where <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>
///     leaves them OPTIONAL); a grant without either is refused as
///     <see cref="IdJagValidationFailureReason.MissingIssuedAt"/> or
///     <see cref="IdJagValidationFailureReason.MissingJti"/>. Refusing a <c>jti</c> of white space only is this
///     library's fail-closed reading: no sentence of Section 3.1 or Section 4.4.1 states it.
///   </description></item>
///   <item><description>
///     a <c>scope</c> claim, when present, is a JSON string of scope tokens delimited by single spaces
///     (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>:
///     "If the scope claim is present, the Resource Authorization Server MUST process it according to Section
///     3.3 of [RFC6749]."; <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 Section 3.3</see>:
///     "scope-token = 1*( %x21 / %x23-5B / %x5D-7E )"); any other value is refused as
///     <see cref="IdJagValidationFailureReason.MalformedScope"/>.
///   </description></item>
///   <item><description>
///     a <c>resource</c> claim, when present, is a JSON string or a non-empty JSON array of JSON strings, each an
///     <c>absolute-URI</c> without a fragment by <see cref="ResourceIndicator.Parse"/>
///     (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>:
///     "If the resource claim is present, the Resource Authorization Server MUST process it according to Section
///     2 of [RFC8707]."), surfaced folded (<see cref="IdJagAssertionValidationResult.Resource"/>); any other value
///     is refused as <see cref="IdJagValidationFailureReason.MalformedResource"/>. Refusing an empty string and an
///     empty array is this library's fail-closed reading: no sentence of Section 3.1 or Section 4.4.1 states it.
///   </description></item>
///   <item><description>
///     an <c>authorization_details</c> claim, when present, is a JSON array
///     (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>:
///     "MUST parse it as a JSON array"); any other value is refused as
///     <see cref="IdJagValidationFailureReason.MalformedAuthorizationDetails"/>.
///   </description></item>
/// </list>
/// <para>
/// The <c>iss</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>, <c>nbf</c> and <c>iat</c> checks are the
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> rule set every jwt-bearer
/// assertion must satisfy, consumed from <see cref="Rfc7523AssertionValidation"/> so they have exactly one
/// implementation. The ID-JAG rules are layered around them: the <c>typ</c> header, the same trust domain, the
/// <c>client_id</c>, the REQUIRED <c>iat</c> and <c>jti</c>, and the reads of the tenant relationship, actor,
/// <c>scope</c>, <c>resource</c> and <c>authorization_details</c> claims.
/// </para>
/// <para>
/// The <c>sub_id</c> claim is read last, under an <see cref="IdJagSubjectIdentifierRule"/>:
/// <see cref="ValidateAsync"/> takes the rule, and <see cref="Validate"/> applies
/// <see cref="IdJagSubjectIdentifierRule.Default"/>, which neither requires nor compares the claim. The step
/// runs after every rule above, so the subject the claim is compared with is the validated one:
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.5">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 9.5</see>:
/// "The ID-JAG MUST first be validated using the iss claim, signature, audience, expiration, and client
/// binding according to this specification." In order:
/// </para>
/// <list type="number">
///   <item><description>
///     An absent claim is refused as <see cref="IdJagValidationFailureReason.SubjectIdentifierRequired"/>
///     under <see cref="IdJagSubjectIdentifierPresence.Required"/>, and is otherwise nothing to read.
///   </description></item>
///   <item><description>
///     A claim that is not a Subject Identifier (<see cref="SubjectIdentifier.FromWireObject"/> reads none),
///     or that is not well formed (<see cref="SubjectIdentifier.IsWellFormed"/>: its format member names a
///     format, and a format the library knows, <see cref="SubjectIdentifierFormats.IsKnown"/>, keeps its member
///     rules), is refused as <see cref="IdJagValidationFailureReason.MalformedSubjectIdentifier"/> when the rule
///     requires or compares the claim, and is otherwise surfaced as <see langword="null"/>. An identifier of a
///     format the library does not know is carried opaque.
///   </description></item>
///   <item><description>
///     A format outside a non-empty <see cref="IdJagSubjectIdentifierRule.AcceptedFormats"/> is refused as
///     <see cref="IdJagValidationFailureReason.UnsupportedSubjectIdentifierFormat"/> under
///     <see cref="IdJagSubjectIdentifierPresence.Required"/>; otherwise the identifier is surfaced and, when the
///     rule compares it, the comparison profile records it <see cref="ComparisonOutcome.Indeterminate"/>, basis
///     <see cref="ComparisonBasis.None"/>, without asking the association.
///   </description></item>
///   <item><description>
///     When the rule names a <see cref="IdJagSubjectIdentifierRule.Relation"/> or requires the claim, the
///     identifier is compared with the grant's validated <c>iss</c>, <c>tenant</c> and <c>sub</c>
///     (<see cref="IdJagSubjectContext"/>) by the library's comparison profile; a
///     <see cref="ComparisonDecision.Deny"/> is refused as
///     <see cref="IdJagValidationFailureReason.SubjectIdentifierMismatch"/> and any other decision than
///     <see cref="ComparisonDecision.Permit"/> as
///     <see cref="IdJagValidationFailureReason.SubjectIdentifierUndetermined"/>. The record rides the result
///     on success and on those two refusals
///     (<see cref="IdJagAssertionValidationResult.SubjectIdentifierComparison"/>).
///   </description></item>
/// </list>
/// </remarks>
public static class IdJagAssertionValidation
{
    /// <summary>
    /// Validates a decoded ID-JAG assertion against the §4.4.1 / §9.3 claim rules.
    /// </summary>
    /// <param name="header">The decoded (signature-verified) JWT header.</param>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="resourceServerIssuer">
    /// The Resource Authorization Server's own issuer identifier (RFC 8414) — the value the grant's
    /// <c>aud</c> must name and that its <c>iss</c> must not equal.
    /// </param>
    /// <param name="authenticatedClientId">
    /// The <c>client_id</c> of the client authenticated on the redeem request — the grant's
    /// <c>client_id</c> claim must equal it.
    /// </param>
    /// <param name="now">The instant the exp, nbf and iat are evaluated against.</param>
    /// <param name="clockSkew">
    /// Tolerance applied to the <c>exp</c>, <c>nbf</c> and <c>iat</c> comparisons: an <c>nbf</c> or an <c>iat</c>
    /// later than the current instant plus this tolerance is <see cref="IdJagValidationFailureReason.NotYetValid"/>.
    /// </param>
    /// <returns>
    /// A successful <see cref="IdJagAssertionValidationResult"/> carrying the validated claims, or a
    /// failed result whose <see cref="IdJagAssertionValidationResult.FailureReason"/> the caller maps
    /// to <c>invalid_grant</c>.
    /// </returns>
    /// <remarks>
    /// Applies <see cref="IdJagSubjectIdentifierRule.Default"/> to the <c>sub_id</c> claim: the claim is
    /// surfaced as read and judged by nothing, so no comparison runs and nothing is awaited.
    /// <see cref="ValidateAsync"/> applies any other rule.
    /// </remarks>
    public static IdJagAssertionValidationResult Validate(
        JwtHeader header,
        JwtPayload payload,
        string resourceServerIssuer,
        string authenticatedClientId,
        DateTimeOffset now,
        TimeSpan clockSkew) =>
        ValidateClaims(header, payload, resourceServerIssuer, authenticatedClientId, now, clockSkew, IdJagSubjectIdentifierRule.Default, out _);


    /// <summary>
    /// The claim rules both entry points share: every
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// and <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.3">Section 9.3</see>
    /// rule, then the <c>sub_id</c> step under <paramref name="rule"/> up to the comparison, which is the
    /// caller's to run.
    /// </summary>
    /// <param name="header">The decoded (signature-verified) JWT header.</param>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="resourceServerIssuer">The Resource Authorization Server's own issuer identifier.</param>
    /// <param name="authenticatedClientId">The <c>client_id</c> of the client authenticated on the redeem request.</param>
    /// <param name="now">The instant the exp, nbf and iat are evaluated against.</param>
    /// <param name="clockSkew">
    /// Tolerance applied to the <c>exp</c>, <c>nbf</c> and <c>iat</c> comparisons: an <c>nbf</c> or an <c>iat</c>
    /// later than the current instant plus this tolerance is <see cref="IdJagValidationFailureReason.NotYetValid"/>.
    /// </param>
    /// <param name="rule">The rule applied to the grant's <c>sub_id</c> claim.</param>
    /// <param name="reference">
    /// The grant's validated subject when the claim is to be compared with it under <paramref name="rule"/>;
    /// otherwise <see langword="null"/>, and the returned result is final.
    /// </param>
    /// <returns>
    /// The failed result of the first rule the grant breaks, or the successful result carrying the validated
    /// claims.
    /// </returns>
    private static IdJagAssertionValidationResult ValidateClaims(
        JwtHeader header,
        JwtPayload payload,
        string resourceServerIssuer,
        string authenticatedClientId,
        DateTimeOffset now,
        TimeSpan clockSkew,
        IdJagSubjectIdentifierRule rule,
        out IdJagSubjectContext? reference)
    {
        reference = null;
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceServerIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedClientId);

        //§4.4.1: validate the JWT typ is oauth-id-jag+jwt (per RFC 8725 §3.11). A missing or wrong
        //typ means the JWT is not an ID-JAG and could be a confused-deputy substitution of an access
        //token or ID Token.
        if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typValue)
            || typValue is not string typ
            || !WellKnownMediaTypes.Jwt.IsOauthIdJagJwt(typ))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.InvalidType,
                "The assertion typ header is not oauth-id-jag+jwt.");
        }

        //§3 item 1 (RFC 7523 §3), consumed rather than reimplemented — see the class remarks.
        if(!Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.Iss, out string? iss))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingIssuer,
                "The assertion is missing the iss claim.");
        }

        //§9.3: a Resource Authorization Server MUST NOT redeem an ID-JAG that was issued in its own
        //trust domain. The degenerate same-domain case is an iss equal to this server's own issuer.
        if(string.Equals(iss, resourceServerIssuer, StringComparison.Ordinal))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.SameTrustDomain,
                "The assertion iss equals this Resource Authorization Server's issuer (same trust domain).");
        }

        //§4.4.1 narrows RFC 7523 §3 item 3's generic "contains this audience" rule to the anti-
        //audience-injection shape ValidateAudience already implements: a string or single-element
        //array naming the Resource Authorization Server's issuer, nothing looser.
        Rfc7523AudienceOutcome audienceOutcome = Rfc7523AssertionValidation.ValidateAudience(payload, resourceServerIssuer, out string? audienceValue);
        if(audienceOutcome == Rfc7523AudienceOutcome.Missing)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingAudience,
                "The assertion is missing the aud claim.");
        }

        if(audienceOutcome == Rfc7523AudienceOutcome.Mismatch)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.AudienceMismatch,
                "The assertion aud must be the Resource Authorization Server's issuer as a string or single-element array.");
        }

        //§4.4.1: the client_id claim MUST identify the same client as the request's client
        //authentication. This preserves the OAuth client binding across the exchange.
        if(!Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.ClientId, out string? clientId))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingClientId,
                "The assertion is missing the client_id claim.");
        }

        if(!string.Equals(clientId, authenticatedClientId, StringComparison.Ordinal))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.ClientMismatch,
                "The assertion client_id does not match the authenticated client.");
        }

        //RFC 7521 Section 5.2 (https://www.rfc-editor.org/rfc/rfc7521#section-5.2) and RFC 7523
        //Section 3 item 2, case A (https://www.rfc-editor.org/rfc/rfc7523#section-3): the subject the
        //access is requested for. A value of white space only identifies no principal (this library's
        //reading of "identifying the principal"; its token factories refuse such a subject), so it is
        //refused here as a value rather than reaching them.
        if(!Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.Sub, out string? sub)
            || string.IsNullOrWhiteSpace(sub))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingSubject,
                "The assertion is missing the sub claim or carries one of white space only.");
        }

        //§3 items 4–6 (RFC 7521 §5.2 / RFC 7523 §3): exp REQUIRED and not expired; nbf/iat OPTIONAL but,
        //when present, numeric and temporally consistent.
        Rfc7523TemporalOutcome temporalOutcome = Rfc7523AssertionValidation.ValidateTemporalClaims(
            payload, now, clockSkew, out DateTimeOffset exp, out DateTimeOffset? iat, out string? temporalFailureDescription);
        if(temporalOutcome != Rfc7523TemporalOutcome.Valid)
        {
            return IdJagAssertionValidationResult.Failure(MapTemporalFailure(temporalOutcome), temporalFailureDescription);
        }

        //Section 3.1 makes iat REQUIRED where RFC 7523 Section 3 leaves it OPTIONAL, so a grant whose temporal
        //claims hold without an iat is refused here; a present iat that is not numeric keeps the temporal answer.
        if(iat is null)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingIssuedAt,
                "The assertion is missing the iat claim.");
        }

        //§9.8.1: a cnf claim binds the grant to a key. A cnf that is present but yields no usable jkt
        //thumbprint is rejected rather than silently treated as unbound, which would let a malformed
        //binding downgrade to a Bearer token and skip the proof-of-possession requirement.
        string? confirmationThumbprint = ReadConfirmationThumbprint(payload);
        if(confirmationThumbprint is null && payload.ContainsKey(WellKnownJwtClaimNames.Cnf))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedConfirmation,
                "The assertion cnf claim carries no usable jkt thumbprint.");
        }

        //RFC 8693 §4.1: an act claim on the grant is the delegation chain the redeemed access token
        //continues — "The outermost act claim represents the current actor while nested act claims
        //represent prior actors." A present act that is not a §4.1 actor object is rejected rather than
        //dropped, so a malformed chain can never downgrade a delegated grant to an undelegated token.
        IReadOnlyDictionary<string, object>? act = ReadActorChain(payload);
        if(act is null && payload.ContainsKey(WellKnownJwtClaimNames.Act))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedActor,
                "The assertion act claim is not a well-formed actor object.");
        }

        //RFC 8693 §4.4: a may_act claim names the party the grant's issuer authorized to become the
        //actor. A present may_act that identifies no party is rejected rather than treated as "no
        //constraint", which would turn a malformed claim into a bypass of the constraint it states.
        IReadOnlyDictionary<string, object>? mayAct = ReadAuthorizedActor(payload);
        if(mayAct is null && payload.ContainsKey(WellKnownJwtClaimNames.MayAct))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedAuthorizedActor,
                "The assertion may_act claim is not a well-formed authorized-actor object.");
        }

        //Section 3.1 tenant relationships: the issuer tenant (tenant), the Resource Authorization Server tenant
        //(aud_tenant) and that server's own subject identifier (aud_sub) are surfaced for the Resource
        //Authorization Server's subject-identifier scoping (iss + tenant + sub) and subject resolution. A member
        //that is present and is not a JSON string with at least one character that is not white space is
        //refused rather than read as absent: the tenant decides which namespace the subject is unique in, and a
        //grant read as carrying no tenant is one the library's own comparison rule may decide.
        if(!TryReadOptionalStringClaim(payload, WellKnownJwtClaimNames.Tenant, out string? tenant))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedTenant,
                "The assertion tenant claim is not a JSON string with a character that is not white space.");
        }

        if(!TryReadOptionalStringClaim(payload, WellKnownJwtClaimNames.AudienceTenant, out string? audienceTenant))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedAudienceTenant,
                "The assertion aud_tenant claim is not a JSON string with a character that is not white space.");
        }

        if(!TryReadOptionalStringClaim(payload, WellKnownJwtClaimNames.AudienceSubject, out string? audienceSubject))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedAudienceSubject,
                "The assertion aud_sub claim is not a JSON string with a character that is not white space.");
        }

        //Section 4.4.1: a present scope claim is processed according to Section 3.3 of RFC 6749, so it is a JSON string
        //of scope tokens delimited by single spaces; any other value refuses the grant rather than being read as
        //absent or carried unchecked.
        bool isScopePresent = payload.TryGetValue(WellKnownJwtClaimNames.Scope, out object? scopeRaw);
        string? scope = scopeRaw as string;
        if(isScopePresent && (scope is null || !ScopeTokenSyntax.IsScopeList(scope)))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedScope,
                "The assertion scope claim is not a space-delimited list of scope tokens (RFC 6749 section 3.3).");
        }

        //Section 3.1 makes jti REQUIRED (RFC 7519 Section 4.1.7); the redeem seam carries it onto the grant, where
        //the jwt-bearer grant applies the RFC 7523 Section 3 (rule 7) replay defense. A value of white space only
        //identifies no JWT, as a sub of white space only identifies no principal: refusing it is this library's
        //fail-closed reading, which no sentence of Section 3.1 or Section 4.4.1 states.
        if(!Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.Jti, out string? jti)
            || string.IsNullOrWhiteSpace(jti))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingJti,
                "The assertion is missing the jti claim.");
        }

        //Section 4.4.1: a present resource claim is processed according to Section 2 of RFC 8707, so every value
        //is checked against the resource indicator grammar and surfaced folded; a value outside it refuses the
        //grant rather than being dropped or carried as sent. An empty string and an empty array are refused too,
        //this library's fail-closed reading, which no sentence of Section 3.1 or Section 4.4.1 states. The fold
        //reaches the resource claim only: the grant's own aud is compared as signed by ValidateAudience above,
        //ordinally, so an aud that differs from the issuer in the case of its scheme or host is AudienceMismatch.
        List<string>? resource = ReadStringOrArray(payload, OAuthRequestParameterNames.Resource);
        if(resource is null)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedResource,
                "The assertion resource claim is not an absolute URI (RFC 3986 section 4.3) without a fragment, or an array of such values.");
        }

        //Section 4.4.1: a present authorization_details claim is parsed as a JSON array; the shape of each
        //authorization detail object is the application's to process.
        IReadOnlyList<object>? authorizationDetails = ReadObjectArray(payload, OAuthRequestParameterNames.AuthorizationDetails);
        if(authorizationDetails is null && payload.ContainsKey(OAuthRequestParameterNames.AuthorizationDetails))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedAuthorizationDetails,
                "The assertion authorization_details claim is not a JSON array.");
        }

        //Section 3.1 and Section 3.2.2: the sub_id step, after every Section 4.4.1 and Section 9.3 rule above so
        //the subject it is compared with is the validated one (Section 9.5). Reading the claim never derives
        //trust from it. A presence outside the enumeration is read as Required, as the comparison profile
        //reads it.
        bool isRequired = rule.Presence is not IdJagSubjectIdentifierPresence.Optional;
        bool isJudged = isRequired || rule.Relation is not null;
        bool isPresent = payload.TryGetValue(WellKnownJwtClaimNames.SubId, out object? subIdRaw);
        if(!isPresent && isRequired)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.SubjectIdentifierRequired,
                "The assertion carries no sub_id claim and this server requires one.");
        }

        //RFC 9493 Section 3: a Subject Identifier is an object whose format member names a format, and every
        //member follows the rules of its format; a format the library does not know is carried opaque. The mint
        //reads the same member before it writes the claim.
        SubjectIdentifier? readIdentifier = isPresent && AsClaimObject(subIdRaw) is { } subIdObject
            ? SubjectIdentifier.FromWireObject(subIdObject)
            : null;
        bool isWellFormed = readIdentifier?.IsWellFormed() is true;
        if(isPresent && !isWellFormed && isJudged)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MalformedSubjectIdentifier,
                "The assertion sub_id claim is not a well-formed Subject Identifier.");
        }

        SubjectIdentifier? subjectIdentifier = isWellFormed ? readIdentifier : null;
        bool isAcceptedFormat = subjectIdentifier is null
            || rule.AcceptedFormats.Count == 0
            || rule.AcceptedFormats.Contains(subjectIdentifier.Format);
        if(!isAcceptedFormat && isRequired)
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.UnsupportedSubjectIdentifierFormat,
                "The assertion sub_id claim uses a Subject Identifier Format this server does not support.");
        }

        SamlNameIdSubjectIdentifier? samlSubjectIdentifier = subjectIdentifier is not null
            && SamlNameIdSubjectIdentifier.TryFrom(subjectIdentifier, out SamlNameIdSubjectIdentifier? projectedSubjectIdentifier)
                ? projectedSubjectIdentifier
                : null;

        IdJagAssertionValidationResult result = new()
        {
            Subject = sub,
            Issuer = iss,
            Audience = [audienceValue!],
            Tenant = tenant,
            AudienceTenant = audienceTenant,
            AudienceSubject = audienceSubject,
            SubjectIdentifier = subjectIdentifier,
            SamlNameIdSubjectIdentifier = samlSubjectIdentifier,
            Resource = resource,
            AuthorizationDetails = authorizationDetails,
            ClientId = clientId,
            ConfirmationKeyThumbprint = confirmationThumbprint,
            Act = act,
            MayAct = mayAct,
            Scope = scope,
            Jti = jti,
            IssuedAt = iat,
            Expiration = exp
        };

        //Nothing is compared when the rule neither requires nor compares the claim, or the grant carries none.
        if(!isJudged || subjectIdentifier is null)
        {
            return result;
        }

        //Every judged, present, well-formed claim goes to the comparison profile, which decides a format the rule
        //does not accept as it decides every other candidate.
        reference = new IdJagSubjectContext
        {
            Issuer = iss!,
            Tenant = tenant,
            Subject = sub
        };

        return result;
    }


    /// <summary>
    /// Validates a decoded ID-JAG assertion against the
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// and <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.3">Section 9.3</see>
    /// claim rules and applies <paramref name="rule"/> to its <c>sub_id</c> claim.
    /// </summary>
    /// <param name="header">The decoded (signature-verified) JWT header.</param>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="resourceServerIssuer">
    /// The Resource Authorization Server's own issuer identifier
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 Section 2</see>): the value the grant's
    /// <c>aud</c> must name and that its <c>iss</c> must not equal.
    /// </param>
    /// <param name="authenticatedClientId">
    /// The <c>client_id</c> of the client authenticated on the redeem request: the grant's
    /// <c>client_id</c> claim must equal it.
    /// </param>
    /// <param name="now">The instant the exp, nbf and iat are evaluated against.</param>
    /// <param name="clockSkew">
    /// Tolerance applied to the <c>exp</c>, <c>nbf</c> and <c>iat</c> comparisons: an <c>nbf</c> or an <c>iat</c>
    /// later than the current instant plus this tolerance is <see cref="IdJagValidationFailureReason.NotYetValid"/>.
    /// </param>
    /// <param name="rule">The rule the redeem applies to the grant's <c>sub_id</c> claim.</param>
    /// <param name="cancellationToken">The token that cancels the application's association.</param>
    /// <returns>
    /// A successful <see cref="IdJagAssertionValidationResult"/> carrying the validated claims and, when the
    /// claim was compared, the record of the comparison; or a failed result whose
    /// <see cref="IdJagAssertionValidationResult.FailureReason"/> the caller maps to <c>invalid_grant</c>.
    /// </returns>
    public static async ValueTask<IdJagAssertionValidationResult> ValidateAsync(
        JwtHeader header,
        JwtPayload payload,
        string resourceServerIssuer,
        string authenticatedClientId,
        DateTimeOffset now,
        TimeSpan clockSkew,
        IdJagSubjectIdentifierRule rule,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rule);

        IdJagAssertionValidationResult result = ValidateClaims(
            header, payload, resourceServerIssuer, authenticatedClientId, now, clockSkew, rule, out IdJagSubjectContext? reference);
        if(reference is null)
        {
            return result;
        }

        ComparisonRecord<SubjectIdentifier, IdJagSubjectContext> comparison = await IdJagSubjectIdentifierComparison.CompareAsync(
            result.SubjectIdentifier!, reference, rule, cancellationToken).ConfigureAwait(false);

        //The profile derives the decision; a refusal keeps the record so an audit sees the attempt.
        IdJagAssertionValidationResult decided = comparison.Decision switch
        {
            ComparisonDecision.Permit => result,
            ComparisonDecision.Deny => IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.SubjectIdentifierMismatch,
                "The assertion sub_id claim does not identify the End-User the grant names."),
            _ => IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.SubjectIdentifierUndetermined,
                "Whether the assertion sub_id claim identifies the End-User the grant names could not be decided.")
        };

        return decided with { SubjectIdentifierComparison = comparison };
    }


    /// <summary>
    /// Maps the outcome of the shared time-claim rules
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> items 4 to 6, read by
    /// <see cref="Rfc7523AssertionValidation.ValidateTemporalClaims"/>) to the ID-JAG failure reason of the same
    /// name. <see cref="Rfc7523TemporalOutcome.Valid"/>, which the caller never passes, and a value outside the
    /// enumeration map to <see cref="IdJagValidationFailureReason.InconsistentTemporalClaims"/>, so the map fails
    /// closed.
    /// </summary>
    /// <param name="outcome">The outcome of the time-claim rules.</param>
    /// <returns>The ID-JAG failure reason.</returns>
    private static IdJagValidationFailureReason MapTemporalFailure(Rfc7523TemporalOutcome outcome) => outcome switch
    {
        Rfc7523TemporalOutcome.MissingExpiration => IdJagValidationFailureReason.MissingExpiration,
        Rfc7523TemporalOutcome.Expired => IdJagValidationFailureReason.Expired,
        Rfc7523TemporalOutcome.NotYetValid => IdJagValidationFailureReason.NotYetValid,
        Rfc7523TemporalOutcome.InconsistentTemporalClaims => IdJagValidationFailureReason.InconsistentTemporalClaims,
        Rfc7523TemporalOutcome.Valid => IdJagValidationFailureReason.InconsistentTemporalClaims,

        _ => IdJagValidationFailureReason.InconsistentTemporalClaims
    };


    /// <summary>
    /// Reads the <c>authorization_details</c> claim as the JSON array
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// requires ("MUST parse it as a JSON array"), its elements as decoded: the shape of each authorization
    /// detail object is the application's to process
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>).
    /// </summary>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="claimName">The name of the claim, <c>authorization_details</c>.</param>
    /// <returns>
    /// The array, or <see langword="null"/> when the claim is absent or is not a JSON array; the caller refuses
    /// a present claim this answers <see langword="null"/> for.
    /// </returns>
    private static IReadOnlyList<object>? ReadObjectArray(JwtPayload payload, string claimName) =>
        payload.TryGetValue(claimName, out object? raw) && raw is IReadOnlyList<object> list
            ? list
            : null;


    /// <summary>
    /// Reads an optional string claim as one of three things: absent; a JSON string with at least one
    /// character that is not white space (<see cref="string.IsNullOrWhiteSpace(string?)"/> answers
    /// <see langword="false"/> for it); or malformed. A claim that is present in any other shape (a number, an
    /// object, a JSON null, an empty string, a string of white space only) is a defect of the grant, which the
    /// caller refuses rather than reading the claim as absent: a value of white space only names no tenant and
    /// no subject, as a <c>sub</c> of white space only names no principal.
    /// </summary>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="claimName">The name of the claim.</param>
    /// <param name="value">
    /// The claim's value when it is a JSON string with at least one character that is not white space;
    /// otherwise <see langword="null"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when the claim is absent or is a JSON string with at least one character that is
    /// not white space; <see langword="false"/> when it is present and malformed.
    /// </returns>
    private static bool TryReadOptionalStringClaim(JwtPayload payload, string claimName, out string? value)
    {
        bool isPresent = payload.TryGetValue(claimName, out object? raw);
        value = raw is string text && !string.IsNullOrWhiteSpace(text) ? text : null;

        return !isPresent || value is not null;
    }


    /// <summary>
    /// Reads the <c>jkt</c> member of the grant's <c>cnf</c> claim, the JWK SHA-256 thumbprint that binds the grant
    /// to a proof-of-possession key
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-9.8.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 9.8.1</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>;
    /// <see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 Section 3.1</see>).
    /// </summary>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <returns>
    /// The thumbprint, or <see langword="null"/> when the claim is absent, is not a JSON object, or carries no
    /// non-empty string <c>jkt</c>; the caller refuses a present claim this answers <see langword="null"/> for.
    /// </returns>
    private static string? ReadConfirmationThumbprint(JwtPayload payload)
    {
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Cnf, out object? raw))
        {
            return null;
        }

        //RFC 9449 §6.1: cnf is a JSON object whose jkt member is the JWK SHA-256 thumbprint.
        return raw switch
        {
            IReadOnlyDictionary<string, object> ro
                when ro.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? v) && v is string jkt && !string.IsNullOrEmpty(jkt) => jkt,
            IDictionary<string, object> rw
                when rw.TryGetValue(WellKnownJwtClaimNames.JwkThumbprint, out object? v) && v is string jkt && !string.IsNullOrEmpty(jkt) => jkt,
            _ => null
        };
    }


    /// <summary>
    /// The deepest <c>act</c> nesting this validator reads. A delegation chain holds one link per hop
    /// actually taken (RFC 8693 §4.1), so a deeper chain describes no reachable delegation and is
    /// treated as malformed — bounding the recursion a caller-built payload could otherwise drive.
    /// </summary>
    private const int MaxActorChainDepth = 16;


    /// <summary>
    /// Reads the grant's <c>act</c> claim as an RFC 8693 §4.1 delegation chain.
    /// </summary>
    /// <param name="payload">The decoded assertion payload.</param>
    /// <returns>
    /// The chain when the claim is present and well-formed, or <see langword="null"/> when it is absent
    /// or malformed — the caller distinguishes the two by claim presence.
    /// </returns>
    private static IReadOnlyDictionary<string, object>? ReadActorChain(JwtPayload payload) =>
        payload.TryGetValue(WellKnownJwtClaimNames.Act, out object? raw)
            ? ReadActorLink(raw, MaxActorChainDepth)
            : null;


    /// <summary>
    /// Reads one link of an RFC 8693 §4.1 delegation chain — an object whose members "identify the
    /// actor" and whose optional nested <c>act</c> member is the prior actor. A link that names no
    /// <c>sub</c>, that states an <c>iss</c> in any shape other than an identifier, or whose nested
    /// prior actor is itself not a link, makes the whole chain malformed: the chain is read wholly or
    /// not at all, so no part of a delegation history is silently discarded.
    /// </summary>
    /// <param name="value">The decoded claim value of this link.</param>
    /// <param name="remainingDepth">The nesting budget left for this link and the ones beneath it.</param>
    /// <returns>The link, or <see langword="null"/> when it is not a well-formed actor object.</returns>
    private static IReadOnlyDictionary<string, object>? ReadActorLink(object? value, int remainingDepth)
    {
        if(remainingDepth <= 0)
        {
            return null;
        }

        IReadOnlyDictionary<string, object>? actor = AsClaimObject(value);
        if(actor is null)
        {
            return null;
        }

        if(!actor.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subRaw)
            || subRaw is not string actorSubject
            || string.IsNullOrEmpty(actorSubject))
        {
            return null;
        }

        //§4.1: "the combination of the two claims iss and sub might be necessary to uniquely identify
        //an actor." An iss present as anything but a non-empty string identifies no namespace, and the
        //link is copied verbatim onto the access token this redemption issues — where the resource
        //server's own reading of §4.1, JwsAccessTokenValidator, rejects exactly that shape. Reading the
        //member the same way at both ends is what keeps redemption from minting a token whose actor
        //claim the resource it was minted for can never validate.
        if(!IsIdentityMemberReadable(actor, WellKnownJwtClaimNames.Iss))
        {
            return null;
        }

        if(actor.TryGetValue(WellKnownJwtClaimNames.Act, out object? nestedRaw)
            && ReadActorLink(nestedRaw, remainingDepth - 1) is null)
        {
            return null;
        }

        return actor;
    }


    /// <summary>
    /// Reads the grant's <c>may_act</c> claim as an RFC 8693 §4.4 authorized-actor object — one whose
    /// members "identify the party that is asserted as being eligible to act", which the §4.4 text
    /// identifies by <c>sub</c>, optionally combined with <c>iss</c>.
    /// </summary>
    /// <param name="payload">The decoded assertion payload.</param>
    /// <returns>
    /// The authorized-actor object, or <see langword="null"/> when the claim is absent, states an
    /// identity member in a shape that is not an identifier, or identifies no party at all — the caller
    /// distinguishes absence from the malformed cases by claim presence.
    /// </returns>
    private static IReadOnlyDictionary<string, object>? ReadAuthorizedActor(JwtPayload payload)
    {
        if(!payload.TryGetValue(WellKnownJwtClaimNames.MayAct, out object? raw))
        {
            return null;
        }

        IReadOnlyDictionary<string, object>? authorizedActor = AsClaimObject(raw);
        if(authorizedActor is null)
        {
            return null;
        }

        //§4.4: "the combination of the two claims iss and sub are sometimes necessary to uniquely
        //identify an authorized actor." A member present in any other shape states half of that pair
        //unreadably, and ignoring it would relax the claim to whichever half happened to parse — a
        //narrower authorization silently widened by a malformed member. The same reading as the act
        //links above and as the resource side applies to the claim it receives.
        if(!IsIdentityMemberReadable(authorizedActor, WellKnownJwtClaimNames.Sub)
            || !IsIdentityMemberReadable(authorizedActor, WellKnownJwtClaimNames.Iss))
        {
            return null;
        }

        bool namesSubject = HasIdentityMember(authorizedActor, WellKnownJwtClaimNames.Sub);
        bool namesIssuer = HasIdentityMember(authorizedActor, WellKnownJwtClaimNames.Iss);

        return namesSubject || namesIssuer ? authorizedActor : null;
    }


    /// <summary>
    /// Whether an actor or authorized-actor object identifies its party by the given member — present,
    /// a string, and non-empty.
    /// </summary>
    /// <param name="claimObject">The actor or authorized-actor object.</param>
    /// <param name="member">The member name.</param>
    /// <returns><see langword="true"/> when the member identifies the party.</returns>
    private static bool HasIdentityMember(IReadOnlyDictionary<string, object> claimObject, string member) =>
        claimObject.TryGetValue(member, out object? raw) && raw is string value && !string.IsNullOrEmpty(value);


    /// <summary>
    /// Whether a member of an actor or authorized-actor object is readable as the identity it states:
    /// either absent, or present as a non-empty string. RFC 8693 §4.1/§4.4 describe these members as
    /// "claims that identify" the party, so a member present in any other shape states an identity
    /// nothing downstream can compare — a defect of the claim, and a different condition from the party
    /// simply not being identified by that member.
    /// </summary>
    /// <param name="claimObject">The actor or authorized-actor object.</param>
    /// <param name="member">The member name.</param>
    /// <returns><see langword="true"/> when the member is absent or is an identifier.</returns>
    private static bool IsIdentityMemberReadable(IReadOnlyDictionary<string, object> claimObject, string member) =>
        !claimObject.TryGetValue(member, out object? raw) || (raw is string value && !string.IsNullOrEmpty(value));


    /// <summary>
    /// Views a decoded nested JSON object claim value as a read-only dictionary, accepting either the
    /// read-only or the mutable dictionary shape a JWT payload parser may produce; any other value is
    /// not an object. The one claim-object view of the ID-JAG readers: the <c>sub_id</c> step here and
    /// <see cref="SamlNameIdSubjectIdentifier.TryParse"/> read a claim through it.
    /// </summary>
    /// <param name="value">The decoded claim value.</param>
    /// <returns>The object view, or <see langword="null"/> when the value is not a JSON object.</returns>
    internal static IReadOnlyDictionary<string, object>? AsClaimObject(object? value) => value switch
    {
        IReadOnlyDictionary<string, object> readOnly => readOnly,
        IDictionary<string, object> mutable => new Dictionary<string, object>(mutable, StringComparer.Ordinal),
        _ => null
    };


    /// <summary>
    /// Reads the <c>resource</c> claim, which
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">Section 3.1</see>
    /// carries as "either a single URI or an array of URIs", as one of three things: absent, read as no value;
    /// a JSON string, or a non-empty JSON array whose every element is a JSON string, each value accepted by
    /// <see cref="ResourceIndicator.Parse"/> (the
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.3">RFC 3986 Section 4.3</see>
    /// <c>absolute-URI</c> without a fragment that
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see> requires); or
    /// malformed. Every accepted value is surfaced folded, as its <see cref="ResourceIndicator.ComparisonKey"/>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 Section 6.2.2.1</see>: the
    /// scheme and host lowered, every other part as sent), in the order given. An empty string, an empty array,
    /// an element that is not a JSON string, a value the grammar refuses and any other JSON type are malformed:
    /// one bad element refuses the claim whole, so no value is dropped and no value is carried unchecked.
    /// </summary>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="claimName">The name of the claim, <c>resource</c>.</param>
    /// <returns>
    /// The folded values, empty when the claim is absent; <see langword="null"/> when the claim is present and
    /// malformed.
    /// </returns>
    private static List<string>? ReadStringOrArray(JwtPayload payload, string claimName)
    {
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return [];
        }

        if(raw is string single)
        {
            Result<ResourceIndicator, ResourceIndicatorFault> parsedSingle = ResourceIndicator.Parse(single);

            return parsedSingle.IsSuccess ? [parsedSingle.Value.ComparisonKey] : null;
        }

        //Array elements decode as object (List<object>, a covariant string[] or typed list of strings included).
        if(raw is not IEnumerable<object?> elements)
        {
            return null;
        }

        List<string> folded = [];
        foreach(object? element in elements)
        {
            if(element is not string value)
            {
                return null;
            }

            Result<ResourceIndicator, ResourceIndicatorFault> parsed = ResourceIndicator.Parse(value);
            if(!parsed.IsSuccess)
            {
                return null;
            }

            folded.Add(parsed.Value.ComparisonKey);
        }

        return folded.Count == 0 ? null : folded;
    }
}
