
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
/// <see cref="Jws.VerifyAndDecodeAsync"/>), and then calls <see cref="Validate"/> to enforce the
/// ID-JAG-specific claim rules. On success the caller shapes a
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
///   <item><description><c>sub</c> and <c>exp</c> are present, the temporal claims are consistent, and the grant is neither expired nor not-yet-valid (RFC 7521 §5.2).</description></item>
///   <item><description>
///     an <c>act</c> or <c>may_act</c> claim, when present, is a well-formed
///     <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> /
///     <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">§4.4</see> object — not a §4.4.1
///     rule (ID-JAG §4.3/§9.7 defines no actor processing), but a fail-closed read: a delegation this
///     server cannot parse is refused rather than dropped from the token it would issue.
///   </description></item>
/// </list>
/// <para>
/// The <c>iss</c>/<c>sub</c>/<c>aud</c>/<c>exp</c>/<c>nbf</c>/<c>iat</c> checks above are the generic
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> rule set every jwt-bearer
/// assertion (ID-JAG or otherwise) must satisfy; this type CONSUMES
/// <see cref="Rfc7523AssertionValidation"/> for those checks and layers only the ID-JAG-specific ones
/// (<c>typ</c>, same-trust-domain, <c>client_id</c>) around them, so the §3 rules have exactly one
/// implementation.
/// </para>
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
    /// <param name="now">The current instant for expiry / not-before evaluation.</param>
    /// <param name="clockSkew">Tolerance applied to the <c>exp</c> and <c>nbf</c> comparisons.</param>
    /// <returns>
    /// A successful <see cref="IdJagAssertionValidationResult"/> carrying the validated claims, or a
    /// failed result whose <see cref="IdJagAssertionValidationResult.FailureReason"/> the caller maps
    /// to <c>invalid_grant</c>.
    /// </returns>
    public static IdJagAssertionValidationResult Validate(
        JwtHeader header,
        JwtPayload payload,
        string resourceServerIssuer,
        string authenticatedClientId,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
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

        //§3 item 2 (RFC 7521 §5.2 / RFC 7523 §3 rule 2.A): the subject the access is requested for.
        if(!Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.Sub, out string? sub))
        {
            return IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.MissingSubject,
                "The assertion is missing the sub claim.");
        }

        //§3 items 4–6 (RFC 7521 §5.2 / RFC 7523 §3): exp REQUIRED and not expired; nbf/iat OPTIONAL but,
        //when present, numeric and temporally consistent.
        Rfc7523TemporalOutcome temporalOutcome = Rfc7523AssertionValidation.ValidateTemporalClaims(
            payload, now, clockSkew, out DateTimeOffset exp, out DateTimeOffset? iat, out string? temporalFailureDescription);
        if(temporalOutcome != Rfc7523TemporalOutcome.Valid)
        {
            return IdJagAssertionValidationResult.Failure(MapTemporalFailure(temporalOutcome), temporalFailureDescription);
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

        string? scope = Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.Scope, out string? scopeValue)
            ? scopeValue
            : null;

        //§3.1 / RFC 7519 §4.1.7: surface jti so a Resource Authorization Server can apply the RFC 7523
        //§3 (rule 7) replay defense from its own store. Not a §4.4.1 MUST, so absence does not fail here.
        string? jti = Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.Jti, out string? jtiValue) ? jtiValue : null;

        //§3.1 tenant relationships: the issuer-tenant (tenant), the Resource Authorization Server tenant
        //(aud_tenant) and that server's own subject identifier (aud_sub) are surfaced for the Resource
        //Authorization Server's subject-identifier scoping (iss + tenant + sub) and subject resolution.
        string? tenant = Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.Tenant, out string? tenantValue) ? tenantValue : null;
        string? audienceTenant = Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.AudienceTenant, out string? audienceTenantValue) ? audienceTenantValue : null;
        string? audienceSubject = Rfc7523AssertionValidation.TryReadStringClaim(payload, WellKnownJwtClaimNames.AudienceSubject, out string? audienceSubjectValue) ? audienceSubjectValue : null;

        //§3.2 / §9.5: surface the saml-nameid sub_id (when well-formed) for the Resource Authorization
        //Server's subject resolution. Parsing never derives trust from sub_id — the grant is already
        //validated by iss / signature / audience / client binding above.
        SamlNameIdSubjectIdentifier? subjectIdentifier =
            payload.TryGetValue(WellKnownJwtClaimNames.SubId, out object? subIdRaw)
            && SamlNameIdSubjectIdentifier.TryParse(subIdRaw, out SamlNameIdSubjectIdentifier? parsedSubjectIdentifier)
                ? parsedSubjectIdentifier
                : null;

        return new IdJagAssertionValidationResult
        {
            Subject = sub,
            Issuer = iss,
            Audience = [audienceValue!],
            Tenant = tenant,
            AudienceTenant = audienceTenant,
            AudienceSubject = audienceSubject,
            SubjectIdentifier = subjectIdentifier,
            Resource = ReadStringOrArray(payload, OAuthRequestParameterNames.Resource),
            AuthorizationDetails = ReadObjectArray(payload, OAuthRequestParameterNames.AuthorizationDetails),
            ClientId = clientId,
            ConfirmationKeyThumbprint = confirmationThumbprint,
            Act = act,
            MayAct = mayAct,
            Scope = scope,
            Jti = jti,
            IssuedAt = iat,
            Expiration = exp
        };
    }


    private static IdJagValidationFailureReason MapTemporalFailure(Rfc7523TemporalOutcome outcome) => outcome switch
    {
        Rfc7523TemporalOutcome.MissingExpiration => IdJagValidationFailureReason.MissingExpiration,
        Rfc7523TemporalOutcome.Expired => IdJagValidationFailureReason.Expired,
        Rfc7523TemporalOutcome.NotYetValid => IdJagValidationFailureReason.NotYetValid,
        _ => IdJagValidationFailureReason.InconsistentTemporalClaims
    };


    private static IReadOnlyList<object>? ReadObjectArray(JwtPayload payload, string claimName) =>
        payload.TryGetValue(claimName, out object? raw) && raw is IReadOnlyList<object> list
            ? list
            : null;


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
    /// not an object.
    /// </summary>
    /// <param name="value">The decoded claim value.</param>
    /// <returns>The object view, or <see langword="null"/> when the value is not a JSON object.</returns>
    private static IReadOnlyDictionary<string, object>? AsClaimObject(object? value) => value switch
    {
        IReadOnlyDictionary<string, object> readOnly => readOnly,
        IDictionary<string, object> mutable => new Dictionary<string, object>(mutable, StringComparer.Ordinal),
        _ => null
    };


    private static List<string> ReadStringOrArray(JwtPayload payload, string claimName)
    {
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return [];
        }

        if(raw is string s)
        {
            return string.IsNullOrEmpty(s) ? [] : [s];
        }

        //Array elements may decode as object (List<object>, including covariant string[]) or, when
        //a typed list is supplied, as string. Keep every non-empty string; ignore other shapes.
        if(raw is IEnumerable<object> mixed)
        {
            List<string> list = [];
            foreach(object item in mixed)
            {
                if(item is string str && !string.IsNullOrEmpty(str))
                {
                    list.Add(str);
                }
            }

            return list;
        }

        if(raw is IEnumerable<string> typed)
        {
            List<string> list = [];
            foreach(string item in typed)
            {
                if(!string.IsNullOrEmpty(item))
                {
                    list.Add(item);
                }
            }

            return list;
        }

        return [];
    }
}
