using System.Diagnostics;

using Verifiable.JCose;

namespace Verifiable.OAuth.IdJag;

/// <summary>
/// The delegation outcome of redeeming an Identity Assertion JWT Authorization Grant (ID-JAG) at a
/// Resource Authorization Server — which
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> <c>act</c>
/// (actor) claim the issued access token carries, or that the redemption is refused because the
/// redeeming client is not the party the grant's
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">§4.4</see> <c>may_act</c> claim
/// authorized to act.
/// </summary>
/// <remarks>
/// Recording the actor at the redemption boundary is a profile decision this authorization server
/// makes, exercising the permission RFC 8693 §1.1 grants ("When and if a composite token is issued is
/// at the discretion of the authorization server and applicable policy and configuration"):
/// draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3 / §9.7 explicitly defines no
/// actor processing and leaves it to profiles, and draft-ietf-oauth-identity-chaining-16 §2.4 — the
/// redemption leg — never mentions <c>act</c> at all. Once the permission is exercised every §4.1
/// clause binds the composite token this server issues, which is what these outcomes encode.
/// </remarks>
public enum IdJagActorDecisionKind
{
    /// <summary>
    /// The grant records no prior actor and the redeeming client is the token's own <c>sub</c>: it acts
    /// directly on its own behalf, which RFC 8693 §1.1 places outside both delegation and impersonation
    /// ("When a principal is acting directly on its own behalf ... neither delegation nor impersonation
    /// are in play"). No <c>act</c> claim is emitted — a self-referential actor would blur the §1.1
    /// boundary by asserting a delegation that never happened.
    /// </summary>
    NoDelegation,

    /// <summary>
    /// The grant carries an <c>act</c> chain whose current (outermost) actor already is the redeeming
    /// client — the same party, identified by the <c>sub</c>/<c>iss</c> combination §4.1 calls out
    /// rather than by a bare subject string: the chain is copied onto the issued access token
    /// unchanged. The current actor has not changed at this boundary, so nesting the chain under a copy
    /// of itself would fabricate a delegation step and violate §4.1's "The outermost <c>act</c> claim
    /// represents the current actor while nested <c>act</c> claims represent prior actors."
    /// </summary>
    ChainPreserved,

    /// <summary>
    /// The grant carries an <c>act</c> chain whose current actor is not the redeeming client: the
    /// redeeming client becomes the new current actor and the grant's chain nests under it as the prior
    /// actors, per §4.1's "A chain of delegation can be expressed by nesting one <c>act</c> claim within
    /// another ... The least recent actor is the most deeply nested."
    /// </summary>
    ChainExtended,

    /// <summary>
    /// The grant carries no <c>act</c> chain and the redeeming client differs from the token's <c>sub</c>:
    /// the client acts for a subject that is not itself, so the issued token records that single
    /// delegation step as <c>act</c> = <c>{ "sub": &lt;redeeming client&gt; }</c>. The token's <c>sub</c>
    /// remains the subject — RFC 8693 §1.1 delegation ("principal A still has its own identity separate
    /// from B"), not impersonation, which would instead replace <c>sub</c> with the client.
    /// </summary>
    DelegationRecorded,

    /// <summary>
    /// The grant's <c>may_act</c> claim does not authorize the redeeming client to become the actor
    /// (RFC 8693 §4.4): the redemption is refused rather than issuing a token whose <c>act</c> names a
    /// party the grant's issuer never authorized.
    /// </summary>
    RefuseUnauthorizedActor,

    /// <summary>
    /// The grant's <c>act</c> claim is not a §4.1 actor object — it names no current actor — so neither
    /// preserving nor extending the chain can identify who is acting. The redemption is refused rather
    /// than silently dropping the chain, which would downgrade a delegated grant to an undelegated
    /// access token.
    /// </summary>
    RefuseMalformedActor
}


/// <summary>
/// Composes the <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>
/// <c>act</c> (actor) claim of the access token minted when an Identity Assertion JWT Authorization
/// Grant is redeemed, and enforces the grant's
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">§4.4</see> <c>may_act</c> claim
/// against the redeeming client.
/// </summary>
/// <remarks>
/// <para>
/// Stamping <c>act</c> here is this authorization server's profile decision, not a mandate of the
/// specifications it implements: draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.3
/// and §9.7 state that specification "does not define normative processing requirements for
/// <c>actor_token</c> or whether an <c>act</c> claim is included in the issued ID-JAG" and leave it to
/// profiles; draft-ietf-oauth-identity-chaining-16 §2.4 — the leg that turns the grant into an access
/// token — never mentions <c>act</c>; and RFC 8693 §1.1 makes composite-token issuance discretionary
/// ("When and if a composite token is issued is at the discretion of the authorization server and
/// applicable policy and configuration"). This profile exercises that discretion, and having done so
/// every §4.1 rule binds the token it issues: the outermost <c>act</c> is the current actor, prior
/// actors nest inside with the least recent deepest, and the token's <c>sub</c> stays the subject so
/// the §1.1 delegation boundary ("principal A still has its own identity separate from B ... any
/// actions taken are being taken by A representing B") is never blurred into impersonation.
/// </para>
/// <para>
/// The decision is pure so each case is testable on its own; the redeeming client's identity, the
/// grant's chain and the grant's authorized-actor statement all reach it through
/// <see cref="JwtBearer.JwtBearerGrant"/>, which the application's
/// <see cref="Server.ValidateJwtBearerAssertionDelegate"/> shapes from
/// <see cref="IdJagAssertionValidationResult"/>. §4.1's consumer rule — "the consumer of a token MUST
/// only consider the token's top-level claims and the party identified as the current actor" — is why
/// only the current actor is ever compared here: the nested prior actors are history and authorize
/// nothing.
/// </para>
/// </remarks>
[DebuggerDisplay("IdJagActorDecision {Kind}")]
public sealed record IdJagActorDecision
{
    /// <summary>The delegation outcome of the redemption.</summary>
    public required IdJagActorDecisionKind Kind { get; init; }

    /// <summary>
    /// The <c>act</c> claim to emit on the issued access token — the current actor's identity object
    /// with any prior actors under its nested <c>act</c> member (§4.1) — or <see langword="null"/> when
    /// the redemption records no delegation or is refused. Flows to
    /// <see cref="IssuanceContext.Act"/>, which the RFC 9068 access-token producer emits verbatim under
    /// the IANA-registered claim name RFC 9068 §2.2.2 directs it to reuse.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Act { get; init; }

    /// <summary>
    /// Whether the outcome refuses the redemption (one of the <c>Refuse*</c> kinds), in which case the
    /// caller answers <c>invalid_grant</c> and no token is issued.
    /// </summary>
    public bool IsRefused => Kind
        is IdJagActorDecisionKind.RefuseUnauthorizedActor
        or IdJagActorDecisionKind.RefuseMalformedActor;


    /// <summary>
    /// Applies the redemption-leg actor composition and the §4.4 authorized-actor check.
    /// </summary>
    /// <param name="grantActor">
    /// The redeemed grant's <c>act</c> claim — the delegation chain the ID-JAG already carries — or
    /// <see langword="null"/> when it carries none. Sourced from
    /// <see cref="JwtBearer.JwtBearerGrant.Act"/>.
    /// </param>
    /// <param name="grantAuthorizedActor">
    /// The redeemed grant's <c>may_act</c> claim — the party its issuer authorized to become the actor
    /// (§4.4) — or <see langword="null"/> when the grant constrains the actor in no way. Sourced from
    /// <see cref="JwtBearer.JwtBearerGrant.MayAct"/>.
    /// </param>
    /// <param name="redeemingClientId">
    /// The <c>client_id</c> of the client authenticated on the redeem request — the party that acts at
    /// this boundary, identified within this Resource Authorization Server's own issuer namespace.
    /// </param>
    /// <param name="subject">The issued token's <c>sub</c> — the principal access is requested for.</param>
    /// <param name="resourceServerIssuer">
    /// This Resource Authorization Server's issuer identifier — the namespace
    /// <paramref name="redeemingClientId"/> is an identifier in, compared against a <c>may_act</c> that
    /// identifies its authorized actor by an <c>iss</c> member as well as a <c>sub</c>.
    /// </param>
    /// <returns>The decision.</returns>
    public static IdJagActorDecision Evaluate(
        IReadOnlyDictionary<string, object>? grantActor,
        IReadOnlyDictionary<string, object>? grantAuthorizedActor,
        string redeemingClientId,
        string subject,
        string resourceServerIssuer)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(redeemingClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceServerIssuer);

        //§4.1: "The act claim value is a JSON object, and members in the JSON object are claims that
        //identify the actor." A chain whose outermost object names no actor identifies nobody, so the
        //current actor cannot be established — fail closed rather than issue a token that drops it.
        string? currentActor = null;
        if(grantActor is not null && !TryReadActorSubject(grantActor, out currentActor))
        {
            return new IdJagActorDecision { Kind = IdJagActorDecisionKind.RefuseMalformedActor };
        }

        //§1.1: "When a principal is acting directly on its own behalf ... neither delegation nor
        //impersonation are in play." The grant records no prior actor and the redeeming client is the
        //subject itself, so no party becomes an actor: no act claim, and the §4.4 authorized-actor
        //statement is not engaged because there is no actor for it to authorize.
        if(grantActor is null && string.Equals(redeemingClientId, subject, StringComparison.Ordinal))
        {
            return new IdJagActorDecision { Kind = IdJagActorDecisionKind.NoDelegation };
        }

        //§4.4: the may_act claim "can be used by the authorization server to determine whether the
        //client ... is authorized to engage in the requested delegation or impersonation." Every
        //remaining outcome makes the redeeming client the current actor of the issued token, so the
        //grant's statement about who may act is enforced against exactly that client.
        if(grantAuthorizedActor is not null
            && !IsAuthorizedActor(grantAuthorizedActor, redeemingClientId, resourceServerIssuer))
        {
            return new IdJagActorDecision { Kind = IdJagActorDecisionKind.RefuseUnauthorizedActor };
        }

        if(grantActor is not null)
        {
            //§4.1: "The outermost act claim represents the current actor." Whether that actor already
            //IS the redeeming client is an identity comparison, not a comparison of sub alone — §4.1:
            //"the combination of the two claims iss and sub might be necessary to uniquely identify an
            //actor" — so the chain crosses unchanged only when its outermost sub names the redeeming
            //client AND the object states either no issuer or this server's own, the same pair rule
            //IsAuthorizedActor applies to may_act. Any other combination is a different party, most
            //sharply a foreign-issuer actor whose sub merely string-collides with a client_id of this
            //server, and takes the extending branch below. That is the fail-safe direction: recording
            //a delegation hop between parties that may turn out to be the same is honest history the
            //§4.1 consumer rule already confines to the outermost actor, whereas preserving the chain
            //on a collision would suppress the delegation record this composition exists to make.
            if(string.Equals(currentActor, redeemingClientId, StringComparison.Ordinal)
                && IsActorInIssuerNamespace(grantActor, resourceServerIssuer))
            {
                return new IdJagActorDecision
                {
                    Kind = IdJagActorDecisionKind.ChainPreserved,
                    Act = grantActor
                };
            }

            //§4.1: "A chain of delegation can be expressed by nesting one act claim within another ...
            //The least recent actor is the most deeply nested." The redeeming client is the new current
            //actor and the grant's chain becomes the prior actors beneath it.
            return new IdJagActorDecision
            {
                Kind = IdJagActorDecisionKind.ChainExtended,
                Act = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [WellKnownJwtClaimNames.Sub] = redeemingClientId,
                    [WellKnownJwtClaimNames.Act] = grantActor
                }
            };
        }

        //§1.1: the client "still has its own identity separate from" the subject and is acting for it,
        //so the single hop that just happened is recorded as the current actor. The token's sub stays
        //the subject, which is what separates this from impersonation.
        return new IdJagActorDecision
        {
            Kind = IdJagActorDecisionKind.DelegationRecorded,
            Act = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = redeemingClientId
            }
        };
    }


    /// <summary>
    /// Reads the <c>sub</c> member identifying the actor of one <c>act</c> object (§4.1).
    /// </summary>
    /// <param name="actor">The actor object.</param>
    /// <param name="actorSubject">The actor's <c>sub</c> when present and non-empty; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the object names an actor.</returns>
    private static bool TryReadActorSubject(IReadOnlyDictionary<string, object> actor, out string? actorSubject)
    {
        actorSubject = actor.TryGetValue(WellKnownJwtClaimNames.Sub, out object? raw)
            && raw is string sub
            && !string.IsNullOrEmpty(sub)
                ? sub
                : null;

        return actorSubject is not null;
    }


    /// <summary>
    /// Whether an <c>act</c> object states the identity of its actor within the issuer namespace the
    /// redeeming client's identifier belongs to — either by carrying no <c>iss</c> member at all, which
    /// leaves the <c>sub</c> unqualified and readable in this server's own namespace, or by naming that
    /// issuer. §4.1: "the combination of the two claims <c>iss</c> and <c>sub</c> might be necessary to
    /// uniquely identify an actor", so an <c>iss</c> naming any other namespace — or stated in any shape
    /// that is not an identifier at all — describes a party this server cannot recognize as its own
    /// client even when the two subjects are the same string.
    /// </summary>
    /// <param name="actor">The outermost <c>act</c> object.</param>
    /// <param name="resourceServerIssuer">The issuer namespace the redeeming client is identified in.</param>
    /// <returns><see langword="true"/> when the actor's identity is stated in that namespace.</returns>
    private static bool IsActorInIssuerNamespace(IReadOnlyDictionary<string, object> actor, string resourceServerIssuer) =>
        !actor.TryGetValue(WellKnownJwtClaimNames.Iss, out object? raw)
            || (raw is string issuer && string.Equals(issuer, resourceServerIssuer, StringComparison.Ordinal));


    /// <summary>
    /// Decides whether a <c>may_act</c> object authorizes the redeeming client to become the actor
    /// (§4.4). Every member that identifies the authorized party must match: the <c>sub</c> against the
    /// client's identifier and, when the object identifies its party by issuer as well, the <c>iss</c>
    /// against the issuer namespace that identifier belongs to — "the combination of the two claims
    /// <c>iss</c> and <c>sub</c> are sometimes necessary to uniquely identify an authorized actor", so a
    /// matching <c>sub</c> under a different issuer is a different, unauthorized party.
    /// </summary>
    /// <param name="authorizedActor">The grant's <c>may_act</c> object.</param>
    /// <param name="redeemingClientId">The redeeming client's identifier.</param>
    /// <param name="resourceServerIssuer">The issuer namespace the redeeming client is identified in.</param>
    /// <returns><see langword="true"/> when the redeeming client is the authorized actor.</returns>
    private static bool IsAuthorizedActor(
        IReadOnlyDictionary<string, object> authorizedActor,
        string redeemingClientId,
        string resourceServerIssuer)
    {
        string? authorizedSubject = ReadIdentityMember(authorizedActor, WellKnownJwtClaimNames.Sub);
        string? authorizedIssuer = ReadIdentityMember(authorizedActor, WellKnownJwtClaimNames.Iss);

        //§4.4: the members "identify the party that is asserted as being eligible to act". An object
        //naming neither a sub nor an iss identifies no party, so it authorizes none — fail closed.
        if(authorizedSubject is null && authorizedIssuer is null)
        {
            return false;
        }

        bool isSubjectAuthorized = authorizedSubject is null
            || string.Equals(authorizedSubject, redeemingClientId, StringComparison.Ordinal);
        bool isIssuerAuthorized = authorizedIssuer is null
            || string.Equals(authorizedIssuer, resourceServerIssuer, StringComparison.Ordinal);

        return isSubjectAuthorized && isIssuerAuthorized;
    }


    /// <summary>
    /// Reads a string identity member of an <c>act</c> / <c>may_act</c> object, treating an absent,
    /// non-string or empty value as "the object does not identify its party by this member".
    /// </summary>
    /// <param name="claimObject">The actor or authorized-actor object.</param>
    /// <param name="member">The member name.</param>
    /// <returns>The member value, or <see langword="null"/>.</returns>
    private static string? ReadIdentityMember(IReadOnlyDictionary<string, object> claimObject, string member) =>
        claimObject.TryGetValue(member, out object? raw) && raw is string value && !string.IsNullOrEmpty(value)
            ? value
            : null;
}
