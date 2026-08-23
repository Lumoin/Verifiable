using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// The party identified as the current actor by an access token's <c>act</c> (actor) claim per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> — the party to
/// whom the token's subject has delegated authority, and the only actor a resource server may consider
/// when applying access control policy.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8693 §4.1: "The outermost 'act' claim represents the current actor while nested 'act' claims
/// represent prior actors. The least recent actor is the most deeply nested." This type is that
/// outermost object: <see cref="Subject"/> — and <see cref="Issuer"/> where "the combination of the
/// two claims 'iss' and 'sub' might be necessary to uniquely identify an actor" — name the current
/// actor, while every nested prior actor is surfaced, read-only, through
/// <see cref="DelegationHistory"/>.
/// </para>
/// <para>
/// RFC 8693 §4.1 binds the consumer: "For the purpose of applying access control policy, the consumer
/// of a token MUST only consider the token's top-level claims and the party identified as the current
/// actor by the 'act' claim. Prior actors identified by any nested 'act' claims are informational only
/// and are not to be considered in access control decisions." An authorization decision is therefore
/// made from <see cref="JwsAccessTokenClaims"/>'s top-level claims plus this type's
/// <see cref="Subject"/>/<see cref="Issuer"/>. <see cref="DelegationHistory"/> is the history trail
/// "that connects the initial request and subject through the various delegation steps undertaken
/// before reaching the current actor" — an audit, logging, and diagnostics surface, never an
/// authorization input.
/// </para>
/// <para>
/// RFC 8693 §4.1 also bounds what an actor carries: "claims within the 'act' claim pertain only to the
/// identity of the actor and are not relevant to the validity of the containing JWT in the same manner
/// as the top-level claims. Consequently, non-identity claims (e.g., 'exp', 'nbf', and 'aud') are not
/// meaningful when used within an 'act' claim and are therefore not used." This type models identity
/// members only — an actor has no lifetime and no audience of its own, and any such member present in
/// the claim is ignored rather than treated as a validity input.
/// </para>
/// </remarks>
[DebuggerDisplay("CurrentActor Sub={Subject,nq} PriorActors={DelegationHistory.Count}")]
public sealed record CurrentActor
{
    /// <summary>
    /// The <c>sub</c> member of the outermost <c>act</c> object — the identifier of the party
    /// currently acting on behalf of the token's subject. Required: an actor the resource server
    /// cannot name cannot be the access-control input RFC 8693 §4.1 allows it to be, so
    /// <see cref="JwsAccessTokenValidator.ValidateAsync"/> rejects a token whose <c>act</c> claim
    /// names no subject rather than surfacing a partially parsed actor.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The <c>iss</c> member of the outermost <c>act</c> object, when present — per RFC 8693 §4.1
    /// "the combination of the two claims 'iss' and 'sub' might be necessary to uniquely identify an
    /// actor." When non-<see langword="null"/>, the current actor is the issuer/subject combination:
    /// the same <see cref="Subject"/> under a different issuer is a different party.
    /// <see langword="null"/> when the claim names no issuer.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// The prior actors nested inside this one, flattened in nesting order: index 0 is the actor
    /// nested immediately within the current actor (the most recent prior actor) and the final
    /// element is the most deeply nested one — per RFC 8693 §4.1, "The least recent actor is the most
    /// deeply nested." Empty when the token records a single delegation step.
    /// </summary>
    /// <remarks>
    /// Informational history only. RFC 8693 §4.1: "Prior actors identified by any nested 'act' claims
    /// are informational only and are not to be considered in access control decisions." Reading this
    /// list to decide whether a request is permitted contradicts that MUST — the delegation this token
    /// authorizes is the one named by <see cref="Subject"/>/<see cref="Issuer"/> alone.
    /// </remarks>
    public IReadOnlyList<PriorActor> DelegationHistory { get; init; } = [];
}
