using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// A prior actor recorded by a nested <c>act</c> claim per
/// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> — a party that
/// acted earlier in the delegation chain and is no longer the current actor. Surfaced through
/// <see cref="CurrentActor.DelegationHistory"/> as history, never as authority.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8693 §4.1: "The nested 'act' claims serve as a history trail that connects the initial request
/// and subject through the various delegation steps undertaken before reaching the current actor."
/// The same section forbids using that trail to decide anything: "Prior actors identified by any
/// nested 'act' claims are informational only and are not to be considered in access control
/// decisions." A resource server therefore reads instances of this type for audit and diagnostics and
/// authorizes against <see cref="JwsAccessTokenClaims"/>'s top-level claims plus
/// <see cref="CurrentActor.Subject"/>/<see cref="CurrentActor.Issuer"/>.
/// </para>
/// <para>
/// The type carries identity members only, matching §4.1's rule that non-identity claims (<c>exp</c>,
/// <c>nbf</c>, <c>aud</c>) "are not meaningful when used within an 'act' claim and are therefore not
/// used". A prior actor deliberately exposes no further nesting of its own: the whole chain is already
/// flattened into <see cref="CurrentActor.DelegationHistory"/> in nesting order, so there is no
/// deeper structure to walk from here and no path that leads a caller back to something resembling an
/// authorization input.
/// </para>
/// </remarks>
[DebuggerDisplay("PriorActor Sub={Subject,nq}")]
public sealed record PriorActor
{
    /// <summary>
    /// The <c>sub</c> member of this nested <c>act</c> object — the identifier of the party that acted
    /// at this step of the delegation chain. Required for the same reason as
    /// <see cref="CurrentActor.Subject"/>: a history entry naming no party is not history, and
    /// <see cref="JwsAccessTokenValidator.ValidateAsync"/> rejects the token rather than recording one.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The <c>iss</c> member of this nested <c>act</c> object, when present — the issuer half of the
    /// RFC 8693 §4.1 issuer/subject combination that uniquely identifies an actor.
    /// <see langword="null"/> when this nested claim names no issuer.
    /// </summary>
    public string? Issuer { get; init; }
}
