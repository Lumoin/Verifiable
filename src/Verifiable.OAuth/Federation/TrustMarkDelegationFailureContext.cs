using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// <see cref="ClaimContext"/> attached to a 1173 Failure when a trust
/// mark's delegation chain does not validate.
/// </summary>
public sealed record TrustMarkDelegationFailureContext : ClaimContext
{
    /// <summary>The trust mark identifier under evaluation.</summary>
    public required string MarkId { get; init; }

    /// <summary>The mark issuer the delegation was meant to authorize.</summary>
    public required EntityIdentifier MarkIssuer { get; init; }

    /// <summary>Why the delegation does not validate, or why a mark carrying none fails (OpenID Federation 1.0 §7.2.2 and §7.3).</summary>
    public required TrustMarkDelegationFailureReason Reason { get; init; }
}


/// <summary>Why a Trust Mark's delegation does not validate, or why a mark carrying none fails (OpenID Federation 1.0 §7.2.2 and §7.3).</summary>
public enum TrustMarkDelegationFailureReason
{
    /// <summary>The delegation's <c>sub</c> is not the mark's issuer.</summary>
    DelegationSubjectMismatch,

    /// <summary>The delegation's Trust Mark type is not the mark's.</summary>
    DelegationIdMismatch,

    /// <summary>The Trust Anchor's <c>trust_mark_owners</c> claim declares no owner of the mark's type, so the delegation has no owner keys to validate against.</summary>
    OwnerNotRegistered,

    /// <summary>
    /// The Trust Anchor's <c>trust_mark_owners</c> claim is no JSON object, or declares the mark's type with a declaration that is no
    /// object of a string <c>sub</c> and an object <c>jwks</c> (§3.1.2): whether and by whom the type is owned is unknown.
    /// </summary>
    OwnerDeclarationMalformed,

    /// <summary>The delegation's signature did not verify under a key of the owner the Trust Anchor declares.</summary>
    DelegationSignatureFailed,

    /// <summary>The delegation's <c>iss</c> is not the owner the Trust Anchor declares for the mark's type.</summary>
    OwnerMismatch,

    /// <summary>The delegation's <c>exp</c> has passed.</summary>
    DelegationExpired,

    /// <summary>The delegation's <c>iat</c> lies in the future.</summary>
    DelegationIssuedInFuture,

    /// <summary>The mark carries no delegation although the Trust Anchor declares an owner of its type (§7.3).</summary>
    DelegationRequired
}
