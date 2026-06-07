using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// <see cref="ClaimContext"/> attached to a 1173 Failure when a trust
/// mark's delegation chain does not validate.
/// </summary>
public sealed record TrustMarkDelegationFailureContext: ClaimContext
{
    /// <summary>The trust mark identifier under evaluation.</summary>
    public required string MarkId { get; init; }

    /// <summary>The mark issuer the delegation was meant to authorize.</summary>
    public required EntityIdentifier MarkIssuer { get; init; }

    /// <summary>Typed failure category.</summary>
    /// <remarks>
    /// One of:
    /// <c>"DelegationSubjectMismatch"</c> (delegation.sub != mark.iss),
    /// <c>"DelegationIdMismatch"</c> (delegation.id != mark.id),
    /// <c>"DelegationSignatureFailed"</c> (sig outcome was false),
    /// <c>"OwnerNotRegistered"</c> (delegation.iss is not in the Trust
    /// Anchor's trust_mark_owners), or
    /// <c>"DelegationExpired"</c> (exp in the past).
    /// </remarks>
    public required string Reason { get; init; }
}
