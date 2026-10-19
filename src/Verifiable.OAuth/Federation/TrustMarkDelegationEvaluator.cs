using Verifiable.Core.Assessment;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Validates a trust mark's delegation per OpenID Federation 1.0 §7.2.2 and decides, per §7.3, whether a mark must carry one.
/// </summary>
/// <remarks>
/// <para>
/// Inputs: the parsed <see cref="TrustMark"/>, the parsed <see cref="TrustMarkDelegation"/>, the trust chain, whose Trust
/// Anchor's <c>trust_mark_owners</c> claim declares, keyed by the Trust Mark type identifier, the owner of the type and the
/// owner's keys (§3.1.2), and a pre-computed bool indicating whether the delegation JWT's signature verified against one of
/// those keys. Async key resolution and JWS verification happen in the orchestrator before this evaluator runs, mirroring the
/// pattern used elsewhere in the federation namespace.
/// </para>
/// <para>
/// Returns a single <see cref="Claim"/> with <see cref="WellKnownFederationClaimIds.TrustMarkDelegationValid"/>.
/// </para>
/// </remarks>
public static class TrustMarkDelegationEvaluator
{
    /// <summary>
    /// Emits a <see cref="ClaimOutcome.NotApplicable"/> 1173 claim — used
    /// when the trust mark carries no <c>delegation</c> claim and so the
    /// delegation pathway does not apply.
    /// </summary>
    public static Claim NotApplicable() =>
        new(WellKnownFederationClaimIds.TrustMarkDelegationValid, ClaimOutcome.NotApplicable);


    /// <summary>
    /// Evaluates a mark carrying no <c>delegation</c> claim (§7.3): "If the trust_mark_type of the instance appears in the
    /// trust_mark_owners Claim in the Trust Anchor's Entity Configuration, then the instance MUST contain a delegation Claim",
    /// so a mark of a type the Trust Anchor declares an owner of fails as a delegation required and absent; a mark of any other
    /// type is not delegated and the pathway does not apply.
    /// </summary>
    /// <param name="mark">The mark.</param>
    /// <param name="chain">The trust chain whose Trust Anchor declares the owners.</param>
    /// <returns>The not-applicable claim, or the failure of a required delegation.</returns>
    public static Claim EvaluateAbsent(TrustMark mark, TrustChain chain)
    {
        ArgumentNullException.ThrowIfNull(mark);
        ArgumentNullException.ThrowIfNull(chain);

        return OwnerListingOf(chain, mark.MarkId) is TrustMarkOwnerNotListed ? NotApplicable() : BuildFailure(mark, "DelegationRequired");
    }


    /// <summary>
    /// Evaluates the delegation a mark carries against the mark and the Trust Anchor's owner declaration of the mark's type
    /// (§7.2.2): its <c>sub</c> the mark's issuer, its type the mark's, its signature verified by one of the declared owner's
    /// keys, its <c>iss</c> the declared owner, its <c>exp</c> not passed and its <c>iat</c> not in the future. A delegation of a
    /// type the Trust Anchor declares no owner of has no owner keys to validate against and fails.
    /// </summary>
    /// <param name="mark">The mark.</param>
    /// <param name="delegation">The delegation the mark carries.</param>
    /// <param name="chain">The trust chain whose Trust Anchor declares the owners.</param>
    /// <param name="delegationSignatureVerified">Whether the delegation's signature verified by a key of the declared owner of the mark's type.</param>
    /// <param name="now">The instant the delegation is judged at.</param>
    /// <param name="clockSkew">The leeway of the date checks.</param>
    /// <returns>The claim.</returns>
    public static Claim Evaluate(
        TrustMark mark,
        TrustMarkDelegation delegation,
        TrustChain chain,
        bool delegationSignatureVerified,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        ArgumentNullException.ThrowIfNull(mark);
        ArgumentNullException.ThrowIfNull(delegation);
        ArgumentNullException.ThrowIfNull(chain);

        //(1) delegation.sub MUST equal mark.iss — the delegation authorizes
        //THIS issuer for this mark id.
        if(!string.Equals(delegation.Issuer.Value, mark.Issuer.Value, StringComparison.Ordinal))
        {
            return BuildFailure(mark, "DelegationSubjectMismatch");
        }

        //(2) delegation.id MUST equal mark.id.
        if(!string.Equals(delegation.MarkId, mark.MarkId, StringComparison.Ordinal))
        {
            return BuildFailure(mark, "DelegationIdMismatch");
        }

        //(3) The Trust Anchor's trust_mark_owners claim declares, under the mark's type, the owner whose keys validate the
        //delegation; a type it declares no owner of leaves the delegation nothing to validate against, and a declaration that is
        //no object of a sub and a jwks (§3.1.2) declares no owner.
        var listing = OwnerListingOf(chain, mark.MarkId);
        if(listing is TrustMarkOwnerNotListed)
        {
            return BuildFailure(mark, "OwnerNotRegistered");
        }

        if(listing is not TrustMarkOwnerListed listed)
        {
            return BuildFailure(mark, "OwnerDeclarationMalformed");
        }

        //(4) signature MUST verify against one of the declared owner's keys (pre-computed).
        if(!delegationSignatureVerified)
        {
            return BuildFailure(mark, "DelegationSignatureFailed");
        }

        //(5) delegation.iss MUST be the owner the Trust Anchor declares for the mark's type.
        if(!string.Equals(delegation.Owner.Value, listed.Owner, StringComparison.Ordinal))
        {
            return BuildFailure(mark, "OwnerMismatch");
        }

        //(6) delegation.exp (if present) MUST be in the future (with skew tolerance).
        if(delegation.ExpiresAt is { } exp && exp.CompareToEarlierBy(now, clockSkew) <= 0)
        {
            return BuildFailure(mark, "DelegationExpired");
        }

        //(7) §7.2.2: the current time MUST be after the delegation's iat (with skew tolerance).
        if(delegation.IssuedAt.CompareToLaterBy(now, clockSkew) > 0)
        {
            return BuildFailure(mark, "DelegationIssuedInFuture");
        }

        return new Claim(WellKnownFederationClaimIds.TrustMarkDelegationValid, ClaimOutcome.Success);
    }


    /// <summary>
    /// The Trust Anchor's declaration of the owner of a Trust Mark type (§3.1.2, <c>trust_mark_owners</c>), the claim read from
    /// the chain's last statement, the Trust Anchor's Entity Configuration, keyed by the type: not listed, listed with its owner
    /// and keys, or listed as no object of a string <c>sub</c> and an object <c>jwks</c>.
    /// </summary>
    /// <param name="chain">The trust chain.</param>
    /// <param name="markType">The Trust Mark type identifier.</param>
    /// <returns>The listing.</returns>
    internal static TrustMarkOwnerListing OwnerListingOf(TrustChain chain, string markType)
    {
        if(chain.Statements.Count == 0
            || chain.Statements[^1] is not EntityConfiguration anchorConfig
            || !anchorConfig.Payload.TryGetValue(WellKnownFederationClaimNames.TrustMarkOwners, out var ownersObj)
            || ownersObj is not IReadOnlyDictionary<string, object> ownersMap
            || !ownersMap.TryGetValue(markType, out var declaration))
        {
            return new TrustMarkOwnerNotListed();
        }

        return declaration is IReadOnlyDictionary<string, object> entry
            && entry.TryGetValue(WellKnownJwtClaimNames.Sub, out var ownerObj)
            && ownerObj is string { Length: > 0 } owner
            && entry.TryGetValue(WellKnownFederationClaimNames.Jwks, out var jwks)
            && jwks is IReadOnlyDictionary<string, object>
                ? new TrustMarkOwnerListed(owner, jwks)
                : new TrustMarkOwnerListedMalformed();
    }


    /// <summary>The failure claim of a delegation, naming the mark and the reason.</summary>
    /// <param name="mark">The mark.</param>
    /// <param name="reason">The reason.</param>
    /// <returns>The claim.</returns>
    private static Claim BuildFailure(TrustMark mark, string reason) =>
        new(
            WellKnownFederationClaimIds.TrustMarkDelegationValid,
            ClaimOutcome.Failure,
            new TrustMarkDelegationFailureContext
            {
                MarkId = mark.MarkId,
                MarkIssuer = mark.Issuer,
                Reason = reason,
            },
            Claim.NoSubClaims);
}


/// <summary>What the Trust Anchor's <c>trust_mark_owners</c> claim declares of one Trust Mark type (OpenID Federation 1.0 §3.1.2).</summary>
internal abstract record TrustMarkOwnerListing;


/// <summary>The Trust Anchor declares no owner of the type: its marks carry no delegation they must.</summary>
internal sealed record TrustMarkOwnerNotListed : TrustMarkOwnerListing;


/// <summary>The Trust Anchor declares the owner of the type and the owner's keys.</summary>
/// <param name="Owner">The owner's Entity Identifier, the declaration's <c>sub</c>.</param>
/// <param name="Jwks">The owner's Federation Entity Keys, the declaration's <c>jwks</c>, as decoded.</param>
internal sealed record TrustMarkOwnerListed(string Owner, object Jwks) : TrustMarkOwnerListing;


/// <summary>The Trust Anchor lists the type with a declaration that is no object of a string <c>sub</c> and an object <c>jwks</c>.</summary>
internal sealed record TrustMarkOwnerListedMalformed : TrustMarkOwnerListing;
