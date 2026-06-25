using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Validates a trust mark's delegation chain per OpenID Federation 1.0
/// §7.2.2.
/// </summary>
/// <remarks>
/// <para>
/// Inputs: the parsed <see cref="TrustMark"/>, the parsed
/// <see cref="TrustMarkDelegation"/>, the trust chain (for
/// <c>trust_mark_owners</c> lookup), and a pre-computed bool indicating
/// whether the delegation JWT's signature verified against the owner's
/// declared key. Async key resolution + JWS verification happen in the
/// orchestrator before this evaluator runs, mirroring the pattern used
/// elsewhere in the federation namespace.
/// </para>
/// <para>
/// Returns a single <see cref="Claim"/> with
/// <see cref="WellKnownFederationClaimIds.TrustMarkDelegationValid"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("TrustMarkDelegationEvaluator")]
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
    /// Evaluates the delegation against the trust mark and chain context.
    /// </summary>
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

        //(3) signature MUST verify against the owner's key (pre-computed).
        if(!delegationSignatureVerified)
        {
            return BuildFailure(mark, "DelegationSignatureFailed");
        }

        //(4) delegation.iss (the owner) MUST appear in the Trust Anchor's
        //trust_mark_owners map.
        if(chain.Statements.Count == 0
            || chain.Statements[^1] is not EntityConfiguration anchorConfig
            || !anchorConfig.Payload.TryGetValue(WellKnownFederationClaimNames.TrustMarkOwners, out object? ownersObj)
            || ownersObj is not IReadOnlyDictionary<string, object> ownersMap
            || !ownersMap.ContainsKey(delegation.Owner.Value))
        {
            return BuildFailure(mark, "OwnerNotRegistered");
        }

        //(5) delegation.exp (if present) MUST be in the future (with skew tolerance).
        if(delegation.ExpiresAt is { } exp && exp <= now - clockSkew)
        {
            return BuildFailure(mark, "DelegationExpired");
        }

        //(6) §7.2.2: the current time MUST be after the delegation's iat (with skew tolerance).
        if(delegation.IssuedAt > now + clockSkew)
        {
            return BuildFailure(mark, "DelegationIssuedInFuture");
        }

        return new Claim(WellKnownFederationClaimIds.TrustMarkDelegationValid, ClaimOutcome.Success);
    }


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
