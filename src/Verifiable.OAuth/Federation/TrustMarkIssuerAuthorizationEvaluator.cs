using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Checks whether a trust mark's issuer is authorized to issue a mark of
/// its declared id per Federation §7.3. Reads the
/// <see cref="WellKnownFederationClaimNames.TrustMarkIssuers"/> claim
/// from the chain's Trust Anchor (position N-1) and matches the trust
/// mark's <see cref="TrustMark.Issuer"/> against the list registered for
/// the mark's <see cref="TrustMark.MarkId"/>; an empty list authorizes any issuer
/// ("If the array following a Trust Mark type identifier is empty, anyone MAY issue Trust Marks with that identifier",
/// §3.1.2).
/// </summary>
/// <remarks>
/// <para>
/// Direct authorization only. Delegation-based authorization (an issuer
/// holding the mark under delegation from a Trust Mark Owner per §7.2.2)
/// is the responsibility of <see cref="TrustMarkDelegationEvaluator"/>
/// and surfaces on the separate
/// <see cref="WellKnownFederationClaimIds.TrustMarkDelegationValid"/>
/// claim. The orchestrator admits a mark carrying no delegation on this
/// check, and a mark carrying one on that delegation's validity alone; a mark
/// of a type the Trust Anchor declares an owner of must carry one (§7.3).
/// </para>
/// <para>
/// <c>trust_mark_issuers</c> on intermediate Subordinate Statements is
/// not considered — §3.1.2 places the authoritative list on the Trust
/// Anchor. Intermediate-statement declarations are observed in the wild
/// but treating them as authoritative would let any intermediate
/// arbitrarily grant trust-mark-issuance rights, which is the wrong
/// security default.
/// </para>
/// </remarks>
public static class TrustMarkIssuerAuthorizationEvaluator
{
    /// <summary>
    /// Evaluates whether <paramref name="mark"/>'s issuer is in the Trust
    /// Anchor's authorized list for the mark's id.
    /// </summary>
    public static Claim Evaluate(TrustMark mark, TrustChain chain)
    {
        ArgumentNullException.ThrowIfNull(mark);
        ArgumentNullException.ThrowIfNull(chain);

        if(chain.Statements.Count == 0
            || chain.Statements[^1] is not EntityConfiguration anchorConfig)
        {
            return BuildFailure(mark, "NoTrustMarkIssuersDeclared");
        }

        if(!anchorConfig.Payload.TryGetValue(WellKnownFederationClaimNames.TrustMarkIssuers, out object? issuersObj)
            || issuersObj is not IReadOnlyDictionary<string, object> issuersMap)
        {
            return BuildFailure(mark, "NoTrustMarkIssuersDeclared");
        }

        if(!issuersMap.TryGetValue(mark.MarkId, out object? allowedObj)
            || allowedObj is not IEnumerable<object> allowedList)
        {
            return BuildFailure(mark, "MarkIdNotListed");
        }

        //§3.1.2: "If the array following a Trust Mark type identifier is empty, anyone MAY issue Trust Marks with that identifier."
        if(!allowedList.Any())
        {
            return new Claim(WellKnownFederationClaimIds.TrustMarkIssuerAuthorized, ClaimOutcome.Success);
        }

        foreach(object item in allowedList)
        {
            if(item is string entry
                && !string.IsNullOrWhiteSpace(entry)
                && string.Equals(entry, mark.Issuer.Value, StringComparison.Ordinal))
            {
                return new Claim(
                    WellKnownFederationClaimIds.TrustMarkIssuerAuthorized,
                    ClaimOutcome.Success);
            }
        }

        return BuildFailure(mark, "IssuerNotInList");
    }


    private static Claim BuildFailure(TrustMark mark, string reason) =>
        new(
            WellKnownFederationClaimIds.TrustMarkIssuerAuthorized,
            ClaimOutcome.Failure,
            new TrustMarkIssuerAuthorizationContext
            {
                MarkId = mark.MarkId,
                Issuer = mark.Issuer,
                Reason = reason,
            },
            Claim.NoSubClaims);
}
