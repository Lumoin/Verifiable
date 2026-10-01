using Verifiable.Core.Assessment;
using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped contributor for the OIDC <c>sid</c> (Session ID) claim.
/// Pattern-matches on <see cref="IdTokenTarget"/> and emits <c>sid</c> from
/// <see cref="IssuanceContext.SessionId"/> when the application established a
/// session-scoped identifier at authorize time; otherwise returns
/// <see cref="ClaimOutcome.NotApplicable"/>.
/// </summary>
/// <remarks>
/// The <c>sid</c> identifies the End-User's authentication session (not merely the
/// subject), so it is the value OIDC Back-Channel / Front-Channel Logout reference per
/// session. It is established at authorize, carried through the flow state, and surfaced
/// on <see cref="IssuanceContext.SessionId"/>; the contributor only reads that resolved
/// value — no seam call — mirroring how <see cref="AcrAmrClaimContributor"/> reads
/// <c>auth_time</c>. Applies only to <see cref="IdTokenTarget"/>: a session identifier
/// belongs in the ID Token, not in access tokens, introspection, or UserInfo.
/// </remarks>
public static class SidClaimContributor
{
    /// <summary>
    /// Emits the <c>sid</c> claim for an <see cref="IdTokenTarget"/> when
    /// <see cref="IssuanceContext.SessionId"/> has a character that is not white space.
    /// </summary>
    /// <remarks>
    /// A session identifier that is empty or white space only identifies no session, so it is contributed as
    /// none: the outcome is <see cref="ClaimOutcome.NotApplicable"/>, as for a target without one, and no ID Token
    /// carries a blank <c>sid</c>
    /// (<see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport">OpenID Connect
    /// Back-Channel Logout 1.0 Section 2.1</see> defines the Claim). The rule is this library's.
    /// </remarks>
    /// <param name="target">The contribution target; only an <see cref="IdTokenTarget"/> receives a <c>sid</c>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>One claim: the <c>sid</c> contribution, or <see cref="ClaimOutcome.NotApplicable"/>.</returns>
    public static ValueTask<List<Claim>> GenerateSidClaim(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(target is IdTokenTarget idt && idt.Issuance.SessionId is { } sid && !string.IsNullOrWhiteSpace(sid))
        {
            return ValueTask.FromResult<List<Claim>>(
            [
                new Claim(
                    WellKnownClaimIds.OidcSessionId,
                    ClaimOutcome.Success,
                    new ClaimContributionContext(WellKnownJwtClaimNames.Sid, sid),
                    Claim.NoSubClaims)
            ]);
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(WellKnownClaimIds.OidcSessionId, ClaimOutcome.NotApplicable)]);
    }
}
