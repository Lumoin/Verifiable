using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped contributor for the RFC 7800 / RFC 9449 §6.1
/// <c>cnf</c> (confirmation) claim. Pattern-matches on
/// <see cref="IdTokenTarget"/>; reads
/// <see cref="IssuanceContext.Confirmation"/>; emits the structured
/// <c>cnf</c> object carrying the populated confirmation members.
/// </summary>
/// <remarks>
/// <para>
/// At present <see cref="Server.ConfirmationMethod.JwkThumbprint"/> is
/// the only populated member, matching the producer's pre-Phase-A
/// inline emission. Future binding methods (RFC 8705 <c>x5t#S256</c>,
/// RFC 7800 <c>jwk</c>) extend the contributor without changing the
/// shape — the wire-format <c>cnf</c> object accumulates members.
/// </para>
/// <para>
/// Applies only to <see cref="IdTokenTarget"/> in chunk 4a. Confirmation
/// is bound to the issued token, not to introspection-style responses, so
/// <see cref="UserInfoTarget"/> and <see cref="IntrospectionTarget"/>
/// return <see cref="ClaimOutcome.NotApplicable"/> here. The access-token
/// producer composes its own <c>cnf</c> claim today; once the
/// access-token walking site adopts the contributor surface (Phase A
/// follow-up), this contributor extends to <see cref="AccessTokenTarget"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("CnfClaimContributor")]
public static class CnfClaimContributor
{
    /// <summary>
    /// Emits the RFC 7800 <c>cnf</c> claim when the issuance carries a
    /// non-empty <see cref="Server.ConfirmationMethod"/>.
    /// </summary>
    public static ValueTask<List<Claim>> GenerateCnfClaim(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(target is not IdTokenTarget idt)
        {
            return new ValueTask<List<Claim>>(
                [new Claim(WellKnownClaimIds.CnfBinding, ClaimOutcome.NotApplicable)]);
        }

        if(idt.Issuance.Confirmation is not { IsEmpty: false } confirmation
            || confirmation.JwkThumbprint is null)
        {
            return new ValueTask<List<Claim>>(
                [new Claim(WellKnownClaimIds.CnfBinding, ClaimOutcome.NotApplicable)]);
        }

        Dictionary<string, object> cnf = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.JwkThumbprint] = confirmation.JwkThumbprint
        };

        Claim cnfClaim = new(
            WellKnownClaimIds.CnfBinding,
            ClaimOutcome.Success,
            new ClaimContributionContext(WellKnownJwtClaimNames.Cnf, cnf),
            Claim.NoSubClaims);

        return new ValueTask<List<Claim>>([cnfClaim]);
    }
}
