using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.JCose;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped contributor for the RFC 7800 / RFC 9449 §6.1
/// <c>cnf</c> (confirmation) claim. Pattern-matches on
/// <see cref="IdTokenTarget"/> and <see cref="AccessTokenTarget"/>;
/// reads <see cref="IssuanceContext.Confirmation"/>; emits the structured
/// <c>cnf</c> object carrying the populated confirmation members.
/// </summary>
/// <remarks>
/// <para>
/// At present <see cref="Server.ConfirmationMethod.JwkThumbprint"/> is
/// the only populated member, matching the producers' pre-Phase-A inline
/// emission. Future binding methods (RFC 8705 <c>x5t#S256</c>,
/// RFC 7800 <c>jwk</c>) extend the contributor without changing the
/// shape — the wire-format <c>cnf</c> object accumulates members.
/// </para>
/// <para>
/// Applies to <see cref="IdTokenTarget"/> (mirroring per
/// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6">RFC 9449 §6</see>:
/// when the token endpoint validates a DPoP proof, the ID Token receives
/// the same <c>cnf.jkt</c> binding as the access token) and to
/// <see cref="AccessTokenTarget"/> (the primary RFC 9449 §6.1 binding
/// surface). Confirmation is bound to issued tokens, not to
/// introspection-style responses, so
/// <see cref="UserInfoTarget"/> and <see cref="IntrospectionTarget"/>
/// return <see cref="ClaimOutcome.NotApplicable"/>.
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

        IssuanceContext? issuance = target switch
        {
            IdTokenTarget idt => idt.Issuance,
            AccessTokenTarget at => at.Issuance,
            _ => null
        };

        if(issuance is null)
        {
            return new ValueTask<List<Claim>>(
                [new Claim(WellKnownClaimIds.CnfBinding, ClaimOutcome.NotApplicable)]);
        }

        if(issuance.Confirmation is not { IsEmpty: false } confirmation
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
