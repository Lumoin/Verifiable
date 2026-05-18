using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped contributor for the OIDC Core §2 authentication-context
/// claims: <c>acr</c>, <c>amr</c>, <c>auth_time</c>. Pattern-matches on
/// <see cref="IdTokenTarget"/>; reads
/// <see cref="OidcClaims.AuthContext"/> when populated and falls back to
/// <see cref="IssuanceContext.AuthTime"/> for <c>auth_time</c> only.
/// </summary>
/// <remarks>
/// <para>
/// Applies only to <see cref="IdTokenTarget"/> — authentication-context
/// claims describe the act of issuing an ID Token. Other targets return
/// <see cref="ClaimOutcome.NotApplicable"/>.
/// </para>
/// <para>
/// Behaviour mirrors the producer's pre-Phase-A inline emission. The
/// <c>acr</c> and <c>amr</c> claims come exclusively from
/// <see cref="OidcClaims.AuthContext"/>; the <c>auth_time</c> claim has
/// the documented fallback chain — <see cref="AuthenticationContext.AuthTime"/>
/// when populated, otherwise <see cref="IssuanceContext.AuthTime"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("AcrAmrClaimContributor")]
public static class AcrAmrClaimContributor
{
    /// <summary>
    /// Emits the authentication-context claims (<c>acr</c>, <c>amr</c>,
    /// <c>auth_time</c>) when populated for an <see cref="IdTokenTarget"/>.
    /// </summary>
    public static async ValueTask<List<Claim>> GenerateAuthClassClaims(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(target is not IdTokenTarget idt)
        {
            return
            [
                new Claim(WellKnownClaimIds.OidcAuthClass, ClaimOutcome.NotApplicable),
                new Claim(WellKnownClaimIds.OidcAuthTime, ClaimOutcome.NotApplicable)
            ];
        }

        AuthenticationContext? authContext = await ResolveAuthContextAsync(
            idt, cancellationToken).ConfigureAwait(false);

        DateTimeOffset? authTime = authContext?.AuthTime ?? idt.Issuance.AuthTime;
        string? acr = authContext?.Acr;
        bool hasAmr = authContext?.Amr is { Count: > 0 };

        List<Claim> claims = [];

        if(authTime is { } t)
        {
            claims.Add(Success(
                WellKnownClaimIds.OidcAuthTime,
                WellKnownJwtClaimNames.AuthTime,
                t.ToUnixTimeSeconds()));
        }
        else
        {
            claims.Add(new Claim(WellKnownClaimIds.OidcAuthTime, ClaimOutcome.NotApplicable));
        }

        if(acr is not null)
        {
            claims.Add(Success(
                WellKnownClaimIds.OidcAuthClass,
                WellKnownJwtClaimNames.Acr,
                acr));
        }

        if(hasAmr)
        {
            claims.Add(Success(
                WellKnownClaimIds.OidcAuthClass,
                WellKnownJwtClaimNames.Amr,
                authContext!.Amr!));
        }

        if(acr is null && !hasAmr)
        {
            claims.Add(new Claim(WellKnownClaimIds.OidcAuthClass, ClaimOutcome.NotApplicable));
        }

        return claims;
    }


    /// <summary>
    /// Returns the <see cref="AuthenticationContext"/> from
    /// <see cref="IdTokenTarget.ResolvedOidcClaims"/> when populated;
    /// otherwise invokes the application's resolver to fetch it. (α)
    /// strategy — contributors are correct standalone whether or not the
    /// walking site has populated the target.
    /// </summary>
    private static async ValueTask<AuthenticationContext?> ResolveAuthContextAsync(
        IdTokenTarget idt,
        CancellationToken cancellationToken)
    {
        if(idt.ResolvedOidcClaims is { AuthContext: { } pre })
        {
            return pre;
        }

        if(idt.ResolvedOidcClaims is not null)
        {
            return null;
        }

        AuthorizationServer? server = idt.Issuance.Context.Server;
        ResolveOidcClaimsDelegate? resolve = server?.Integration.ResolveOidcClaimsAsync;
        if(resolve is null)
        {
            return null;
        }

        OidcClaims? resolved = await resolve(
            idt.Issuance.Subject,
            idt.Issuance.Scope,
            idt.Issuance.Registration.TenantId,
            idt.Issuance.Context,
            cancellationToken).ConfigureAwait(false);

        return resolved?.AuthContext;
    }


    private static Claim Success(ClaimId id, string claimName, object claimValue) =>
        new(id, ClaimOutcome.Success, new ClaimContributionContext(claimName, claimValue), Claim.NoSubClaims);
}
