using System.Diagnostics;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped contributor for the OIDC Core §2 authentication-context
/// claims: <c>acr</c>, <c>amr</c>, <c>auth_time</c>. Handles
/// <see cref="IdTokenTarget"/> (full <c>acr</c>/<c>amr</c>/<c>auth_time</c> from
/// <see cref="OidcClaims.AuthContext"/>) and <see cref="AccessTokenTarget"/>
/// (<c>acr</c>/<c>auth_time</c> from the threaded <see cref="IssuanceContext"/>
/// per RFC 9068 §2.2.1 / RFC 9470 §5).
/// </summary>
/// <remarks>
/// <para>
/// On an <see cref="IdTokenTarget"/> the <c>acr</c> and <c>amr</c> claims come
/// exclusively from <see cref="OidcClaims.AuthContext"/>; the <c>auth_time</c>
/// claim has the documented fallback chain —
/// <see cref="AuthenticationContext.AuthTime"/> when populated, otherwise
/// <see cref="IssuanceContext.AuthTime"/> (the instant the End-User authenticated
/// as observed by the AS).
/// </para>
/// <para>
/// On an <see cref="AccessTokenTarget"/> the claims come from the threaded
/// per-request <see cref="IssuanceContext"/> — <c>acr</c> from
/// <see cref="IssuanceContext.Acr"/> (the reference established at authorize time)
/// and <c>auth_time</c> from <see cref="IssuanceContext.AuthTime"/>. Access tokens
/// carry no <see cref="OidcClaims"/>, so there is no resolver call and no <c>amr</c>:
/// per <see href="https://www.rfc-editor.org/rfc/rfc9470#section-5">RFC 9470 §5</see>
/// the Resource Server reads <c>acr</c> and <c>auth_time</c> from the JWT access token.
/// </para>
/// <para>
/// Other targets (UserInfo, introspection) return
/// <see cref="ClaimOutcome.NotApplicable"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("AcrAmrClaimContributor")]
public static class AcrAmrClaimContributor
{
    /// <summary>
    /// Emits the authentication-context claims for the supported targets:
    /// <c>acr</c>/<c>amr</c>/<c>auth_time</c> for an <see cref="IdTokenTarget"/>,
    /// and <c>acr</c>/<c>auth_time</c> for an <see cref="AccessTokenTarget"/>.
    /// </summary>
    public static async ValueTask<List<Claim>> GenerateAuthClassClaims(
        ClaimContributionTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if(target is AccessTokenTarget at)
        {
            return GenerateAccessTokenClaims(at);
        }

        if(target is not IdTokenTarget idt)
        {
            return NotApplicable();
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
    /// Emits the access token's <c>acr</c> (from <see cref="IssuanceContext.Acr"/>)
    /// and <c>auth_time</c> (from <see cref="IssuanceContext.AuthTime"/>) per
    /// RFC 9068 §2.2.1 / RFC 9470 §5. Reads only the threaded per-request values —
    /// access tokens carry no <see cref="OidcClaims"/>, so there is no resolver call
    /// and no <c>amr</c>. Both claims are OPTIONAL per RFC 9068 §2.2.1: each is
    /// emitted only when the AS established its value, and reported as
    /// <see cref="ClaimOutcome.NotApplicable"/> when no value exists to emit.
    /// </summary>
    private static List<Claim> GenerateAccessTokenClaims(AccessTokenTarget at)
    {
        List<Claim> claims = [];

        if(at.Issuance.AuthTime is { } authTime)
        {
            claims.Add(Success(
                WellKnownClaimIds.OidcAuthTime,
                WellKnownJwtClaimNames.AuthTime,
                authTime.ToUnixTimeSeconds()));
        }
        else
        {
            claims.Add(new Claim(WellKnownClaimIds.OidcAuthTime, ClaimOutcome.NotApplicable));
        }

        if(at.Issuance.Acr is { Length: > 0 } acr)
        {
            claims.Add(Success(
                WellKnownClaimIds.OidcAuthClass,
                WellKnownJwtClaimNames.Acr,
                acr));
        }
        else
        {
            claims.Add(new Claim(WellKnownClaimIds.OidcAuthClass, ClaimOutcome.NotApplicable));
        }

        return claims;
    }


    /// <summary>
    /// The "no authentication-context claims" outcome — both <c>acr</c> and
    /// <c>auth_time</c> reported as <see cref="ClaimOutcome.NotApplicable"/> for
    /// targets the contributor does not handle (UserInfo, introspection).
    /// </summary>
    private static List<Claim> NotApplicable() =>
    [
        new Claim(WellKnownClaimIds.OidcAuthClass, ClaimOutcome.NotApplicable),
        new Claim(WellKnownClaimIds.OidcAuthTime, ClaimOutcome.NotApplicable)
    ];


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
