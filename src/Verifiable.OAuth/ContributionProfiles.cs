using System.Diagnostics;
using Verifiable.Core.Assessment;

namespace Verifiable.OAuth;

/// <summary>
/// Library-shipped claim contribution profiles. Each method returns a
/// list of <see cref="ClaimDelegate{T}"/> the application composes into
/// its <see cref="Server.ServerConfiguration.ClaimIssuer"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="Validation.ValidationProfiles"/> — rules are
/// pre-built lists the application can extend with custom contributors
/// before passing to a <see cref="ClaimIssuer{T}"/>. Adding a new
/// profile means adding a method here.
/// </para>
/// <para>
/// Example: extending the standard OIDC contributor set with a custom
/// tenancy-tag contributor.
/// </para>
/// <code>
/// var rules = ContributionProfiles.StandardRules();
/// rules.Add(new ClaimDelegate&lt;ClaimContributionTarget&gt;(
///     MyContributors.GenerateTenancyTagClaims,
///     [MyClaimIds.TenancyTag]));
///
/// var issuer = new ClaimIssuer&lt;ClaimContributionTarget&gt;(
///     WellKnownAssessorIds.ClaimContributors, rules, timeProvider);
/// </code>
/// </remarks>
[DebuggerDisplay("ContributionProfiles")]
public static class ContributionProfiles
{
    /// <summary>
    /// The standard OIDC Core §5.4 contributor set — profile, email,
    /// address, phone, plus authentication context (acr/amr/auth_time)
    /// and cnf binding emission. Returns a fresh mutable list per call
    /// so the application can extend it without affecting future calls.
    /// </summary>
    /// <remarks>
    /// Six rules: profile / email / address / phone (OIDC Core §5.4), the
    /// RFC 7800 / RFC 9449 §6.1 <c>cnf</c> confirmation claim, and the
    /// OIDC Core §2 authentication-context family (<c>acr</c>, <c>amr</c>,
    /// <c>auth_time</c>). Rules return
    /// <see cref="ClaimOutcome.NotApplicable"/> for targets they don't
    /// apply to and for scope-gated claims when the granted scope omits
    /// their family.
    /// </remarks>
    public static List<ClaimDelegate<ClaimContributionTarget>> StandardRules() =>
    [
        new ClaimDelegate<ClaimContributionTarget>(
            OidcStandardClaimsContributor.GenerateProfileClaims,
            [WellKnownClaimIds.OidcProfile]),
        new ClaimDelegate<ClaimContributionTarget>(
            OidcStandardClaimsContributor.GenerateEmailClaims,
            [WellKnownClaimIds.OidcEmail]),
        new ClaimDelegate<ClaimContributionTarget>(
            OidcStandardClaimsContributor.GenerateAddressClaims,
            [WellKnownClaimIds.OidcAddress]),
        new ClaimDelegate<ClaimContributionTarget>(
            OidcStandardClaimsContributor.GeneratePhoneClaims,
            [WellKnownClaimIds.OidcPhone]),
        new ClaimDelegate<ClaimContributionTarget>(
            CnfClaimContributor.GenerateCnfClaim,
            [WellKnownClaimIds.CnfBinding]),
        new ClaimDelegate<ClaimContributionTarget>(
            AcrAmrClaimContributor.GenerateAuthClassClaims,
            [WellKnownClaimIds.OidcAuthClass, WellKnownClaimIds.OidcAuthTime])
    ];


    /// <summary>
    /// Convenience helper returning a <see cref="ClaimIssuer{T}"/>
    /// wired with <see cref="StandardRules"/> plus optional extra rules.
    /// The most common application wiring; equivalent to constructing a
    /// <see cref="ClaimIssuer{T}"/> manually with the standard rule list.
    /// </summary>
    /// <param name="timeProvider">
    /// Time source for the issuer's claim timestamps. Required by
    /// <see cref="ClaimIssuer{T}"/>; library code never reads
    /// <see cref="DateTime.UtcNow"/> directly.
    /// </param>
    /// <param name="extraRules">
    /// Optional additional contribution rules merged after the standard
    /// rules. Rules run in list order; later rules emitting the same
    /// claim name overwrite earlier values when the walking site merges
    /// successful claims.
    /// </param>
    public static ClaimIssuer<ClaimContributionTarget> StandardClaimIssuer(
        TimeProvider timeProvider,
        List<ClaimDelegate<ClaimContributionTarget>>? extraRules = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        List<ClaimDelegate<ClaimContributionTarget>> rules = StandardRules();
        if(extraRules is { Count: > 0 })
        {
            rules.AddRange(extraRules);
        }

        return new ClaimIssuer<ClaimContributionTarget>(
            WellKnownAssessorIds.ClaimContributors,
            rules,
            timeProvider);
    }
}
