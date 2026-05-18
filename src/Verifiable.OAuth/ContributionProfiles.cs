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
    /// Populated by chunk 4a; returns an empty list until then. The
    /// empty list is well-formed for
    /// <see cref="StandardClaimIssuer"/> — the resulting issuer produces
    /// zero claims, equivalent to the pre-Phase-A
    /// <see cref="Server.ServerConfiguration.ClaimContributors"/> being
    /// <c>ClaimContributorSet.Empty</c> (which is the test fixture's
    /// default today).
    /// </remarks>
    public static List<ClaimDelegate<ClaimContributionTarget>> StandardRules() =>
        [];


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
