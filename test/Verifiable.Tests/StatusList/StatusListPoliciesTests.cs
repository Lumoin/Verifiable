using System;
using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Construction guards for the two Relying Party policy types a status evaluation is parameterised
/// by: <see cref="StatusListFreshnessPolicy"/> (Section 8.3 step 4.b's <c>iat</c> check) and
/// <see cref="StatusListCachingBounds"/> (Section 11.5's configured lower/upper bounds on the
/// <c>ttl</c>-driven refresh interval). Both express a range, so both refuse a range that cannot
/// describe one — a policy built from a nonsensical duration would silently either never fire or
/// fire always, which is exactly the accidental request storm Section 11.5 warns about.
/// </summary>
[TestClass]
internal sealed class StatusListPoliciesTests
{
    /// <summary>
    /// "If the Relying Party has local policies regarding the freshness of the Status List Token, it
    /// SHOULD check the issued at claim (iat or 6)."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// A maximum age of zero or less describes no freshness window at all — every token, however
    /// recently issued, would be at least that old — so it is refused at construction rather than
    /// becoming a policy that rejects everything it is asked about.
    /// </summary>
    /// <param name="maximumAgeSeconds">The non-positive maximum age offered to the policy.</param>
    [TestMethod]
    [DataRow(0d)]
    [DataRow(-1d)]
    [DataRow(-3600d)]
    public void AFreshnessPolicyRefusesANonPositiveMaximumAge(double maximumAgeSeconds)
    {
        TimeSpan maximumAge = TimeSpan.FromSeconds(maximumAgeSeconds);

        ArgumentOutOfRangeException caught = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new StatusListFreshnessPolicy(maximumAge),
            $"A freshness policy whose maximum age is {maximumAge} describes no window in which a "
            + "Status List Token's iat could be considered fresh, so step 4.b's check must not be "
            + "constructible from it.");

        Assert.AreEqual("maximumAge", caught.ParamName,
            "The refusal names the maximum age as the offending argument.");
    }


    /// <summary>
    /// A positive maximum age is the only shape step 4.b's check can be run from — "If the Relying
    /// Party has local policies regarding the freshness of the Status List Token, it SHOULD check the
    /// issued at claim (iat or 6)".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// The policy carries the duration through unmodified, since it is the value
    /// <see cref="StatusListValidation.GetStatus"/> compares the token's age against.
    /// </summary>
    [TestMethod]
    public void AFreshnessPolicyCarriesAPositiveMaximumAgeThrough()
    {
        TimeSpan maximumAge = TimeSpan.FromHours(1);

        var policy = new StatusListFreshnessPolicy(maximumAge);

        Assert.AreEqual(maximumAge, policy.MaximumAge,
            "The freshness window step 4.b compares the token's iat against is the one the Relying Party configured.");
    }


    /// <summary>
    /// "Reasonable values for both claims highly depend on the use-case requirements and clients
    /// should be configured with lower/upper bounds for these values that fit their respective
    /// use-cases."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// A floor of zero or less is not a lower bound on the request rate at all, and a ceiling below
    /// the floor is not a range, so neither can be configured — the clamp such a pair would produce
    /// is precisely what would let a Status Issuer "accidentally or maliciously use this mechanism to
    /// effectively DDoS the contained URL of the Status Provider".
    /// </summary>
    /// <param name="minimumSeconds">The refresh-interval floor offered to the bounds.</param>
    /// <param name="maximumSeconds">The refresh-interval ceiling offered to the bounds.</param>
    /// <param name="expectedParameterName">The argument the refusal is expected to name.</param>
    [TestMethod]
    [DataRow(0d, 3600d, "minimumRefreshInterval")]
    [DataRow(-1d, 3600d, "minimumRefreshInterval")]
    [DataRow(-3600d, -60d, "minimumRefreshInterval")]
    [DataRow(3600d, 60d, "maximumRefreshInterval")]
    [DataRow(60d, 0d, "maximumRefreshInterval")]
    public void CachingBoundsRefuseARangeThatIsNotALowerAndUpperBound(
        double minimumSeconds,
        double maximumSeconds,
        string expectedParameterName)
    {
        TimeSpan minimumRefreshInterval = TimeSpan.FromSeconds(minimumSeconds);
        TimeSpan maximumRefreshInterval = TimeSpan.FromSeconds(maximumSeconds);

        ArgumentOutOfRangeException caught = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new StatusListCachingBounds(minimumRefreshInterval, maximumRefreshInterval),
            $"[{minimumRefreshInterval}, {maximumRefreshInterval}] is not the lower/upper bound pair "
            + "Section 11.5 tells a client to be configured with, so it must not be constructible.");

        Assert.AreEqual(expectedParameterName, caught.ParamName,
            "The refusal names the bound that makes the pair unusable.");
    }


    /// <summary>
    /// "Reasonable values for both claims highly depend on the use-case requirements and clients
    /// should be configured with lower/upper bounds for these values that fit their respective
    /// use-cases."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// A positive floor with a ceiling at or above it is a range, and both endpoints reach
    /// <see cref="StatusListValidation.ShouldRefresh"/> unmodified — a single-point range
    /// (floor equal to ceiling) is a client pinned to one refresh interval regardless of the
    /// <c>ttl</c> a Status Issuer publishes.
    /// </summary>
    /// <param name="minimumSeconds">The refresh-interval floor.</param>
    /// <param name="maximumSeconds">The refresh-interval ceiling.</param>
    [TestMethod]
    [DataRow(60d, 3600d)]
    [DataRow(300d, 300d)]
    public void CachingBoundsCarryAConfiguredLowerAndUpperBoundThrough(double minimumSeconds, double maximumSeconds)
    {
        TimeSpan minimumRefreshInterval = TimeSpan.FromSeconds(minimumSeconds);
        TimeSpan maximumRefreshInterval = TimeSpan.FromSeconds(maximumSeconds);

        var bounds = new StatusListCachingBounds(minimumRefreshInterval, maximumRefreshInterval);

        Assert.AreEqual(minimumRefreshInterval, bounds.MinimumRefreshInterval,
            "The floor a client is configured with is the floor the refresh decision clamps to.");
        Assert.AreEqual(maximumRefreshInterval, bounds.MaximumRefreshInterval,
            "The ceiling a client is configured with is the ceiling the refresh decision clamps to.");
    }
}
