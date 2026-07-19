using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;

namespace Verifiable.Tests.OAuth.Contributors;

/// <summary>
/// Unit tests for <see cref="AcrAmrClaimContributor"/>. Verifies the
/// authentication-context fallback chain: <see cref="OidcClaims.AuthContext"/>
/// is the primary source, with <see cref="IssuanceContext.AuthTime"/>
/// supplying the <c>auth_time</c> value when not present on the resolved
/// claims.
/// </summary>
[TestClass]
internal sealed class AcrAmrClaimContributorTests
{
    public TestContext TestContext { get; set; } = null!;

    private static string[] ExpectedAmrPwdMfa { get; } = ["pwd", "mfa"];


    [TestMethod]
    public async Task EmitsAllThreeClaimsWhenAuthContextIsFullyPopulated()
    {
        DateTimeOffset authContextTime = new(2026, 5, 17, 10, 0, 0, TimeSpan.Zero);
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            AuthContext = new AuthenticationContext
            {
                Acr = "loa-substantial",
                Amr = ["pwd", "mfa"],
                AuthTime = authContextTime
            }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid", oidcClaims, authTime: ContributorTestFixtures.FixedAuthTime);

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.AreEqual("loa-substantial", emitted[WellKnownJwtClaimNames.Acr]);
        Assert.AreEqual(authContextTime.ToUnixTimeSeconds(), emitted[WellKnownJwtClaimNames.AuthTime]);

        IReadOnlyList<string> amr = (IReadOnlyList<string>)emitted[WellKnownJwtClaimNames.Amr];
        Assert.AreSequenceEqual(ExpectedAmrPwdMfa, (System.Collections.ICollection)amr);
    }


    [TestMethod]
    public async Task FallsBackToIssuanceAuthTimeWhenAuthContextOmitsIt()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            AuthContext = new AuthenticationContext { Acr = "loa-low" }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid", oidcClaims, authTime: ContributorTestFixtures.FixedAuthTime);

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.AreEqual(
            ContributorTestFixtures.FixedAuthTime.ToUnixTimeSeconds(),
            emitted[WellKnownJwtClaimNames.AuthTime],
            "auth_time falls back to IssuanceContext.AuthTime when AuthContext.AuthTime is null.");
    }


    [TestMethod]
    public async Task ReturnsNotApplicableForAuthTimeAndClassWhenAllSourcesAreNull()
    {
        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid",
            resolvedClaims: new OidcClaims { Subject = "subject-contributor-test" },
            authTime: null);

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(claims.All(c => c.Outcome == ClaimOutcome.NotApplicable),
            "When no auth-context signals are present, every claim must be NotApplicable.");
    }


    [TestMethod]
    public async Task EmitsAuthTimeOnlyWhenAcrAndAmrAreAbsent()
    {
        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid",
            resolvedClaims: new OidcClaims { Subject = "subject-contributor-test" },
            authTime: ContributorTestFixtures.FixedAuthTime);

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.IsTrue(emitted.ContainsKey(WellKnownJwtClaimNames.AuthTime));
        Assert.IsFalse(emitted.ContainsKey(WellKnownJwtClaimNames.Acr));
        Assert.IsFalse(emitted.ContainsKey(WellKnownJwtClaimNames.Amr));
    }


    [TestMethod]
    public async Task OmitsAmrWhenListIsEmpty()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            AuthContext = new AuthenticationContext { Acr = "loa-low", Amr = [] }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid", oidcClaims);

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.IsFalse(emitted.ContainsKey(WellKnownJwtClaimNames.Amr),
            "Empty amr list must be treated as 'not populated'; the OIDC Core §2 amr claim is omitted rather than emitted as an empty JSON array.");
        Assert.AreEqual("loa-low", emitted[WellKnownJwtClaimNames.Acr]);
    }


    [TestMethod]
    public async Task ReturnsNotApplicableForUserInfoTarget()
    {
        UserInfoTarget target = ContributorTestFixtures.BuildUserInfoTarget(
            "openid",
            new OidcClaims
            {
                Subject = "subject-contributor-test",
                AuthContext = new AuthenticationContext { Acr = "loa-low" }
            });

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(claims.All(c => c.Outcome == ClaimOutcome.NotApplicable),
            "AcrAmr applies only to IdTokenTarget — UserInfo responses don't carry authentication-context claims.");
    }


    /// <summary>
    /// RFC 9068 §2.2.1 / RFC 9470 §5 — the access token carries <c>acr</c> and
    /// <c>auth_time</c> from the threaded <see cref="IssuanceContext"/> so the
    /// Resource Server can read the authentication strength actually achieved.
    /// </summary>
    [TestMethod]
    public async Task EmitsAcrAndAuthTimeForAccessTokenTarget()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget(
            "openid",
            authTime: ContributorTestFixtures.FixedAuthTime,
            acr: "loa-substantial");

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.AreEqual("loa-substantial", emitted[WellKnownJwtClaimNames.Acr]);
        Assert.AreEqual(
            ContributorTestFixtures.FixedAuthTime.ToUnixTimeSeconds(),
            emitted[WellKnownJwtClaimNames.AuthTime]);
    }


    /// <summary>
    /// Access tokens carry no <see cref="OidcClaims"/>, so the contributor never
    /// emits <c>amr</c> on an <see cref="AccessTokenTarget"/> — RFC 9470 §5 names
    /// only <c>acr</c> and <c>auth_time</c> for the Resource Server.
    /// </summary>
    [TestMethod]
    public async Task NeverEmitsAmrForAccessTokenTarget()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget(
            "openid",
            authTime: ContributorTestFixtures.FixedAuthTime,
            acr: "loa-substantial");

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.IsFalse(emitted.ContainsKey(WellKnownJwtClaimNames.Amr),
            "An access token carries no amr — it has no resolved OidcClaims.AuthContext to source one from.");
    }


    /// <summary>
    /// A deployment that does no step-up / authentication-context tracking stamps no
    /// <c>acr</c>; the auth-code flow still carries an <c>auth_time</c>, so the access
    /// token emits <c>auth_time</c> only and reports <c>acr</c> as
    /// <see cref="ClaimOutcome.NotApplicable"/>.
    /// </summary>
    [TestMethod]
    public async Task EmitsAuthTimeOnlyWhenAccessTokenHasNoAcr()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget(
            "openid",
            authTime: ContributorTestFixtures.FixedAuthTime,
            acr: null);

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.IsTrue(emitted.ContainsKey(WellKnownJwtClaimNames.AuthTime));
        Assert.IsFalse(emitted.ContainsKey(WellKnownJwtClaimNames.Acr),
            "No stamped acr — the acr claim must be NotApplicable, not emitted.");
    }


    /// <summary>
    /// An access token with neither a stamped <c>acr</c> nor an <c>auth_time</c>
    /// (e.g. a grant shape with no End-User authentication) emits no
    /// authentication-context claims.
    /// </summary>
    [TestMethod]
    public async Task ReturnsNotApplicableForAccessTokenTargetWhenNoAuthContext()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget(
            "openid",
            authTime: null,
            acr: null);

        List<Claim> claims = await AcrAmrClaimContributor.GenerateAuthClassClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(claims.All(c => c.Outcome == ClaimOutcome.NotApplicable),
            "With no acr and no auth_time, every authentication-context claim must be NotApplicable.");
    }
}
