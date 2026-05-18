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
        CollectionAssert.AreEqual(ExpectedAmrPwdMfa, (System.Collections.ICollection)amr);
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
}
