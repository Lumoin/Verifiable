using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth.Contributors;

/// <summary>
/// Unit tests for <see cref="CnfClaimContributor"/>. The contributor
/// composes the RFC 7800 <c>cnf</c> claim from the
/// <see cref="ConfirmationMethod"/> on the issuance.
/// </summary>
[TestClass]
internal sealed class CnfClaimContributorTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task EmitsCnfWithJwkThumbprintWhenConfirmationCarriesJkt()
    {
        const string FixedThumbprint = "dpop-jkt-base64url-abc123";

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid",
            confirmation: new ConfirmationMethod { JwkThumbprint = FixedThumbprint });

        List<Claim> claims = await CnfClaimContributor.GenerateCnfClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);

        ClaimContributionContext ctx = (ClaimContributionContext)claims[0].Context;
        Assert.AreEqual(WellKnownJwtClaimNames.Cnf, ctx.ClaimName);

        Dictionary<string, object> cnf = (Dictionary<string, object>)ctx.ClaimValue;
        Assert.AreEqual(FixedThumbprint, cnf[WellKnownJwtClaimNames.JwkThumbprint]);
    }


    [TestMethod]
    public async Task ReturnsNotApplicableWhenConfirmationIsAbsent()
    {
        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget("openid", confirmation: null);

        List<Claim> claims = await CnfClaimContributor.GenerateCnfClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task ReturnsNotApplicableWhenConfirmationIsEmpty()
    {
        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid", confirmation: new ConfirmationMethod());

        List<Claim> claims = await CnfClaimContributor.GenerateCnfClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task ReturnsNotApplicableForUserInfoTarget()
    {
        UserInfoTarget target = ContributorTestFixtures.BuildUserInfoTarget("openid");

        List<Claim> claims = await CnfClaimContributor.GenerateCnfClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task EmitsCnfForAccessTokenTargetWhenConfirmationCarriesJkt()
    {
        const string FixedThumbprint = "dpop-jkt-base64url-access-token";

        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget(
            "openid",
            confirmation: new ConfirmationMethod { JwkThumbprint = FixedThumbprint });

        List<Claim> claims = await CnfClaimContributor.GenerateCnfClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);

        ClaimContributionContext ctx = (ClaimContributionContext)claims[0].Context;
        Assert.AreEqual(WellKnownJwtClaimNames.Cnf, ctx.ClaimName);

        Dictionary<string, object> cnf = (Dictionary<string, object>)ctx.ClaimValue;
        Assert.AreEqual(FixedThumbprint, cnf[WellKnownJwtClaimNames.JwkThumbprint]);
    }


    [TestMethod]
    public async Task ReturnsNotApplicableForAccessTokenTargetWithoutConfirmation()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget("openid");

        List<Claim> claims = await CnfClaimContributor.GenerateCnfClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }
}
