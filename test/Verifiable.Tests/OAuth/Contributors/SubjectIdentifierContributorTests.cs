using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Contributors;

/// <summary>
/// Per-target unit tests for <see cref="SubjectIdentifierContributor"/>.
/// The contributor invokes
/// <see cref="AuthorizationServerIntegration.ResolveSubjectIdentifierAsync"/>
/// for <see cref="IdTokenTarget"/> and <see cref="UserInfoTarget"/> and
/// returns <see cref="ClaimOutcome.NotApplicable"/> for every other
/// target.
/// </summary>
[TestClass]
internal sealed class SubjectIdentifierContributorTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch.AddDays(-15));


    /// <summary>
    /// The ID-token contributor emits the application-resolved subject identifier as its single subject claim.
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">Core §2</see>.
    /// </summary>
    [TestMethod]
    public async Task IdTokenTargetEmitsResolvedSubject()
    {
        await using TestHostShell host = new(TimeProvider);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectIdentifierAsync =
                (endUserId, _, _, _) => ValueTask.FromResult($"hashed-{endUserId}");
        }).ConfigureAwait(false);

        IdTokenTarget target = BuildIdTokenTargetWithServer(host.Server, "subject-X");

        List<Claim> claims = await SubjectIdentifierContributor.GenerateSubjectClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);
        ClaimContributionContext ctx = (ClaimContributionContext)claims[0].Context;
        Assert.AreEqual(WellKnownJwtClaimNames.Sub, ctx.ClaimName);
        Assert.AreEqual("hashed-subject-X", ctx.ClaimValue);
    }


    /// <summary>
    /// The UserInfo contributor emits the application-resolved subject identifier as its single subject claim.
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">Core §5.3.2</see>.
    /// </summary>
    [TestMethod]
    public async Task UserInfoTargetEmitsResolvedSubject()
    {
        await using TestHostShell host = new(TimeProvider);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubjectIdentifierAsync =
                (endUserId, _, _, _) => ValueTask.FromResult($"hashed-{endUserId}");
        }).ConfigureAwait(false);

        UserInfoTarget target = BuildUserInfoTargetWithServer(host.Server, "subject-Y");

        List<Claim> claims = await SubjectIdentifierContributor.GenerateSubjectClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);
        ClaimContributionContext ctx = (ClaimContributionContext)claims[0].Context;
        Assert.AreEqual(WellKnownJwtClaimNames.Sub, ctx.ClaimName);
        Assert.AreEqual("hashed-subject-Y", ctx.ClaimValue);
    }


    [TestMethod]
    public async Task AccessTokenTargetReturnsNotApplicable()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget("openid");

        List<Claim> claims = await SubjectIdentifierContributor.GenerateSubjectClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task IntrospectionTargetReturnsNotApplicable()
    {
        IntrospectionTarget target = ContributorTestFixtures.BuildIntrospectionTarget("openid");

        List<Claim> claims = await SubjectIdentifierContributor.GenerateSubjectClaim(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    private static IdTokenTarget BuildIdTokenTargetWithServer(
        EndpointServer server, string subject)
    {
        ClientRecord registration = ContributorTestFixtures.BuildRegistration();
        ExchangeContext ExchangeContext = [];
        ExchangeContext.SetServer(server);
        IssuanceContext issuance = new()
        {
            Registration = registration,
            Context = ExchangeContext,
            IssuerUri = new Uri("https://issuer.contributor-test/"),
            Subject = subject,
            Scope = WellKnownScopes.OpenId,
            ClientId = registration.ClientId,
            GrantType = WellKnownGrantTypes.AuthorizationCode,
            IssuedAt = ContributorTestFixtures.FixedIssuedAt,
            Nonce = null,
            AuthTime = null
        };
        return new IdTokenTarget(issuance);
    }


    private static UserInfoTarget BuildUserInfoTargetWithServer(
        EndpointServer server, string subject)
    {
        ClientRecord registration = ContributorTestFixtures.BuildRegistration();
        ExchangeContext ExchangeContext = [];
        ExchangeContext.SetServer(server);
        return new UserInfoTarget(
            registration, subject, WellKnownScopes.OpenId, ExchangeContext);
    }
}
