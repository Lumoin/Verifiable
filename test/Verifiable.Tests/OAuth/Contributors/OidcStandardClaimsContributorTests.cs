using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;

namespace Verifiable.Tests.OAuth.Contributors;

/// <summary>
/// Per-family unit tests for <see cref="OidcStandardClaimsContributor"/>.
/// Each contributor is exercised against pre-populated targets so the
/// tests don't depend on a wired <c>AuthorizationServer</c> resolver.
/// </summary>
[TestClass]
internal sealed class OidcStandardClaimsContributorTests
{
    public TestContext TestContext { get; set; } = null!;


    //ProfileClaims contributor.

    [TestMethod]
    public async Task ProfileEmitsAllPopulatedClaims()
    {
        DateTimeOffset updatedAt = new(2026, 5, 17, 0, 0, 0, TimeSpan.Zero);
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Profile = new ProfileClaims
            {
                Name = "Ada Lovelace",
                FamilyName = "Lovelace",
                GivenName = "Ada",
                MiddleName = "Augusta",
                Nickname = "ada",
                PreferredUsername = "ada.lovelace",
                Profile = new Uri("https://example.test/profile/ada"),
                Picture = new Uri("https://example.test/picture/ada.png"),
                Website = new Uri("https://example.test/ada"),
                Gender = "female",
                Birthdate = new DateOnly(1815, 12, 10),
                Zoneinfo = "Europe/London",
                Locale = "en-GB",
                UpdatedAt = updatedAt
            }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid profile", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateProfileClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(claims.All(c => c.Outcome == ClaimOutcome.Success),
            "All emitted claims must be Success for a fully-populated profile.");

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.AreEqual("Ada Lovelace", emitted[WellKnownJwtClaimNames.Name]);
        Assert.AreEqual("Lovelace", emitted[WellKnownJwtClaimNames.FamilyName]);
        Assert.AreEqual("Ada", emitted[WellKnownJwtClaimNames.GivenName]);
        Assert.AreEqual("https://example.test/profile/ada", emitted[WellKnownJwtClaimNames.Profile]);
        Assert.AreEqual("1815-12-10", emitted[WellKnownJwtClaimNames.Birthdate]);
        Assert.AreEqual(updatedAt.ToUnixTimeSeconds(), emitted[WellKnownJwtClaimNames.UpdatedAt]);
    }


    [TestMethod]
    public async Task ProfileReturnsNotApplicableWhenScopeMissing()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Profile = new ProfileClaims { Name = "Ada" }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateProfileClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task ProfileReturnsNotApplicableWhenSubRecordAbsent()
    {
        OidcClaims oidcClaims = new() { Subject = "subject-contributor-test" };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid profile", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateProfileClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task ProfileReturnsNotApplicableForAccessTokenTarget()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget("openid profile");

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateProfileClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    //EmailClaims contributor.

    [TestMethod]
    public async Task EmailEmitsAddressAndVerifiedFlag()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Email = new EmailClaims { Email = "ada@example.test", EmailVerified = true }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid email", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateEmailClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.AreEqual("ada@example.test", emitted[WellKnownJwtClaimNames.Email]);
        Assert.IsTrue((bool)emitted[WellKnownJwtClaimNames.EmailVerified]);
    }


    [TestMethod]
    public async Task EmailOmitsVerifiedFlagWhenNull()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Email = new EmailClaims { Email = "ada@example.test" }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid email", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateEmailClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.IsTrue(emitted.ContainsKey(WellKnownJwtClaimNames.Email));
        Assert.IsFalse(emitted.ContainsKey(WellKnownJwtClaimNames.EmailVerified));
    }


    [TestMethod]
    public async Task EmailReturnsNotApplicableForUserInfoTargetWithoutScope()
    {
        UserInfoTarget target = ContributorTestFixtures.BuildUserInfoTarget(
            "openid",
            new OidcClaims
            {
                Subject = "subject-contributor-test",
                Email = new EmailClaims { Email = "ada@example.test" }
            });

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateEmailClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task EmailReturnsNotApplicableForAccessTokenTarget()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget("openid email");

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateEmailClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    //AddressClaims contributor.

    [TestMethod]
    public async Task AddressEmitsStructuredObjectForPopulatedFields()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Address = new AddressClaims
            {
                Formatted = "10 Downing St\nLondon SW1A 2AA\nUK",
                StreetAddress = "10 Downing St",
                Locality = "London",
                PostalCode = "SW1A 2AA",
                Country = "UK"
            }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid address", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateAddressClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.Success, claims[0].Outcome);
        ClaimContributionContext ctx = (ClaimContributionContext)claims[0].Context;
        Assert.AreEqual(WellKnownJwtClaimNames.Address, ctx.ClaimName);

        Dictionary<string, object> addr = (Dictionary<string, object>)ctx.ClaimValue;
        Assert.AreEqual("10 Downing St", addr["street_address"]);
        Assert.AreEqual("London", addr["locality"]);
        Assert.AreEqual("UK", addr["country"]);
        Assert.IsFalse(addr.ContainsKey("region"),
            "Region was not populated and must be omitted from the wire-format object.");
    }


    [TestMethod]
    public async Task AddressReturnsNotApplicableWhenAllFieldsAreNull()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Address = new AddressClaims()
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid address", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateAddressClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task AddressReturnsNotApplicableForAccessTokenTarget()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget("openid address");

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateAddressClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    //PhoneClaims contributor.

    [TestMethod]
    public async Task PhoneEmitsNumberAndVerifiedFlag()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Phone = new PhoneClaims
            {
                PhoneNumber = "+44 20 7946 0958",
                PhoneNumberVerified = false
            }
        };

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget(
            "openid phone", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GeneratePhoneClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.AreEqual("+44 20 7946 0958", emitted[WellKnownJwtClaimNames.PhoneNumber]);
        Assert.IsFalse((bool)emitted[WellKnownJwtClaimNames.PhoneNumberVerified]);
    }


    [TestMethod]
    public async Task PhoneReturnsNotApplicableForIntrospectionTarget()
    {
        IntrospectionTarget target = ContributorTestFixtures.BuildIntrospectionTarget("openid phone");

        List<Claim> claims = await OidcStandardClaimsContributor.GeneratePhoneClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    [TestMethod]
    public async Task PhoneReturnsNotApplicableForAccessTokenTarget()
    {
        AccessTokenTarget target = ContributorTestFixtures.BuildAccessTokenTarget("openid phone");

        List<Claim> claims = await OidcStandardClaimsContributor.GeneratePhoneClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ClaimOutcome.NotApplicable, claims[0].Outcome);
    }


    //UserInfo target wiring.

    [TestMethod]
    public async Task UserInfoTargetWithProfileScopeEmitsProfileClaims()
    {
        OidcClaims oidcClaims = new()
        {
            Subject = "subject-contributor-test",
            Profile = new ProfileClaims { Name = "Ada Lovelace", GivenName = "Ada" }
        };

        UserInfoTarget target = ContributorTestFixtures.BuildUserInfoTarget(
            "openid profile", oidcClaims);

        List<Claim> claims = await OidcStandardClaimsContributor.GenerateProfileClaims(
            target, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> emitted = ContributorTestFixtures.ExtractEmitted(claims);
        Assert.AreEqual("Ada Lovelace", emitted[WellKnownJwtClaimNames.Name]);
        Assert.AreEqual("Ada", emitted[WellKnownJwtClaimNames.GivenName]);
    }


    private static Dictionary<string, object> ExtractEmitted(List<Claim> claims)
    {
        Dictionary<string, object> emitted = new(StringComparer.Ordinal);
        foreach(Claim c in claims)
        {
            if(c.Outcome == ClaimOutcome.Success && c.Context is ClaimContributionContext ctx)
            {
                emitted[ctx.ClaimName] = ctx.ClaimValue;
            }
        }

        return emitted;
    }
}
