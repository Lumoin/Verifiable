using System.Globalization;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Contributors;

/// <summary>
/// Lock-in regression tests for the Phase A composed contributor chain.
/// These tests pin behavioural invariants that the assessment-pattern
/// contributor surface needs to keep across future refactors:
/// rule ordering, the standard rule registration order, and the canonical
/// output for a fully-populated input.
/// </summary>
/// <remarks>
/// <para>
/// Different layer than the per-contributor tests in
/// <see cref="OidcStandardClaimsContributorTests"/>,
/// <see cref="CnfClaimContributorTests"/>, and
/// <see cref="AcrAmrClaimContributorTests"/>. The per-contributor tests
/// pin each rule's output in isolation. These tests pin the composition
/// itself — the
/// <see cref="ClaimIssuer{T}.GenerateClaimsAsync"/> iteration order, the
/// dictionary-merge "later writes win" semantic the walking site applies,
/// and the alphabetised canonical projection of a known-rich input.
/// </para>
/// <para>
/// Different layer also than <see cref="Oidc10IdTokenProducerTests"/>'s
/// baseline. That test pins the end-to-end wire output for a minimally-
/// configured input (no scope-driven claims). This test pins the
/// contributor chain's extension-claim output for a richly-populated
/// input. Together they bracket every claim the token endpoint can emit.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ContributorChainRegressionTests
{
    public TestContext TestContext { get; set; } = null!;


    //Marker ClaimIds for the ordering test. Codes 90000+ are outside the
    //library's reservation ranges (1-602 crypto/DID, 700-999 Validation,
    //1000-1099 Phase A, 1100+ reserved for future tracks).
    private static readonly ClaimId FirstMarkerId =
        ClaimId.Create(90001, "ContributorChainTestFirstMarker");

    private static readonly ClaimId SecondMarkerId =
        ClaimId.Create(90002, "ContributorChainTestSecondMarker");


    [TestMethod]
    public async Task RulesRunInListOrderAndLaterWritesWin()
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules =
        [
            new ClaimDelegate<ClaimContributionTarget>(EmitFirst, [FirstMarkerId]),
            new ClaimDelegate<ClaimContributionTarget>(EmitSecond, [SecondMarkerId])
        ];

        ClaimIssuer<ClaimContributionTarget> issuer = new(
            "test-chain-order-issuer", rules, new FakeTimeProvider(TestClock.CanonicalEpoch));

        IdTokenTarget target = ContributorTestFixtures.BuildIdTokenTarget("openid");

        ClaimIssueResult result = await issuer.GenerateClaimsAsync(
            target, "test-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, result.Claims, "One claim per registered rule must appear in the result.");

        ClaimContributionContext firstCtx = (ClaimContributionContext)result.Claims[0].Context;
        ClaimContributionContext secondCtx = (ClaimContributionContext)result.Claims[1].Context;

        Assert.AreEqual("first", firstCtx.ClaimValue,
            "result.Claims[0] must carry the first rule's output — rule iteration order matches list registration.");
        Assert.AreEqual("second", secondCtx.ClaimValue,
            "result.Claims[1] must carry the second rule's output.");

        //Dictionary-merge semantic: walking site applies indexer writes in order,
        //so later writes win for the same claim name.
        Dictionary<string, object> merged = new(StringComparer.Ordinal);
        foreach(Claim c in result.Claims)
        {
            if(c.Outcome == ClaimOutcome.Success && c.Context is ClaimContributionContext ctx)
            {
                merged[ctx.ClaimName] = ctx.ClaimValue;
            }
        }

        Assert.AreEqual("second", merged["chain_test_marker"],
            "The walking-site merge applies in result.Claims order; later writes overwrite earlier values.");
    }


    [TestMethod]
    public void StandardRulesAreRegisteredInExpectedOrder()
    {
        List<ClaimDelegate<ClaimContributionTarget>> rules = ContributionProfiles.StandardRules();

        Assert.HasCount(8, rules,
            "StandardRules registers eight contributor rules: sub, profile, email, address, phone, cnf, acr+amr+auth_time, sid.");

        ClaimId[] expectedFirstIds =
        [
            WellKnownClaimIds.SubjectIdentifier,
            WellKnownClaimIds.OidcProfile,
            WellKnownClaimIds.OidcEmail,
            WellKnownClaimIds.OidcAddress,
            WellKnownClaimIds.OidcPhone,
            WellKnownClaimIds.CnfBinding,
            WellKnownClaimIds.OidcAuthClass,
            WellKnownClaimIds.OidcSessionId
        ];

        for(int i = 0; i < rules.Count; i++)
        {
            Assert.AreEqual(
                expectedFirstIds[i],
                rules[i].ExpectedClaimIds[0],
                $"StandardRules position {i} must carry expected ClaimId. Reordering or inserting a new standard rule must be a deliberate edit that updates this test.");
        }
    }


    [TestMethod]
    public async Task StandardClaimIssuerEmitsBaselineForRichOidcClaims()
    {
        DateTimeOffset fixedAuthTime = new(2026, 5, 17, 11, 30, 0, TimeSpan.Zero);
        DateTimeOffset fixedUpdatedAt = new(2026, 5, 16, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset fixedIssuedAt = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);
        const string FixedThumbprint = "dpop-jkt-baseline-abc123";

        OidcClaims oidcClaims = new()
        {
            Subject = "subject-baseline",
            Profile = new ProfileClaims
            {
                Name = "Ada Lovelace",
                FamilyName = "Lovelace",
                GivenName = "Ada",
                PreferredUsername = "ada",
                Birthdate = new DateOnly(1815, 12, 10),
                Locale = "en-GB",
                UpdatedAt = fixedUpdatedAt
            },
            Email = new EmailClaims
            {
                Email = "ada@example.test",
                EmailVerified = true
            },
            Address = new AddressClaims
            {
                Locality = "London",
                Country = "GB",
                PostalCode = "SW1A 2AA"
            },
            Phone = new PhoneClaims
            {
                PhoneNumber = "+44 20 7946 0958"
            },
            AuthContext = new AuthenticationContext
            {
                Acr = "loa-substantial",
                Amr = ["pwd", "mfa"],
                AuthTime = fixedAuthTime
            }
        };

        IssuanceContext issuance = new()
        {
            Registration = ContributorTestFixtures.BuildRegistration(),
            Context = new ExchangeContext(),
            IssuerUri = new Uri("https://issuer.baseline.test/"),
            Subject = "subject-baseline",
            Scope = "openid profile email address phone",
            ClientId = "client-baseline",
            IssuedAt = fixedIssuedAt,
            Confirmation = new ConfirmationMethod { JwkThumbprint = FixedThumbprint }
        };

        IdTokenTarget target = new(issuance) { ResolvedOidcClaims = oidcClaims };

        ClaimIssuer<ClaimContributionTarget> issuer = ContributionProfiles.StandardClaimIssuer(new FakeTimeProvider(TestClock.CanonicalEpoch));

        ClaimIssueResult result = await issuer.GenerateClaimsAsync(
            target, "baseline-correlation", TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, object> merged = new(StringComparer.Ordinal);
        foreach(Claim c in result.Claims)
        {
            if(c.Outcome == ClaimOutcome.Success && c.Context is ClaimContributionContext ctx)
            {
                merged[ctx.ClaimName] = ctx.ClaimValue;
            }
        }

        string actualCanonical = Canonicalise(merged);

        //Future legitimate changes — a new claim emitted by default, a value
        //format change — fail this assertion. If intentional, uncomment the
        //TestContext.WriteLine, run the test once, paste the printed canonical
        //into ExpectedCanonical below.
        //TestContext.WriteLine(actualCanonical);

        const string ExpectedCanonical =
            """
            {"acr":"loa-substantial","address":{"country":"GB","locality":"London","postal_code":"SW1A 2AA"},"amr":["pwd","mfa"],"auth_time":1779017400,"birthdate":"1815-12-10","cnf":{"jkt":"dpop-jkt-baseline-abc123"},"email":"ada@example.test","email_verified":true,"family_name":"Lovelace","given_name":"Ada","locale":"en-GB","name":"Ada Lovelace","phone_number":"+44 20 7946 0958","preferred_username":"ada","updated_at":1778889600}
            """;

        Assert.AreEqual(ExpectedCanonical, actualCanonical,
            "Standard contributor chain output diverged from the baseline. "
            + "Any legitimate change (a new claim, a value format change) must "
            + "regenerate the baseline literal — uncomment TestContext.WriteLine "
            + "in this test, run it, paste the printed string into ExpectedCanonical.");
    }


    private static ValueTask<List<Claim>> EmitFirst(
        ClaimContributionTarget target, CancellationToken cancellationToken) =>
        new(new List<Claim>
        {
            new(FirstMarkerId, ClaimOutcome.Success,
                new ClaimContributionContext("chain_test_marker", "first"),
                Claim.NoSubClaims)
        });


    private static ValueTask<List<Claim>> EmitSecond(
        ClaimContributionTarget target, CancellationToken cancellationToken) =>
        new(new List<Claim>
        {
            new(SecondMarkerId, ClaimOutcome.Success,
                new ClaimContributionContext("chain_test_marker", "second"),
                Claim.NoSubClaims)
        });


    /// <summary>
    /// Canonicalises a claim dictionary by sorting keys lexicographically
    /// at every level and emitting JSON-shaped output. Handles the value
    /// shapes the six standard contributors produce: strings, longs/ints,
    /// booleans, string lists (<c>amr</c>), and nested
    /// <see cref="Dictionary{TKey, TValue}"/> objects (<c>cnf</c>,
    /// <c>address</c>). Not a general JSON serializer — exists to keep
    /// this test independent of the production payload serializer.
    /// </summary>
    private static string Canonicalise(IDictionary<string, object> map)
    {
        StringBuilder sb = new();
        AppendObject(sb, map);
        return sb.ToString();
    }


    private static void AppendObject(StringBuilder sb, IDictionary<string, object> map)
    {
        sb.Append('{');
        bool first = true;
        foreach(KeyValuePair<string, object> entry in map.OrderBy(
            e => e.Key, StringComparer.Ordinal))
        {
            if(!first)
            {
                sb.Append(',');
            }
            first = false;

            sb.Append('"').Append(entry.Key).Append("\":");
            AppendValue(sb, entry.Value);
        }

        sb.Append('}');
    }


    private static void AppendValue(StringBuilder sb, object value)
    {
        switch(value)
        {
            case string s:
                sb.Append('"').Append(s).Append('"');
                break;

            case long l:
                sb.Append(l.ToString(CultureInfo.InvariantCulture));
                break;

            case int i:
                sb.Append(i.ToString(CultureInfo.InvariantCulture));
                break;

            case bool b:
                sb.Append(b ? "true" : "false");
                break;

            case IReadOnlyList<string> list:
                sb.Append('[');
                for(int idx = 0; idx < list.Count; idx++)
                {
                    if(idx > 0)
                    {
                        sb.Append(',');
                    }
                    sb.Append('"').Append(list[idx]).Append('"');
                }
                sb.Append(']');
                break;

            case IDictionary<string, object> nested:
                AppendObject(sb, nested);
                break;

            default:
                sb.Append('"').Append(value).Append('"');
                break;
        }
    }
}
