using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Focused tests for <see cref="ValidationChecks.CheckSaltReuse"/> — the disclosure salt-reuse rule.
/// The reuse signal (<see cref="ValidationContext.SaltReused"/>) is derived in the verify step against
/// the application's salt-reuse store and is only ever set when a store was wired, so a detected reuse
/// always fails (enforce-when-wired, the DPoP-JTI replay posture — no separate policy gate). The full
/// verify-side wiring is exercised by the OID4VP verification tests; these pin the rule directly.
/// </summary>
[TestClass]
internal sealed class SaltReuseCheckTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset Now =
        new(2026, 5, 29, 12, 0, 0, TimeSpan.Zero);


    [TestMethod]
    public async Task RejectsReusedSalt()
    {
        ClaimOutcome outcome = await RunAsync(saltReused: true);

        Assert.AreEqual(ClaimOutcome.Failure, outcome,
            "A detected salt reuse must fail — it is only ever set when the store was wired.");
    }


    [TestMethod]
    public async Task AcceptsWhenNoReuse()
    {
        //false covers both "no reuse found" and "no salt-reuse store wired".
        ClaimOutcome outcome = await RunAsync(saltReused: false);

        Assert.AreEqual(ClaimOutcome.Success, outcome,
            "With no reuse (or no store wired) the check passes.");
    }


    private async ValueTask<ClaimOutcome> RunAsync(bool saltReused)
    {
        ValidationContext context = new()
        {
            Context = new ExchangeContext(),
            Now = Now,
            SaltReused = saltReused
        };

        List<Claim> claims = await ValidationChecks.CheckSaltReuse(
            context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ValidationClaimIds.SaltNotReused, claims[0].Id);

        return claims[0].Outcome;
    }
}
