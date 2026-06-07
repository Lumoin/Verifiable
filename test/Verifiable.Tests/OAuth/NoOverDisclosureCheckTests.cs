using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Focused tests for <see cref="ValidationChecks.CheckNoOverDisclosure"/> — the
/// data-minimization rule. The over-disclosure signal
/// (<see cref="ValidationContext.DcqlOverDisclosed"/>) is derived in the verify
/// step; this rule gates enforcement on the per-request policy
/// (<see cref="PolicyExchangeContextExtensions.EnforceNoOverDisclosure"/>, default
/// enforce). The full pipeline path is covered by the OID4VP wallet/flow tests;
/// these pin the gate × signal matrix directly.
/// </summary>
[TestClass]
internal sealed class NoOverDisclosureCheckTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset Now =
        new(2026, 5, 29, 12, 0, 0, TimeSpan.Zero);


    [TestMethod]
    public async Task RejectsOverDisclosureWhenEnforcedByDefault()
    {
        //Default policy (no key set) → enforce. Over-disclosed → Failure.
        ClaimOutcome outcome = await RunAsync(new ExchangeContext(), overDisclosed: true);

        Assert.AreEqual(ClaimOutcome.Failure, outcome,
            "With enforcement on (the default) an over-disclosing presentation must fail.");
    }


    [TestMethod]
    public async Task AcceptsMinimalDisclosureWhenEnforced()
    {
        ClaimOutcome outcome = await RunAsync(new ExchangeContext(), overDisclosed: false);

        Assert.AreEqual(ClaimOutcome.Success, outcome,
            "A presentation that did not over-disclose passes regardless of enforcement.");
    }


    [TestMethod]
    public async Task AcceptsOverDisclosureWhenEnforcementDisabled()
    {
        //Deployment opted out of strict minimization: over-disclosure is recorded
        //as a (passing) signal rather than rejected.
        ExchangeContext context = new();
        context.SetEnforceNoOverDisclosure(false);

        ClaimOutcome outcome = await RunAsync(context, overDisclosed: true);

        Assert.AreEqual(ClaimOutcome.Success, outcome,
            "With enforcement disabled, over-disclosure must not fail verification.");
    }


    private async ValueTask<ClaimOutcome> RunAsync(ExchangeContext ExchangeContext, bool overDisclosed)
    {
        ValidationContext context = new()
        {
            Context = ExchangeContext,
            Now = Now,
            DcqlOverDisclosed = overDisclosed
        };

        List<Claim> claims = await ValidationChecks.CheckNoOverDisclosure(
            context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ValidationClaimIds.NoOverDisclosure, claims[0].Id);

        return claims[0].Outcome;
    }
}
