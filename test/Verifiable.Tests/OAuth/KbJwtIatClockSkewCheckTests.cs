using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Focused tests for the per-flow clock-skew resolution in
/// <see cref="ValidationChecks.CheckKbJwtIatNotInFuture"/>. The check reads the
/// deployment's per-request policy
/// (<see cref="PolicyExchangeContextExtensions.ClockSkewToleranceOverride"/>) when
/// set, falling back to the <see cref="ValidationContext.ClockSkew"/> field —
/// mirroring how <see cref="ValidationChecks.CheckKbJwtIatNotTooOld"/> resolves
/// its window. This pins the wiring so an OID4VP deployment's profile (resolved
/// onto the ExchangeContext at dispatch entry) actually governs KB-JWT <c>iat</c>
/// leeway, rather than a hardcoded default.
/// </summary>
[TestClass]
internal sealed class KbJwtIatClockSkewCheckTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset Now =
        new(2026, 5, 29, 12, 0, 0, TimeSpan.Zero);

    //A KB-JWT iat ten seconds ahead of the verifier's clock — inside a generous
    //skew window, outside a tight one.
    private static readonly DateTimeOffset IatTenSecondsAhead = Now.AddSeconds(10);


    [TestMethod]
    public async Task TightPerFlowPolicySkewRejectsFutureIat()
    {
        ExchangeContext ExchangeContext = new();
        ExchangeContext.SetClockSkewTolerance(TimeSpan.FromSeconds(1));

        ClaimOutcome outcome = await RunAsync(ExchangeContext, fieldClockSkew: TimeSpan.FromMinutes(5));

        Assert.AreEqual(ClaimOutcome.Failure, outcome,
            "A 1-second per-flow policy skew must reject an iat 10 seconds in the future, "
            + "even though the ValidationContext field would have permitted it.");
    }


    [TestMethod]
    public async Task PermissivePerFlowPolicySkewAcceptsFutureIat()
    {
        ExchangeContext ExchangeContext = new();
        ExchangeContext.SetClockSkewTolerance(TimeSpan.FromMinutes(5));

        ClaimOutcome outcome = await RunAsync(ExchangeContext, fieldClockSkew: TimeSpan.FromSeconds(1));

        Assert.AreEqual(ClaimOutcome.Success, outcome,
            "A 5-minute per-flow policy skew must accept an iat 10 seconds in the future, "
            + "overriding the tighter ValidationContext field.");
    }


    [TestMethod]
    public async Task FallsBackToFieldWhenNoPolicySkewSet()
    {
        //No SetClockSkewTolerance on the context → ClockSkewToleranceOverride is
        //null → the check uses the ValidationContext.ClockSkew field.
        ExchangeContext ExchangeContext = new();

        ClaimOutcome tightFieldOutcome = await RunAsync(ExchangeContext, fieldClockSkew: TimeSpan.FromSeconds(1));
        Assert.AreEqual(ClaimOutcome.Failure, tightFieldOutcome,
            "With no per-flow policy, a 1-second ValidationContext field skew must reject the future iat.");

        ClaimOutcome permissiveFieldOutcome = await RunAsync(ExchangeContext, fieldClockSkew: TimeSpan.FromMinutes(5));
        Assert.AreEqual(ClaimOutcome.Success, permissiveFieldOutcome,
            "With no per-flow policy, a 5-minute ValidationContext field skew must accept the future iat.");
    }


    private async ValueTask<ClaimOutcome> RunAsync(ExchangeContext ExchangeContext, TimeSpan fieldClockSkew)
    {
        ValidationContext context = new()
        {
            Context = ExchangeContext,
            Now = Now,
            ClockSkew = fieldClockSkew,
            KbJwtIat = IatTenSecondsAhead
        };

        List<Claim> claims = await ValidationChecks.CheckKbJwtIatNotInFuture(
            context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ValidationClaimIds.KbJwtIatNotInFuture, claims[0].Id);

        return claims[0].Outcome;
    }
}
