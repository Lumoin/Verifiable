using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Validation;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Focused tests for <see cref="ValidationChecks.CheckDisclosureSaltLength"/> — the disclosure
/// salt-length signal. The shortest observed salt length
/// (<see cref="ValidationContext.MinimumDisclosureSaltLengthBytes"/>) is captured in the verify step;
/// this rule compares it against <see cref="Salt.RecommendedByteLength"/> and only fails when the
/// deployment opts into enforcement (<see cref="PolicyExchangeContextExtensions.EnforceMinimumSaltLength"/>,
/// default observe — RFC 9901 §9.3 RECOMMENDS rather than mandates the length). These pin the gate ×
/// signal matrix directly.
/// </summary>
[TestClass]
internal sealed class SaltLengthCheckTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly DateTimeOffset Now =
        new(2026, 5, 29, 12, 0, 0, TimeSpan.Zero);


    [TestMethod]
    public async Task ObservesUnderLengthSaltByDefault()
    {
        //Default policy (no key set) → observe, do not reject. The short salt is a passing signal.
        ClaimOutcome outcome = await RunAsync(new ExchangeContext(), minimumSaltLength: Salt.RecommendedByteLength - 8);

        Assert.AreEqual(ClaimOutcome.Success, outcome,
            "By default a below-recommended salt length is observed, not rejected.");
    }


    [TestMethod]
    public async Task RejectsUnderLengthSaltWhenEnforced()
    {
        ExchangeContext context = new();
        context.SetEnforceMinimumSaltLength(true);

        ClaimOutcome outcome = await RunAsync(context, minimumSaltLength: Salt.RecommendedByteLength - 8);

        Assert.AreEqual(ClaimOutcome.Failure, outcome,
            "With enforcement on, a salt shorter than the recommended length must fail.");
    }


    [TestMethod]
    public async Task AcceptsRecommendedLengthSaltWhenEnforced()
    {
        ExchangeContext context = new();
        context.SetEnforceMinimumSaltLength(true);

        ClaimOutcome outcome = await RunAsync(context, minimumSaltLength: Salt.RecommendedByteLength);

        Assert.AreEqual(ClaimOutcome.Success, outcome,
            "A salt at the recommended length passes even under enforcement.");
    }


    [TestMethod]
    public async Task AcceptsAbsentSaltLengthWhenEnforced()
    {
        //null = a format with no disclosure salts (mdoc) or no disclosures — nothing to fail on.
        ExchangeContext context = new();
        context.SetEnforceMinimumSaltLength(true);

        ClaimOutcome outcome = await RunAsync(context, minimumSaltLength: null);

        Assert.AreEqual(ClaimOutcome.Success, outcome,
            "When no disclosure salt length was observed the check passes.");
    }


    private async ValueTask<ClaimOutcome> RunAsync(ExchangeContext ExchangeContext, int? minimumSaltLength)
    {
        ValidationContext context = new()
        {
            Context = ExchangeContext,
            Now = Now,
            MinimumDisclosureSaltLengthBytes = minimumSaltLength
        };

        List<Claim> claims = await ValidationChecks.CheckDisclosureSaltLength(
            context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, claims);
        Assert.AreEqual(ValidationClaimIds.DisclosureSaltLength, claims[0].Id);

        return claims[0].Outcome;
    }
}
