using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;


namespace Verifiable.Tests.Assessment;

/// <summary>
/// Tests for <see cref="ClaimIssuer{TInput}"/> functionality including tracing,
/// partial results, and cancellation handling.
/// </summary>
[TestClass]
internal sealed class ClaimIssuerTests
{
    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    private const string TestIssuerId = "test-issuer-id";
    private const string TestCorrelationId = "test-correlation-id";
    private const string TestClaimIdValue = "generated-claim-id-12345";

    /// <summary>
    /// Fake time provider for deterministic timestamp testing.
    /// </summary>
    private static FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(
        new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero));


    [TestMethod]
    public async Task GenerateClaimsAsyncProducesCompleteResult()
    {
        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid]),
            new(FailingRule, [ClaimId.AlgIsNone])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsComplete, "Result should be complete.");
        Assert.AreEqual(ClaimIssueCompletionStatus.Complete, result.CompletionStatus);
        Assert.AreEqual(2, result.RulesExecuted);
        Assert.AreEqual(2, result.TotalRules);
        Assert.HasCount(2, result.Claims);
        Assert.AreEqual(TestCorrelationId, result.CorrelationId);
        Assert.AreEqual(TestIssuerId, result.ClaimIssuerId);
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncUsesProvidedTimeProvider()
    {
        var fixedTime = new DateTimeOffset(2025, 1, 15, 10, 30, 0, TimeSpan.Zero);
        var fakeTimeProvider = new FakeTimeProvider(fixedTime);

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            fakeTimeProvider);

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(fixedTime.UtcDateTime, result.CreationTimestampInUtc);
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncUsesCustomClaimIdGenerator()
    {
        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider,
            claimIdGenerator: (ct) => ValueTask.FromResult(TestClaimIdValue));

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TestClaimIdValue, result.ClaimIssueResultId);
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncCapturesTracingInformation()
    {
        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Tracing information should always be present.
        Assert.IsNotNull(result.ClaimIssuerTraceId, "TraceId should be captured.");
        Assert.IsNotNull(result.ClaimIssuerSpanId, "SpanId should be captured.");
        Assert.IsNotNull(result.Baggage, "Baggage should be captured.");

        //TraceId should be 32 hex characters (16 bytes).
        Assert.AreEqual(32, result.ClaimIssuerTraceId.Length, "TraceId should be 32 hex characters.");
        //SpanId should be 16 hex characters (8 bytes).
        Assert.AreEqual(16, result.ClaimIssuerSpanId.Length, "SpanId should be 16 hex characters.");
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncWithActivityPropagatesTracing()
    {
        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        //Create an activity to simulate distributed tracing context.
        using var activitySource = new ActivitySource("Verifiable.Tests");
        using var listener = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData
        };
        ActivitySource.AddActivityListener(listener);

        using var activity = activitySource.StartActivity("TestOperation");
        Assert.IsNotNull(activity, "Activity should be created.");

        //Add baggage to the activity.
        activity.AddBaggage("test-key", "test-value");

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Tracing should capture the activity context.
        Assert.AreEqual(activity.TraceId.ToString(), result.ClaimIssuerTraceId);
        Assert.IsNotNull(result.ClaimIssuerSpanId);

        //Baggage should be propagated.
        Assert.IsTrue(result.Baggage!.ContainsKey("test-key"));
        Assert.AreEqual("test-value", result.Baggage["test-key"]);
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncReturnsPartialResultOnCancellation()
    {
        using var cts = new CancellationTokenSource();

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid]),
            new(async (input, ct) =>
            {
                //Cancel after the first rule completes.
                await cts.CancelAsync().ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                return await SuccessfulRule(input, ct).ConfigureAwait(false);
            }, [ClaimId.AlgExists]),
            new(SuccessfulRule, [ClaimId.AlgIsNone])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            cts.Token).ConfigureAwait(false);

        Assert.IsFalse(result.IsComplete, "Result should be partial.");
        Assert.AreEqual(ClaimIssueCompletionStatus.Cancelled, result.CompletionStatus);
        Assert.AreEqual(1, result.RulesExecuted, "Only the first rule should have executed.");
        Assert.AreEqual(3, result.TotalRules);
        Assert.HasCount(1, result.Claims, "Only claims from the first rule should be present.");
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncHandlesRuleExceptionsGracefully()
    {
        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid]),
            new(ThrowingRule, [ClaimId.AlgExists]),
            new(SuccessfulRule, [ClaimId.AlgIsNone])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        //All rules should be counted as executed, including the failing one.
        Assert.IsTrue(result.IsComplete);
        Assert.AreEqual(3, result.RulesExecuted);
        Assert.HasCount(3, result.Claims);

        //The second claim should be a FailedClaim.
        var failedClaim = result.Claims[1];
        Assert.AreEqual(ClaimId.FailedClaim, failedClaim.Id);
        Assert.AreEqual(ClaimOutcome.Failure, failedClaim.Outcome);
        Assert.IsInstanceOfType<FailedClaimContext>(failedClaim.Context);

        var failedContext = (FailedClaimContext)failedClaim.Context;
        Assert.IsTrue(failedContext.FailureMessage.Contains("Simulated rule failure", StringComparison.Ordinal));
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncCapturesInputInContext()
    {
        const string testInput = "specific-test-input-value";

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        var result = await issuer.GenerateClaimsAsync(
            testInput,
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.IssuingContext);
        Assert.AreEqual(testInput, result.IssuingContext.Inputs);
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncWithNoRulesReturnsEmptyClaims()
    {
        var rules = new List<ClaimDelegate<string>>();

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        var result = await issuer.GenerateClaimsAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsComplete);
        Assert.AreEqual(0, result.RulesExecuted);
        Assert.AreEqual(0, result.TotalRules);
        Assert.HasCount(0, result.Claims);
    }


    [TestMethod]
    public void ConstructorThrowsOnNullIssuerId()
    {
        var rules = new List<ClaimDelegate<string>>();

        Assert.Throws<ArgumentException>(() =>
            new ClaimIssuer<string>(null!, rules, TimeProvider));
    }


    [TestMethod]
    public void ConstructorThrowsOnEmptyIssuerId()
    {
        var rules = new List<ClaimDelegate<string>>();

        Assert.Throws<ArgumentException>(() =>
            new ClaimIssuer<string>(string.Empty, rules, TimeProvider));
    }


    [TestMethod]
    public void ConstructorThrowsOnNullValidationRules()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new ClaimIssuer<string>(TestIssuerId, null!, TimeProvider));
    }


    [TestMethod]
    public async Task GenerateClaimsAsyncWithBlockingRulesCanBeCancelled()
    {
        using var cts = new CancellationTokenSource();
        var firstRuleCompleted = new TaskCompletionSource<bool>();

        //A rule that signals when it completes.
        ValueTask<List<Claim>> SignalingRule(string input, CancellationToken ct)
        {
            List<Claim> claims = [new Claim(ClaimId.AlgIsValid, ClaimOutcome.Success)];
            firstRuleCompleted.TrySetResult(true);

            return ValueTask.FromResult(claims);
        }

        var rules = new List<ClaimDelegate<string>>
        {
            new(SignalingRule, [ClaimId.AlgIsValid]),
            new(BlockingRule, [ClaimId.AlgExists]),
            new(BlockingRule, [ClaimId.AlgIsNone])
        };

        var issuer = new ClaimIssuer<string>(
            TestIssuerId,
            rules,
            TimeProvider);

        //Start the claim generation in the background.
        var generateTask = issuer.GenerateClaimsAsync("test-input", TestCorrelationId, cts.Token);

        //Wait for the first rule to complete, then cancel.
        await firstRuleCompleted.Task.ConfigureAwait(false);
        await cts.CancelAsync().ConfigureAwait(false);

        var result = await generateTask.ConfigureAwait(false);

        //Should have partial results due to cancellation.
        Assert.AreEqual(ClaimIssueCompletionStatus.Cancelled, result.CompletionStatus);
        Assert.AreEqual(1, result.RulesExecuted);
        Assert.AreEqual(3, result.TotalRules);
        Assert.HasCount(1, result.Claims);
    }


    /// <summary>
    /// A simple validation rule that always succeeds.
    /// </summary>
    private static ValueTask<List<Claim>> SuccessfulRule(
        string input,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        List<Claim> claims = [new Claim(ClaimId.AlgIsValid, ClaimOutcome.Success)];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// A validation rule that always fails.
    /// </summary>
    private static ValueTask<List<Claim>> FailingRule(
        string input,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        List<Claim> claims = [new Claim(ClaimId.AlgIsNone, ClaimOutcome.Failure)];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// A validation rule that blocks indefinitely until cancelled.
    /// </summary>
    private static async ValueTask<List<Claim>> BlockingRule(
        string input,
        CancellationToken cancellationToken = default)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);

        //This line is never reached; the delay throws on cancellation.
        List<Claim> claims = [new Claim(ClaimId.AlgExists, ClaimOutcome.Success)];

        return claims;
    }


    /// <summary>
    /// A validation rule that throws an exception.
    /// </summary>
    private static ValueTask<List<Claim>> ThrowingRule(
        string input,
        CancellationToken cancellationToken = default)
    {
        throw new InvalidOperationException("Simulated rule failure.");
    }
}