using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;


namespace Verifiable.Tests.Assessment;

/// <summary>
/// Tests for <see cref="ClaimAssessor{TInput}"/> functionality including tracing propagation,
/// timestamp handling, and integration with <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
[TestClass]
internal sealed class ClaimAssessorTests
{
    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    //Test constants.
    private const string TestIssuerId = "test-issuer-id";
    private const string TestAssessorId = "test-assessor-id";
    private const string TestCorrelationId = "test-correlation-id";


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


    [TestMethod]
    public async Task AssessAsyncProducesSuccessfulResultForValidClaims()
    {
        var fixedTime = new DateTimeOffset(2025, 3, 20, 14, 30, 0, TimeSpan.Zero);
        var timeProvider = new FakeTimeProvider(fixedTime);

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            DefaultAssessors.DefaultKeyDidAssessorAsync,
            TestAssessorId,
            timeProvider);

        var result = await assessor.AssessAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, "Assessment should succeed when all claims succeed.");
        Assert.AreEqual(TestAssessorId, result.AssessorId);
        Assert.AreEqual(TestCorrelationId, result.CorrelationId);
        Assert.AreEqual(fixedTime.UtcDateTime, result.CreationTimestampInUtc);
    }


    [TestMethod]
    public async Task AssessAsyncProducesFailedResultForInvalidClaims()
    {
        var timeProvider = new FakeTimeProvider(new DateTimeOffset(2025, 3, 20, 14, 30, 0, TimeSpan.Zero));

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid]),
            new(FailingRule, [ClaimId.AlgIsNone])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            DefaultAssessors.DefaultKeyDidAssessorAsync,
            TestAssessorId,
            timeProvider);

        var result = await assessor.AssessAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "Assessment should fail when any claim fails.");
    }


    [TestMethod]
    public async Task AssessAsyncPropagatesTracingInformation()
    {
        var timeProvider = new FakeTimeProvider();

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            DefaultAssessors.DefaultKeyDidAssessorAsync,
            TestAssessorId,
            timeProvider);

        var result = await assessor.AssessAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Assessment result should have tracing information.
        Assert.IsNotNull(result.TraceId, "Assessment TraceId should be captured.");
        Assert.IsNotNull(result.SpanId, "Assessment SpanId should be captured.");
        Assert.IsNotNull(result.Baggage, "Assessment Baggage should be captured.");

        //Claims result should also have tracing information.
        Assert.IsNotNull(result.ClaimsResult.ClaimIssuerTraceId, "Claims TraceId should be captured.");
        Assert.IsNotNull(result.ClaimsResult.ClaimIssuerSpanId, "Claims SpanId should be captured.");
    }


    [TestMethod]
    public async Task AssessAsyncWithActivityPropagatesDistributedTracing()
    {
        var timeProvider = new FakeTimeProvider();

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            DefaultAssessors.DefaultKeyDidAssessorAsync,
            TestAssessorId,
            timeProvider);

        //Create an activity to simulate distributed tracing context.
        using var activitySource = new ActivitySource("Verifiable.Tests.Assessor");
        using var listener = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData
        };
        ActivitySource.AddActivityListener(listener);

        using var activity = activitySource.StartActivity("AssessmentOperation");
        Assert.IsNotNull(activity, "Activity should be created.");

        activity.AddBaggage("correlation-context", "assessment-test");
        activity.AddBaggage("user-id", "test-user-123");

        var result = await assessor.AssessAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        //TraceId should match the activity.
        Assert.AreEqual(activity.TraceId.ToString(), result.TraceId);
        Assert.AreEqual(activity.TraceId.ToString(), result.ClaimsResult.ClaimIssuerTraceId);

        //Baggage should be propagated through the entire pipeline.
        Assert.IsTrue(result.Baggage!.ContainsKey("correlation-context"));
        Assert.AreEqual("assessment-test", result.Baggage["correlation-context"]);
        Assert.IsTrue(result.Baggage.ContainsKey("user-id"));
        Assert.AreEqual("test-user-123", result.Baggage["user-id"]);

        //Verify claims result also has the baggage.
        Assert.IsTrue(result.ClaimsResult.Baggage!.ContainsKey("correlation-context"));
    }


    [TestMethod]
    public async Task AssessAsyncFailsForIncompleteClaimResults()
    {
        var timeProvider = new FakeTimeProvider();
        using var cts = new CancellationTokenSource();

        //A rule that cancels after running.
        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid]),
            new(async (input, ct) =>
            {
                await cts.CancelAsync().ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                return await SuccessfulRule(input, ct).ConfigureAwait(false);
            }, [ClaimId.AlgExists])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            DefaultAssessors.DefaultKeyDidAssessorAsync,
            TestAssessorId,
            timeProvider);

        var result = await assessor.AssessAsync(
            "test-input",
            TestCorrelationId,
            cts.Token).ConfigureAwait(false);

        //Default assessor should fail for incomplete claim results.
        Assert.IsFalse(result.IsSuccess, "Assessment should fail when claim generation was incomplete.");
        Assert.IsFalse(result.ClaimsResult.IsComplete, "Claims result should be incomplete.");
        Assert.AreEqual(ClaimIssueCompletionStatus.Cancelled, result.ClaimsResult.CompletionStatus);
    }


    [TestMethod]
    public async Task AssessAsyncPreservesCorrelationIdThroughPipeline()
    {
        var timeProvider = new FakeTimeProvider();
        const string specificCorrelationId = "unique-correlation-id-abc123";

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            DefaultAssessors.DefaultKeyDidAssessorAsync,
            TestAssessorId,
            timeProvider);

        var result = await assessor.AssessAsync(
            "test-input",
            specificCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Correlation ID should flow through to both assessment and claims results.
        Assert.AreEqual(specificCorrelationId, result.CorrelationId);
        Assert.AreEqual(specificCorrelationId, result.ClaimsResult.CorrelationId);
    }


    [TestMethod]
    public async Task AssessAsyncWithCustomAssessorLogic()
    {
        var timeProvider = new FakeTimeProvider();
        const string customVersion = "2.0.0-custom";

        //Custom assessor that has different logic.
        AssessDelegateAsync customAssessor = (claims, assessorId, timestamp, traceId, spanId, baggage, ct) =>
        {
            //Custom logic: succeed only if there are exactly 2 successful claims.
            var successCount = claims.Claims.Count(c => c.Outcome == ClaimOutcome.Success);
            var isSuccess = claims.IsComplete && successCount == 2;

            return ValueTask.FromResult(new AssessmentResult(
                IsSuccess: isSuccess,
                AssessorId: assessorId,
                AssessmentId: Guid.NewGuid().ToString(),
                CorrelationId: claims.CorrelationId,
                AssessorVersion: customVersion,
                CreationTimestampInUtc: timestamp,
                AssessmentContext: new AssessmentContext(),
                ClaimsResult: claims,
                TraceId: traceId,
                SpanId: spanId,
                Baggage: baggage));
        };

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid]),
            new(SuccessfulRule, [ClaimId.AlgExists])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            customAssessor,
            TestAssessorId,
            timeProvider);

        var result = await assessor.AssessAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, "Custom assessor should succeed with exactly 2 successful claims.");
        Assert.AreEqual(customVersion, result.AssessorVersion);
    }


    [TestMethod]
    public void ConstructorThrowsOnNullClaimIssuer()
    {
        var timeProvider = new FakeTimeProvider();

        Assert.Throws<ArgumentNullException>(() =>
            new ClaimAssessor<string>(
                null!,
                DefaultAssessors.DefaultKeyDidAssessorAsync,
                TestAssessorId,
                timeProvider));
    }


    [TestMethod]
    public void ConstructorThrowsOnNullAssessor()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>>();
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        Assert.Throws<ArgumentNullException>(() =>
            new ClaimAssessor<string>(issuer, null!, TestAssessorId, timeProvider));
    }


    [TestMethod]
    public void ConstructorThrowsOnEmptyAssessorId()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>>();
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        Assert.Throws<ArgumentException>(() =>
            new ClaimAssessor<string>(
                issuer,
                DefaultAssessors.DefaultKeyDidAssessorAsync,
                string.Empty,
                timeProvider));
    }


    [TestMethod]
    public async Task AssessAsyncUsesSystemTimeProviderWhenNotSpecified()
    {
        //Use a FakeTimeProvider to verify the timestamp is used correctly.
        var fixedTime = new DateTimeOffset(2025, 5, 10, 8, 0, 0, TimeSpan.Zero);
        var timeProvider = new FakeTimeProvider(fixedTime);

        var rules = new List<ClaimDelegate<string>>
        {
            new(SuccessfulRule, [ClaimId.AlgIsValid])
        };

        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(
            issuer,
            DefaultAssessors.DefaultKeyDidAssessorAsync,
            TestAssessorId,
            timeProvider);

        var result = await assessor.AssessAsync(
            "test-input",
            TestCorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Timestamp should match the TimeProvider's time.
        Assert.AreEqual(fixedTime.UtcDateTime, result.CreationTimestampInUtc);
    }
}