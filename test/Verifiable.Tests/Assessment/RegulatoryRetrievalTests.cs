using System.Diagnostics;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;


namespace Verifiable.Tests.Assessment;

/// <summary>
/// Tests for <see cref="CompositeClaimAssessor{TInput}"/> functionality including
/// parallel execution, partial results, timeout handling, and aggregation strategies.
/// </summary>
[TestClass]
internal sealed class CompositeClaimAssessorTests
{
    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    private const string TestIssuerId = "test-issuer";
    private const string TestCorrelationId = "test-correlation";


    /// <summary>
    /// Example assessment context for AI/ML model metadata.
    /// </summary>
    private sealed class MachineLearningClaimContext: AssessmentContext
    {
        public string? ModelVersion { get; init; }
    }


    [TestMethod]
    public async Task AllAssessorsRunInParallel()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("fast-1", FastSuccessAssessor),
            new("fast-2", FastSuccessAssessor),
            new("fast-3", FastSuccessAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.AllMustSucceed,
            timeProvider);

        var stopwatch = Stopwatch.StartNew();
        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);
        stopwatch.Stop();

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(3, result.CompletedCount);
        Assert.IsTrue(result.AllCompleted);
        Assert.HasCount(3, result.IndividualResults);

        //All should have unique span IDs.
        var spanIds = result.IndividualResults.Select(r => r.SpanId).Distinct().ToList();
        Assert.HasCount(3, spanIds);
    }


    [TestMethod]
    public async Task AllMustSucceedFailsIfAnyFails()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("success-1", FastSuccessAssessor),
            new("failure-1", FastFailureAssessor),
            new("success-2", FastSuccessAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.AllMustSucceed,
            timeProvider);

        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "AllMustSucceed should fail when any assessor fails.");
        Assert.AreEqual(3, result.CompletedCount, "All assessors should complete.");
        Assert.AreEqual(2, result.IndividualResults.Count(r => r.IsSuccess));
    }


    [TestMethod]
    public async Task AnyMustSucceedPassesIfOneSucceeds()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("failure-1", FastFailureAssessor),
            new("success-1", FastSuccessAssessor),
            new("failure-2", FastFailureAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.AnyMustSucceed,
            timeProvider);

        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, "AnyMustSucceed should pass when at least one assessor succeeds.");
    }


    [TestMethod]
    public async Task MajorityMustSucceedPassesWithMajority()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("success-1", FastSuccessAssessor),
            new("success-2", FastSuccessAssessor),
            new("failure-1", FastFailureAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.MajorityMustSucceed,
            timeProvider);

        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, "MajorityMustSucceed should pass with 2/3 success.");
    }


    [TestMethod]
    public async Task FaultingAssessorDoesNotPreventOthers()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("success-1", FastSuccessAssessor),
            new("faulting", FaultingAssessor),
            new("success-2", FastSuccessAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.AnyMustSucceed,
            timeProvider);

        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, "Faulting assessor should not prevent others from succeeding.");
        Assert.AreEqual(2, result.CompletedCount);
        Assert.AreEqual(1, result.FaultedCount);

        var faultedResult = result.IndividualResults.First(r => r.AssessorId == "faulting");
        Assert.AreEqual(AssessorCompletionStatus.Faulted, faultedResult.CompletionStatus);
        Assert.IsTrue(faultedResult.ErrorMessage!.Contains("Remote AI service unavailable", StringComparison.Ordinal));
    }


    [TestMethod]
    public async Task TimeoutAssessorIsMarkedAsTimedOut()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("fast", FastSuccessAssessor),
            new("blocking", BlockingAssessor, Timeout: TimeSpan.FromMilliseconds(1))
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.AnyMustSucceed,
            timeProvider);

        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, "Fast assessor should still succeed.");
        Assert.AreEqual(1, result.CompletedCount);

        var timedOutResult = result.IndividualResults.First(r => r.AssessorId == "blocking");
        Assert.AreEqual(AssessorCompletionStatus.TimedOut, timedOutResult.CompletionStatus);
    }


    [TestMethod]
    public async Task CancellationCollectsPartialResults()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        //Use a TaskCompletionSource to control cancellation timing precisely.
        using var cts = new CancellationTokenSource();
        var fastAssessorCompleted = new TaskCompletionSource<bool>();

        //A fast assessor that signals when it completes.
        ValueTask<AssessmentResult> SignalingFastAssessor(
            ClaimIssueResult claims,
            string assessorId,
            DateTime timestamp,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage,
            CancellationToken ct = default)
        {
            var result = new AssessmentResult(
                IsSuccess: true,
                AssessorId: assessorId,
                AssessmentId: Guid.NewGuid().ToString(),
                CorrelationId: claims.CorrelationId,
                AssessorVersion: "1.0.0",
                CreationTimestampInUtc: timestamp,
                AssessmentContext: new AssessmentContext(),
                ClaimsResult: claims,
                TraceId: traceId,
                SpanId: spanId,
                Baggage: baggage);

            fastAssessorCompleted.TrySetResult(true);
            return ValueTask.FromResult(result);
        }

        var assessors = new List<AssessorConfiguration>
        {
            new("fast", SignalingFastAssessor),
            new("blocking", BlockingAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.AnyMustSucceed,
            timeProvider);

        //Start the assessment in the background.
        var assessTask = composite.AssessAsync("test-input", TestCorrelationId, cts.Token);

        //Wait for the fast assessor to complete, then cancel.
        await fastAssessorCompleted.Task.ConfigureAwait(false);
        await cts.CancelAsync().ConfigureAwait(false);

        var result = await assessTask.ConfigureAwait(false);

        //Fast one should complete, blocking one should be cancelled.
        Assert.IsTrue(result.IsSuccess, "Fast assessor result should make AnyMustSucceed pass.");
        Assert.AreEqual(1, result.CompletedCount);
        Assert.AreEqual(1, result.CancelledCount);

        var cancelledResult = result.IndividualResults.First(r => r.AssessorId == "blocking");
        Assert.AreEqual(AssessorCompletionStatus.Cancelled, cancelledResult.CompletionStatus);
    }


    [TestMethod]
    public async Task TracingInformationIsPropagated()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("assessor-1", FastSuccessAssessor),
            new("assessor-2", FastSuccessAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            timeProvider: timeProvider);

        //Create activity for distributed tracing.
        using var activitySource = new ActivitySource("Verifiable.Tests.Composite");
        using var listener = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData
        };
        ActivitySource.AddActivityListener(listener);

        using var activity = activitySource.StartActivity("CompositeTest");
        activity?.AddBaggage("model-version", "v2.1");
        activity?.AddBaggage("docker-sha", "sha256:abc123");

        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        //Aggregated result should have trace info.
        Assert.IsNotNull(result.TraceId);
        Assert.IsNotNull(result.SpanId);
        Assert.IsTrue(result.Baggage!.ContainsKey("model-version"));
        Assert.AreEqual("v2.1", result.Baggage["model-version"]);

        //Each individual result should have its own span ID.
        foreach(var individual in result.IndividualResults)
        {
            Assert.IsNotNull(individual.SpanId);
            if(individual.Result != null)
            {
                Assert.AreEqual(result.TraceId, individual.Result.TraceId);
            }
        }
    }


    [TestMethod]
    public async Task QuorumStrategyWithPartialCompletion()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        var assessors = new List<AssessorConfiguration>
        {
            new("success-1", FastSuccessAssessor),
            new("success-2", FastSuccessAssessor),
            new("faulting", FaultingAssessor),
            new("success-3", FastSuccessAssessor)
        };

        var composite = new CompositeClaimAssessor<string>(
            issuer,
            assessors,
            AssessmentAggregationStrategy.QuorumMustSucceed,
            timeProvider,
            requiredQuorum: 2);

        var result = await composite.AssessAsync("test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, "Quorum of 2 should be met with 3 successful assessors.");
        Assert.AreEqual(3, result.CompletedCount);
        Assert.AreEqual(1, result.FaultedCount);
    }


    [TestMethod]
    public void ConstructorThrowsOnEmptyAssessors()
    {
        var timeProvider = new FakeTimeProvider();
        var rules = new List<ClaimDelegate<string>> { new(SimpleRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);

        Assert.Throws<ArgumentException>(() =>
            new CompositeClaimAssessor<string>(issuer, []));
    }


    #region Test Helpers

    /// <summary>
    /// A simple claim rule for testing.
    /// </summary>
    private static ValueTask<List<Claim>> SimpleRule(string input, CancellationToken ct = default)
    {
        List<Claim> claims = [new Claim(ClaimId.AlgIsValid, ClaimOutcome.Success)];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// A fast assessor that always succeeds.
    /// </summary>
    private static ValueTask<AssessmentResult> FastSuccessAssessor(
        ClaimIssueResult claims,
        string assessorId,
        DateTime timestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken ct = default)
    {
        return ValueTask.FromResult(new AssessmentResult(
            IsSuccess: true,
            AssessorId: assessorId,
            AssessmentId: Guid.NewGuid().ToString(),
            CorrelationId: claims.CorrelationId,
            AssessorVersion: "1.0.0",
            CreationTimestampInUtc: timestamp,
            AssessmentContext: new AssessmentContext(),
            ClaimsResult: claims,
            TraceId: traceId,
            SpanId: spanId,
            Baggage: baggage));
    }


    /// <summary>
    /// A fast assessor that always fails.
    /// </summary>
    private static ValueTask<AssessmentResult> FastFailureAssessor(
        ClaimIssueResult claims,
        string assessorId,
        DateTime timestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken ct = default)
    {
        return ValueTask.FromResult(new AssessmentResult(
            IsSuccess: false,
            AssessorId: assessorId,
            AssessmentId: Guid.NewGuid().ToString(),
            CorrelationId: claims.CorrelationId,
            AssessorVersion: "1.0.0",
            CreationTimestampInUtc: timestamp,
            AssessmentContext: new AssessmentContext(),
            ClaimsResult: claims,
            TraceId: traceId,
            SpanId: spanId,
            Baggage: baggage));
    }


    /// <summary>
    /// An assessor that waits indefinitely until cancelled.
    /// </summary>
    private static async ValueTask<AssessmentResult> BlockingAssessor(
        ClaimIssueResult claims,
        string assessorId,
        DateTime timestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken ct = default)
    {
        await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);

        //This line is never reached; the delay throws on cancellation.
        return new AssessmentResult(
            IsSuccess: true,
            AssessorId: assessorId,
            AssessmentId: Guid.NewGuid().ToString(),
            CorrelationId: claims.CorrelationId,
            AssessorVersion: "1.0.0",
            CreationTimestampInUtc: timestamp,
            AssessmentContext: new AssessmentContext(),
            ClaimsResult: claims,
            TraceId: traceId,
            SpanId: spanId,
            Baggage: baggage);
    }


    /// <summary>
    /// An assessor that throws an exception.
    /// </summary>
    private static ValueTask<AssessmentResult> FaultingAssessor(
        ClaimIssueResult claims,
        string assessorId,
        DateTime timestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken ct = default)
    {
        throw new InvalidOperationException("Remote AI service unavailable.");
    }

    #endregion
}