using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Assessment;

/// <summary>
/// Tests for <see cref="AssessmentArchiver"/>'s identifier contract and time handling: the archiver
/// mints the identifier for each archiving operation itself, enforces that the archiving delegate
/// echoes that same identifier back, and drives the archiving timestamp from its own
/// <see cref="TimeProvider"/>, independent of whatever clock produced the <see cref="AssessmentResult"/>
/// being archived.
/// </summary>
[TestClass]
internal sealed class AssessmentArchiverTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    private const string TestIssuerId = "test-issuer-id";
    private const string TestAssessorId = "test-assessor-id";
    private const string TestCorrelationId = "test-correlation-id";
    private const string TestArchiverId = "test-archiver-id";


    /// <summary>
    /// Deterministic <see cref="GenerateArchivingIdAsync"/> test double that mints sequential,
    /// distinguishable identifiers instead of the GUID-based
    /// <see cref="AssessmentArchiver.DefaultArchivingIdGenerator"/>, so a test can assert exactly
    /// which minted identifier reached which call.
    /// </summary>
    private sealed class CountingIdGenerator
    {
        /// <summary>Gets or sets the number of identifiers minted so far, the source of the next identifier's ordinal.</summary>
        private int Count { get; set; }

        /// <summary>Gets every identifier this generator has minted, in minting order.</summary>
        public List<string> MintedIds { get; } = [];

        /// <summary>
        /// Mints the next sequential identifier ("archiving-id-N"), honoring
        /// <paramref name="cancellationToken"/> before minting.
        /// </summary>
        /// <param name="cancellationToken">Token to monitor for cancellation.</param>
        /// <returns>The newly minted identifier.</returns>
        public ValueTask<string> GenerateAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var id = $"archiving-id-{Count}";
            Count++;
            MintedIds.Add(id);

            return ValueTask.FromResult(id);
        }
    }


    /// <summary>A rule that always succeeds, enough to drive a real <see cref="AssessmentResult"/> through the pipeline.</summary>
    private static ValueTask<List<Claim>> SuccessfulRule(string input, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        List<Claim> claims = [new Claim(ClaimId.AlgIsValid, ClaimOutcome.Success)];

        return ValueTask.FromResult(claims);
    }


    /// <summary>
    /// Builds a real <see cref="AssessmentResult"/> by running <see cref="SuccessfulRule"/> through a
    /// <see cref="ClaimIssuer{TInput}"/> and <see cref="ClaimAssessor{TInput}"/>, the pipeline every
    /// proving test in this class archives.
    /// </summary>
    /// <param name="timeProvider">Time source for the issuer and the assessor.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation.</param>
    /// <returns>A successful <see cref="AssessmentResult"/> for <c>"test-input"</c>.</returns>
    private static async ValueTask<AssessmentResult> CreateAssessmentResultAsync(
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        var rules = new List<ClaimDelegate<string>> { new(SuccessfulRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessor = new ClaimAssessor<string>(issuer, DefaultAssessors.DefaultKeyDidAssessorAsync, TestAssessorId, timeProvider);

        return await assessor.AssessAsync(
            "test-input", TestCorrelationId, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Echoes the archiving call's own <paramref name="creationTimestamp"/> and <paramref name="archivingId"/> straight into the result, the shape every real archiving backend follows.</summary>
    private static ValueTask<ArchivingResult> EchoArchiver(
        AssessmentResult assessmentToArchive,
        string archiverId,
        string archivingId,
        DateTime creationTimestamp,
        string? traceId,
        string? spanId,
        IReadOnlyDictionary<string, string>? baggage,
        CancellationToken cancellationToken = default)
    {
        var result = new ArchivingResult(
            IsSuccess: true,
            ArchivingId: archivingId,
            ArchiveId: Guid.NewGuid().ToString(),
            CorrelationId: assessmentToArchive.CorrelationId,
            ArchiverVersion: "1.0.0",
            CreationTimestampInUtc: creationTimestamp,
            ArchivingContext: new ArchiveContext(),
            TraceId: traceId,
            SpanId: spanId,
            Baggage: baggage);

        return ValueTask.FromResult(result);
    }


    /// <summary>
    /// <see cref="AssessmentArchiver.ArchiveAsync"/>'s <c>CreationTimestampInUtc</c> is the exact instant
    /// the ARCHIVER's own passed <see cref="TimeProvider"/> reports — distinct from, and never overwritten
    /// by, the clock that produced the <see cref="AssessmentResult"/> being archived.
    /// </summary>
    [TestMethod]
    public async Task ArchiveAsyncCreationTimestampIsTheArchiversOwnPassedTimeProvidersInstant()
    {
        var assessmentTimeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        AssessmentResult assessmentResult = await CreateAssessmentResultAsync(
            assessmentTimeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        var archiverTimeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch.AddHours(3));
        var archiver = new AssessmentArchiver(EchoArchiver, TestArchiverId, archiverTimeProvider, new CountingIdGenerator().GenerateAsync);

        ArchivingResult archived = await archiver.ArchiveAsync(assessmentResult, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            archiverTimeProvider.GetUtcNow().UtcDateTime, archived.CreationTimestampInUtc,
            "CreationTimestampInUtc must equal the archiver's own passed TimeProvider's instant exactly.");
        Assert.AreNotEqual(
            assessmentResult.CreationTimestampInUtc, archived.CreationTimestampInUtc,
            "The archiver's own clock must drive the archiving timestamp, never the assessment's own clock.");
    }


    /// <summary>
    /// <see cref="AssessmentArchiver.ArchiveAsync"/> mints exactly one identifier via its
    /// <c>ArchivingIdGenerator</c>, passes that identifier as the delegate's <c>archivingId</c>
    /// argument, and returns a result whose <see cref="ArchivingResult.ArchivingId"/> is that same value.
    /// </summary>
    [TestMethod]
    public async Task ArchiveAsyncMintsTheIdentifierTheDelegateReceivesAndTheResultCarries()
    {
        var idGenerator = new CountingIdGenerator();
        string? archivingIdSeenByDelegate = null;

        ValueTask<ArchivingResult> CapturingArchiver(
            AssessmentResult assessmentToArchive,
            string archiverId,
            string archivingId,
            DateTime creationTimestamp,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage,
            CancellationToken cancellationToken = default)
        {
            archivingIdSeenByDelegate = archivingId;

            return EchoArchiver(assessmentToArchive, archiverId, archivingId, creationTimestamp, traceId, spanId, baggage, cancellationToken);
        }

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        AssessmentResult assessmentResult = await CreateAssessmentResultAsync(
            timeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        var archiver = new AssessmentArchiver(CapturingArchiver, TestArchiverId, timeProvider, idGenerator.GenerateAsync);

        ArchivingResult archived = await archiver.ArchiveAsync(assessmentResult, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, idGenerator.MintedIds, "ArchiveAsync mints exactly one identifier per operation.");
        Assert.AreEqual(idGenerator.MintedIds[0], archivingIdSeenByDelegate, "The delegate must receive the identifier the generator minted.");
        Assert.AreEqual(idGenerator.MintedIds[0], archived.ArchivingId, "The result's ArchivingId must equal the identifier the generator minted.");
    }


    /// <summary>
    /// <see cref="AssessmentArchiver.ArchiveAggregatedAsync"/> mints one identifier per individual
    /// completed result — never a single identifier reused across the aggregation — so every
    /// archived result in the returned list carries its own distinct <see cref="ArchivingResult.ArchivingId"/>.
    /// </summary>
    [TestMethod]
    public async Task ArchiveAggregatedAsyncMintsOneDistinctIdentifierPerIndividualResult()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        var rules = new List<ClaimDelegate<string>> { new(SuccessfulRule, [ClaimId.AlgIsValid]) };
        var issuer = new ClaimIssuer<string>(TestIssuerId, rules, timeProvider);
        var assessors = new List<AssessorConfiguration>
        {
            new("assessor-1", DefaultAssessors.DefaultKeyDidAssessorAsync),
            new("assessor-2", DefaultAssessors.DefaultKeyDidAssessorAsync),
            new("assessor-3", DefaultAssessors.DefaultKeyDidAssessorAsync),
        };
        var composite = new CompositeClaimAssessor<string>(issuer, assessors, timeProvider, AssessmentAggregationStrategy.AllMustSucceed);
        AggregatedAssessmentResult aggregated = await composite.AssessAsync(
            "test-input", TestCorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

        var idGenerator = new CountingIdGenerator();
        var archiver = new AssessmentArchiver(EchoArchiver, TestArchiverId, timeProvider, idGenerator.GenerateAsync);

        IReadOnlyList<ArchivingResult> archived = await archiver.ArchiveAggregatedAsync(
            aggregated, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, idGenerator.MintedIds, "One identifier is minted per individual result.");
        Assert.HasCount(3, idGenerator.MintedIds.Distinct().ToList(), "Every minted identifier is distinct.");
        Assert.AreSequenceEqual(
            idGenerator.MintedIds, archived.Select(a => a.ArchivingId).ToList(),
            "Each archived result's ArchivingId is the identifier minted for it, in minting order.");
    }


    /// <summary>
    /// A delegate that returns an <see cref="ArchivingResult.ArchivingId"/> other than the identifier
    /// <see cref="AssessmentArchiver.ArchiveAsync"/> minted for the operation breaches the contract:
    /// the archiver never silently rewrites the delegate's result, it throws instead.
    /// </summary>
    [TestMethod]
    public async Task ArchiveAsyncThrowsWhenTheDelegateReturnsADifferentArchivingId()
    {
        const string DivergentArchivingId = "a-different-identifier-than-was-minted";

        static ValueTask<ArchivingResult> MismatchingArchiver(
            AssessmentResult assessmentToArchive,
            string archiverId,
            string archivingId,
            DateTime creationTimestamp,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage,
            CancellationToken cancellationToken = default)
        {
            return EchoArchiver(assessmentToArchive, archiverId, DivergentArchivingId, creationTimestamp, traceId, spanId, baggage, cancellationToken);
        }

        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        AssessmentResult assessmentResult = await CreateAssessmentResultAsync(
            timeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        var archiver = new AssessmentArchiver(MismatchingArchiver, TestArchiverId, timeProvider, new CountingIdGenerator().GenerateAsync);

        InvalidOperationException exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await archiver.ArchiveAsync(assessmentResult, TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains(DivergentArchivingId, exception.Message, StringComparison.Ordinal, "The exception must name the delegate's returned ArchivingId.");
        Assert.Contains("archiving-id-0", exception.Message, StringComparison.Ordinal, "The exception must name the identifier the archiver minted.");
    }


    /// <summary>
    /// The <c>archivingIdGenerator</c> constructor argument is required: a null generator must fail
    /// fast with <see cref="ArgumentNullException"/> rather than silently falling back to
    /// <see cref="AssessmentArchiver.DefaultArchivingIdGenerator"/>.
    /// </summary>
    [TestMethod]
    public void ConstructorThrowsArgumentNullExceptionWhenArchivingIdGeneratorIsNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            new AssessmentArchiver(EchoArchiver, TestArchiverId, new FakeTimeProvider(TestClock.CanonicalEpoch), null!));
    }


    /// <summary>
    /// Pins the identifier-minting ordering contract: an already-cancelled token surfaces as
    /// <see cref="OperationCanceledException"/> from the identifier minting itself, so no identifier
    /// is minted and the archiving delegate is never invoked. This holds regardless of whether
    /// <see cref="AssessmentArchiver.ArchiveAsync"/> checks cancellation before minting or simply lets
    /// the generator's own <see cref="CancellationToken.ThrowIfCancellationRequested"/> propagate.
    /// </summary>
    [TestMethod]
    public async Task ArchiveAsyncSurfacesOperationCanceledExceptionWhenCancelledBeforeMinting()
    {
        var idGenerator = new CountingIdGenerator();
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        AssessmentResult assessmentResult = await CreateAssessmentResultAsync(
            timeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        var wasArchiverInvoked = false;

        ValueTask<ArchivingResult> RecordingArchiver(
            AssessmentResult assessmentToArchive,
            string archiverId,
            string archivingId,
            DateTime creationTimestamp,
            string? traceId,
            string? spanId,
            IReadOnlyDictionary<string, string>? baggage,
            CancellationToken cancellationToken = default)
        {
            wasArchiverInvoked = true;

            return EchoArchiver(assessmentToArchive, archiverId, archivingId, creationTimestamp, traceId, spanId, baggage, cancellationToken);
        }

        var archiver = new AssessmentArchiver(RecordingArchiver, TestArchiverId, timeProvider, idGenerator.GenerateAsync);

        using var cancellationSource = new CancellationTokenSource();

        await cancellationSource.CancelAsync().ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await archiver.ArchiveAsync(assessmentResult, cancellationSource.Token).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.IsEmpty(idGenerator.MintedIds, "Cancellation before minting must leave no identifier minted.");
        Assert.IsFalse(wasArchiverInvoked, "Cancellation before minting must leave the archiving delegate uninvoked.");
    }
}
