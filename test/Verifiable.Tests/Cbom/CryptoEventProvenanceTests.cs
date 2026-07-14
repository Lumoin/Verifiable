using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Lumoin.Base;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cbom;

/// <summary>
/// Tests for <see cref="CryptoEventProvenance"/> — the wave-7 CLI/MCP consumer of
/// <see cref="CryptographicKeyEvents.Events"/>. <see cref="CryptoEventProvenance.CaptureAsync{TResult}"/>'s
/// subscription lifetime (bounded to exactly one workload call, never leaking) and
/// <see cref="CryptoEventProvenance.RenderSummary"/>'s grouping/formatting are both testable without
/// spawning the real CLI process, since <c>Verifiable.Tests</c> has <c>InternalsVisibleTo</c> access to the
/// <c>Verifiable</c> CLI/MCP project (see <c>ToolTests/CbomCliTests.cs</c> for the end-to-end, real-exe
/// proof that both the choke-point and wave-7-widened paths land in this summary together).
/// </summary>
[TestClass]
internal sealed class CryptoEventProvenanceTests
{
    [TestMethod]
    public void RenderSummaryReturnsPlaceholderWhenNoEventsCaptured()
    {
        string summary = CryptoEventProvenance.RenderSummary([]);

        Assert.AreEqual("(no events captured)", summary);
    }


    /// <summary>
    /// Distinct (event type, algorithm, backend) combinations render as separate lines; the SAME
    /// combination occurring more than once collapses into a single line whose count is the occurrence
    /// total. Built entirely from synthetic events constructed via each record's own <c>Create</c> factory
    /// — no real crypto call, no shared global-stream state, fully deterministic.
    /// </summary>
    [TestMethod]
    public void RenderSummaryGroupsByEventTypeAlgorithmAndBackendWithOccurrenceCounts()
    {
        CryptoEvent[] events =
        [
            KeyMaterialGeneratedEvent.Create(CryptoAlgorithm.P256, Purpose.Signing, MaterialSemantics.Direct, "Microsoft"),
            SignatureProducedEvent.Create(CryptoAlgorithm.P256, dataLength: 32, signatureLength: 64, "Microsoft"),
            SignatureProducedEvent.Create(CryptoAlgorithm.P256, dataLength: 48, signatureLength: 64, "Microsoft"),
            VerificationCompletedEvent.Create(CryptoAlgorithm.P256, VerificationOutcome.Valid, dataLength: 32, "Microsoft")
        ];

        string summary = CryptoEventProvenance.RenderSummary(events);
        string[] lines = summary.Split(Environment.NewLine);

        Assert.HasCount(3, lines, "Three distinct (type, algorithm, backend) combinations must render as three lines.");
        Assert.Contains("KeyMaterialGeneratedEvent x1 (P256 via Microsoft)", lines);
        Assert.Contains("SignatureProducedEvent x2 (P256 via Microsoft)", lines, "Two SignatureProduced events with the same algorithm/backend must collapse into one counted line.");
        Assert.Contains("VerificationCompletedEvent x1 (P256 via Microsoft)", lines);
    }


    /// <summary>
    /// The entropy and digest event families do not carry a <see cref="CryptoAlgorithm"/>/backend pair the
    /// way sign/verify/keygen events do; the summary renders their closest analogous fields (purpose and
    /// source for entropy; algorithm name and a documented "not recorded" placeholder for digest, since
    /// <see cref="DigestComputedEvent"/> carries no backend field today) rather than throwing.
    /// </summary>
    [TestMethod]
    public void RenderSummaryRendersEntropyAndDigestEventsWithTheirDocumentedFields()
    {
        CryptoEvent[] events =
        [
            EntropyConsumedEvent.Create(EntropySource.Csprng, byteCount: 16, Purpose.Nonce, EntropyHealthObservation.Unknown),
            DigestComputedEvent.Create("SHA-256", inputLength: 10, digestLength: 32, Purpose.Digest)
        ];

        string[] lines = CryptoEventProvenance.RenderSummary(events).Split(Environment.NewLine);

        Assert.Contains("EntropyConsumedEvent x1 (Nonce via Csprng)", lines);
        Assert.Contains("DigestComputedEvent x1 (SHA-256 via (not recorded))", lines);
    }


    /// <summary>
    /// <see cref="CryptoEventProvenance.CaptureAsync{TResult}"/> propagates the workload's own result and
    /// observes what it emits. Presence-only on the emitted event (never an exact count), and no assertion
    /// on the process-wide subscriber count here — see
    /// <see cref="CaptureAsyncDoesNotAccumulateSubscriptionsAcrossRepeatedSuccessAndFailureCalls"/> for the
    /// dedicated, noise-tolerant leak check.
    /// </summary>
    [TestMethod]
    public async Task CaptureAsyncPropagatesTheWorkloadResultAndObservesItsEmittedEvents()
    {
        (int workloadResult, IReadOnlyList<CryptoEvent> events) = await CryptoEventProvenance.CaptureAsync(async () =>
        {
            using Nonce nonce = CryptographicKeyEvents.GenerateNonce(16, CryptoTags.AesGcmIv, BaseMemoryPool.Shared);
            _ = nonce.UseNonce();
            await Task.CompletedTask.ConfigureAwait(false);

            return 42;
        }).ConfigureAwait(false);

        Assert.AreEqual(42, workloadResult, "CaptureAsync must propagate the workload's own result.");
        Assert.Contains(
            (EntropyConsumedEvent e) => e.Purpose == Purpose.Nonce,
            events.OfType<EntropyConsumedEvent>(),
            "CaptureAsync must observe the EntropyConsumedEvent the workload's GenerateNonce call emitted.");
    }


    /// <summary>
    /// The subscription-lifetime property the wave-7 contract calls for: <c>CaptureAsync</c> must never
    /// leave a residual subscription running after it returns, whether the workload completed normally or
    /// threw. Proven across many repeated calls rather than a single before/after sample of
    /// <see cref="CryptographicKeyEvents.SubscriberCountForTests"/>: that counter is shared with every
    /// concurrently running test (MSTest parallelizes at class scope), so a single strict before/after
    /// equality check is inherently racy — another test's own transient subscription can tick the shared
    /// count up or down at the exact instant this test samples it (reproduced: an earlier version of this
    /// test asserting strict equality around one call failed intermittently under the full parallel run).
    /// A genuine per-call leak in <c>CaptureAsync</c> would instead grow the count by roughly one per
    /// iteration, which running many iterations makes unmistakable against that background noise.
    /// </summary>
    [TestMethod]
    public async Task CaptureAsyncDoesNotAccumulateSubscriptionsAcrossRepeatedSuccessAndFailureCalls()
    {
        const int Iterations = 50;
        int subscriberCountBefore = CryptographicKeyEvents.SubscriberCountForTests;

        for(int i = 0; i < Iterations; ++i)
        {
            if(i % 5 == 4)
            {
                //Every fifth iteration throws — CaptureAsync's using block must unwind on an exception
                //exactly as it does on a normal return, so a failing observed workload can never leak a
                //subscription either.
                await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                    await CryptoEventProvenance.CaptureAsync<int>(
                        () => throw new InvalidOperationException("Synthetic workload failure.")).ConfigureAwait(false))
                    .ConfigureAwait(false);
            }
            else
            {
                _ = await CryptoEventProvenance.CaptureAsync(async () =>
                {
                    using Nonce nonce = CryptographicKeyEvents.GenerateNonce(16, CryptoTags.AesGcmIv, BaseMemoryPool.Shared);
                    _ = nonce.UseNonce();
                    await Task.CompletedTask.ConfigureAwait(false);

                    return 0;
                }).ConfigureAwait(false);
            }
        }

        int subscriberCountAfter = CryptographicKeyEvents.SubscriberCountForTests;

        Assert.IsLessThan(
            Iterations / 2, Math.Abs(subscriberCountAfter - subscriberCountBefore),
            $"CaptureAsync must not accumulate a subscription per call across {Iterations} success/failure " +
            "iterations; a genuine leak would grow the subscriber count by roughly one per iteration, far " +
            "more than the background noise of other parallel tests' own transient subscriptions.");
    }
}
