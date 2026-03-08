using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Verifiable.Core.EventLogs;

namespace Verifiable.Tests.EventLogs;

/// <summary>
/// Tests for <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> covering
/// genesis, update, deactivation, heartbeat, chain integrity failure, proof
/// validation failure, cancellation, live-stream semantics, and custom classification
/// composition via <see cref="LogReplayDefaults"/>.
/// </summary>
[TestClass]
internal sealed class LogReplayerTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SingleGenesisEntryProducesActiveState()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, BuildContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, results);
        Assert.IsTrue(results[0].IsSuccess);
        Assert.IsInstanceOfType<ActiveLogState<string>>(results[0].State);
        Assert.AreEqual("state:create", ((ActiveLogState<string>)results[0].State).Value);
        Assert.AreEqual(LogEntryClassification.Genesis, results[0].Classification);
    }

    [TestMethod]
    public async Task UpdateEntryAdvancesActiveState()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> update = BuildEntry(1, genesis.Digest, "update-1", "proof-1");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis, update], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, BuildContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsTrue(results[1].IsSuccess);
        Assert.IsInstanceOfType<ActiveLogState<string>>(results[1].State);
        Assert.AreEqual("state:update-1", ((ActiveLogState<string>)results[1].State).Value);
        Assert.AreEqual(LogEntryClassification.Update, results[1].Classification);
    }

    [TestMethod]
    public async Task DeactivateEntryProducesDeactivatedState()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> deactivate = BuildEntry(1, genesis.Digest, "deactivate", "proof-1");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis, deactivate], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, BuildContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsTrue(results[1].IsSuccess);
        Assert.IsInstanceOfType<DeactivatedLogState<string>>(results[1].State);
        Assert.AreEqual("deactivated:state:create", ((DeactivatedLogState<string>)results[1].State).Value);
        Assert.AreEqual(LogEntryClassification.Deactivate, results[1].Classification);
    }

    [TestMethod]
    public async Task HeartbeatEntryDoesNotMutateState()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> heartbeat = BuildEntry(1, genesis.Digest, null, "proof-1");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis, heartbeat], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, BuildContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsTrue(results[1].IsSuccess);
        Assert.AreEqual(results[0].State, results[1].State);
        Assert.AreEqual(LogEntryClassification.Heartbeat, results[1].Classification);
    }

    [TestMethod]
    public async Task ChainIntegrityFailureTerminatesStream()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");

        //Deliberately uses the wrong previous digest to break the chain.
        LogEntry<string, string> broken = BuildEntry(1, "wrong-digest"u8.ToArray(), "update-1", "proof-1");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis, broken], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, BuildContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsTrue(results[0].IsSuccess);
        Assert.IsFalse(results[1].IsSuccess);
        Assert.IsNotNull(results[1].Error);
    }

    [TestMethod]
    public async Task ProofValidationFailureTerminatesStream()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> badProof = BuildEntry(1, genesis.Digest, "update-1", "invalid");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis, badProof], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, BuildContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsTrue(results[0].IsSuccess);
        Assert.IsFalse(results[1].IsSuccess);
        Assert.IsNotNull(results[1].Error);
        Assert.Contains("invalid", results[1].Error!);
    }

    [TestMethod]
    public async Task OnEntryProcessedIsCalledForEachSuccessfulEntry()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> update = BuildEntry(1, genesis.Digest, "update-1", "proof-1");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis, update], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> observed = [];
        LogReplayContext<string, string, string, NoContext> context = BuildContext(
            onEntryProcessed: (result, _) =>
            {
                observed.Add(result);
                return ValueTask.CompletedTask;
            });

        await CollectAsync(source, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, observed);
    }

    [TestMethod]
    public async Task OnEntryProcessedIsNotCalledForFailedEntry()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> badProof = BuildEntry(1, genesis.Digest, "update-1", "invalid");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([genesis, badProof], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> observed = [];
        LogReplayContext<string, string, string, NoContext> context = BuildContext(
            onEntryProcessed: (result, _) =>
            {
                observed.Add(result);
                return ValueTask.CompletedTask;
            });

        await CollectAsync(source, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, observed);
    }

    [TestMethod]
    public async Task ReplayFromResumesFromCheckpointState()
    {
        LogEntry<string, string> update = BuildEntry(5, "some-digest"u8.ToArray(), "update-5", "proof-5");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream([update], TestContext.CancellationToken);
        LogReplayer<string, string, string, NoContext> replayer = new();

        List<LogReplayResult<string, string, string>> results = await CollectFromAsync(
            replayer,
            source,
            startState: new ActiveLogState<string>("checkpoint"),
            startDigest: "some-digest"u8.ToArray(),
            BuildContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, results);
        Assert.IsTrue(results[0].IsSuccess);
        Assert.IsInstanceOfType<ActiveLogState<string>>(results[0].State);
        Assert.AreEqual("state:update-5", ((ActiveLogState<string>)results[0].State).Value);
    }

    [TestMethod]
    public async Task CancellationStopsStream()
    {
        TaskCompletionSource streamBlocked = new();
        using CancellationTokenSource cts = new();
        await cts.CancelAsync().ConfigureAwait(false);

        IAsyncEnumerable<LogEntry<string, string>> source = BlockingStreamAsync(streamBlocked, cts.Token);

        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await CollectAsync(source, BuildContext(), cts.Token).ConfigureAwait(false))
            .ConfigureAwait(false);
    }

    [TestMethod]
    public async Task MultipleUpdatesProduceCorrectStateSequence()
    {
        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> update1 = BuildEntry(1, genesis.Digest, "update-1", "proof-1");
        LogEntry<string, string> update2 = BuildEntry(2, update1.Digest, "update-2", "proof-2");
        LogEntry<string, string> update3 = BuildEntry(3, update2.Digest, "update-3", "proof-3");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream(
            [genesis, update1, update2, update3], TestContext.CancellationToken);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, BuildContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(4, results);
        Assert.AreEqual("state:create", ((ActiveLogState<string>)results[0].State).Value);
        Assert.AreEqual("state:update-1", ((ActiveLogState<string>)results[1].State).Value);
        Assert.AreEqual("state:update-2", ((ActiveLogState<string>)results[2].State).Value);
        Assert.AreEqual("state:update-3", ((ActiveLogState<string>)results[3].State).Value);
    }

    [TestMethod]
    public async Task CustomClassificationComposesWithBaseApply()
    {
        LogEntryClassification snapshot = new("snapshot");

        LogEntry<string, string> genesis = BuildEntry(0, null, "create", "proof-0");
        LogEntry<string, string> snapshotEntry = BuildEntry(1, genesis.Digest, "snap", "proof-1");
        IAsyncEnumerable<LogEntry<string, string>> source = ToStream(
            [genesis, snapshotEntry], TestContext.CancellationToken);

        ApplyDelegate<string, string, string> baseApply = BuildBaseApply();
        ApplyDelegate<string, string, string> composedApply =
            async (classification, state, entry, ct) =>
            {
                if(classification == snapshot)
                {
                    //Snapshot entries carry state forward unchanged as a no-op.
                    return (state, null);
                }

                return await baseApply(classification, state, entry, ct).ConfigureAwait(false);
            };

        ClassifyOperationDelegate<string, string> classify = entry =>
            entry.Operation is "snap" ? snapshot
            : entry.Operation is null ? LogEntryClassification.Heartbeat
            : entry.Operation is "deactivate" ? LogEntryClassification.Deactivate
            : entry.Index is 0 ? LogEntryClassification.Genesis
            : LogEntryClassification.Update;

        LogReplayContext<string, string, string, NoContext> context = BuildContext(
            applyOverride: composedApply,
            classifyOverride: classify);

        List<LogReplayResult<string, string, string>> results = await CollectAsync(
            source, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, results);
        Assert.IsTrue(results[1].IsSuccess);
        Assert.AreEqual(results[0].State, results[1].State);
        Assert.AreEqual(snapshot, results[1].Classification);
    }


    private static LogEntry<string, string> BuildEntry(
        ulong index,
        byte[]? previousDigest,
        string? operation,
        string proof)
    {
        byte[] canonical = Encoding.UTF8.GetBytes($"{index}:{operation ?? "heartbeat"}");
        byte[] digest = SHA256.HashData(canonical);

        return new LogEntry<string, string>
        {
            Index = index,
            PreviousDigest = previousDigest,
            Digest = digest,
            CanonicalBytes = canonical,
            Operation = operation,
            Proofs = [proof]
        };
    }

    private static LogEntry<string, string> BuildEntry(
        ulong index,
        ReadOnlyMemory<byte> previousDigest,
        string? operation,
        string proof) =>
        BuildEntry(index, previousDigest.ToArray(), operation, proof);

    private static ApplyDelegate<string, string, string> BuildBaseApply() =>
        LogReplayDefaults.CreateApplyDelegate<string, string, string>(
            genesis: (_, entry, _) =>
                ValueTask.FromResult<(ActiveLogState<string>, string?)>(
                    (new ActiveLogState<string>($"state:{entry.Operation}"), null)),

            update: (active, entry, _) =>
                ValueTask.FromResult<(ActiveLogState<string>, string?)>(
                    (new ActiveLogState<string>($"state:{entry.Operation}"), null)),

            deactivate: (active, _, _) =>
                ValueTask.FromResult<(DeactivatedLogState<string>, string?)>(
                    (new DeactivatedLogState<string>($"deactivated:{active.Value}"), null)));

    private static LogReplayContext<string, string, string, NoContext> BuildContext(
        OnEntryProcessedDelegate<string, string, string>? onEntryProcessed = null,
        ApplyDelegate<string, string, string>? applyOverride = null,
        ClassifyOperationDelegate<string, string>? classifyOverride = null)
    {
        ClassifyOperationDelegate<string, string> classify = classifyOverride ?? (entry =>
            entry.Operation is null ? LogEntryClassification.Heartbeat
            : entry.Operation is "deactivate" ? LogEntryClassification.Deactivate
            : entry.Index is 0 ? LogEntryClassification.Genesis
            : LogEntryClassification.Update);

        return new LogReplayContext<string, string, string, NoContext>
        {
            Classify = classify,

            VerifyChainIntegrity = (entry, previousEntryDigest, _) =>
            {
                if(previousEntryDigest is null && entry.Index is 0)
                {
                    return ValueTask.FromResult<string?>(null);
                }

                if(previousEntryDigest is null)
                {
                    return ValueTask.FromResult<string?>("Missing previous digest.");
                }

                bool matches = entry.PreviousDigest.HasValue
                    && entry.PreviousDigest.Value.Span.SequenceEqual(previousEntryDigest.Value.Span);

                return ValueTask.FromResult<string?>(matches ? null : "Chain integrity failure.");
            },

            ValidateProof = (entry, _, _, _) =>
            {
                bool valid = entry.Proofs.All(p => string.Equals(p, "invalid", StringComparison.Ordinal) is false);
                return ValueTask.FromResult<string?>(valid ? null : "Proof validation failed: invalid.");
            },

            ValidationContext = default,
            Apply = applyOverride ?? BuildBaseApply(),
            OnEntryProcessed = onEntryProcessed,
            TimeProvider = System.TimeProvider.System
        };
    }

    private static async Task<List<LogReplayResult<TState, TOperation, TProof>>> CollectAsync<TState, TOperation, TProof>(
        IAsyncEnumerable<LogEntry<TOperation, TProof>> source,
        LogReplayContext<TState, TOperation, TProof, NoContext> context,
        CancellationToken cancellationToken)
    {
        LogReplayer<TState, TOperation, TProof, NoContext> replayer = new();
        List<LogReplayResult<TState, TOperation, TProof>> results = [];

        await foreach(LogReplayResult<TState, TOperation, TProof> result in replayer
            .ReplayAsync(source, context, cancellationToken)
            .ConfigureAwait(false))
        {
            results.Add(result);
        }

        return results;
    }

    private static async Task<List<LogReplayResult<TState, TOperation, TProof>>> CollectFromAsync<TState, TOperation, TProof>(
        LogReplayer<TState, TOperation, TProof, NoContext> replayer,
        IAsyncEnumerable<LogEntry<TOperation, TProof>> source,
        LogState<TState> startState,
        ReadOnlyMemory<byte>? startDigest,
        LogReplayContext<TState, TOperation, TProof, NoContext> context,
        CancellationToken cancellationToken)
    {
        List<LogReplayResult<TState, TOperation, TProof>> results = [];

        await foreach(LogReplayResult<TState, TOperation, TProof> result in replayer
            .ReplayFromAsync(source, startState, startDigest, context, cancellationToken)
            .ConfigureAwait(false))
        {
            results.Add(result);
        }

        return results;
    }

    private static async IAsyncEnumerable<LogEntry<string, string>> ToStream(
        IEnumerable<LogEntry<string, string>> entries,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach(LogEntry<string, string> entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return entry;
            await Task.Yield();
        }
    }

    private static async IAsyncEnumerable<LogEntry<string, string>> BlockingStreamAsync(
        TaskCompletionSource blocked,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await blocked.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        yield break;
    }


    /// <summary>
    /// A placeholder proof validation context for tests that do not require
    /// external trust anchors or revocation information.
    /// </summary>
    private readonly struct NoContext;
}
