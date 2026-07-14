using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EventLogs;

/// <summary>
/// Replays a single genesis <see cref="LogEntry{TOperation,TProof}"/> carrying generic <see cref="CryptoProof"/>
/// proofs through the production <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>, so a test only
/// supplies the entry and asserts on the result. The state is a simple verified-entry count; the integrity check
/// recomputes the SHA-256 digest over the canonical bytes; the proof check is the domain-agnostic
/// <see cref="CryptoProofValidation"/> path.
/// </summary>
internal static class CryptoProofLogReplayHarness
{
    /// <summary>
    /// Replays <paramref name="entry"/> as the genesis entry of a one-entry log and returns the single result.
    /// </summary>
    /// <param name="entry">The genesis entry to replay.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The replay result for the entry.</returns>
    public static async Task<LogReplayResult<int, ReadOnlyMemory<byte>, CryptoProof>> ReplayGenesisAsync(
        LogEntry<ReadOnlyMemory<byte>, CryptoProof> entry,
        CancellationToken cancellationToken)
    {
        var context = new LogReplayContext<int, ReadOnlyMemory<byte>, CryptoProof, object>
        {
            Classify = OperationClassifiers.ByIndex<ReadOnlyMemory<byte>, CryptoProof>(),
            VerifyChainIntegrity = VerifyDigestIntegrity,
            ValidateProof = CryptoProofValidation.CreateValidateProof<int, ReadOnlyMemory<byte>, object>(),
            ValidationContext = new object(),
            Apply = LogReplayDefaults.CreateApplyDelegate<int, ReadOnlyMemory<byte>, CryptoProof>(
                genesis: static (_, _, _) => ValueTask.FromResult((new ActiveLogState<int>(1), (string?)null)),
                update: static (active, _, _) => ValueTask.FromResult((new ActiveLogState<int>(active.Value + 1), (string?)null)),
                deactivate: static (active, _, _) => ValueTask.FromResult((new DeactivatedLogState<int>(active.Value), (string?)null))),
            TimeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch)
        };

        var replayer = new LogReplayer<int, ReadOnlyMemory<byte>, CryptoProof, object>();
        LogReplayResult<int, ReadOnlyMemory<byte>, CryptoProof>? last = null;
        await foreach(LogReplayResult<int, ReadOnlyMemory<byte>, CryptoProof> result in replayer
            .ReplayAsync(Single(entry, cancellationToken), context, cancellationToken)
            .ConfigureAwait(false))
        {
            last = result;
        }

        Assert.IsNotNull(last, "The replayer must emit a result for the single entry.");

        return last;
    }

    /// <summary>
    /// Verifies a genesis entry's hash-chain position: it must have no predecessor and its digest must equal the
    /// SHA-256 of its canonical bytes.
    /// </summary>
    /// <param name="entry">The entry to verify.</param>
    /// <param name="previousEntryDigest">The predecessor digest threaded by the replayer; <see langword="null"/> for genesis.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="null"/> when integrity holds; otherwise an error message.</returns>
    private static ValueTask<string?> VerifyDigestIntegrity(
        LogEntry<ReadOnlyMemory<byte>, CryptoProof> entry,
        ReadOnlyMemory<byte>? previousEntryDigest,
        CancellationToken cancellationToken)
    {
        if(previousEntryDigest is not null)
        {
            return ValueTask.FromResult<string?>("The genesis entry must have no predecessor digest.");
        }

        Span<byte> recomputed = stackalloc byte[32];
        SHA256.HashData(entry.CanonicalBytes.Span, recomputed);
        bool matches = recomputed.SequenceEqual(entry.Digest.Span);

        return ValueTask.FromResult(matches ? null : "The entry digest does not match its canonical bytes.");
    }

    /// <summary>
    /// Wraps a single item as an asynchronous sequence for the replayer's stream source.
    /// </summary>
    /// <typeparam name="T">The item type.</typeparam>
    /// <param name="item">The single item to yield.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A one-element asynchronous sequence.</returns>
    private static async IAsyncEnumerable<T> Single<T>(T item, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        yield return item;
        await Task.CompletedTask.ConfigureAwait(false);
    }
}
