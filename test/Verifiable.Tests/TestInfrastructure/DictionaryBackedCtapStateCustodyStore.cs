using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.Foundation;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An in-memory, dictionary-backed <see cref="CtapStateCustody"/> test double: persists/loads/wipes
/// snapshot bytes in a plain dictionary keyed by run id, and records the order every operation ran in.
/// </summary>
/// <remarks>
/// <para>
/// Models "the process holding the CTAP simulator died and a new one started" (contract R-1's own
/// spec-external third lifecycle event) entirely in-process: constructing a second
/// <c>CtapAuthenticatorSimulator</c> from THIS SAME instance's <see cref="CreateBundle"/> output, after
/// disposing the first, proves rehydration without any real process boundary — the dictionary itself
/// plays the role a file, a database row, or (package C) a sealed TPM object would in production.
/// </para>
/// <para>
/// <see cref="OperationLog"/> is this instance's own field, not a variable captured by a lambda closure
/// (house rule: no closure capture) — the three delegates <see cref="CreateBundle"/> hands out are bound
/// INSTANCE methods, so the only "context" any of them closes over is the explicit receiver
/// (<see langword="this"/>), the same non-capturing shape a production file- or database-backed adapter's
/// own instance methods would have. Ordering assertions read <see cref="OperationLog"/> directly, rather
/// than re-deriving order from timestamps.
/// </para>
/// </remarks>
internal sealed class DictionaryBackedCtapStateCustodyStore
{
    /// <summary>Every persisted snapshot's bytes, by run id.</summary>
    private readonly Dictionary<string, byte[]> snapshotsByRunId = [];

    /// <summary>
    /// The order every load/persist/wipe operation ran in, one entry per call, formatted
    /// <c>"{Operation}:{runId}"</c>.
    /// </summary>
    public List<string> OperationLog { get; } = [];


    /// <summary>Builds a <see cref="CtapStateCustody"/> bundle backed by this instance's own dictionary and log.</summary>
    /// <returns>The seam-bundle record.</returns>
    public CtapStateCustody CreateBundle() => new(TryLoadSnapshotAsync, PersistSnapshotAsync, WipeSnapshotAsync);


    /// <summary>Whether a snapshot is currently persisted for <paramref name="runId"/>.</summary>
    /// <param name="runId">The run id to check.</param>
    /// <returns><see langword="true"/> if a snapshot is persisted; otherwise <see langword="false"/>.</returns>
    public bool HasSnapshot(string runId) => snapshotsByRunId.ContainsKey(runId);


    /// <summary>
    /// Returns a mutable copy of the bytes currently persisted for <paramref name="runId"/>, for a test to
    /// capture a snapshot at one point in time and later restore it via <see cref="ReplaceSnapshotBytes"/> —
    /// the plaintext-snapshot-layer sibling of <c>DictionaryBackedTpmSealedSnapshotBlobStore.GetStoredBytesCopy</c>.
    /// </summary>
    /// <param name="runId">The run id whose persisted bytes to copy.</param>
    /// <returns>An independent copy of the persisted bytes.</returns>
    public byte[] GetSnapshotBytesCopy(string runId) => (byte[])snapshotsByRunId[runId].Clone();


    /// <summary>
    /// Overwrites the bytes persisted for <paramref name="runId"/> directly, bypassing
    /// <see cref="PersistSnapshotAsync"/> entirely — lets a test replay an earlier, now-stale snapshot
    /// captured via <see cref="GetSnapshotBytesCopy"/> ahead of a later composition.
    /// </summary>
    /// <param name="runId">The run id whose persisted bytes to replace.</param>
    /// <param name="bytes">The replacement bytes.</param>
    public void ReplaceSnapshotBytes(string runId, byte[] bytes) => snapshotsByRunId[runId] = bytes;


    /// <summary>Attempts to load the snapshot bytes persisted for <paramref name="runId"/>. Has the <see cref="TryLoadSnapshotAsyncDelegate"/> shape.</summary>
    private ValueTask<PooledMemory?> TryLoadSnapshotAsync(string runId, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        OperationLog.Add($"Load:{runId}");

        if(!snapshotsByRunId.TryGetValue(runId, out byte[]? bytes))
        {
            return ValueTask.FromResult<PooledMemory?>(null);
        }

        return ValueTask.FromResult<PooledMemory?>(PooledMemory.FromBytes(bytes, pool, CtapAuthenticatorCustodyBufferTags.SnapshotPayload));
    }


    /// <summary>Persists a copy of <paramref name="snapshot"/>'s bytes for <paramref name="runId"/>. Has the <see cref="PersistSnapshotAsyncDelegate"/> shape.</summary>
    private ValueTask PersistSnapshotAsync(string runId, PooledMemory snapshot, CancellationToken cancellationToken)
    {
        snapshotsByRunId[runId] = snapshot.AsReadOnlySpan().ToArray();
        OperationLog.Add($"Persist:{runId}");

        return ValueTask.CompletedTask;
    }


    /// <summary>Deletes whatever snapshot is persisted for <paramref name="runId"/>. Has the <see cref="WipeSnapshotAsyncDelegate"/> shape.</summary>
    private ValueTask WipeSnapshotAsync(string runId, CancellationToken cancellationToken)
    {
        snapshotsByRunId.Remove(runId);
        OperationLog.Add($"Wipe:{runId}");

        return ValueTask.CompletedTask;
    }
}
