using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody;
using Verifiable.Foundation;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An in-memory, dictionary-backed test double for the three caller-supplied blob-store delegates
/// <see cref="Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody.TpmSealedStateCustody.Create"/> composes
/// (<see cref="TryFetchSealedSnapshotBlobAsyncDelegate"/>, <see cref="StoreSealedSnapshotBlobAsyncDelegate"/>,
/// <see cref="DeleteSealedSnapshotBlobAsyncDelegate"/>): persists/loads/wipes the OPAQUE, TPM-sealed blob
/// bytes in a plain dictionary keyed by run id — the same role <see cref="DictionaryBackedCtapStateCustodyStore"/>
/// plays one layer up, for the plaintext snapshot bytes.
/// </summary>
/// <remarks>
/// <para>
/// The library performs no I/O of its own (contract R-7): this double plays the file/database/dictionary
/// a real deployment would choose. Its three exposed methods are bound INSTANCE methods (house rule: no
/// closure capture) — the only "context" any of them closes over is the explicit receiver
/// (<see langword="this"/>), mirroring <see cref="DictionaryBackedCtapStateCustodyStore"/>'s identical
/// discipline.
/// </para>
/// <para>
/// <see cref="ReplaceStoredBytes"/> and <see cref="GetStoredBytesCopy"/> exist only for the fail-closed
/// negative capstone: they let a test corrupt an already-persisted sealed blob's bytes directly, entirely
/// outside <c>TpmSealedStateCustody</c>'s own seal/unseal path, to prove rehydration rejects tampered
/// bytes rather than silently accepting them.
/// </para>
/// </remarks>
internal sealed class DictionaryBackedTpmSealedSnapshotBlobStore
{
    /// <summary>Every stored sealed blob's serialized bytes, by run id.</summary>
    private readonly Dictionary<string, byte[]> sealedBlobsByRunId = [];

    /// <summary>The total number of times <see cref="TryFetchSealedBlobAsync"/> has been called.</summary>
    public int FetchCallCount { get; private set; }

    /// <summary>The number of <see cref="TryFetchSealedBlobAsync"/> calls that found a stored sealed blob (as opposed to nothing).</summary>
    public int FetchHitCount { get; private set; }


    /// <summary>Whether a sealed blob is currently stored for <paramref name="runId"/>.</summary>
    /// <param name="runId">The run id to check.</param>
    /// <returns><see langword="true"/> if a sealed blob is stored; otherwise <see langword="false"/>.</returns>
    public bool HasSealedBlob(string runId) => sealedBlobsByRunId.ContainsKey(runId);


    /// <summary>Attempts to fetch the sealed blob bytes stored for <paramref name="runId"/>. Has the <see cref="TryFetchSealedSnapshotBlobAsyncDelegate"/> shape.</summary>
    /// <param name="runId">The run id to fetch a sealed blob for.</param>
    /// <param name="pool">The memory pool the returned carrier rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The stored bytes, copied into a pooled carrier, or <see langword="null"/> when nothing is stored.</returns>
    public ValueTask<PooledMemory?> TryFetchSealedBlobAsync(string runId, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        FetchCallCount++;

        if(!sealedBlobsByRunId.TryGetValue(runId, out byte[]? bytes))
        {
            return ValueTask.FromResult<PooledMemory?>(null);
        }

        FetchHitCount++;

        return ValueTask.FromResult<PooledMemory?>(PooledMemory.FromBytes(bytes, pool, TpmSealedStateCustodyBufferTags.SealedSnapshotBlobPayload));
    }


    /// <summary>Stores a copy of <paramref name="sealedBlobBytes"/>'s bytes for <paramref name="runId"/>. Has the <see cref="StoreSealedSnapshotBlobAsyncDelegate"/> shape.</summary>
    /// <param name="runId">The run id this sealed blob belongs to.</param>
    /// <param name="sealedBlobBytes">The sealed blob's serialized bytes.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    public ValueTask StoreSealedBlobAsync(string runId, PooledMemory sealedBlobBytes, CancellationToken cancellationToken)
    {
        sealedBlobsByRunId[runId] = sealedBlobBytes.AsReadOnlySpan().ToArray();

        return ValueTask.CompletedTask;
    }


    /// <summary>Deletes whatever sealed blob is stored for <paramref name="runId"/>. Has the <see cref="DeleteSealedSnapshotBlobAsyncDelegate"/> shape.</summary>
    /// <param name="runId">The run id whose sealed blob should be deleted.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    public ValueTask DeleteSealedBlobAsync(string runId, CancellationToken cancellationToken)
    {
        sealedBlobsByRunId.Remove(runId);

        return ValueTask.CompletedTask;
    }


    /// <summary>Returns a mutable copy of the bytes currently stored for <paramref name="runId"/>, for a test to tamper with before writing back via <see cref="ReplaceStoredBytes"/>.</summary>
    /// <param name="runId">The run id whose stored bytes to copy.</param>
    /// <returns>An independent copy of the stored bytes.</returns>
    public byte[] GetStoredBytesCopy(string runId) => (byte[])sealedBlobsByRunId[runId].Clone();


    /// <summary>Overwrites the bytes stored for <paramref name="runId"/> directly, bypassing <c>TpmSealedStateCustody</c>'s own seal path entirely — the fail-closed tamper capstone's own corruption seam.</summary>
    /// <param name="runId">The run id whose stored bytes to replace.</param>
    /// <param name="bytes">The replacement bytes.</param>
    public void ReplaceStoredBytes(string runId, byte[] bytes) => sealedBlobsByRunId[runId] = bytes;
}
