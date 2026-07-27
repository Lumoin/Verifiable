using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Attempts to fetch the opaque, TPM-sealed snapshot blob bytes a prior
/// <see cref="StoreSealedSnapshotBlobAsyncDelegate"/> call stored for <paramref name="runId"/> — the
/// caller-supplied I/O half of <see cref="TpmSealedStateCustody"/> (contract R-7): this adapter performs
/// no I/O of its own, only the seal/unseal step; where the opaque bytes actually live (a file, a database
/// row, an in-memory dictionary) is the caller's business.
/// </summary>
/// <param name="runId">
/// The stable identifier of the authenticator instance to fetch a sealed blob for — the SAME value the
/// composed <see cref="CtapStateCustody"/> bundle's own delegates are keyed by, threaded through unchanged
/// (contract R-3, house rule: no closure capture).
/// </param>
/// <param name="pool">The memory pool the returned bytes carrier rents from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The previously stored sealed blob's serialized bytes (<see cref="Verifiable.Tpm.Extensions.Seal.TpmSealedBlob.WriteTo"/>'s
/// own wire form), copied into a pooled carrier the caller owns and must dispose, or <see langword="null"/>
/// when nothing has ever been stored for <paramref name="runId"/> — <see cref="TpmSealedStateCustody"/>
/// propagates this directly as "no snapshot" (contract R-1: first boot).
/// </returns>
/// <remarks>
/// Implementations SHOULD treat a missing/never-written entry as this ordinary "first boot" case rather
/// than throwing; a genuine I/O failure should still propagate as an exception, distinct from "nothing was
/// ever stored."
/// </remarks>
public delegate ValueTask<PooledMemory?> TryFetchSealedSnapshotBlobAsyncDelegate(string runId, MemoryPool<byte> pool, CancellationToken cancellationToken);
