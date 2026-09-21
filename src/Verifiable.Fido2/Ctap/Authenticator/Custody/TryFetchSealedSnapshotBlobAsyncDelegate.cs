namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Attempts to fetch the opaque, TPM-sealed snapshot blob bytes a prior
/// <see cref="StoreSealedSnapshotBlobAsyncDelegate"/> call stored for <paramref name="runId"/> — the
/// caller-supplied I/O half of <c>TpmSealedStateCustody</c>: this adapter performs
/// no I/O of its own, only the seal/unseal step; where the opaque bytes actually live (a file, a database
/// row, an in-memory dictionary) is the caller's business.
/// </summary>
/// <param name="runId">
/// The stable identifier of the authenticator instance to fetch a sealed blob for — the SAME value the
/// composed <see cref="CtapStateCustody"/> bundle's own delegates are keyed by, threaded through unchanged
/// (house rule: no closure capture).
/// </param>
/// <param name="pool">The memory pool the returned bytes carrier rents from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The previously stored sealed blob's serialized bytes (<c>Verifiable.Tpm.Extensions.Seal.TpmSealedBlob.WriteTo</c>'s
/// own wire form), copied into a pooled carrier the caller owns and must dispose, or <see langword="null"/>
/// when nothing has ever been stored for <paramref name="runId"/> — <c>TpmSealedStateCustody</c>
/// propagates this directly as "no snapshot" (first boot).
/// </returns>
/// <remarks>
/// Implementations SHOULD treat a missing/never-written entry as this ordinary "first boot" case rather
/// than throwing; a genuine I/O failure should still propagate as an exception, distinct from "nothing was
/// ever stored."
/// </remarks>
public delegate ValueTask<PooledMemory?> TryFetchSealedSnapshotBlobAsyncDelegate(string runId, BaseMemoryPool pool, CancellationToken cancellationToken);
