using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Composes a <see cref="CtapStateCustody"/> bundle whose snapshot bytes are sealed to, and recovered
/// from, an in-house simulated TPM (contract R-7) — a thin adapter over the
/// <see cref="TpmDeviceExtensions"/> business-capability verbs package B shipped (<c>SealAsync</c>/
/// <c>UnsealAsync</c>), and their first production consumer.
/// </summary>
/// <remarks>
/// <para>
/// The CTAP-side custody seam (<see cref="CtapStateCustody"/>) is backend-neutral by design: any store may
/// implement its three delegates. This adapter is one such implementation. It performs NO I/O of its own —
/// every byte it needs to persist crosses a caller-supplied <see cref="StoreSealedSnapshotBlobAsyncDelegate"/>/
/// <see cref="TryFetchSealedSnapshotBlobAsyncDelegate"/>/<see cref="DeleteSealedSnapshotBlobAsyncDelegate"/>
/// triple — a file, a database row, an in-memory dictionary is the caller's business — while this
/// adapter's own job is exactly the seal/unseal step in between (TPM 2.0 Library Part 3, Sections 12.1,
/// 12.2, 12.7).
/// </para>
/// <para>
/// <b>Persist</b>: seals the received plaintext snapshot bytes under <c>sealAuth</c> via
/// <see cref="TpmDeviceExtensions.SealAsync"/>, serializes the resulting <see cref="TpmSealedBlob"/>
/// (<see cref="TpmSealedBlob.GetSerializedSize"/>/<see cref="TpmSealedBlob.WriteTo"/>), and hands the
/// opaque bytes to the caller's store delegate. <b>Load</b>: fetches the opaque bytes via the caller's
/// fetch delegate (absent ⇒ <see langword="null"/>, contract R-1's "no snapshot" case), reparses them with
/// <see cref="TpmSealedBlob.Parse"/>, and recovers the plaintext snapshot via
/// <see cref="TpmDeviceExtensions.UnsealAsync"/>. <b>Wipe</b>: drives the caller's delete delegate only —
/// nothing this adapter seals is ever loaded into the TPM's own persistent object store, so there is
/// nothing else to evict.
/// </para>
/// <para>
/// Every TPM-side failure — a seal, an unseal, or a parse of the stored bytes — surfaces as a
/// <see cref="TpmSealedStateCustodyException"/> rather than a silently empty or partially rehydrated
/// snapshot (fail closed).
/// </para>
/// </remarks>
public static class TpmSealedStateCustody
{
    /// <summary>
    /// Builds a <see cref="CtapStateCustody"/> bundle backed by an in-house simulated TPM.
    /// </summary>
    /// <param name="tpm">The TPM device to seal to and unseal from.</param>
    /// <param name="storageParentHandle">
    /// The handle of an already-loaded storage parent (see <see cref="TpmDeviceExtensions.SealAsync"/>'s
    /// own parent-constraint remarks) — this adapter neither creates nor loads it; the caller composes the
    /// parent and owns its lifetime.
    /// </param>
    /// <param name="parentAuth">The storage parent's authorization value, or empty when it has none.</param>
    /// <param name="sealAuth">
    /// The authorization value every snapshot is sealed under and must be presented to recover — the TPM
    /// counterpart of a CTAP custody backend's own "unlock secret."
    /// </param>
    /// <param name="fetchSealedBlobAsync">Fetches the caller-stored sealed blob bytes for a run id.</param>
    /// <param name="storeSealedBlobAsync">Stores the sealed blob bytes this adapter produces for a run id.</param>
    /// <param name="deleteSealedBlobAsync">Deletes the caller-stored sealed blob bytes for a run id.</param>
    /// <param name="pool">
    /// The memory pool this adapter's own seal/unseal scratch work rents from. Defaults to
    /// <see cref="BaseMemoryPool.Shared"/> when <see langword="null"/>.
    /// </param>
    /// <returns>The composed seam-bundle record.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="tpm"/>, <paramref name="fetchSealedBlobAsync"/>, <paramref name="storeSealedBlobAsync"/>,
    /// or <paramref name="deleteSealedBlobAsync"/> is <see langword="null"/>.
    /// </exception>
    public static CtapStateCustody Create(
        TpmDevice tpm,
        uint storageParentHandle,
        ReadOnlyMemory<byte> parentAuth,
        ReadOnlyMemory<byte> sealAuth,
        TryFetchSealedSnapshotBlobAsyncDelegate fetchSealedBlobAsync,
        StoreSealedSnapshotBlobAsyncDelegate storeSealedBlobAsync,
        DeleteSealedSnapshotBlobAsyncDelegate deleteSealedBlobAsync,
        MemoryPool<byte>? pool = null)
    {
        ArgumentNullException.ThrowIfNull(tpm);
        ArgumentNullException.ThrowIfNull(fetchSealedBlobAsync);
        ArgumentNullException.ThrowIfNull(storeSealedBlobAsync);
        ArgumentNullException.ThrowIfNull(deleteSealedBlobAsync);

        var binding = new TpmSealedStateCustodyBinding(
            tpm, storageParentHandle, parentAuth, sealAuth, fetchSealedBlobAsync, storeSealedBlobAsync, deleteSealedBlobAsync,
            pool ?? BaseMemoryPool.Shared);

        return new CtapStateCustody(binding.TryLoadSnapshotAsync, binding.PersistSnapshotAsync, binding.WipeSnapshotAsync);
    }
}


/// <summary>
/// The bound configuration <see cref="TpmSealedStateCustody.Create"/> composes into a
/// <see cref="CtapStateCustody"/> bundle: every delegate <see cref="TpmSealedStateCustody.Create"/> returns
/// is a bound instance method on one of these, so the only "context" any of them closes over is the
/// explicit receiver (<see langword="this"/>), never a captured local (house rule: no closure capture) —
/// the same discipline the test-side <c>DictionaryBackedCtapStateCustodyStore</c> double follows.
/// </summary>
internal sealed class TpmSealedStateCustodyBinding
{
    /// <summary>The TPM device this binding seals to and unseals from.</summary>
    private TpmDevice Tpm { get; }

    /// <summary>The handle of the already-loaded storage parent every seal/unseal is performed under.</summary>
    private uint StorageParentHandle { get; }

    /// <summary>The storage parent's own authorization value.</summary>
    private ReadOnlyMemory<byte> ParentAuth { get; }

    /// <summary>The authorization value every snapshot is sealed under.</summary>
    private ReadOnlyMemory<byte> SealAuth { get; }

    /// <summary>The caller-supplied delegate that fetches previously stored sealed-blob bytes.</summary>
    private TryFetchSealedSnapshotBlobAsyncDelegate FetchSealedBlobAsync { get; }

    /// <summary>The caller-supplied delegate that stores freshly sealed blob bytes.</summary>
    private StoreSealedSnapshotBlobAsyncDelegate StoreSealedBlobAsync { get; }

    /// <summary>The caller-supplied delegate that deletes stored sealed-blob bytes.</summary>
    private DeleteSealedSnapshotBlobAsyncDelegate DeleteSealedBlobAsync { get; }

    /// <summary>The memory pool this binding's own TPM-facing scratch work rents from.</summary>
    private MemoryPool<byte> Pool { get; }


    /// <summary>
    /// Initializes a new binding. Use <see cref="TpmSealedStateCustody.Create"/>.
    /// </summary>
    /// <param name="tpm">The TPM device to seal to and unseal from.</param>
    /// <param name="storageParentHandle">The handle of the already-loaded storage parent.</param>
    /// <param name="parentAuth">The storage parent's own authorization value.</param>
    /// <param name="sealAuth">The authorization value every snapshot is sealed under.</param>
    /// <param name="fetchSealedBlobAsync">Fetches previously stored sealed-blob bytes.</param>
    /// <param name="storeSealedBlobAsync">Stores freshly sealed blob bytes.</param>
    /// <param name="deleteSealedBlobAsync">Deletes stored sealed-blob bytes.</param>
    /// <param name="pool">The memory pool this binding's own TPM-facing scratch work rents from.</param>
    internal TpmSealedStateCustodyBinding(
        TpmDevice tpm,
        uint storageParentHandle,
        ReadOnlyMemory<byte> parentAuth,
        ReadOnlyMemory<byte> sealAuth,
        TryFetchSealedSnapshotBlobAsyncDelegate fetchSealedBlobAsync,
        StoreSealedSnapshotBlobAsyncDelegate storeSealedBlobAsync,
        DeleteSealedSnapshotBlobAsyncDelegate deleteSealedBlobAsync,
        MemoryPool<byte> pool)
    {
        Tpm = tpm;
        StorageParentHandle = storageParentHandle;
        ParentAuth = parentAuth;
        SealAuth = sealAuth;
        FetchSealedBlobAsync = fetchSealedBlobAsync;
        StoreSealedBlobAsync = storeSealedBlobAsync;
        DeleteSealedBlobAsync = deleteSealedBlobAsync;
        Pool = pool;
    }


    /// <summary>
    /// Attempts to load and unseal a previously persisted snapshot for <paramref name="runId"/>. Has the
    /// <see cref="TryLoadSnapshotAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="runId">The run id to load a snapshot for.</param>
    /// <param name="pool">The memory pool the returned snapshot bytes carrier rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recovered plaintext snapshot bytes, or <see langword="null"/> when none was ever stored.</returns>
    /// <exception cref="TpmSealedStateCustodyException">
    /// The stored bytes did not parse as a well-formed <see cref="TpmSealedBlob"/>, or the TPM rejected the
    /// unseal (for example a wrong <c>sealAuth</c>) — fails closed, never a partial or empty snapshot.
    /// </exception>
    internal async ValueTask<PooledMemory?> TryLoadSnapshotAsync(string runId, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        PooledMemory? sealedBlobBytes = await FetchSealedBlobAsync(runId, Pool, cancellationToken).ConfigureAwait(false);
        if(sealedBlobBytes is null)
        {
            return null;
        }

        using TpmSealedBlob sealedBlob = ParseSealedBlob(runId, sealedBlobBytes);

        TpmResult<UnsealResponse> unsealResult = await Tpm.UnsealAsync(
            StorageParentHandle, ParentAuth, sealedBlob, SealAuth, cancellationToken).ConfigureAwait(false);

        if(!unsealResult.IsSuccess)
        {
            throw new TpmSealedStateCustodyException(
                $"Unsealing the TPM-sealed snapshot blob for run id '{runId}' failed: {DescribeFailure(unsealResult)}.");
        }

        using UnsealResponse unsealed = unsealResult.Value;

        return PooledMemory.FromBytes(unsealed.OutData.AsReadOnlySpan(), pool, CtapAuthenticatorCustodyBufferTags.SnapshotPayload);
    }


    /// <summary>
    /// Seals <paramref name="snapshot"/> and hands the resulting sealed blob's serialized bytes to the
    /// store delegate. Has the <see cref="PersistSnapshotAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="runId">The run id this snapshot belongs to.</param>
    /// <param name="snapshot">The plaintext snapshot bytes to seal.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmSealedStateCustodyException">The TPM rejected the seal.</exception>
    internal async ValueTask PersistSnapshotAsync(string runId, PooledMemory snapshot, CancellationToken cancellationToken)
    {
        TpmResult<TpmSealedBlob> sealResult = await Tpm.SealAsync(
            StorageParentHandle, ParentAuth, snapshot.AsReadOnlyMemory(), SealAuth, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!sealResult.IsSuccess)
        {
            throw new TpmSealedStateCustodyException($"Sealing the snapshot for run id '{runId}' failed: {DescribeFailure(sealResult)}.");
        }

        using TpmSealedBlob sealedBlob = sealResult.Value;
        int size = sealedBlob.GetSerializedSize();
        using IMemoryOwner<byte> scratch = Pool.Rent(size);
        var writer = new TpmWriter(scratch.Memory.Span[..size]);
        sealedBlob.WriteTo(ref writer);

        using PooledMemory serializedSealedBlob = PooledMemory.FromBytes(
            scratch.Memory.Span[..size], Pool, TpmSealedStateCustodyBufferTags.SealedSnapshotBlobPayload);

        await StoreSealedBlobAsync(runId, serializedSealedBlob, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Deletes whatever sealed blob is stored for <paramref name="runId"/>. Has the
    /// <see cref="WipeSnapshotAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="runId">The run id whose sealed blob should be deleted.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    internal ValueTask WipeSnapshotAsync(string runId, CancellationToken cancellationToken) =>
        DeleteSealedBlobAsync(runId, cancellationToken);


    /// <summary>
    /// Parses previously fetched sealed-blob bytes into a <see cref="TpmSealedBlob"/>, disposing
    /// <paramref name="sealedBlobBytes"/> once parsed (or on a parse failure) and wrapping any parse
    /// failure into a fail-closed <see cref="TpmSealedStateCustodyException"/> — a tampered or truncated
    /// stored blob never yields a partially restored snapshot.
    /// </summary>
    /// <param name="runId">The run id the failed-parse exception message names.</param>
    /// <param name="sealedBlobBytes">The fetched sealed-blob bytes, consumed and disposed by this call.</param>
    /// <returns>The parsed sealed blob. The caller owns it and must dispose it.</returns>
    /// <exception cref="TpmSealedStateCustodyException">The bytes do not parse as a well-formed sealed blob.</exception>
    private TpmSealedBlob ParseSealedBlob(string runId, PooledMemory sealedBlobBytes)
    {
        using(sealedBlobBytes)
        {
            try
            {
                var reader = new TpmReader(sealedBlobBytes.AsReadOnlySpan());

                return TpmSealedBlob.Parse(ref reader, Pool);
            }
            catch(Exception ex) when(ex is InvalidOperationException or ArgumentException)
            {
                throw new TpmSealedStateCustodyException(
                    $"The stored TPM-sealed snapshot blob for run id '{runId}' did not parse as a well-formed sealed blob.", ex);
            }
        }
    }


    /// <summary>Describes a non-success <see cref="TpmResult{T}"/> for a fail-closed exception message.</summary>
    /// <typeparam name="T">The result's success-value type.</typeparam>
    /// <param name="result">The non-success result to describe.</param>
    /// <returns>A short, human-readable description of the TPM or transport failure.</returns>
    private static string DescribeFailure<T>(TpmResult<T> result) =>
        result.IsTpmError ? result.ResponseCode.GetDescription() : $"transport error 0x{result.TransportErrorCode:X8}";
}
