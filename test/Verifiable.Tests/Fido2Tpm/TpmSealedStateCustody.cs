using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody;

/// <summary>
/// Composes a <see cref="CtapStateCustody"/> bundle whose snapshot bytes are protected by, and recovered
/// through, an in-house simulated TPM — a thin adapter over the <see cref="TpmDeviceExtensions"/> seal
/// envelope verbs (<c>SealEnvelopeAsync</c>/<c>UnsealEnvelopeAsync</c>), and their first production consumer.
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
/// A sealed data object carries at most <c>MAX_SYM_DATA</c> (128) octets (TPM 2.0 Library Part 2, clause
/// 11.1.13, Table 169; clause 11.1.14, Table 170) — an authenticator snapshot never fits — so what the TPM
/// seals is a content-encryption key and the snapshot rides under it, which is exactly what
/// <see cref="TpmSealedEnvelope"/> carries. <b>Persist</b>: hands the snapshot to
/// <see cref="TpmDeviceExtensions.SealEnvelopeAsync(uint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, bool, CancellationToken)"/>
/// under <c>sealAuth</c> and stores the envelope's serialized form (<see cref="TpmSealedEnvelope.WriteTo"/>)
/// through the caller's store delegate. <b>Load</b>: fetches the envelope via the caller's fetch delegate
/// (absent ⇒ <see langword="null"/>, the "no snapshot" case), parses it
/// (<see cref="TpmSealedEnvelope.Parse"/>), and recovers the snapshot through
/// <see cref="TpmDeviceExtensions.UnsealEnvelopeAsync(uint, ReadOnlyMemory{byte}, TpmSealedEnvelope, ReadOnlyMemory{byte}, CancellationToken)"/>.
/// <b>Wipe</b>: drives the caller's delete delegate only — nothing this adapter seals is ever loaded into the
/// TPM's own persistent object store, so there is nothing else to evict.
/// </para>
/// <para>
/// Every failure — a seal, an unseal, a parse of the stored envelope, or the ciphertext's authentication —
/// surfaces as a <see cref="TpmSealedStateCustodyException"/> rather than a silently empty or partially
/// rehydrated snapshot (fail closed).
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code: public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
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
    /// The authorization value every snapshot's content key is sealed under and must be presented to
    /// recover — the TPM counterpart of a CTAP custody backend's own "unlock secret."
    /// </param>
    /// <param name="fetchSealedBlobAsync">Fetches the caller-stored envelope bytes for a run id.</param>
    /// <param name="storeSealedBlobAsync">Stores the envelope bytes this adapter produces for a run id.</param>
    /// <param name="deleteSealedBlobAsync">Deletes the caller-stored envelope bytes for a run id.</param>
    /// <param name="pool">
    /// The memory pool this adapter's own envelope scratch work rents from. Defaults to
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
        BaseMemoryPool? pool = null)
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

    /// <summary>The authorization value every snapshot's content key is sealed under.</summary>
    private ReadOnlyMemory<byte> SealAuth { get; }

    /// <summary>The caller-supplied delegate that fetches previously stored envelope bytes.</summary>
    private TryFetchSealedSnapshotBlobAsyncDelegate FetchSealedBlobAsync { get; }

    /// <summary>The caller-supplied delegate that stores freshly produced envelope bytes.</summary>
    private StoreSealedSnapshotBlobAsyncDelegate StoreSealedBlobAsync { get; }

    /// <summary>The caller-supplied delegate that deletes stored envelope bytes.</summary>
    private DeleteSealedSnapshotBlobAsyncDelegate DeleteSealedBlobAsync { get; }

    /// <summary>The memory pool this binding's own envelope scratch work rents from.</summary>
    private BaseMemoryPool Pool { get; }


    /// <summary>
    /// Initializes a new binding. Use <see cref="TpmSealedStateCustody.Create"/>.
    /// </summary>
    /// <param name="tpm">The TPM device to seal to and unseal from.</param>
    /// <param name="storageParentHandle">The handle of the already-loaded storage parent.</param>
    /// <param name="parentAuth">The storage parent's own authorization value.</param>
    /// <param name="sealAuth">The authorization value every snapshot's content key is sealed under.</param>
    /// <param name="fetchSealedBlobAsync">Fetches previously stored envelope bytes.</param>
    /// <param name="storeSealedBlobAsync">Stores freshly produced envelope bytes.</param>
    /// <param name="deleteSealedBlobAsync">Deletes stored envelope bytes.</param>
    /// <param name="pool">The memory pool this binding's own scratch work rents from.</param>
    internal TpmSealedStateCustodyBinding(
        TpmDevice tpm,
        uint storageParentHandle,
        ReadOnlyMemory<byte> parentAuth,
        ReadOnlyMemory<byte> sealAuth,
        TryFetchSealedSnapshotBlobAsyncDelegate fetchSealedBlobAsync,
        StoreSealedSnapshotBlobAsyncDelegate storeSealedBlobAsync,
        DeleteSealedSnapshotBlobAsyncDelegate deleteSealedBlobAsync,
        BaseMemoryPool pool)
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
    /// Attempts to load a previously persisted snapshot for <paramref name="runId"/>: parses the stored
    /// envelope and recovers the snapshot through the TPM. Has the <see cref="TryLoadSnapshotAsyncDelegate"/>
    /// shape.
    /// </summary>
    /// <param name="runId">The run id to load a snapshot for.</param>
    /// <param name="pool">The memory pool the returned snapshot bytes carrier rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recovered plaintext snapshot bytes, or <see langword="null"/> when none was ever stored.</returns>
    /// <exception cref="TpmSealedStateCustodyException">
    /// The stored bytes did not parse as a well-formed envelope, the TPM rejected the unseal (for example a
    /// wrong <c>sealAuth</c>), the unsealed object is not a content key, or the ciphertext failed
    /// authentication — fails closed, never a partial or empty snapshot.
    /// </exception>
    internal async ValueTask<PooledMemory?> TryLoadSnapshotAsync(string runId, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        PooledMemory? envelopeBytes = await FetchSealedBlobAsync(runId, Pool, cancellationToken).ConfigureAwait(false);
        if(envelopeBytes is null)
        {
            return null;
        }

        using TpmSealedEnvelope envelope = ParseEnvelope(runId, envelopeBytes);

        try
        {
            TpmResult<DecryptedContent> unsealResult = await Tpm.UnsealEnvelopeAsync(
                StorageParentHandle, ParentAuth, envelope, SealAuth, cancellationToken).ConfigureAwait(false);

            if(!unsealResult.IsSuccess)
            {
                throw new TpmSealedStateCustodyException(
                    $"Unsealing the content key of the snapshot envelope for run id '{runId}' failed: {DescribeFailure(unsealResult)}.");
            }

            using DecryptedContent plaintext = unsealResult.Value;

            return PooledMemory.FromBytes(plaintext.AsReadOnlySpan(), pool, CtapAuthenticatorCustodyBufferTags.SnapshotPayload);
        }
        catch(CryptographicException ex)
        {
            throw new TpmSealedStateCustodyException(
                $"The snapshot envelope for run id '{runId}' failed authentication under its unsealed content key.", ex);
        }
    }


    /// <summary>
    /// Seals <paramref name="snapshot"/> as an envelope through the TPM and hands the envelope's serialized
    /// bytes to the store delegate. Has the <see cref="PersistSnapshotAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="runId">The run id this snapshot belongs to.</param>
    /// <param name="snapshot">The plaintext snapshot bytes to protect — borrowed; the caller owns and disposes them.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <exception cref="TpmSealedStateCustodyException">The TPM rejected the seal of the content key.</exception>
    internal async ValueTask PersistSnapshotAsync(string runId, PooledMemory snapshot, CancellationToken cancellationToken)
    {
        TpmResult<TpmSealedEnvelope> sealResult = await Tpm.SealEnvelopeAsync(
            StorageParentHandle, ParentAuth, snapshot.AsReadOnlyMemory(), SealAuth, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!sealResult.IsSuccess)
        {
            throw new TpmSealedStateCustodyException($"Sealing the content key for run id '{runId}' failed: {DescribeFailure(sealResult)}.");
        }

        using TpmSealedEnvelope envelope = sealResult.Value;
        int size = envelope.GetSerializedSize();
        using IMemoryOwner<byte> serialized = Pool.Rent(size);
        var writer = new TpmWriter(serialized.Memory.Span[..size]);
        envelope.WriteTo(ref writer);

        using PooledMemory serializedEnvelope = PooledMemory.FromBytes(
            serialized.Memory.Span[..size], Pool, TpmSealedStateCustodyBufferTags.SealedSnapshotBlobPayload);

        await StoreSealedBlobAsync(runId, serializedEnvelope, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Deletes whatever envelope is stored for <paramref name="runId"/>. Has the
    /// <see cref="WipeSnapshotAsyncDelegate"/> shape.
    /// </summary>
    /// <param name="runId">The run id whose envelope should be deleted.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    internal ValueTask WipeSnapshotAsync(string runId, CancellationToken cancellationToken) =>
        DeleteSealedBlobAsync(runId, cancellationToken);


    /// <summary>
    /// Parses previously fetched envelope bytes, disposing <paramref name="envelopeBytes"/> once parsed (or on
    /// a parse failure) and wrapping any parse failure into a fail-closed
    /// <see cref="TpmSealedStateCustodyException"/> — a tampered or truncated stored envelope never yields a
    /// partially restored snapshot.
    /// </summary>
    /// <param name="runId">The run id the failed-parse exception message names.</param>
    /// <param name="envelopeBytes">The fetched envelope bytes, consumed and disposed by this call.</param>
    /// <returns>The parsed envelope. The caller owns it and must dispose it.</returns>
    /// <exception cref="TpmSealedStateCustodyException">The bytes do not parse as a well-formed envelope.</exception>
    private TpmSealedEnvelope ParseEnvelope(string runId, PooledMemory envelopeBytes)
    {
        using(envelopeBytes)
        {
            try
            {
                var reader = new TpmReader(envelopeBytes.AsReadOnlySpan());

                return TpmSealedEnvelope.Parse(ref reader, Pool);
            }
            catch(Exception ex) when(ex is InvalidOperationException or ArgumentException or OverflowException)
            {
                throw new TpmSealedStateCustodyException(
                    $"The stored snapshot envelope for run id '{runId}' did not parse as a well-formed envelope.", ex);
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
