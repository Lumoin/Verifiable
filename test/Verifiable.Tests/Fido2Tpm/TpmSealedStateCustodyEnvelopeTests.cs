using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.Fido2.Tpm.Ctap.Authenticator.Custody;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Tpm;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Fido2Tpm;

/// <summary>
/// Proving tests for the envelope <see cref="TpmSealedStateCustody"/> persists: the TPM seals a 256-bit content
/// key — never the snapshot, which exceeds the <c>MAX_SYM_DATA</c> (128) octets a sealed data object may carry
/// (TPM 2.0 Library Part 2, clause 11.1.13, Table 169; clause 11.1.14, Table 170) — and the snapshot rides under
/// that key with AES-256-GCM, bound to the sealed key through the additional authenticated data.
/// </summary>
[TestClass]
internal sealed class TpmSealedStateCustodyEnvelopeTests
{
    /// <summary>The MSTest-provided per-test context, its cancellation token observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The authorization value the content key is sealed under.</summary>
    private static byte[] SealAuth { get; } = "custody-seal-auth"u8.ToArray();

    /// <summary>A snapshot width eight times the widest sealed data object.</summary>
    private const int WideSnapshotLength = 8 * Tpm2bSensitiveData.MaxSize;

    /// <summary>The width of the content key the envelope seals.</summary>
    private const int ContentKeyLength = 32;

    /// <summary>
    /// A snapshot wider than any sealed data object persists and loads back byte for byte, and the stored
    /// envelope carries it only in encrypted form.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.14, Table 170; Part 3, clauses 12.1 and 12.7</see>.
    /// </summary>
    [TestMethod]
    public async Task ASnapshotWiderThanMaxSymDataRoundTripsThroughTheEnvelope()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ASnapshotWiderThanMaxSymDataRoundTripsThroughTheEnvelope), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        (TpmResponseRegistry registry, uint parentHandle, DictionaryBackedTpmSealedSnapshotBlobStore store, CtapStateCustody custody) = await ComposeAsync(tpm, pool).ConfigureAwait(false);

        using IMemoryOwner<byte> plaintext = FilledSnapshot(pool);
        using(PooledMemory snapshot = PooledMemory.FromBytes(plaintext.Memory.Span[..WideSnapshotLength], pool, CtapAuthenticatorCustodyBufferTags.SnapshotPayload))
        {
            await custody.PersistSnapshotAsync("run-a", snapshot, TestContext.CancellationToken).ConfigureAwait(false);
        }

        byte[] stored = store.GetStoredBytesCopy("run-a");
        Assert.IsGreaterThan(WideSnapshotLength, stored.Length, "The envelope must carry the sealed key, the IV and the tag beside the ciphertext.");
        Assert.IsLessThan(0, stored.AsSpan().IndexOf(plaintext.Memory.Span[..64]), "The stored envelope must not carry the snapshot in the clear.");

        PooledMemory? loaded = await custody.TryLoadSnapshotAsync("run-a", pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsNotNull(loaded, "A persisted snapshot must load back.");
        using(loaded)
        {
            Assert.IsTrue(loaded.AsReadOnlySpan().SequenceEqual(plaintext.Memory.Span[..WideSnapshotLength]), "The snapshot must load back byte for byte.");
        }

        await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The sealed object inside the envelope is the content key — <c>TPM2_Unseal()</c> on it yields 32 octets,
    /// well within the <c>MAX_SYM_DATA</c> bound a real TPM enforces — not the snapshot.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.13, Table 169; Part 3, clause 12.7</see>.
    /// </summary>
    [TestMethod]
    public async Task TheEnvelopeSealsAContentKeyNotTheSnapshot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(TheEnvelopeSealsAContentKeyNotTheSnapshot), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        (TpmResponseRegistry registry, uint parentHandle, DictionaryBackedTpmSealedSnapshotBlobStore store, CtapStateCustody custody) = await ComposeAsync(tpm, pool).ConfigureAwait(false);

        await PersistFilledSnapshotAsync(custody, "run-a", pool).ConfigureAwait(false);

        byte[] stored = store.GetStoredBytesCopy("run-a");
        var reader = new TpmReader(stored);
        using TpmSealedBlob sealedKey = TpmSealedBlob.Parse(ref reader, pool);
        Assert.IsLessThan(stored.Length, reader.Consumed, "The sealed key must be a prefix of the envelope, not the whole of it.");

        TpmResult<UnsealResponse> unsealResult = await tpm.UnsealAsync(parentHandle, ReadOnlyMemory<byte>.Empty, sealedKey, SealAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"Unsealing the envelope's sealed object failed: '{unsealResult.ResponseCode}'.");
        using UnsealResponse unsealed = unsealResult.Value;

        Assert.AreEqual(ContentKeyLength, unsealed.OutData.Length, "The sealed object must be the 32-octet content key.");

        await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// A stored envelope whose ciphertext was altered fails authentication and the load fails closed with
    /// <see cref="TpmSealedStateCustodyException"/> — no partial or garbled snapshot is ever returned.
    /// </summary>
    [TestMethod]
    public async Task ATamperedCiphertextIsRefusedFailClosed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ATamperedCiphertextIsRefusedFailClosed), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        (TpmResponseRegistry registry, uint parentHandle, DictionaryBackedTpmSealedSnapshotBlobStore store, CtapStateCustody custody) = await ComposeAsync(tpm, pool).ConfigureAwait(false);

        await PersistFilledSnapshotAsync(custody, "run-a", pool).ConfigureAwait(false);

        byte[] tampered = store.GetStoredBytesCopy("run-a");
        tampered[^1] ^= 0x01;
        store.ReplaceStoredBytes("run-a", tampered);

        _ = await Assert.ThrowsExactlyAsync<TpmSealedStateCustodyException>(
            () => custody.TryLoadSnapshotAsync("run-a", pool, TestContext.CancellationToken).AsTask(),
            "An altered ciphertext must fail authentication and the load must fail closed.");

        await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// The ciphertext is bound to exactly the sealed key that opens it: grafting another run's sealed key onto
    /// an envelope unseals a different content key, so the authentication fails and the load fails closed.
    /// </summary>
    [TestMethod]
    public async Task ASealedKeyFromAnotherRunIsRefusedFailClosed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ASealedKeyFromAnotherRunIsRefusedFailClosed), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        (TpmResponseRegistry registry, uint parentHandle, DictionaryBackedTpmSealedSnapshotBlobStore store, CtapStateCustody custody) = await ComposeAsync(tpm, pool).ConfigureAwait(false);

        await PersistFilledSnapshotAsync(custody, "run-a", pool).ConfigureAwait(false);
        await PersistFilledSnapshotAsync(custody, "run-b", pool).ConfigureAwait(false);

        byte[] envelopeA = store.GetStoredBytesCopy("run-a");
        byte[] envelopeB = store.GetStoredBytesCopy("run-b");
        int sealedKeyLengthA = SealedKeyLength(envelopeA, pool);
        int sealedKeyLengthB = SealedKeyLength(envelopeB, pool);
        Assert.AreEqual(sealedKeyLengthA, sealedKeyLengthB, "Two content keys sealed under one parent must serialize to the same width.");

        envelopeB.AsSpan(0, sealedKeyLengthB).CopyTo(envelopeA);
        store.ReplaceStoredBytes("run-a", envelopeA);

        _ = await Assert.ThrowsExactlyAsync<TpmSealedStateCustodyException>(
            () => custody.TryLoadSnapshotAsync("run-a", pool, TestContext.CancellationToken).AsTask(),
            "A grafted sealed key must not open another run's ciphertext.");

        await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Composes a custody bundle over a fresh ECC storage parent and a dictionary-backed envelope store.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The codec registry, the loaded storage parent's handle (the caller flushes it), the store double, and the composed bundle.</returns>
    private async Task<(TpmResponseRegistry Registry, uint ParentHandle, DictionaryBackedTpmSealedSnapshotBlobStore Store, CtapStateCustody Custody)> ComposeAsync(TpmDevice tpm, BaseMemoryPool pool)
    {
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        uint parentHandle;
        using(CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false))
        {
            parentHandle = parent.ObjectHandle.Value;
        }

        var store = new DictionaryBackedTpmSealedSnapshotBlobStore();
        CtapStateCustody custody = TpmSealedStateCustody.Create(
            tpm, parentHandle, ReadOnlyMemory<byte>.Empty, SealAuth, store.TryFetchSealedBlobAsync, store.StoreSealedBlobAsync, store.DeleteSealedBlobAsync, pool);

        return (registry, parentHandle, store, custody);
    }

    /// <summary>Persists a filled wide snapshot for <paramref name="runId"/>.</summary>
    /// <param name="custody">The custody bundle.</param>
    /// <param name="runId">The run id.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A task that completes once the snapshot is stored.</returns>
    private async Task PersistFilledSnapshotAsync(CtapStateCustody custody, string runId, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> plaintext = FilledSnapshot(pool);
        using PooledMemory snapshot = PooledMemory.FromBytes(plaintext.Memory.Span[..WideSnapshotLength], pool, CtapAuthenticatorCustodyBufferTags.SnapshotPayload);
        await custody.PersistSnapshotAsync(runId, snapshot, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Rents a wide snapshot whose octets follow a fixed, non-repeating-per-block pattern.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rented buffer; its first <see cref="WideSnapshotLength"/> octets are the snapshot.</returns>
    private static IMemoryOwner<byte> FilledSnapshot(BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(WideSnapshotLength);
        Span<byte> span = owner.Memory.Span[..WideSnapshotLength];
        for(int i = 0; i < span.Length; i++)
        {
            span[i] = (byte)((i * 7) + 3);
        }

        return owner;
    }

    /// <summary>Measures the sealed-key prefix of a stored envelope.</summary>
    /// <param name="envelope">The stored envelope octets.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The serialized width of the sealed key.</returns>
    private static int SealedKeyLength(byte[] envelope, BaseMemoryPool pool)
    {
        var reader = new TpmReader(envelope);
        using TpmSealedBlob sealedKey = TpmSealedBlob.Parse(ref reader, pool);

        return reader.Consumed;
    }
}
