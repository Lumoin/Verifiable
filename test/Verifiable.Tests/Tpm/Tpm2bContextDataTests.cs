using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves <see cref="Tpm2bContextData"/> — the opaque, pooled <c>TPM2B_CONTEXT_DATA</c> sized buffer a saved
/// context's octets ride in — against its <c>Parse</c>/<c>Create</c>/<c>WriteTo</c> round trip, its
/// <see cref="Tpm2bContextData.MaxSize"/> ceiling, its rental-adopting <see cref="Tpm2bContextData.FromMarshaled"/>
/// factory, and disposal.
/// </summary>
[TestClass]
internal sealed class Tpm2bContextDataTests
{
    /// <summary>
    /// A size-zero <c>TPM2B_CONTEXT_DATA</c> parses to the shared <see cref="Tpm2bContextData.Empty"/> instance
    /// without renting any storage — the same size-driven shape <see cref="Tpm2bContextData.Parse"/> shares with
    /// every other <c>TPM2B</c> sized buffer in this library.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.4, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataParseWithSizeZeroReturnsEmptyWithoutRenting()
    {
        byte[] wire = [0x00, 0x00];
        using var trackingPool = new MeteredHousePool();
        long baselineRented = trackingPool.RentedCount;

        var reader = new TpmReader(wire);
        using Tpm2bContextData data = Tpm2bContextData.Parse(ref reader, trackingPool.Pool);

        Assert.IsTrue(data.IsEmpty, "A size-zero TPM2B_CONTEXT_DATA must parse to the Empty singleton.");
        Assert.AreEqual(0, data.Size, "The Empty singleton carries no octets.");
        Assert.AreEqual(2, reader.Consumed, "Parse must consume exactly the two-octet size field.");
        Assert.AreEqual(baselineRented, trackingPool.RentedCount, "A size-zero buffer must rent nothing.");
    }

    /// <summary>
    /// <see cref="Tpm2bContextData.MaxSize"/> — "the UINT16 ceiling, 65535 octets" — is itself an admitted size:
    /// the buffer's own size field width is the only ceiling this type enforces at parse time, so the widest
    /// value a <c>UINT16</c> can declare parses rather than being refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.4, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataParseAdmitsTheUint16CeilingAtMaxSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] wire = new byte[sizeof(ushort) + Tpm2bContextData.MaxSize];
        wire[0] = 0xFF;
        wire[1] = 0xFF;
        wire[2] = 0xAB;
        wire[^1] = 0xCD;

        var reader = new TpmReader(wire);
        using Tpm2bContextData data = Tpm2bContextData.Parse(ref reader, pool);

        Assert.AreEqual(Tpm2bContextData.MaxSize, data.Size, "The UINT16 ceiling itself must be admitted, not refused.");
        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the declared payload.");
        Assert.AreEqual((byte)0xAB, data.Span[0], "The first payload octet must survive the parse.");
        Assert.AreEqual((byte)0xCD, data.Span[^1], "The last payload octet must survive the parse.");
    }

    /// <summary>
    /// A declared size past the octets the reader actually holds is a truncated frame, refused with
    /// <c>ArgumentOutOfRangeException</c> BEFORE any storage is rented — the same bounds-before-rent guard every
    /// other <c>TPM2B</c> sized buffer in this library applies.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.4, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataParseWithADeclaredSizePastTheReaderThrowsAndRentsNothing()
    {
        byte[] wire = [0x00, 0x0A, 0x01, 0x02];
        using var trackingPool = new MeteredHousePool();
        long baselineRented = trackingPool.RentedCount;

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => ParseContextData(wire, trackingPool.Pool),
            "A declared size past the reader's remaining octets must be refused before any rental is issued.");

        Assert.AreEqual(baselineRented, trackingPool.RentedCount, "The bounds check runs before the rental it would otherwise size, so a truncated frame never rents at all.");
    }

    /// <summary>
    /// <see cref="Tpm2bContextData.Create"/> copies the supplied octets into pooled storage, and the resulting
    /// buffer's <see cref="Tpm2bContextData.WriteTo"/>/<see cref="Tpm2bContextData.SerializedSize"/> round-trip
    /// through <see cref="Tpm2bContextData.Parse"/> byte-for-byte.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.4, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataCreateWriteToAndSerializedSizeRoundTrip()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] original = [0x11, 0x22, 0x33, 0x44];
        using Tpm2bContextData data = Tpm2bContextData.Create(original, pool);

        Assert.AreEqual(original.Length, data.Length, "Create must adopt exactly the supplied octet count.");
        Assert.AreEqual(sizeof(ushort) + original.Length, data.SerializedSize, "SerializedSize must be the two-octet size field plus the payload.");

        byte[] wire = new byte[data.SerializedSize];
        var writer = new TpmWriter(wire);
        data.WriteTo(ref writer);
        Assert.AreEqual(wire.Length, writer.Written, "WriteTo must fill exactly SerializedSize octets.");

        var reader = new TpmReader(wire);
        using Tpm2bContextData roundTripped = Tpm2bContextData.Parse(ref reader, pool);
        Assert.IsTrue(roundTripped.Span.SequenceEqual(original), "Parse must reproduce Create's octets exactly.");
    }

    /// <summary>
    /// <see cref="Tpm2bContextData.FromMarshaled"/> adopts an already-filled rental as this structure's storage
    /// "with no second rental and no copy" — the effect that marshals a <c>TPMS_CONTEXT</c>'s fields into a
    /// rented buffer adopts that same buffer here rather than renting and copying a second time.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.4, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataFromMarshaledAdoptsTheRentalWithoutRentingAgain()
    {
        using var trackingPool = new MeteredHousePool();
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(4);
        byte[] filled = [0xAA, 0xBB, 0xCC, 0xDD];
        filled.CopyTo(storage.Memory.Span);
        long rentedAfterTheOneRent = trackingPool.RentedCount;

        using Tpm2bContextData data = Tpm2bContextData.FromMarshaled(storage, 4);

        Assert.AreEqual(rentedAfterTheOneRent, trackingPool.RentedCount, "FromMarshaled must adopt the caller's rental rather than renting a second time.");
        Assert.AreEqual(4, data.Size, "The adopted size must be the octet count FromMarshaled was given.");
        Assert.IsTrue(data.Span.SequenceEqual(filled), "The adopted buffer must expose exactly the octets already written into the rental.");
    }

    /// <summary>
    /// A zero-length adoption releases the caller's rental immediately and yields the shared
    /// <see cref="Tpm2bContextData.Empty"/> singleton, "since the singleton rents nothing and its Dispose is a
    /// no-op" — the caller's storage must not be orphaned outstanding.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.4, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataFromMarshaledWithSizeZeroReleasesTheRentalAndReturnsEmpty()
    {
        using var trackingPool = new MeteredHousePool();
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(4);
        long outstandingAfterTheRent = trackingPool.OutstandingCount;

        Tpm2bContextData data = Tpm2bContextData.FromMarshaled(storage, 0);

        Assert.AreSame(Tpm2bContextData.Empty, data, "A size-zero adoption must return the shared Empty singleton.");
        Assert.AreEqual(outstandingAfterTheRent - 1, trackingPool.OutstandingCount, "The zero-size adoption must release the caller's rental immediately.");
    }

    /// <summary>
    /// A size claiming more octets than the adopted storage actually holds is refused with
    /// <c>ArgumentOutOfRangeException</c>, and the rejected rental is released before the exception leaves — "a
    /// rejected adoption never orphans the rental".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 14.4, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataFromMarshaledWithASizePastTheStorageThrowsAndDisposesTheRental()
    {
        using var trackingPool = new MeteredHousePool();
        IMemoryOwner<byte> storage = trackingPool.Pool.Rent(4);
        long outstandingAfterTheRent = trackingPool.OutstandingCount;

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => Tpm2bContextData.FromMarshaled(storage, 5),
            "A size past the adopted storage's own length must be refused.");

        Assert.AreEqual(outstandingAfterTheRent - 1, trackingPool.OutstandingCount, "The refused adoption must release the rental before the exception leaves.");
    }

    /// <summary>
    /// <see cref="Tpm2bContextData.Dispose"/> is idempotent: a second call performs no further release and
    /// raises nothing, while the first call's release is observable through <c>ObjectDisposedException</c> on a
    /// later member access.
    /// </summary>
    [TestMethod]
    public void Tpm2bContextDataDisposeIsIdempotent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Tpm2bContextData data = Tpm2bContextData.Create([0x01, 0x02], pool);

        data.Dispose();
        data.Dispose();

        _ = Assert.ThrowsExactly<ObjectDisposedException>(
            () => data.Span.Length,
            "Reading Span after Dispose must throw, proving the first Dispose call actually released the storage and the second call raised nothing new.");
    }

    /// <summary>
    /// Parses a <c>TPM2B_CONTEXT_DATA</c> from a complete wire fragment and releases it, so a refusal can be
    /// asserted as a single expression (a <see cref="TpmReader"/> is a <see langword="ref"/> struct and cannot be
    /// captured by a lambda).
    /// </summary>
    /// <param name="wire">The wire fragment beginning at the size field.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    private static void ParseContextData(byte[] wire, BaseMemoryPool pool)
    {
        var reader = new TpmReader(wire);
        using Tpm2bContextData data = Tpm2bContextData.Parse(ref reader, pool);
    }
}
