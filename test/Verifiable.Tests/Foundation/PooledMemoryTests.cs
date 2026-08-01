using System;
using System.Buffers;

namespace Verifiable.Tests.Foundation;

/// <summary>
/// Tests for <see cref="PooledMemory"/>, the pooled, disposable counterpart to <see cref="TaggedMemory{T}"/>.
/// </summary>
[TestClass]
internal sealed class PooledMemoryTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A dedicated tag distinct from any production tag, so assertions never coincide with a real buffer role by accident.</summary>
    private static Tag TestTag { get; } = Tag.Create((typeof(PooledMemoryTests), "test-buffer"));

    /// <summary>The ownership-transfer constructor round-trips exactly the bytes written into the rented storage, sliced to the tracked length.</summary>
    [TestMethod]
    public void ConstructorTransfersOwnershipAndTracksLength()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] source = [0x01, 0x02, 0x03, 0x04, 0x05];

        IMemoryOwner<byte> storage = pool.Rent(source.Length);
        source.CopyTo(storage.Memory.Span);

        using var pooledMemory = new PooledMemory(storage, source.Length, TestTag);

        Assert.AreEqual(source.Length, pooledMemory.Length);
        Assert.IsTrue(pooledMemory.AsReadOnlySpan().SequenceEqual(source));
        Assert.IsTrue(pooledMemory.AsReadOnlyMemory().Span.SequenceEqual(source));
        Assert.AreEqual(TestTag, pooledMemory.Tag);
    }


    /// <summary>
    /// <see cref="PooledMemory.AsReadOnlySpan"/> and <see cref="PooledMemory.AsReadOnlyMemory"/> slice
    /// to <see cref="PooledMemory.Length"/> even when the pool rents a larger backing buffer than requested.
    /// </summary>
    [TestMethod]
    public void AccessorsSliceToTrackedLengthNotRentedCapacity()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int requestedLength = 3;
        byte[] source = [0xAA, 0xBB, 0xCC];

        using PooledMemory pooledMemory = PooledMemory.FromBytes(source, pool, TestTag);

        Assert.AreEqual(requestedLength, pooledMemory.Length);
        Assert.HasCount(requestedLength, pooledMemory.AsReadOnlySpan());
        Assert.HasCount(requestedLength, pooledMemory.AsReadOnlyMemory());
        Assert.IsTrue(pooledMemory.AsReadOnlySpan().SequenceEqual(source));
    }


    /// <summary><see cref="PooledMemory.FromBytes"/> copies the source bytes rather than aliasing them: mutating the source after the call leaves the pooled copy unchanged.</summary>
    [TestMethod]
    public void FromBytesCopiesRatherThanAliasesSource()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] source = [0x10, 0x20, 0x30];

        using PooledMemory pooledMemory = PooledMemory.FromBytes(source, pool, TestTag);
        source[0] = 0xFF;

        Assert.AreEqual(0x10, pooledMemory.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// <see cref="PooledMemory.FromBytes"/> accepts an empty source and produces a zero-length carrier,
    /// even against a pool that rejects a zero-length rental request outright.
    /// </summary>
    [TestMethod]
    public void FromBytesAcceptsEmptySource()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using PooledMemory pooledMemory = PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, TestTag);

        Assert.AreEqual(0, pooledMemory.Length);
        Assert.IsTrue(pooledMemory.AsReadOnlySpan().IsEmpty);
    }


    /// <summary><see cref="PooledMemory.FromBytes"/> rejects a <see langword="null"/> pool before renting anything.</summary>
    [TestMethod]
    public void FromBytesThrowsOnNullPool()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(
            () => PooledMemory.FromBytes([0x01], null!, TestTag));
    }


    /// <summary>Disposing a <see cref="PooledMemory"/> returns the buffer to the pool and is idempotent (a second call must not throw), per <see cref="SensitiveMemory"/>'s own contract.</summary>
    [TestMethod]
    public void DisposeIsIdempotent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        PooledMemory pooledMemory = PooledMemory.FromBytes([0x01, 0x02], pool, TestTag);

        pooledMemory.Dispose();
        pooledMemory.Dispose();
    }


    /// <summary>
    /// The undersized-rental negative that used to live here — a misbehaving <see cref="MemoryPool{T}"/>
    /// whose rentals came up one byte short, driving <see cref="PooledMemory.FromBytes"/>'s
    /// catch-dispose-rethrow path — is unrepresentable since the surface takes
    /// <see cref="BaseMemoryPool"/>: the type is sealed and its rentals are exact-length by its own
    /// contract, so the overrun cannot be assembled through any pool a caller can supply. The production
    /// path remains as defense in depth.
    /// </summary>
    [TestMethod]
    public void FromBytesRequiresTheHousePoolByType()
    {
        //The compile-time shape is the assertion: the parameter is the house pool, not the abstract
        //MemoryPool<byte> seam, so the exact-length and zero-on-return guarantees ride along by type.
        using PooledMemory pooledMemory = PooledMemory.FromBytes([0x01], BaseMemoryPool.Shared, TestTag);

        Assert.AreEqual(1, pooledMemory.Length);
    }
}
