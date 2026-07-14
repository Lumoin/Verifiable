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
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
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
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        const int requestedLength = 3;
        byte[] source = [0xAA, 0xBB, 0xCC];

        using PooledMemory pooledMemory = PooledMemory.FromBytes(source, pool, TestTag);

        Assert.AreEqual(requestedLength, pooledMemory.Length);
        Assert.AreEqual(requestedLength, pooledMemory.AsReadOnlySpan().Length);
        Assert.AreEqual(requestedLength, pooledMemory.AsReadOnlyMemory().Length);
        Assert.IsTrue(pooledMemory.AsReadOnlySpan().SequenceEqual(source));
    }


    /// <summary><see cref="PooledMemory.FromBytes"/> copies the source bytes rather than aliasing them: mutating the source after the call leaves the pooled copy unchanged.</summary>
    [TestMethod]
    public void FromBytesCopiesRatherThanAliasesSource()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
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
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

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
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        PooledMemory pooledMemory = PooledMemory.FromBytes([0x01, 0x02], pool, TestTag);

        pooledMemory.Dispose();
        pooledMemory.Dispose();
    }


    /// <summary>
    /// When copying into the rented buffer fails, <see cref="PooledMemory.FromBytes"/> disposes the
    /// rented storage before rethrowing rather than leaking it — the same buffer-protection
    /// <c>Verifiable.Apdu.ApduResponse.FromResponseBytes</c> establishes.
    /// </summary>
    [TestMethod]
    public void FromBytesDisposesRentedStorageWhenCopyFails()
    {
        using var pool = new UndersizedRentalMemoryPool();

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => PooledMemory.FromBytes([0x01, 0x02, 0x03], pool, TestTag));

        Assert.IsTrue(pool.LastRentedOwner!.WasDisposed,
            "The rented owner must be disposed when the copy into it fails, so no buffer leaks back to the caller undisposed.");
    }


    /// <summary>
    /// A test-only <see cref="MemoryPool{T}"/> whose rented owner's <see cref="IMemoryOwner{T}.Memory"/>
    /// is deliberately smaller than requested, forcing <see cref="Span{T}.CopyTo(Span{T})"/> to throw
    /// inside <see cref="PooledMemory.FromBytes"/> so its catch-dispose-rethrow path is exercised.
    /// </summary>
    private sealed class UndersizedRentalMemoryPool: MemoryPool<byte>
    {
        /// <summary>The most recently rented owner, exposed so the test can assert it was disposed.</summary>
        public TrackedMemoryOwner? LastRentedOwner { get; private set; }

        /// <inheritdoc />
        public override int MaxBufferSize => int.MaxValue;

        /// <inheritdoc />
        public override IMemoryOwner<byte> Rent(int minBufferSize = -1)
        {
            //One byte short of what the caller asked for, so the copy inside FromBytes overruns.
            int undersized = Math.Max(0, minBufferSize - 1);
            var owner = new TrackedMemoryOwner(undersized);
            LastRentedOwner = owner;

            return owner;
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
        }
    }


    /// <summary>A minimal <see cref="IMemoryOwner{T}"/> over a plain array that records whether it was disposed.</summary>
    private sealed class TrackedMemoryOwner: IMemoryOwner<byte>
    {
        private readonly byte[] buffer;

        /// <summary>Gets a value indicating whether <see cref="Dispose"/> has been called.</summary>
        public bool WasDisposed { get; private set; }

        /// <summary>
        /// Initializes a new tracked owner over a fresh array of the given size.
        /// </summary>
        /// <param name="size">The backing array's size.</param>
        public TrackedMemoryOwner(int size)
        {
            buffer = new byte[size];
        }

        /// <inheritdoc />
        public Memory<byte> Memory => buffer;

        /// <inheritdoc />
        public void Dispose()
        {
            WasDisposed = true;
        }
    }
}
