using System;
using System.Buffers;
using System.Collections.Generic;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// A <see cref="MemoryPool{T}"/> decorator over <see cref="BaseMemoryPool.Shared"/> that records, for
/// every rented owner whose requested size equals <see cref="TrackedSize"/>, whether that owner's memory
/// was all-zero at the moment <see cref="IDisposable.Dispose"/> was called on it — the observable proof,
/// through whichever pool-seam parameter a production call site already takes, that a pooled buffer was
/// cleared before returning to the pool, without any test-only hook added to production code.
/// </summary>
internal sealed class ZeroOnDisposeTrackingMemoryPool: MemoryPool<byte>
{
    /// <summary>The rented buffer size this pool observes; rentals of any other size pass through untracked.</summary>
    private int TrackedSize { get; }

    /// <summary>Whether each tracked-size owner's memory was all-zero at dispose time, in rental order.</summary>
    private List<bool> DisposalWasZero { get; } = [];

    /// <summary>Gets how many tracked-size owners have been disposed so far.</summary>
    public int TrackedDisposalCount => DisposalWasZero.Count;

    /// <summary>Gets whether every tracked-size owner disposed so far was all-zero at dispose time.</summary>
    public bool AllTrackedDisposalsWereZero => DisposalWasZero.TrueForAll(static wasZero => wasZero);

    /// <inheritdoc />
    public override int MaxBufferSize => BaseMemoryPool.Shared.MaxBufferSize;

    /// <summary>Initializes a new tracking pool over <see cref="BaseMemoryPool.Shared"/> for the given tracked rental size.</summary>
    /// <param name="trackedSize">The rented buffer size to observe dispose-time zeroing for.</param>
    public ZeroOnDisposeTrackingMemoryPool(int trackedSize)
    {
        TrackedSize = trackedSize;
    }

    /// <inheritdoc />
    public override IMemoryOwner<byte> Rent(int minBufferSize = -1)
    {
        IMemoryOwner<byte> inner = BaseMemoryPool.Shared.Rent(minBufferSize);

        return minBufferSize == TrackedSize
            ? new TrackedOwner(inner, DisposalWasZero)
            : inner;
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
    }

    /// <summary>A decorator that records whether its wrapped owner's memory was all-zero right before forwarding <see cref="Dispose"/> to it.</summary>
    private sealed class TrackedOwner: IMemoryOwner<byte>
    {
        /// <summary>The wrapped pooled owner.</summary>
        private readonly IMemoryOwner<byte> inner;

        /// <summary>The list this owner's zero-at-dispose observation is appended to.</summary>
        private readonly List<bool> sink;

        /// <summary>Wraps <paramref name="inner"/>, appending its zero-at-dispose observation to <paramref name="sink"/> when disposed.</summary>
        /// <param name="inner">The wrapped pooled owner.</param>
        /// <param name="sink">The list this owner's zero-at-dispose observation is appended to.</param>
        public TrackedOwner(IMemoryOwner<byte> inner, List<bool> sink)
        {
            this.inner = inner;
            this.sink = sink;
        }

        /// <inheritdoc />
        public Memory<byte> Memory => inner.Memory;

        /// <inheritdoc />
        public void Dispose()
        {
            sink.Add(inner.Memory.Span.IndexOfAnyExcept((byte)0) < 0);
            inner.Dispose();
        }
    }
}
