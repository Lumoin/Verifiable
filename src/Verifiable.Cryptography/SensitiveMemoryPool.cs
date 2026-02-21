using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Threading;

namespace Verifiable.Cryptography
{
    /// <summary>
    /// Determines the number of segments to allocate per slab based on segment size.
    /// </summary>
    /// <param name="segmentSize">The size of each segment in elements.</param>
    /// <returns>The number of segments to allocate in the new slab.</returns>
    public delegate int SlabCapacityStrategy(int segmentSize);


    /// <summary>
    /// A thread-safe memory pool designed for cryptographic operations that returns memory
    /// of exactly the requested size. The pool automatically creates size-specific internal
    /// sub-pools to optimize allocation patterns for different buffer sizes commonly used
    /// in cryptographic operations.
    /// </summary>
    /// <typeparam name="T">The type of memory elements to be reserved, typically <see cref="byte"/>.</typeparam>
    /// <remarks>
    /// <para>
    /// This memory pool is specifically designed for sensitive cryptographic material where:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description>Exact buffer sizes are required (no over-allocation).</description>
    /// </item>
    /// <item>
    /// <description>Memory is automatically cleared on disposal for security.</description>
    /// </item>
    /// <item>
    /// <description>Size-specific pooling optimizes for common crypto buffer sizes.</description>
    /// </item>
    /// <item>
    /// <description>Comprehensive metrics and tracing support operational monitoring.</description>
    /// </item>
    /// <item>
    /// <description>Thread-safe operations support concurrent cryptographic operations.</description>
    /// </item>
    /// </list>
    /// <para>
    /// The pool maintains separate collections of slabs for each requested buffer size,
    /// ensuring that buffers of different sizes never interfere with each other and
    /// allowing for size-specific optimization strategies.
    /// </para>
    /// <para>
    /// Slab capacity is determined by a <see cref="SlabCapacityStrategy"/> delegate,
    /// allowing callers to tune amortization. The default strategy allocates more segments
    /// for smaller buffers (common key/hash sizes) and fewer for larger buffers.
    /// </para>
    /// </remarks>
    [DebuggerDisplay("SensitiveMemoryPool<{typeof(T).Name,nq}>: Slabs={totalSlabs}, Active={activeRentals}, Allocated={totalMemoryAllocated} bytes")]
    public class SensitiveMemoryPool<T>: MemoryPool<T>
    {
        /// <summary>
        /// Dictionary mapping buffer sizes to their corresponding slab collections.
        /// Each size gets its own list of slabs to prevent cross-contamination and
        /// enable size-specific allocation strategies.
        /// </summary>
        private Dictionary<int, List<Slab<T>>> Slabs { get; } = new();

        /// <summary>
        /// Indicates whether this memory pool instance has been disposed.
        /// </summary>
        private bool IsDisposed { get; set; }

        /// <summary>
        /// Lock object for synchronizing access to the slabs dictionary and metrics.
        /// </summary>
        private Lock LockObject { get; } = new();

        /// <summary>
        /// Activity source for distributed tracing of memory operations.
        /// </summary>
        private static ActivitySource ActivitySource { get; } = new("SensitiveMemoryPool");

        /// <summary>
        /// Diagnostic source for detailed operational logging and debugging.
        /// </summary>
        private static DiagnosticSource DiagnosticSource { get; } = new DiagnosticListener("SensitiveMemoryPool");

        /// <summary>
        /// Meter instance for collecting and reporting memory pool metrics.
        /// </summary>
        private Meter PoolMeter { get; }

        /// <summary>
        /// Histogram tracking the distribution of requested buffer sizes.
        /// </summary>
        private Histogram<int> BufferSizeHistogram { get; }

        /// <summary>
        /// Counter tracking successful rent operations.
        /// </summary>
        private Counter<long> RentSuccessCounter { get; }

        /// <summary>
        /// Counter tracking memory return operations.
        /// </summary>
        private Counter<long> ReturnCounter { get; }

        /// <summary>
        /// Strategy for determining slab capacity based on segment size.
        /// </summary>
        private SlabCapacityStrategy CapacityStrategy { get; }

        /// <summary>
        /// Controls whether distributed tracing activities are created for memory operations.
        /// Disable for high-frequency cryptographic workloads where tracing overhead is unacceptable.
        /// </summary>
        public bool TracingEnabled { get; }

        /// <summary>
        /// Thread-safe counter for the total number of slabs created.
        /// </summary>
        private int totalSlabs;

        /// <summary>
        /// Thread-safe counter for the total memory allocated in bytes.
        /// </summary>
        private long totalMemoryAllocated;

        /// <summary>
        /// Thread-safe counter for the number of currently active rentals.
        /// </summary>
        private int activeRentals;

        /// <summary>
        /// Thread-safe counter for the total number of segments across all slabs.
        /// </summary>
        private int totalSegments;

        /// <summary>
        /// Default initial capacity for new slabs when no allocation strategy is specified.
        /// </summary>
        public const int DefaultInitialSlabCapacity = 4;


        /// <summary>
        /// Default strategy that allocates more segments for smaller buffers
        /// and fewer for larger ones, tuned for common cryptographic material sizes.
        /// </summary>
        /// <param name="segmentSize">The size of each segment in elements.</param>
        /// <returns>The number of segments to allocate in the new slab.</returns>
        /// <example>
        /// <code>
        /// //Use the default strategy explicitly.
        /// var pool = new SensitiveMemoryPool&lt;byte&gt;(
        ///     capacityStrategy: SensitiveMemoryPool&lt;byte&gt;.DefaultCapacityStrategy);
        /// </code>
        /// </example>
        public static int DefaultCapacityStrategy(int segmentSize) => segmentSize switch
        {
            <= 64 => 32,
            <= 256 => 16,
            <= 4096 => 8,
            _ => 4
        };


        /// <summary>
        /// Lazy singleton backing the <see cref="Shared"/> property.
        /// </summary>
        private static readonly Lazy<SensitiveMemoryPool<T>> SharedInstance =
            new(() => new SensitiveMemoryPool<T>());

        /// <summary>
        /// Gets a shared singleton instance of the memory pool.
        /// </summary>
        /// <value>A singleton instance of memory pool for cryptographic material.</value>
        /// <remarks>
        /// Unlike the base <see cref="MemoryPool{T}.Shared"/>, this returns a lazily-initialized
        /// singleton so that callers who expect shared-state semantics get correct behavior.
        /// The shared instance uses the default capacity strategy and has tracing enabled.
        /// </remarks>
        public static new SensitiveMemoryPool<T> Shared => SharedInstance.Value;


        /// <summary>
        /// Initializes a new instance with default settings.
        /// </summary>
        public SensitiveMemoryPool()
            : this(new Meter(CryptographyMetrics.MeterName, "1.0.0"))
        {
        }


        /// <summary>
        /// Initializes a new instance with the specified meter.
        /// </summary>
        /// <param name="meter">The meter instance for collecting operational metrics.</param>
        /// <param name="capacityStrategy">
        /// Optional strategy for determining slab capacity. When <see langword="null"/>,
        /// <see cref="DefaultCapacityStrategy"/> is used.
        /// </param>
        /// <param name="tracingEnabled">
        /// When <see langword="true"/>, distributed tracing activities are created for
        /// rent and return operations. Disable for high-frequency workloads.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="meter"/> is null.</exception>
        public SensitiveMemoryPool(
            Meter meter,
            SlabCapacityStrategy? capacityStrategy = null,
            bool tracingEnabled = true)
        {
            ArgumentNullException.ThrowIfNull(meter);

            PoolMeter = meter;
            CapacityStrategy = capacityStrategy ?? DefaultCapacityStrategy;
            TracingEnabled = tracingEnabled;
            IsDisposed = false;

            //Initialize observable counters for automatic metric collection.
            meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolTotalSlabs,
                () => totalSlabs,
                "slabs",
                "Total number of memory slabs created across all buffer sizes.");

            meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolTotalMemoryAllocated,
                () => totalMemoryAllocated,
                "bytes",
                "Total memory allocated across all slabs including available segments.");

            meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolActiveRentals,
                () => activeRentals,
                "segments",
                "Number of currently rented memory segments.");

            meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolAllocationEfficiency,
                CalculateAllocationEfficiency,
                "percent",
                "Percentage of allocated memory currently in use.");

            BufferSizeHistogram = meter.CreateHistogram<int>(
                CryptographyMetrics.SensitiveMemoryPoolBufferSizeDistribution,
                "bytes",
                "Distribution of requested buffer sizes.");

            RentSuccessCounter = meter.CreateCounter<long>(
                CryptographyMetrics.SensitiveMemoryPoolRentOperationsTotal,
                "operations",
                "Total number of successful rent operations.");

            ReturnCounter = meter.CreateCounter<long>(
                CryptographyMetrics.SensitiveMemoryPoolReturnOperationsTotal,
                "operations",
                "Total number of memory return operations.");
        }


        /// <summary>
        /// Gets the maximum buffer size that this pool can allocate.
        /// </summary>
        public override int MaxBufferSize => int.MaxValue;


        /// <summary>
        /// Rents a memory buffer of exactly the specified size from the pool.
        /// </summary>
        /// <param name="bufferSize">The exact number of elements required in the buffer.</param>
        /// <returns>
        /// An <see cref="IMemoryOwner{T}"/> that provides access to the rented memory.
        /// The returned memory will be exactly <paramref name="bufferSize"/> elements.
        /// </returns>
        /// <exception cref="ObjectDisposedException">Thrown when the pool has been disposed.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="bufferSize"/> is less than or equal to zero.</exception>
        /// <remarks>
        /// <para>
        /// This method is thread-safe and will automatically create size-specific slabs
        /// as needed. The returned memory is guaranteed to be exactly the requested size,
        /// unlike some memory pools that may return larger buffers for efficiency.
        /// </para>
        /// <para>
        /// A single tracing activity spans the full rental lifecycle from rent to return.
        /// The activity records buffer size tags and a return event upon disposal.
        /// Tracing can be disabled via <see cref="TracingEnabled"/> for hot paths.
        /// </para>
        /// </remarks>
        [SuppressMessage("Naming", "CA1725:Parameter names should match base declaration", Justification = "This memory pool returns buffers of the specified size.")]
        public override IMemoryOwner<T> Rent(int bufferSize)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);

            if(bufferSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bufferSize),
                    "Buffer size must be greater than zero.");
            }

            //Single activity spans the entire rental lifecycle from rent to return.
            //Ownership is transferred to ExactSizeMemoryOwner which disposes it on return.
            //StartActivity sets Activity.Current to the new activity. This is the intended
            //behavior: the lifecycle activity is the ambient context during the rental scope.
            //When ExactSizeMemoryOwner.Dispose calls LifecycleActivity.Dispose, Activity.Stop
            //automatically restores Activity.Current to its parent.
            Activity? activity = TracingEnabled
                ? ActivitySource.StartActivity("Rent", ActivityKind.Internal,
                    Activity.Current?.Context ?? default)
                : null;

            activity?.AddTag("bufferSize", bufferSize.ToString(CultureInfo.InvariantCulture));
            activity?.AddTag("poolType", typeof(T).Name);

            if(DiagnosticSource.IsEnabled("Rent.Start"))
            {
                DiagnosticSource.Write("Rent.Start", new { bufferSize, poolType = typeof(T).Name });
            }

            BufferSizeHistogram.Record(bufferSize);

            IMemoryOwner<T> result;

            using(LockObject.EnterScope())
            {
                if(!Slabs.TryGetValue(bufferSize, out List<Slab<T>>? slabList))
                {
                    slabList = new List<Slab<T>>();
                    Slabs.Add(bufferSize, slabList);
                }

                Slab<T>? availableSlab = null;
                ArraySegment<T> rentedSegment = default;

                foreach(var slab in slabList)
                {
                    if(slab.TryRent(out rentedSegment))
                    {
                        availableSlab = slab;
                        break;
                    }
                }

                if(availableSlab is null)
                {
                    int capacity = CapacityStrategy(bufferSize);
                    availableSlab = new Slab<T>(bufferSize, capacity);
                    slabList.Add(availableSlab);

                    Interlocked.Increment(ref totalSlabs);
                    Interlocked.Add(ref totalMemoryAllocated, bufferSize * capacity);
                    Interlocked.Add(ref totalSegments, capacity);

                    bool rentSuccess = availableSlab.TryRent(out rentedSegment);
                    Debug.Assert(rentSuccess, "New slab should always have available capacity.");
                }

                Interlocked.Increment(ref activeRentals);

                result = new ExactSizeMemoryOwner<T>(rentedSegment, availableSlab, this, activity);
            }

            RentSuccessCounter.Add(1, new KeyValuePair<string, object?>("bufferSize", bufferSize));

            if(DiagnosticSource.IsEnabled("Rent.Stop"))
            {
                DiagnosticSource.Write("Rent.Stop", new { bufferSize, success = true });
            }

            return result;
        }


        /// <summary>
        /// Releases all slabs that have no active rentals, reclaiming their memory.
        /// </summary>
        /// <returns>The number of slabs reclaimed.</returns>
        /// <remarks>
        /// <para>
        /// Call this method periodically in long-running services to return unused memory
        /// to the operating system. Slabs that still have rented segments are left untouched.
        /// </para>
        /// <para>
        /// This operation acquires the pool lock for the duration of the trim. Avoid
        /// calling it on hot paths.
        /// </para>
        /// </remarks>
        public int TrimExcess()
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);

            int reclaimed = 0;

            using(LockObject.EnterScope())
            {
                foreach(var slabList in Slabs.Values)
                {
                    for(int i = slabList.Count - 1; i >= 0; i--)
                    {
                        var slab = slabList[i];
                        if(slab.IsFull)
                        {
                            int segmentCount = slab.SegmentCount;
                            int segmentSize = slab.SegmentSize;

                            slab.Dispose();
                            slabList.RemoveAt(i);

                            Interlocked.Decrement(ref totalSlabs);
                            Interlocked.Add(ref totalMemoryAllocated, -(long)(segmentSize * segmentCount));
                            Interlocked.Add(ref totalSegments, -segmentCount);
                            reclaimed++;
                        }
                    }
                }
            }

            return reclaimed;
        }


        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if(!IsDisposed)
            {
                if(disposing)
                {
                    using(LockObject.EnterScope())
                    {
                        foreach(var slabList in Slabs.Values)
                        {
                            foreach(var slab in slabList)
                            {
                                slab.Dispose();
                            }
                        }
                        Slabs.Clear();

                        totalSlabs = 0;
                        totalMemoryAllocated = 0;
                        activeRentals = 0;
                        totalSegments = 0;
                    }

                    PoolMeter?.Dispose();
                }

                IsDisposed = true;
            }
        }


        /// <summary>
        /// Returns a previously rented memory segment to its originating slab.
        /// </summary>
        /// <param name="segment">The memory segment to return to the pool.</param>
        /// <param name="slab">The slab that originally provided the segment.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="slab"/> is null.</exception>
        internal void Return(ArraySegment<T> segment, Slab<T> slab)
        {
            ArgumentNullException.ThrowIfNull(slab);

            using(LockObject.EnterScope())
            {
                //Clear the memory segment for security before returning.
                segment.AsSpan().Clear();
                slab.Return(segment);
                Interlocked.Decrement(ref activeRentals);
                ReturnCounter.Add(1);
            }

            if(DiagnosticSource.IsEnabled("Return.Complete"))
            {
                DiagnosticSource.Write("Return.Complete", new
                {
                    segmentOffset = segment.Offset,
                    segmentCount = segment.Count
                });
            }
        }


        /// <summary>
        /// Calculates the current allocation efficiency as a percentage.
        /// </summary>
        private double CalculateAllocationEfficiency()
        {
            int currentTotalSegments = totalSegments;
            int currentActiveRentals = activeRentals;

            if(currentTotalSegments == 0)
            {
                return 0.0;
            }

            return (double)currentActiveRentals / currentTotalSegments * 100.0;
        }


        /// <summary>
        /// Represents a contiguous block of memory divided into fixed-size segments.
        /// Each slab manages segments of a specific size and tracks their availability
        /// using a <see cref="BitArray"/> to prevent double-return vulnerabilities.
        /// </summary>
        /// <typeparam name="TElement">The type of elements stored in the slab.</typeparam>
        [DebuggerDisplay("Slab<{typeof(TElement).Name,nq}>: SegmentSize={SegmentSize}, Available={AvailableSegments.Count}/{SegmentCount}")]
        internal class Slab<TElement>: IDisposable
        {
            /// <summary>
            /// The size of each segment in this slab, measured in number of elements.
            /// </summary>
            public int SegmentSize { get; }

            /// <summary>
            /// The total number of segments that this slab can provide.
            /// </summary>
            public int SegmentCount { get; }

            /// <summary>
            /// The underlying memory buffer that contains all segments.
            /// </summary>
            private TElement[] Buffer { get; }

            /// <summary>
            /// Stack tracking the indices of available segments for O(1) allocation.
            /// </summary>
            private Stack<int> AvailableSegments { get; }

            /// <summary>
            /// Tracks which segments are currently rented. A set bit at position N means
            /// segment N is rented. This prevents double-return corruption of the stack.
            /// </summary>
            private BitArray RentedSegments { get; }

            /// <summary>
            /// Indicates whether this slab has been disposed.
            /// </summary>
            private bool IsDisposed { get; set; }


            /// <summary>
            /// Initializes a new slab with the specified segment size and count.
            /// </summary>
            /// <param name="segmentSize">The size of each segment in elements.</param>
            /// <param name="segmentCount">The number of segments to create in this slab.</param>
            /// <exception cref="ArgumentOutOfRangeException">
            /// Thrown when <paramref name="segmentSize"/> or <paramref name="segmentCount"/> is less than or equal to zero.
            /// </exception>
            public Slab(int segmentSize, int segmentCount)
            {
                if(segmentSize <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(segmentSize),
                        "Segment size must be greater than zero.");
                }
                if(segmentCount <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(segmentCount),
                        "Segment count must be greater than zero.");
                }

                SegmentSize = segmentSize;
                SegmentCount = segmentCount;
                Buffer = new TElement[segmentSize * segmentCount];
                RentedSegments = new BitArray(segmentCount, false);

                AvailableSegments = new Stack<int>(segmentCount);
                for(int i = 0; i < segmentCount; i++)
                {
                    AvailableSegments.Push(i);
                }

                IsDisposed = false;
            }

            /// <summary>
            /// Gets a value indicating whether all segments in this slab are available
            /// (none are currently rented).
            /// </summary>
            public bool IsFull => AvailableSegments.Count == SegmentCount;

            /// <summary>
            /// Gets a value indicating whether any segments are available for rent.
            /// </summary>
            public bool HasAvailableSegments => AvailableSegments.Count > 0;


            /// <summary>
            /// Attempts to rent a segment from this slab.
            /// </summary>
            /// <param name="segment">
            /// When this method returns, contains the rented segment if successful;
            /// otherwise, the default value.
            /// </param>
            /// <returns>
            /// <see langword="true"/> if a segment was successfully rented;
            /// otherwise, <see langword="false"/>.
            /// </returns>
            public bool TryRent(out ArraySegment<TElement> segment)
            {
                if(IsDisposed)
                {
                    segment = default;
                    return false;
                }

                if(AvailableSegments.TryPop(out int segmentIndex))
                {
                    Debug.Assert(!RentedSegments[segmentIndex],
                        "Segment popped from available stack should not already be marked as rented.");

                    RentedSegments[segmentIndex] = true;
                    int offset = segmentIndex * SegmentSize;
                    segment = new ArraySegment<TElement>(Buffer, offset, SegmentSize);
                    return true;
                }

                segment = default;
                return false;
            }


            /// <summary>
            /// Returns a previously rented segment to this slab.
            /// </summary>
            /// <param name="segment">The segment to return.</param>
            /// <exception cref="ArgumentException">
            /// Thrown when the segment does not belong to this slab, has invalid parameters,
            /// or was not currently rented (double-return protection).
            /// </exception>
            /// <exception cref="ObjectDisposedException">Thrown when the slab has been disposed.</exception>
            public void Return(ArraySegment<TElement> segment)
            {
                ObjectDisposedException.ThrowIf(IsDisposed, nameof(Slab<TElement>));

                if(segment.Array != Buffer)
                {
                    throw new ArgumentException("Segment does not belong to this slab.", nameof(segment));
                }

                if(segment.Count != SegmentSize)
                {
                    throw new ArgumentException("Segment size does not match slab segment size.", nameof(segment));
                }

                int segmentIndex = segment.Offset / SegmentSize;

                if(segment.Offset % SegmentSize != 0 || segmentIndex >= SegmentCount)
                {
                    throw new ArgumentException("Invalid segment offset for this slab.", nameof(segment));
                }

                //Double-return protection: verify the segment is actually rented.
                if(!RentedSegments[segmentIndex])
                {
                    throw new InvalidOperationException(
                        "Segment was not rented or has already been returned.");
                }

                RentedSegments[segmentIndex] = false;
                AvailableSegments.Push(segmentIndex);
            }


            /// <summary>
            /// Releases all resources used by this slab and clears its memory.
            /// </summary>
            public void Dispose()
            {
                if(!IsDisposed)
                {
                    Array.Clear(Buffer);
                    AvailableSegments.Clear();
                    IsDisposed = true;
                }
            }
        }


        /// <summary>
        /// Provides ownership of a memory segment rented from a <see cref="SensitiveMemoryPool{T}"/>.
        /// Automatically returns the memory to the pool when disposed and ensures sensitive data is cleared.
        /// </summary>
        /// <typeparam name="TOwner">The type of elements in the memory segment.</typeparam>
        /// <remarks>
        /// <para>
        /// A single tracing activity spans the full rental lifecycle. On disposal, a return
        /// event is recorded on the activity and then the activity is stopped and disposed.
        /// This eliminates the need to manipulate <see cref="Activity.Current"/> and avoids
        /// async context pollution.
        /// </para>
        /// </remarks>
        [DebuggerDisplay("ExactSizeMemoryOwner<{typeof(TOwner).Name,nq}>: Size={Segment.Count}, Disposed={Disposed}")]
        private class ExactSizeMemoryOwner<TOwner>: IMemoryOwner<TOwner>
        {
            /// <summary>
            /// Activity tracking the full rental lifecycle from rent to return.
            /// Null when tracing is disabled or no listener is attached.
            /// </summary>
            private Activity? LifecycleActivity { get; }

            private ArraySegment<TOwner> Segment { get; }

            private SensitiveMemoryPool<TOwner>.Slab<TOwner> Slab { get; }

            private SensitiveMemoryPool<TOwner> Pool { get; }

            private bool Disposed { get; set; }


            /// <summary>
            /// Initializes a new instance managing the given segment.
            /// </summary>
            /// <param name="segment">The memory segment to manage.</param>
            /// <param name="slab">The slab that provided the segment.</param>
            /// <param name="pool">The memory pool that owns the slab.</param>
            /// <param name="lifecycleActivity">
            /// The activity tracking this rental. Ownership is transferred to this instance.
            /// </param>
            /// <exception cref="InvalidOperationException">
            /// Thrown when the segment is invalid or has no backing array.
            /// </exception>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="slab"/> or <paramref name="pool"/> is null.
            /// </exception>
            public ExactSizeMemoryOwner(
                ArraySegment<TOwner> segment,
                SensitiveMemoryPool<TOwner>.Slab<TOwner> slab,
                SensitiveMemoryPool<TOwner> pool,
                Activity? lifecycleActivity)
            {
                if(segment.Array is null || segment.Count == 0)
                {
                    throw new InvalidOperationException("Failed to rent a valid memory segment.");
                }

                ArgumentNullException.ThrowIfNull(slab);
                ArgumentNullException.ThrowIfNull(pool);

                Segment = segment;
                Slab = slab;
                Pool = pool;
                LifecycleActivity = lifecycleActivity;
                Disposed = false;
            }


            /// <summary>
            /// Gets the memory managed by this owner.
            /// </summary>
            /// <exception cref="ObjectDisposedException">Thrown when this owner has been disposed.</exception>
            public Memory<TOwner> Memory
            {
                get
                {
                    ObjectDisposedException.ThrowIf(Disposed, nameof(ExactSizeMemoryOwner<TOwner>));
                    return Segment;
                }
            }


            /// <summary>
            /// Returns the managed memory to the pool and clears it for security.
            /// The lifecycle activity is finalized with a return event and then disposed.
            /// </summary>
            /// <remarks>
            /// If the pool or slab has already been disposed (e.g. during application shutdown),
            /// the return operation fails gracefully. The lifecycle activity records an error
            /// status but no exception propagates, since throwing from Dispose causes cascading
            /// failures in <see langword="finally"/> blocks.
            /// </remarks>
            public void Dispose()
            {
                if(!Disposed)
                {
                    try
                    {
                        LifecycleActivity?.AddEvent(new ActivityEvent("Return", tags: new ActivityTagsCollection
                        {
                            { "segmentSize", Segment.Count },
                            { "segmentOffset", Segment.Offset }
                        }));

                        Pool.Return(Segment, Slab);
                        LifecycleActivity?.SetStatus(ActivityStatusCode.Ok);
                    }
                    catch(ObjectDisposedException ex)
                    {
                        //The pool or slab was disposed before this rental was returned.
                        //This is expected during shutdown or when the pool is disposed
                        //while rentals are still outstanding.
                        LifecycleActivity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                    }
                    catch(Exception ex)
                    {
                        LifecycleActivity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                        throw;
                    }
                    finally
                    {
                        LifecycleActivity?.Dispose();
                        Disposed = true;
                    }
                }
            }
        }
    }
}