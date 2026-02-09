using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Threading;

namespace Verifiable.Cryptography
{
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
    /// <description>Exact buffer sizes are required (no over-allocation)</description>
    /// </item>
    /// <item>
    /// <description>Memory is automatically cleared on disposal for security</description>
    /// </item>
    /// <item>
    /// <description>Size-specific pooling optimizes for common crypto buffer sizes</description>
    /// </item>
    /// <item>
    /// <description>Comprehensive metrics and tracing support operational monitoring</description>
    /// </item>
    /// <item>
    /// <description>Thread-safe operations support concurrent cryptographic operations</description>
    /// </item>
    /// </list>
    /// <para>
    /// The pool maintains separate collections of slabs for each requested buffer size,
    /// ensuring that buffers of different sizes never interfere with each other and
    /// allowing for size-specific optimization strategies in the future.
    /// </para>
    /// </remarks>
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
        /// Used to prevent operations on disposed instances.
        /// </summary>
        private bool IsDisposed { get; set; }

        /// <summary>
        /// Lock object for synchronizing access to the slabs dictionary and metrics.
        /// Uses the new Lock type for improved performance and explicit locking semantics.
        /// </summary>
        private Lock LockObject { get; } = new();

        /// <summary>
        /// Activity source for distributed tracing of memory operations.
        /// Enables tracking of rent and return operations across service boundaries.
        /// </summary>
        private static ActivitySource ActivitySource { get; } = new("SensitiveMemoryPool");

        /// <summary>
        /// Diagnostic source for detailed operational logging and debugging.
        /// Provides fine-grained insights into memory pool operations.
        /// </summary>
        private static DiagnosticSource DiagnosticSource { get; } = new DiagnosticListener("SensitiveMemoryPool");

        /// <summary>
        /// Meter instance for collecting and reporting memory pool metrics.
        /// Provides operational insights for monitoring and alerting.
        /// </summary>
        private Meter PoolMeter { get; }

        /// <summary>
        /// Histogram tracking the distribution of requested buffer sizes.
        /// Helps identify optimization opportunities for common sizes.
        /// </summary>
        private Histogram<int> BufferSizeHistogram { get; }

        /// <summary>
        /// Counter tracking successful rent operations.
        /// Used for calculating allocation rates and success metrics.
        /// </summary>
        private Counter<long> RentSuccessCounter { get; }

        /// <summary>
        /// Counter tracking memory return operations.
        /// Should correlate with rent operations for proper resource management.
        /// </summary>
        private Counter<long> ReturnCounter { get; }

        /// <summary>
        /// Thread-safe counter for the total number of slabs created.
        /// Updated atomically to ensure accuracy in multi-threaded scenarios.
        /// </summary>
        private int totalSlabs;

        /// <summary>
        /// Thread-safe counter for the total memory allocated in bytes.
        /// Includes all memory in all slabs, both used and available.
        /// </summary>
        private long totalMemoryAllocated;

        /// <summary>
        /// Thread-safe counter for the number of currently active rentals.
        /// Decremented when memory is returned to the pool.
        /// </summary>
        private int activeRentals;

        /// <summary>
        /// Thread-safe counter for the total number of segments across all slabs.
        /// Used for calculating allocation efficiency metrics.
        /// </summary>
        private int totalSegments;

        /// <summary>
        /// Default initial capacity for new slabs when no allocation strategy is specified.
        /// This value represents a balance between memory usage and allocation overhead
        /// for typical cryptographic operations.
        /// </summary>
        public const int InitialSlabCapacity = 4;

        /// <summary>
        /// Initializes a new instance of the <see cref="SensitiveMemoryPool{T}"/> class
        /// with default meter configuration.
        /// </summary>
        public SensitiveMemoryPool() : this(new Meter(CryptographyMetrics.MeterName, "1.0.0"))
        {
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="SensitiveMemoryPool{T}"/> class
        /// with the specified meter for metrics collection.
        /// </summary>
        /// <param name="meter">The meter instance for collecting operational metrics.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="meter"/> is null.</exception>
        public SensitiveMemoryPool(Meter meter)
        {
            ArgumentNullException.ThrowIfNull(meter);

            PoolMeter = meter;
            IsDisposed = false;

            //Initialize observable counters for automatic metric collection.
            ObservableUpDownCounter<int> observableUpDownCounter3 = meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolTotalSlabs,
                () => totalSlabs,
                "slabs",
                "Total number of memory slabs created across all buffer sizes");

            ObservableUpDownCounter<long> observableUpDownCounter2 = meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolTotalMemoryAllocated,
                () => totalMemoryAllocated,
                "bytes",
                "Total memory allocated across all slabs including available segments");

            ObservableUpDownCounter<int> observableUpDownCounter1 = meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolActiveRentals,
                () => activeRentals,
                "segments",
                "Number of currently rented memory segments");

            ObservableUpDownCounter<double> observableUpDownCounter = meter.CreateObservableUpDownCounter(
                CryptographyMetrics.SensitiveMemoryPoolAllocationEfficiency,
                CalculateAllocationEfficiency,
                "percent",
                "Percentage of allocated memory currently in use");

            //Initialize counters and histograms that we actively use.
            BufferSizeHistogram = meter.CreateHistogram<int>(
                CryptographyMetrics.SensitiveMemoryPoolBufferSizeDistribution,
                "bytes",
                "Distribution of requested buffer sizes");

            RentSuccessCounter = meter.CreateCounter<long>(
                CryptographyMetrics.SensitiveMemoryPoolRentOperationsTotal,
                "operations",
                "Total number of successful rent operations");

            ReturnCounter = meter.CreateCounter<long>(
                CryptographyMetrics.SensitiveMemoryPoolReturnOperationsTotal,
                "operations",
                "Total number of memory return operations");
        }


        /// <summary>
        /// Gets a singleton instance of a memory pool based on arrays.
        /// </summary>
        /// <value>A singleton instance of memory pool for cryptographic material.</value>
        /// <remarks>
        /// This property creates a new instance each time it's accessed, which is intentional
        /// to avoid sharing state between different parts of an application. For shared usage,
        /// consider creating and managing a single instance explicitly.
        /// </remarks>
        public static new SensitiveMemoryPool<T> Shared => new();

        /// <summary>
        /// Gets the maximum buffer size that this pool can allocate.
        /// </summary>
        /// <value>The maximum buffer size in elements, which is <see cref="int.MaxValue"/>.</value>
        /// <remarks>
        /// While the theoretical maximum is <see cref="int.MaxValue"/>, practical limitations
        /// may apply based on available system memory and the specific allocation strategy.
        /// </remarks>
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
        /// This method is thread-safe and will automatically create size-specific slabs
        /// as needed. The returned memory is guaranteed to be exactly the requested size,
        /// unlike some memory pools that may return larger buffers for efficiency.
        ///
        /// The rented memory will be automatically cleared when disposed, ensuring that
        /// sensitive cryptographic material does not remain in memory.
        /// </remarks>
        [SuppressMessage("Naming", "CA1725:Parameter names should match base declaration", Justification = "This memorypool returns buffers on the specificed size.")]
        public override IMemoryOwner<T> Rent(int bufferSize)
        {
            //Validate preconditions before proceeding with allocation.
            ObjectDisposedException.ThrowIf(IsDisposed, this);

            if(bufferSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bufferSize),
                    "Buffer size must be greater than zero.");
            }

            //Create tracing activity for this rent operation.
            //IMPORTANT: Do NOT use 'using' here - the activity ownership is transferred to ExactSizeMemoryOwner.
            var activity = ActivitySource.StartActivity("Rent", ActivityKind.Internal,
                Activity.Current?.Context ?? default);
            activity?.AddTag("bufferSize", bufferSize.ToString(CultureInfo.InvariantCulture));
            activity?.AddTag("poolType", typeof(T).Name);

            DiagnosticSource.Write("Rent.Start", new { bufferSize, poolType = typeof(T).Name });

            //Record buffer size distribution for optimization insights.
            BufferSizeHistogram.Record(bufferSize);

            IMemoryOwner<T> result;

            using(LockObject.EnterScope())
            {
                //Get or create the slab list for this specific buffer size.
                if(!Slabs.TryGetValue(bufferSize, out List<Slab<T>>? slabList))
                {
                    slabList = new List<Slab<T>>();
                    Slabs.Add(bufferSize, slabList);
                }

                //Try to find an existing slab with available capacity.
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

                //Create a new slab if no existing slab has capacity.
                if(availableSlab == null)
                {
                    availableSlab = new Slab<T>(bufferSize, InitialSlabCapacity);
                    slabList.Add(availableSlab);

                    //Update metrics for the new slab.
                    Interlocked.Increment(ref totalSlabs);
                    Interlocked.Add(ref totalMemoryAllocated, bufferSize * InitialSlabCapacity);
                    Interlocked.Add(ref totalSegments, InitialSlabCapacity);

                    //Rent from the newly created slab.
                    bool rentSuccess = availableSlab.TryRent(out rentedSegment);
                    Debug.Assert(rentSuccess, "New slab should always have available capacity");
                }

                //Update active rental metrics.
                Interlocked.Increment(ref activeRentals);

                //Create the memory owner wrapper, passing the activity for proper lifecycle management.
                result = new ExactSizeMemoryOwner<T>(rentedSegment, availableSlab, this, activity);
            }

            //Record successful rent operation.
            RentSuccessCounter.Add(1, new KeyValuePair<string, object?>("bufferSize", bufferSize));

            DiagnosticSource.Write("Rent.Stop", new { bufferSize, success = true });
            activity?.SetStatus(ActivityStatusCode.Ok);

            return result;
        }


        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="SensitiveMemoryPool{T}"/>
        /// and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">
        /// <see langword="true"/> to release both managed and unmanaged resources;
        /// <see langword="false"/> to release only unmanaged resources.
        /// </param>
        /// <remarks>
        /// When disposing, this method clears all slabs and their associated memory,
        /// ensuring that any sensitive cryptographic material is properly zeroed.
        /// The pool becomes unusable after disposal.
        /// </remarks>
        protected override void Dispose(bool disposing)
        {
            if(!IsDisposed)
            {
                if(disposing)
                {
                    using(LockObject.EnterScope())
                    {
                        //Clear all slabs to ensure sensitive memory is zeroed.
                        foreach(var slabList in Slabs.Values)
                        {
                            foreach(var slab in slabList)
                            {
                                slab.Dispose();
                            }
                        }
                        Slabs.Clear();

                        //Reset metrics to reflect disposal.
                        totalSlabs = 0;
                        totalMemoryAllocated = 0;
                        activeRentals = 0;
                        totalSegments = 0;
                    }

                    //Dispose of metrics resources.
                    PoolMeter?.Dispose();
                }

                IsDisposed = true;
            }
        }


        /// <summary>
        /// Returns a previously rented memory segment to its originating slab.
        /// This method is called internally by <see cref="ExactSizeMemoryOwner{T}"/> during disposal.
        /// </summary>
        /// <param name="segment">The memory segment to return to the pool.</param>
        /// <param name="slab">The slab that originally provided the segment.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="slab"/> is null.</exception>
        /// <remarks>
        /// This method is thread-safe and automatically updates rental metrics.
        /// The memory segment is cleared before being returned to ensure security.
        /// </remarks>
        internal void Return(ArraySegment<T> segment, Slab<T> slab)
        {
            ArgumentNullException.ThrowIfNull(slab);

            using(LockObject.EnterScope())
            {
                //Clear the memory segment for security before returning.
                segment.AsSpan().Clear();

                //Return the segment to its originating slab.
                slab.Return(segment);

                //Update metrics.
                Interlocked.Decrement(ref activeRentals);
                ReturnCounter.Add(1);
            }

            DiagnosticSource.Write("Return.Complete", new
            {
                segmentOffset = segment.Offset,
                segmentCount = segment.Count
            });
        }


        /// <summary>
        /// Calculates the current allocation efficiency as a percentage.
        /// </summary>
        /// <returns>
        /// The allocation efficiency as a percentage (0-100), or 0 if no segments are allocated.
        /// </returns>
        /// <remarks>
        /// Allocation efficiency indicates how well the pool is utilizing its allocated memory.
        /// Higher values indicate better efficiency, while lower values may suggest fragmentation
        /// or over-allocation relative to current usage patterns.
        /// </remarks>
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
        /// Each slab manages segments of a specific size and tracks their availability.
        /// </summary>
        /// <typeparam name="TElement">The type of elements stored in the slab.</typeparam>
        /// <remarks>
        /// Slabs use a stack-based allocation strategy for O(1) rent and return operations.
        /// All segments within a slab are the same size, ensuring no fragmentation within the slab.
        /// </remarks>
        internal class Slab<TElement>: IDisposable
        {
            /// <summary>
            /// The size of each segment in this slab, measured in number of elements.
            /// </summary>
            private int SegmentSize { get; }

            /// <summary>
            /// The total number of segments that this slab can provide.
            /// </summary>
            private int SegmentCount { get; }

            /// <summary>
            /// The underlying memory buffer that contains all segments.
            /// </summary>
            private TElement[] Buffer { get; }

            /// <summary>
            /// Stack tracking the indices of available segments.
            /// Using a stack provides O(1) allocation and deallocation.
            /// </summary>
            private Stack<int> AvailableSegments { get; }

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

                //Allocate the backing buffer for all segments.
                Buffer = new TElement[segmentSize * segmentCount];

                //Initialize the stack with all segment indices.
                AvailableSegments = new Stack<int>(segmentCount);
                for(int i = 0; i < segmentCount; i++)
                {
                    AvailableSegments.Push(i);
                }

                IsDisposed = false;
            }

            /// <summary>
            /// Gets a value indicating whether all segments in this slab are available.
            /// </summary>
            /// <value><see langword="true"/> if all segments are available; otherwise, <see langword="false"/>.</value>
            /// <remarks>
            /// A full slab has no rented segments and all segments are available for allocation.
            /// This property can be used to identify slabs that could potentially be deallocated
            /// during memory pressure scenarios.
            /// </remarks>
            public bool IsFull => AvailableSegments.Count == SegmentCount;

            /// <summary>
            /// Gets a value indicating whether any segments are available for rent.
            /// </summary>
            /// <value><see langword="true"/> if segments are available; otherwise, <see langword="false"/>.</value>
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
            /// <remarks>
            /// This method is thread-safe when called from within appropriate synchronization context.
            /// The caller is responsible for external synchronization across multiple slabs.
            /// </remarks>
            public bool TryRent(out ArraySegment<TElement> segment)
            {
                if(IsDisposed)
                {
                    segment = default;
                    return false;
                }

                if(AvailableSegments.TryPop(out int segmentIndex))
                {
                    int offset = segmentIndex * SegmentSize;
                    segment = new ArraySegment<TElement>(Buffer, offset, SegmentSize);
                    return true;
                }
                else
                {
                    segment = default;
                    return false;
                }
            }


            /// <summary>
            /// Returns a previously rented segment to this slab.
            /// </summary>
            /// <param name="segment">The segment to return.</param>
            /// <exception cref="ArgumentException">
            /// Thrown when the segment does not belong to this slab or has invalid parameters.
            /// </exception>
            /// <exception cref="ObjectDisposedException">Thrown when the slab has been disposed.</exception>
            /// <remarks>
            /// This method validates that the segment belongs to this slab before returning it.
            /// The segment must have been previously rented from this specific slab instance.
            /// </remarks>
            public void Return(ArraySegment<TElement> segment)
            {
                ObjectDisposedException.ThrowIf(IsDisposed, nameof(Slab<TElement>));

                //Validate that the segment belongs to this slab.
                if(segment.Array != Buffer)
                {
                    throw new ArgumentException("Segment does not belong to this slab.", nameof(segment));
                }

                if(segment.Count != SegmentSize)
                {
                    throw new ArgumentException("Segment size does not match slab segment size.", nameof(segment));
                }

                int segmentIndex = segment.Offset / SegmentSize;

                //Validate segment alignment.
                if(segment.Offset % SegmentSize != 0 || segmentIndex >= SegmentCount)
                {
                    throw new ArgumentException("Invalid segment offset for this slab.", nameof(segment));
                }

                AvailableSegments.Push(segmentIndex);
            }


            /// <summary>
            /// Releases all resources used by this slab and clears its memory.
            /// </summary>
            /// <remarks>
            /// This method clears the entire backing buffer to ensure that sensitive
            /// cryptographic material does not remain in memory.
            /// </remarks>
            public void Dispose()
            {
                if(!IsDisposed)
                {
                    //Clear the entire buffer for security.
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
        /// This class ensures that rented memory is properly returned to the pool and cleared
        /// for security purposes. It integrates with distributed tracing to track memory usage
        /// across service boundaries.
        /// </remarks>
        private class ExactSizeMemoryOwner<TOwner>: IMemoryOwner<TOwner>
        {
            /// <summary>
            /// The activity that tracks the entire rental lifecycle.
            /// This activity is owned by this instance and disposed when the memory is returned.
            /// </summary>
            private Activity? RentActivity { get; }

            /// <summary>
            /// The memory segment managed by this owner.
            /// </summary>
            private ArraySegment<TOwner> Segment { get; }

            /// <summary>
            /// The slab that provided this memory segment.
            /// </summary>
            private SensitiveMemoryPool<TOwner>.Slab<TOwner> Slab { get; }

            /// <summary>
            /// The memory pool that owns the slab.
            /// </summary>
            private SensitiveMemoryPool<TOwner> Pool { get; }

            /// <summary>
            /// Indicates whether this memory owner has been disposed.
            /// </summary>
            private bool Disposed { get; set; }


            /// <summary>
            /// Initializes a new instance of the <see cref="ExactSizeMemoryOwner{TOwner}"/> class.
            /// </summary>
            /// <param name="segment">The memory segment to manage.</param>
            /// <param name="slab">The slab that provided the segment.</param>
            /// <param name="pool">The memory pool that owns the slab.</param>
            /// <param name="rentActivity">The activity tracking this rental, ownership is transferred to this instance.</param>
            /// <exception cref="InvalidOperationException">
            /// Thrown when the segment is invalid or has no backing array.
            /// </exception>
            /// <exception cref="ArgumentNullException">
            /// Thrown when <paramref name="slab"/> or <paramref name="pool"/> is null.
            /// </exception>
            public ExactSizeMemoryOwner(ArraySegment<TOwner> segment, SensitiveMemoryPool<TOwner>.Slab<TOwner> slab,
                SensitiveMemoryPool<TOwner> pool, Activity? rentActivity)
            {
                if(segment.Array == null || segment.Count == 0)
                {
                    throw new InvalidOperationException("Failed to rent a valid memory segment.");
                }

                ArgumentNullException.ThrowIfNull(slab);
                ArgumentNullException.ThrowIfNull(pool);

                RentActivity = rentActivity;  //Take ownership of the activity.
                Segment = segment;
                Slab = slab;
                Pool = pool;
                Disposed = false;
            }


            /// <summary>
            /// Gets the memory managed by this owner.
            /// </summary>
            /// <value>The memory segment of exactly the requested size.</value>
            /// <exception cref="ObjectDisposedException">Thrown when this owner has been disposed.</exception>
            /// <remarks>
            /// The returned memory is guaranteed to be exactly the size that was originally
            /// requested from the memory pool, ensuring no over-allocation for security-sensitive scenarios.
            /// </remarks>
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
            /// </summary>
            /// <remarks>
            /// This method is thread-safe and can be called multiple times safely.
            /// The memory is automatically cleared before being returned to the pool
            /// to ensure that sensitive cryptographic material does not persist.
            /// </remarks>
            public void Dispose()
            {
                if(!Disposed)
                {
                    //Create dispose activity as a child of the rent activity.
                    //We set the rent activity as current to ensure proper parent-child relationship.
                    Activity? disposeActivity = null;
                    var previousCurrent = Activity.Current;

                    try
                    {
                        //Set rent activity as current so dispose becomes its child.
                        if(RentActivity != null)
                        {
                            Activity.Current = RentActivity;
                        }

                        //Create the dispose activity which will automatically use Activity.Current as parent.
                        disposeActivity = ActivitySource.StartActivity("Dispose", ActivityKind.Internal);

                        disposeActivity?.AddTag("segmentSize", Segment.Count.ToString(CultureInfo.InvariantCulture));
                        disposeActivity?.AddTag("segmentOffset", Segment.Offset.ToString(CultureInfo.InvariantCulture));

                        DiagnosticSource.Write("Dispose.Start", new
                        {
                            segmentOffset = Segment.Offset,
                            segmentCount = Segment.Count
                        });

                        //Return the segment to the pool (which will clear it).
                        Pool.Return(Segment, Slab);

                        DiagnosticSource.Write("Dispose.Stop", new
                        {
                            segmentOffset = Segment.Offset,
                            segmentCount = Segment.Count
                        });

                        disposeActivity?.SetStatus(ActivityStatusCode.Ok);
                    }
                    finally
                    {
                        //Stop and dispose activities in correct order.
                        disposeActivity?.Stop();
                        disposeActivity?.Dispose();

                        //Restore previous current before stopping rent activity.
                        Activity.Current = previousCurrent;

                        RentActivity?.Stop();
                        RentActivity?.Dispose();

                        Disposed = true;
                    }
                }
            }
        }
    }
}