using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class ExactSizeMemoryPool<T>: MemoryPool<T>
    {
        private readonly Dictionary<int, List<Slab<T>>> slabs;
        private bool isDisposed;

        private readonly Meter poolMeter;
        private readonly ObservableUpDownCounter<int> totalSlabsCounter;
        private readonly ObservableUpDownCounter<long> totalMemoryUsedCounter;

        private int totalSlabs = 0;
        private long totalMemoryUsed = 0;
        private readonly object lockObject = new object();

        private static readonly ActivitySource activitySource = new("ExactSizeMemoryPool");
        private static readonly DiagnosticSource diagnosticSource = new DiagnosticListener("ExactSizeMemoryPool");

        public const int InitialSlabCapacity = 4;

        public ExactSizeMemoryPool() : this(new Meter("ExactSizeMemoryPool", "1.0.0")) { }

        /// <summary>
        /// Gets a singleton instance of a memory pool based on arrays.
        /// </summary>
        /// <remarks>A singleton instance of memory pool for cryptographic material.</remarks>
        public static new ExactSizeMemoryPool<T> Shared => new();


        public ExactSizeMemoryPool(Meter meter)
        {
            ArgumentNullException.ThrowIfNull(meter);

            poolMeter = meter;
            totalSlabsCounter = meter.CreateObservableUpDownCounter("TotalSlabs", () => totalSlabs, "slabs");
            totalMemoryUsedCounter = meter.CreateObservableUpDownCounter("TotalMemoryUsed", () => totalMemoryUsed, "bytes");

            slabs = new Dictionary<int, List<Slab<T>>>();
            isDisposed = false;
        }


        public override IMemoryOwner<T> Rent(int bufferSize)
        {
            if(isDisposed)
            {
                throw new ObjectDisposedException(nameof(ExactSizeMemoryPool<T>));
            }

            if(bufferSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bufferSize));
            }

            using var activity = activitySource.StartActivity("Rent", ActivityKind.Internal, Activity.Current?.Context ?? default);
            activity?.AddTag("bufferSize", bufferSize.ToString());
            activity?.Start();

            diagnosticSource.Write("Rent.Start", new { bufferSize });

            lock(lockObject)
            {
                if(!slabs.TryGetValue(bufferSize, out List<Slab<T>>? slabList))
                {
                    slabList = new List<Slab<T>>();
                    slabs.Add(bufferSize, slabList);
                }

                Slab<T>? slab = null;
                ArraySegment<T> rentedSegment = default;
                foreach(var s in slabList)
                {
                    if(s.TryRent(out rentedSegment))
                    {
                        slab = s;
                        break;
                    }
                }

                if(slab == null)
                {
                    slab = new Slab<T>(bufferSize, InitialSlabCapacity);
                    slabList.Add(slab);
                    totalSlabs++;
                    totalMemoryUsed += bufferSize * InitialSlabCapacity;

                    slab.TryRent(out rentedSegment); // Rent the segment from the newly created slab
                }

                var memoryOwner = new ExactSizeMemoryOwner<T>(rentedSegment, slab);
                diagnosticSource.Write("Rent.Stop", new { bufferSize });
                
                return memoryOwner;
            }
        }




        protected override void Dispose(bool disposing)
        {
            if(!isDisposed)
            {
                if(disposing)
                {
                    lock(lockObject)
                    {
                        slabs.Clear();
                    }
                }

                isDisposed = true;
            }
        }

        public override int MaxBufferSize => int.MaxValue;


        private void Return(ArraySegment<T> segment, Slab<T> slab)
        {
            ArgumentNullException.ThrowIfNull(slab);

            lock(lockObject)
            {
                slab.Return(segment);
            }
        }

        private class Slab<TS>
        {
            private readonly int segmentSize;
            private readonly int segmentCount;
            private readonly TS[] buffer;
            private readonly Stack<int> segments;

            public Slab(int segmentSize, int segmentCount)
            {
                this.segmentSize = segmentSize;
                this.segmentCount = segmentCount;
                buffer = new TS[segmentSize * segmentCount];

                segments = new Stack<int>(segmentCount);
                for(int i = 0; i < segmentCount; i++)
                {
                    segments.Push(i);
                }
            }

            public bool TryRent(out ArraySegment<TS> segment)
            {
                if(segments.TryPop(out int offset))
                {
                    segment = new ArraySegment<TS>(buffer, offset * segmentSize, segmentSize);
                    return true;
                }
                else
                {
                    segment = default;
                    return false;
                }
            }

            public void Return(ArraySegment<TS> segment)
            {
                int offset = segment.Offset / segmentSize;
                segments.Push(offset);
            }

            public bool IsFull => segments.Count == segmentCount;
        }




        private class ExactSizeMemoryOwner<TO>: IMemoryOwner<TO>
        {
            private Activity? rentActivity;
            private ArraySegment<TO> segment;
            private Slab<TO> slab;
            private bool disposed;

            public ExactSizeMemoryOwner(ArraySegment<TO> segment, Slab<TO> slab)
            {
                if(segment.Array == null || segment.Count == 0)
                {
                    throw new InvalidOperationException("Failed to rent a valid memory segment.");
                }

                this.rentActivity = Activity.Current;
                this.segment = segment;
                this.slab = slab;
                disposed = false;
            }

            public Memory<TO> Memory
            {
                get
                {
                    if(disposed)
                    {
                        throw new ObjectDisposedException(nameof(ExactSizeMemoryOwner<TO>));
                    }

                    return segment;
                }
            }

            public void Dispose()
            {
                if(!disposed)
                {
                    using var activity = activitySource.StartActivity("Dispose", ActivityKind.Internal, rentActivity?.Context ?? default);
                    activity?.SetStatus(ActivityStatusCode.Error, "Unauthorized memory usage discovered");
                    diagnosticSource.Write("Dispose.Start (clears the rented segmented).", new { segment.Offset, segment.Count });

                    segment.AsSpan().Clear();                    
                    slab.Return(segment);

                    diagnosticSource.Write("Dispose.Stop (the rented segmented cleared).", new { segment.Offset, segment.Count });
                    disposed = true;
                }
            }
        }        
    }
}
