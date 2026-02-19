using BenchmarkDotNet.Attributes;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using Verifiable.Cryptography;

namespace Verifiable.Benchmarks
{
    /// <summary>
    /// Benchmarks testing memory pressure, capacity strategies, and trim behavior.
    /// </summary>
    [MemoryDiagnoser]
    [SimpleJob]
    [SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "Cleanup handled in GlobalCleanup.")]
    internal class SensitiveMemoryPoolMemoryPressureBenchmarks
    {
        private Meter defaultMeter = null!;
        private Meter flatMeter = null!;
        private Meter perIterationMeter = null!;
        private SensitiveMemoryPool<byte> defaultStrategyPool = null!;
        private SensitiveMemoryPool<byte> flatStrategyPool = null!;

        [GlobalSetup]
        public void Setup()
        {
            defaultMeter = new Meter("BenchDefault", "1.0.0");
            flatMeter = new Meter("BenchFlat", "1.0.0");
            perIterationMeter = new Meter("BenchPerIteration", "1.0.0");

            defaultStrategyPool = new SensitiveMemoryPool<byte>(
                defaultMeter,
                tracingEnabled: false);

            flatStrategyPool = new SensitiveMemoryPool<byte>(
                flatMeter,
                capacityStrategy: _ => 4,
                tracingEnabled: false);
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            defaultStrategyPool?.Dispose();
            flatStrategyPool?.Dispose();
            defaultMeter?.Dispose();
            flatMeter?.Dispose();
            perIterationMeter?.Dispose();
        }


        /// <summary>
        /// Default capacity strategy: 32 segments for small buffers, fewer for larger ones.
        /// Measures amortized allocation cost for the most common key sizes.
        /// </summary>
        [Benchmark(Baseline = true)]
        public void DefaultStrategySmallBuffers()
        {
            for(int i = 0; i < 500; i++)
            {
                using var buffer = defaultStrategyPool.Rent(32);
                buffer.Memory.Span[0] = (byte)i;
            }
        }


        /// <summary>
        /// Flat capacity strategy (always 4 segments per slab) for comparison.
        /// Forces more frequent slab creation.
        /// </summary>
        [Benchmark]
        public void FlatStrategySmallBuffers()
        {
            for(int i = 0; i < 500; i++)
            {
                using var buffer = flatStrategyPool.Rent(32);
                buffer.Memory.Span[0] = (byte)i;
            }
        }


        /// <summary>
        /// Measures the overhead of many simultaneous small allocations.
        /// This pattern occurs when processing batches of credentials.
        /// </summary>
        [Benchmark]
        [Arguments(100)]
        [Arguments(500)]
        [Arguments(1000)]
        public void SimultaneousSmallAllocations(int count)
        {
            var buffers = new List<IMemoryOwner<byte>>(count);
            try
            {
                for(int i = 0; i < count; i++)
                {
                    buffers.Add(defaultStrategyPool.Rent(16));
                }
            }
            finally
            {
                foreach(var buffer in buffers)
                {
                    buffer.Dispose();
                }
            }
        }


        /// <summary>
        /// Overlapping lifetimes with a sliding window. Models a pipeline where
        /// new buffers are rented while older ones are still in flight.
        /// </summary>
        [Benchmark]
        [Arguments(5)]
        [Arguments(20)]
        public void SlidingWindowLifetimes(int windowSize)
        {
            var window = new Queue<IMemoryOwner<byte>>(windowSize);
            try
            {
                for(int i = 0; i < 200; i++)
                {
                    window.Enqueue(defaultStrategyPool.Rent(64));

                    if(window.Count > windowSize)
                    {
                        window.Dequeue().Dispose();
                    }
                }
            }
            finally
            {
                while(window.Count > 0)
                {
                    window.Dequeue().Dispose();
                }
            }
        }


        /// <summary>
        /// Measures the cost of TrimExcess after a burst of allocations.
        /// Models a long-running service that periodically reclaims memory.
        /// </summary>
        [Benchmark]
        public void BurstThenTrim()
        {
            using var pool = new SensitiveMemoryPool<byte>(
                perIterationMeter,
                capacityStrategy: _ => 4,
                tracingEnabled: false);

            //Burst: hold many buffers simultaneously to force slab creation.
            var burst = new List<IMemoryOwner<byte>>(50);
            for(int i = 0; i < 50; i++)
            {
                burst.Add(pool.Rent(32));
            }

            //Return everything.
            foreach(var b in burst)
            {
                b.Dispose();
            }

            //Trim the excess slabs.
            pool.TrimExcess();

            //Re-rent to verify the pool still works after trimming.
            using var after = pool.Rent(32);
            after.Memory.Span[0] = 0xFF;
        }


        /// <summary>
        /// Allocation-heavy scenario with many distinct sizes.
        /// Worst case for slab segregation: every size creates its own slab list.
        /// </summary>
        [Benchmark]
        public void ManyDistinctSizes()
        {
            using var pool = new SensitiveMemoryPool<byte>(
                perIterationMeter,
                tracingEnabled: false);

            for(int size = 1; size <= 128; size++)
            {
                using var buffer = pool.Rent(size);
                buffer.Memory.Span[0] = (byte)size;
            }
        }
    }
}