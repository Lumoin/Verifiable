using BenchmarkDotNet.Attributes;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Benchmarks
{
    /// <summary>
    /// Benchmarks comparing SensitiveMemoryPool against standard .NET memory allocation approaches.
    /// Tests various allocation patterns common in cryptographic operations.
    /// </summary>
    [MemoryDiagnoser]
    [SimpleJob]
    [SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "Cleanup handled in GlobalCleanup.")]
    internal class SensitiveMemoryPoolBenchmarks
    {
        private Meter meter = null!;
        private Meter coldMeter = null!;
        private SensitiveMemoryPool<byte> sensitivePool = null!;
        private SensitiveMemoryPool<byte> sensitivePoolNoTracing = null!;
        private ArrayPool<byte> arrayPool = null!;

        [GlobalSetup]
        public void Setup()
        {
            meter = new Meter("Bench", "1.0.0");
            coldMeter = new Meter("BenchCold", "1.0.0");
            sensitivePool = new SensitiveMemoryPool<byte>();
            sensitivePoolNoTracing = new SensitiveMemoryPool<byte>(
                meter,
                tracingEnabled: false);
            arrayPool = ArrayPool<byte>.Shared;
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            sensitivePool?.Dispose();
            sensitivePoolNoTracing?.Dispose();
            meter?.Dispose();
            coldMeter?.Dispose();
        }


        [Benchmark(Baseline = true)]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public void SensitivePoolRentReturn(int bufferSize)
        {
            using var buffer = sensitivePool.Rent(bufferSize);
            buffer.Memory.Span[0] = 0x42;
        }


        /// <summary>
        /// Quantifies the tracing overhead by comparing against a pool with tracing disabled.
        /// </summary>
        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public void SensitivePoolRentReturnNoTracing(int bufferSize)
        {
            using var buffer = sensitivePoolNoTracing.Rent(bufferSize);
            buffer.Memory.Span[0] = 0x42;
        }


        /// <summary>
        /// Standard MemoryPool comparison. This is the natural baseline since SensitiveMemoryPool
        /// extends MemoryPool. Note that MemoryPool may return buffers larger than requested.
        /// </summary>
        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public static void MemoryPoolSharedRentReturn(int bufferSize)
        {
            using var buffer = MemoryPool<byte>.Shared.Rent(bufferSize);
            buffer.Memory.Span[0] = 0x42;
        }


        /// <summary>
        /// ArrayPool comparison with explicit clearing to match SensitiveMemoryPool's
        /// security guarantee of zeroing memory on return.
        /// </summary>
        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public void ArrayPoolRentReturnWithClear(int bufferSize)
        {
            var buffer = arrayPool.Rent(bufferSize);
            try
            {
                buffer[0] = 0x42;
            }
            finally
            {
                arrayPool.Return(buffer, clearArray: true);
            }
        }


        /// <summary>
        /// ArrayPool without clearing. Shows the cost of the security guarantee.
        /// </summary>
        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public void ArrayPoolRentReturnNoClear(int bufferSize)
        {
            var buffer = arrayPool.Rent(bufferSize);
            try
            {
                buffer[0] = 0x42;
            }
            finally
            {
                arrayPool.Return(buffer);
            }
        }


        /// <summary>
        /// Raw byte array allocation as a GC-pressure baseline.
        /// Includes explicit clearing to match the security guarantee.
        /// </summary>
        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public static void ByteArrayAllocateAndClear(int bufferSize)
        {
            var buffer = new byte[bufferSize];
            buffer[0] = 0x42;
            Array.Clear(buffer);
        }


        /// <summary>
        /// Tests slab reuse efficiency. After warmup, the pool should serve
        /// all requests from existing slabs with zero new allocations.
        /// </summary>
        [Benchmark]
        [Arguments(64, 100)]
        [Arguments(256, 50)]
        public void SensitivePoolSteadyStateReuse(int bufferSize, int count)
        {
            for(int i = 0; i < count; i++)
            {
                using var buffer = sensitivePool.Rent(bufferSize);
                buffer.Memory.Span[0] = (byte)(i % 256);
            }
        }


        /// <summary>
        /// Cold path: first allocation for a new size forces slab creation.
        /// Uses a fresh pool per iteration to measure the cold-start cost.
        /// </summary>
        [Benchmark]
        public void SensitivePoolColdSlabCreation()
        {
            using var pool = new SensitiveMemoryPool<byte>(
                coldMeter,
                tracingEnabled: false);

            using var b1 = pool.Rent(32);
            using var b2 = pool.Rent(64);
            using var b3 = pool.Rent(128);
            using var b4 = pool.Rent(256);
        }


        /// <summary>
        /// Tests contention on the pool lock under parallel load.
        /// Uses Parallel.For for lower scheduling overhead than Task.Run.
        /// </summary>
        [Benchmark]
        [Arguments(32, 10)]
        [Arguments(64, 20)]
        public void SensitivePoolParallelContention(int bufferSize, int concurrency)
        {
            Parallel.For(0, concurrency, _ =>
            {
                for(int i = 0; i < 50; i++)
                {
                    using var buffer = sensitivePool.Rent(bufferSize);
                    buffer.Memory.Span[0] = 0x33;
                }
            });
        }


        /// <summary>
        /// Mixed size allocation pattern matching realistic cryptographic workloads.
        /// Common key, hash, and signature sizes.
        /// </summary>
        [Benchmark]
        public void SensitivePoolMixedCryptoSizes()
        {
            ReadOnlySpan<int> sizes = [16, 32, 48, 64, 96, 128, 256, 384, 512];

            for(int round = 0; round < 20; round++)
            {
                foreach(int size in sizes)
                {
                    using var buffer = sensitivePool.Rent(size);
                    buffer.Memory.Span[0] = (byte)(size % 256);
                }
            }
        }
    }
}