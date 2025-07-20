using BenchmarkDotNet.Attributes;
using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Core.Cryptography;

namespace Verifiable.Benchmarks
{
    /// <summary>
    /// Benchmarks comparing SensitiveMemoryPool against standard .NET memory allocation approaches.
    /// Tests various allocation patterns common in cryptographic operations.
    /// </summary>
    [MemoryDiagnoser]
    [SimpleJob]
    public class SensitiveMemoryPoolBenchmarks
    {
        private SensitiveMemoryPool<byte> sensitivePool = null!;
        private ArrayPool<byte> arrayPool = null!;

        [GlobalSetup]
        public void Setup()
        {
            sensitivePool = new SensitiveMemoryPool<byte>();
            arrayPool = ArrayPool<byte>.Shared;
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            sensitivePool?.Dispose();
        }


        /// <summary>
        /// Benchmark single allocation and immediate disposal pattern.
        /// Common in cryptographic operations that need temporary buffers.
        /// </summary>
        [Benchmark]
        [Arguments(32)]   //AES block size
        [Arguments(64)]   //SHA-512 hash size
        [Arguments(256)]  //RSA-2048 key material
        [Arguments(512)]  //Larger crypto operations
        public void SensitivePoolSingleAllocation(int bufferSize)
        {
            using var buffer = sensitivePool.Rent(bufferSize);
            //Simulate some work.
            buffer.Memory.Span.Fill(0x42);
        }


        /// <summary>
        /// Benchmark standard ArrayPool for comparison.
        /// </summary>
        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public void ArrayPoolSingleAllocation(int bufferSize)
        {
            var buffer = arrayPool.Rent(bufferSize);
            try
            {
                //Simulate some work.
                new Span<byte>(buffer, 0, bufferSize).Fill(0x42);
            }
            finally
            {
                arrayPool.Return(buffer);
            }
        }


        /// <summary>
        /// Benchmark standard byte array allocation for comparison.
        /// </summary>
        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(256)]
        [Arguments(512)]
        public void ByteArraySingleAllocation(int bufferSize)
        {
            var buffer = new byte[bufferSize];
            //Simulate some work.
            buffer.AsSpan().Fill(0x42);
            //No explicit cleanup needed.
        }


        /// <summary>
        /// Benchmark multiple allocations of the same size.
        /// Tests slab reuse efficiency in SensitiveMemoryPool.
        /// </summary>
        [Benchmark]
        [Arguments(64, 100)]
        [Arguments(256, 50)]
        public void SensitivePoolMultipleAllocations(int bufferSize, int count)
        {
            for(int i = 0; i < count; i++)
            {
                using var buffer = sensitivePool.Rent(bufferSize);
                buffer.Memory.Span.Fill((byte)(i % 256));
            }
        }


        /// <summary>
        /// Benchmark ArrayPool with multiple allocations for comparison.
        /// </summary>
        [Benchmark]
        [Arguments(64, 100)]
        [Arguments(256, 50)]
        public void ArrayPoolMultipleAllocations(int bufferSize, int count)
        {
            for(int i = 0; i < count; i++)
            {
                var buffer = arrayPool.Rent(bufferSize);
                try
                {
                    new Span<byte>(buffer, 0, Math.Min(bufferSize, buffer.Length)).Fill((byte)(i % 256));
                }
                finally
                {
                    arrayPool.Return(buffer);
                }
            }
        }


        /// <summary>
        /// Benchmark multiple concurrent allocations.
        /// Tests allocation performance under concurrent load.
        /// </summary>
        [Benchmark]
        [Arguments(32, 10)]
        [Arguments(64, 20)]
        public void SensitivePoolConcurrentAllocations(int bufferSize, int concurrency)
        {
            var tasks = new Task[concurrency];
            for(int t = 0; t < concurrency; t++)
            {
                tasks[t] = Task.Run(() =>
                {
                    for(int i = 0; i < 50; i++)
                    {
                        using var buffer = sensitivePool.Rent(bufferSize);
                        buffer.Memory.Span.Fill(0x33);
                    }
                });
            }
            Task.WaitAll(tasks);
        }


        /// <summary>
        /// Benchmark mixed size allocation pattern.
        /// Simulates realistic cryptographic workload with varying buffer sizes.
        /// </summary>
        [Benchmark]
        public void SensitivePoolMixedSizePattern()
        {
            var sizes = new[] { 16, 32, 48, 64, 96, 128, 256, 384, 512 };

            for(int round = 0; round < 20; round++)
            {
                foreach(int size in sizes)
                {
                    using var buffer = sensitivePool.Rent(size);
                    buffer.Memory.Span.Fill((byte)(size % 256));
                }
            }
        }


        /// <summary>
        /// Benchmark ArrayPool with mixed sizes for comparison.
        /// </summary>
        [Benchmark]
        public void ArrayPoolMixedSizePattern()
        {
            var sizes = new[] { 16, 32, 48, 64, 96, 128, 256, 384, 512 };

            for(int round = 0; round < 20; round++)
            {
                foreach(int size in sizes)
                {
                    var buffer = arrayPool.Rent(size);
                    try
                    {
                        new Span<byte>(buffer, 0, Math.Min(size, buffer.Length)).Fill((byte)(size % 256));
                    }
                    finally
                    {
                        arrayPool.Return(buffer);
                    }
                }
            }
        }
    }
}
