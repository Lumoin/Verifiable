using BenchmarkDotNet.Attributes;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Benchmarks
{
    /// <summary>
    /// Benchmarks testing memory pressure and allocation patterns.
    /// </summary>
    [MemoryDiagnoser]
    [SimpleJob]
    [SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "Cleanup handled in GlobalCleanup.")]
    internal class SensitiveMemoryPoolMemoryPressureBenchmarks
    {
        private SensitiveMemoryPool<byte> sensitivePool = null!;

        [GlobalSetup]
        public void Setup()
        {
            sensitivePool = new SensitiveMemoryPool<byte>();
        }


        [GlobalCleanup]
        public void Cleanup()
        {
            sensitivePool?.Dispose();
        }


        /// <summary>
        /// Test allocation efficiency with many small buffers.
        /// </summary>
        [Benchmark]
        public void SensitivePoolManySmallAllocations()
        {
            var buffers = new List<IMemoryOwner<byte>>();

            try
            {
                //Allocate many small buffers.
                for(int i = 0; i < 1000; i++)
                {
                    buffers.Add(sensitivePool.Rent(16));
                }

                //Use the buffers.
                for(int i = 0; i < buffers.Count; i++)
                {
                    buffers[i].Memory.Span.Fill((byte)(i % 256));
                }
            }
            finally
            {
                //Clean up all buffers.
                foreach(var buffer in buffers)
                {
                    buffer.Dispose();
                }
            }
        }


        /// <summary>
        /// Test allocation pattern with overlapping lifetimes.
        /// </summary>
        [Benchmark]
        public void SensitivePoolOverlappingLifetimes()
        {
            var buffers = new Queue<IMemoryOwner<byte>>();
            try
            {
                //Build up allocated buffers.
                for(int i = 0; i < 100; i++)
                {
                    buffers.Enqueue(sensitivePool.Rent(64));

                    //Periodically dispose some buffers.
                    if(i > 10 && i % 5 == 0)
                    {
                        for(int j = 0; j < 3 && buffers.Count > 0; j++)
                        {
                            buffers.Dequeue().Dispose();
                        }
                    }
                }
            }
            finally
            {
                //Clean up remaining buffers.
                while(buffers.Count > 0)
                {
                    buffers.Dequeue().Dispose();
                }
            }
        }
    }
}
