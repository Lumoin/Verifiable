using BenchmarkDotNet.Attributes;
using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core.Cryptography;

namespace Verifiable.Benchmarks
{
    /// <summary>
    /// Benchmarks specifically focused on cryptographic operation patterns.
    /// Tests realistic scenarios where SensitiveMemoryPool would be used.
    /// </summary>
    [MemoryDiagnoser]
    [SimpleJob]
    public class SensitiveMemoryPoolCryptographicWorkloadBenchmarks
    {
        private SensitiveMemoryPool<byte> sensitivePool = null!;
        private ArrayPool<byte> arrayPool = null!;
        private readonly byte[] testData = new byte[1024];

        [GlobalSetup]
        public void Setup()
        {
            sensitivePool = new SensitiveMemoryPool<byte>();
            arrayPool = ArrayPool<byte>.Shared;
            new Random(42).NextBytes(testData);
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            sensitivePool?.Dispose();
        }

        /// <summary>
        /// Simulate AES encryption workflow with SensitiveMemoryPool.
        /// Allocates buffers for key, IV, and result.
        /// </summary>
        [Benchmark]
        public void SensitivePoolAesWorkflow()
        {
            //Allocate AES key buffer (32 bytes for AES-256).
            using var keyBuffer = sensitivePool.Rent(32);
            keyBuffer.Memory.Span.Fill(0x01);

            //Allocate IV buffer (16 bytes).
            using var ivBuffer = sensitivePool.Rent(16);
            ivBuffer.Memory.Span.Fill(0x02);

            //Allocate result buffer.
            using var resultBuffer = sensitivePool.Rent(testData.Length);
            testData.CopyTo(resultBuffer.Memory);

            //Simulate some processing.
            for(int i = 0; i < resultBuffer.Memory.Length; i++)
            {
                resultBuffer.Memory.Span[i] ^= keyBuffer.Memory.Span[i % 32];
            }
        }

        /// <summary>
        /// Simulate AES encryption workflow with ArrayPool for comparison.
        /// </summary>
        [Benchmark]
        public void ArrayPoolAesWorkflow()
        {
            var keyBuffer = arrayPool.Rent(32);
            var ivBuffer = arrayPool.Rent(16);
            var resultBuffer = arrayPool.Rent(testData.Length);

            try
            {
                new Span<byte>(keyBuffer, 0, 32).Fill(0x01);
                new Span<byte>(ivBuffer, 0, 16).Fill(0x02);
                testData.CopyTo(new Span<byte>(resultBuffer, 0, testData.Length));

                //Simulate some processing.
                for(int i = 0; i < testData.Length; i++)
                {
                    resultBuffer[i] ^= keyBuffer[i % 32];
                }
            }
            finally
            {
                arrayPool.Return(keyBuffer, clearArray: true);
                arrayPool.Return(ivBuffer, clearArray: true);
                arrayPool.Return(resultBuffer, clearArray: true);
            }
        }

        /// <summary>
        /// Simulate hash computation workflow requiring temporary buffers.
        /// </summary>
        [Benchmark]
        public void SensitivePoolHashWorkflow()
        {
            //Allocate working buffer for hash computation.
            using var workBuffer = sensitivePool.Rent(64); //SHA-512 block size
            using var hashBuffer = sensitivePool.Rent(64); //SHA-512 output size

            //Simulate hash rounds.
            for(int round = 0; round < 10; round++)
            {
                //Copy data to working buffer.
                testData.AsSpan(0, Math.Min(64, testData.Length)).CopyTo(workBuffer.Memory.Span);

                //Simulate hash computation.
                for(int i = 0; i < 64; i++)
                {
                    hashBuffer.Memory.Span[i] = (byte)(workBuffer.Memory.Span[i] + round);
                }
            }
        }

        /// <summary>
        /// Simulate RSA key generation requiring large temporary buffers.
        /// </summary>
        [Benchmark]
        public void SensitivePoolRsaKeyGenWorkflow()
        {
            //Allocate buffers for RSA-2048 key generation.
            using var primeBuffer = sensitivePool.Rent(128); //1024-bit prime
            using var keyBuffer = sensitivePool.Rent(256);   //2048-bit key
            using var tempBuffer = sensitivePool.Rent(512);  //Working space

            //Simulate key generation steps.
            primeBuffer.Memory.Span.Fill(0x03);

            //Simulate modular arithmetic operations.
            for(int i = 0; i < 256; i++)
            {
                keyBuffer.Memory.Span[i] = (byte)(primeBuffer.Memory.Span[i % 128] * 2);
            }

            //Simulate additional computations.
            keyBuffer.Memory.CopyTo(tempBuffer.Memory.Slice(0, 256));
        }

        /// <summary>
        /// Simulate ECDSA signature workflow with multiple small allocations.
        /// </summary>
        [Benchmark]
        public void SensitivePoolEcdsaWorkflow()
        {
            //Allocate buffers for P-256 ECDSA.
            using var privateKeyBuffer = sensitivePool.Rent(32); //256-bit private key
            using var nonceBuffer = sensitivePool.Rent(32);      //256-bit nonce
            using var rBuffer = sensitivePool.Rent(32);          //r component
            using var sBuffer = sensitivePool.Rent(32);          //s component
            using var hashBuffer = sensitivePool.Rent(32);       //SHA-256 hash

            //Simulate signature generation.
            privateKeyBuffer.Memory.Span.Fill(0x04);
            nonceBuffer.Memory.Span.Fill(0x05);
            testData.AsSpan(0, 32).CopyTo(hashBuffer.Memory.Span);

            //Simulate elliptic curve operations.
            for(int i = 0; i < 32; i++)
            {
                rBuffer.Memory.Span[i] = (byte)(nonceBuffer.Memory.Span[i] ^ hashBuffer.Memory.Span[i]);
                sBuffer.Memory.Span[i] = (byte)(privateKeyBuffer.Memory.Span[i] + rBuffer.Memory.Span[i]);
            }
        }

        /// <summary>
        /// Simulate high-frequency cryptographic operations.
        /// Tests performance under sustained load.
        /// </summary>
        [Benchmark]
        public void SensitivePoolHighFrequencyOperations()
        {
            for(int i = 0; i < 1000; i++)
            {
                using var buffer = sensitivePool.Rent(32);
                //Simulate quick cryptographic operation.
                buffer.Memory.Span[0] = (byte)(i % 256);
                buffer.Memory.Span[31] = (byte)((i * 2) % 256);
            }
        }
    }
}
