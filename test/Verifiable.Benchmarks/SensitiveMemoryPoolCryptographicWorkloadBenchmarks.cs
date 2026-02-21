using BenchmarkDotNet.Attributes;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Benchmarks
{
    /// <summary>
    /// Benchmarks modelling realistic cryptographic allocation patterns.
    /// Each benchmark isolates the pool overhead by keeping simulated work minimal.
    /// </summary>
    [MemoryDiagnoser]
    [SimpleJob]
    [SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "Cleanup handled in GlobalCleanup.")]
    internal class SensitiveMemoryPoolCryptographicWorkloadBenchmarks
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
        /// AES-256 workflow: key (32) + IV (16) + plaintext buffer (1024).
        /// Three concurrent rentals of different sizes.
        /// </summary>
        [Benchmark]
        public void SensitivePoolAesPattern()
        {
            using var key = sensitivePool.Rent(32);
            using var iv = sensitivePool.Rent(16);
            using var data = sensitivePool.Rent(1024);

            key.Memory.Span[0] = 0x01;
            iv.Memory.Span[0] = 0x02;
            data.Memory.Span[0] = 0x03;
        }

        [Benchmark]
        public void ArrayPoolAesPattern()
        {
            var key = arrayPool.Rent(32);
            var iv = arrayPool.Rent(16);
            var data = arrayPool.Rent(1024);
            try
            {
                key[0] = 0x01;
                iv[0] = 0x02;
                data[0] = 0x03;
            }
            finally
            {
                arrayPool.Return(data, clearArray: true);
                arrayPool.Return(iv, clearArray: true);
                arrayPool.Return(key, clearArray: true);
            }
        }


        /// <summary>
        /// P-256 ECDSA sign: private key (32) + nonce (32) + hash (32) + signature r (32) + signature s (32).
        /// Five concurrent rentals of the same size, exercising slab reuse within a single operation.
        /// </summary>
        [Benchmark]
        public void SensitivePoolEcdsaP256SignPattern()
        {
            using var privateKey = sensitivePool.Rent(32);
            using var nonce = sensitivePool.Rent(32);
            using var hash = sensitivePool.Rent(32);
            using var r = sensitivePool.Rent(32);
            using var s = sensitivePool.Rent(32);

            privateKey.Memory.Span[0] = 0x04;
            nonce.Memory.Span[0] = 0x05;
            hash.Memory.Span[0] = 0x06;
            r.Memory.Span[0] = 0x07;
            s.Memory.Span[0] = 0x08;
        }

        [Benchmark]
        public void ArrayPoolEcdsaP256SignPattern()
        {
            var privateKey = arrayPool.Rent(32);
            var nonce = arrayPool.Rent(32);
            var hash = arrayPool.Rent(32);
            var r = arrayPool.Rent(32);
            var s = arrayPool.Rent(32);
            try
            {
                privateKey[0] = 0x04;
                nonce[0] = 0x05;
                hash[0] = 0x06;
                r[0] = 0x07;
                s[0] = 0x08;
            }
            finally
            {
                arrayPool.Return(s, clearArray: true);
                arrayPool.Return(r, clearArray: true);
                arrayPool.Return(hash, clearArray: true);
                arrayPool.Return(nonce, clearArray: true);
                arrayPool.Return(privateKey, clearArray: true);
            }
        }


        /// <summary>
        /// Batch signature verification: 100 iterations of rent-verify-return for a 64-byte signature.
        /// Models a verifier processing a stream of credentials.
        /// </summary>
        [Benchmark]
        public void SensitivePoolBatchVerify100()
        {
            for(int i = 0; i < 100; i++)
            {
                using var sig = sensitivePool.Rent(64);
                using var pubKey = sensitivePool.Rent(65);
                using var hash = sensitivePool.Rent(32);

                sig.Memory.Span[0] = (byte)i;
            }
        }

        [Benchmark]
        public void ArrayPoolBatchVerify100()
        {
            for(int i = 0; i < 100; i++)
            {
                var sig = arrayPool.Rent(64);
                var pubKey = arrayPool.Rent(65);
                var hash = arrayPool.Rent(32);
                try
                {
                    sig[0] = (byte)i;
                }
                finally
                {
                    arrayPool.Return(hash, clearArray: true);
                    arrayPool.Return(pubKey, clearArray: true);
                    arrayPool.Return(sig, clearArray: true);
                }
            }
        }


        /// <summary>
        /// High-frequency single-size allocation. Models a hot loop processing
        /// many HMAC operations with the same key size.
        /// </summary>
        [Benchmark]
        public void SensitivePoolHmacHotLoop1000()
        {
            for(int i = 0; i < 1000; i++)
            {
                using var buffer = sensitivePool.Rent(32);
                buffer.Memory.Span[0] = (byte)(i % 256);
            }
        }

        [Benchmark]
        public void ArrayPoolHmacHotLoop1000()
        {
            for(int i = 0; i < 1000; i++)
            {
                var buffer = arrayPool.Rent(32);
                try
                {
                    buffer[0] = (byte)(i % 256);
                }
                finally
                {
                    arrayPool.Return(buffer, clearArray: true);
                }
            }
        }
    }
}