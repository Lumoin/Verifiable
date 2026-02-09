using CsCheck;
using System.Buffers;
using System.Collections.Concurrent;
using Verifiable.Cryptography;

namespace Verifiable.Tests.SensitiveMemoryPool
{
    /// <summary>
    /// Property-based tests using CsCheck for comprehensive validation.
    /// </summary>
    [TestClass]
    internal sealed class SensitiveMemoryPoolPropertyTests
    {
        public TestContext TestContext { get; set; }


        [TestMethod]
        public void PropertyRentAlwaysReturnsExactSize()
        {
            Gen.Int[1, 10000].Sample(bufferSize =>
            {
                using var pool = new SensitiveMemoryPool<byte>();
                using var buffer = pool.Rent(bufferSize);

                Assert.AreEqual(bufferSize, buffer.Memory.Length, $"Buffer size {bufferSize} should return exactly {bufferSize} elements.");
            });
        }


        [TestMethod]
        public void PropertyMultipleRentReturnCycles()
        {
            Gen.Int[1, 100].Sample(cycleCount =>
            {
                using var pool = new SensitiveMemoryPool<byte>();

                for(int i = 0; i < cycleCount; i++)
                {
                    var bufferSize = (i % 10) + 1; //Small range to test slab reuse.
                    using var buffer = pool.Rent(bufferSize);

                    Assert.AreEqual(bufferSize, buffer.Memory.Length);

                    //Write some data to verify buffer is writable.
                    if(buffer.Memory.Length > 0)
                    {
                        buffer.Memory.Span[0] = (byte)(i % 256);
                    }
                }
            });
        }


        [TestMethod]
        public void PropertyConcurrentOperationsAreThreadSafe()
        {
            Gen.Int[1, 20].Sample(threadCount =>
            {
                using var pool = new SensitiveMemoryPool<byte>();
                var tasks = new Task[threadCount];
                var exceptions = new ConcurrentBag<Exception>();

                for(int i = 0; i < threadCount; i++)
                {
                    int threadId = i;
                    tasks[i] = Task.Run(() =>
                    {
                        try
                        {
                            for(int j = 0; j < 100; j++)
                            {
                                var size = (j % 50) + 1;
                                using var buffer = pool.Rent(size);

                                Assert.AreEqual(size, buffer.Memory.Length);

                                //Simulate some work.
                                if(buffer.Memory.Length > 0)
                                {
                                    buffer.Memory.Span.Fill((byte)(threadId % 256));
                                }
                            }
                        }
                        catch(Exception ex)
                        {
                            exceptions.Add(ex);
                        }
                    }, TestContext.CancellationToken);
                }

                Task.WaitAll(tasks, TestContext.CancellationToken);

                Assert.IsTrue(exceptions.IsEmpty, $"No exceptions should occur during concurrent operations. Found: {string.Join(", ", exceptions)}.");
            });
        }


        [TestMethod]
        public void PropertyMemoryIsClearedAfterDisposal()
        {
            Gen.Int[1, 1000].Sample(bufferSize =>
            {
                using var pool = new SensitiveMemoryPool<byte>();

                //The underlying array can't be accessed after disposal. So, the test checks indirectly via
                //disposal and attempting to access the disposed buffer.
                var buffer = pool.Rent(bufferSize);

                //Fill with non-zero pattern.
                buffer.Memory.Span.Fill(0xAA);

                //Dispose should clear the memory and make the buffer inaccessible.
                buffer.Dispose();

                //Accessing disposed buffer should throw.
                Assert.ThrowsExactly<ObjectDisposedException>(() => _ = buffer.Memory, "Accessing disposed buffer should throw ObjectDisposedException.");
            });
        }


        [TestMethod]
        public void PropertyHandlesVariousBufferSizeDistributions()
        {
            //Test common cryptographic buffer sizes.
            var cryptoSizes = new[] { 16, 20, 32, 48, 64, 128, 256, 384, 512, 1024 };

            Gen.Int[0, cryptoSizes.Length - 1].Array[1, 100].Sample(sizeIndices =>
            {
                using var pool = new SensitiveMemoryPool<byte>();
                var buffers = new List<IMemoryOwner<byte>>();
                try
                {
                    foreach(int index in sizeIndices)
                    {
                        int size = cryptoSizes[index];
                        var buffer = pool.Rent(size);
                        buffers.Add(buffer);

                        Assert.AreEqual(size, buffer.Memory.Length);
                    }
                }
                finally
                {
                    foreach(var buffer in buffers)
                    {
                        buffer.Dispose();
                    }
                }
            });
        }
    }
}
