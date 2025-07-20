using CsCheck;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Diagnostics.Tracing;
using Verifiable.Core;
using Verifiable.Core.Cryptography;

namespace Verifiable.Tests.SensitiveMemoryPool
{



    [TestClass]
    public sealed class SensitiveMemoryPoolTests
    {
        [TestMethod]
        public void RentReturnsExactBufferSize()
        {
            using var pool = new SensitiveMemoryPool<byte>();

            //Test various buffer sizes to ensure exact sizing.
            int[] testSizes = { 1, 16, 32, 64, 128, 256, 512, 1024 };

            foreach(int size in testSizes)
            {
                using var buffer = pool.Rent(size);
                Assert.AreEqual(size, buffer.Memory.Length, $"Buffer size should be exactly {size} bytes.");
            }
        }


        [TestMethod]
        public void RentReusesSlabsForSameSize()
        {
            using var pool = new SensitiveMemoryPool<byte>();
            const int bufferSize = 64;
            const int rentCount = 10;

            var buffers = new List<IMemoryOwner<byte>>();

            try
            {
                //Rent multiple buffers of the same size.
                for(int i = 0; i < rentCount; i++)
                {
                    buffers.Add(pool.Rent(bufferSize));
                }

                //All buffers should have the correct size.
                foreach(var buffer in buffers)
                {
                    Assert.AreEqual(bufferSize, buffer.Memory.Length);
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


        [TestMethod]
        public void DisposeClearsMemoryAndPreventsAccess()
        {
            using var pool = new SensitiveMemoryPool<byte>();
            var buffer = pool.Rent(32);

            //Fill buffer with non-zero data.
            buffer.Memory.Span.Fill(0xFF);

            //Dispose should clear the memory.
            buffer.Dispose();

            //Accessing disposed buffer should throw.
            Assert.ThrowsExactly<ObjectDisposedException>(() => _ = buffer.Memory);
        }


        [TestMethod]
        public void RentHandlesEdgeCases()
        {
            using var pool = new SensitiveMemoryPool<byte>();

            //Test minimum valid size.
            using(var buffer = pool.Rent(1))
            {
                Assert.AreEqual(1, buffer.Memory.Length);
            }

            //Test invalid sizes.
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => pool.Rent(0));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => pool.Rent(-1));
        }


        [TestMethod]
        public void RentThrowsWhenPoolDisposed()
        {
            var pool = new SensitiveMemoryPool<byte>();
            pool.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => pool.Rent(32));
        }


        [TestMethod]
        public void SharedReturnsWorkingPoolInstance()
        {
            var sharedPool = SensitiveMemoryPool<byte>.Shared;

            using var buffer = sharedPool.Rent(64);
            Assert.AreEqual(64, buffer.Memory.Length);
        }


        [TestMethod]
        public async Task MetricsAreReportedCorrectly()
        {
            var meter = new Meter(VerifiableMetrics.CoreMeterName, "1.0.0");
            var reportedMetrics = new ConcurrentDictionary<string, long>();

            using var listener = new MeterListener();

            listener.InstrumentPublished = (instrument, listener) =>
            {
                if(instrument.Meter == meter)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };

            listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
            {
                reportedMetrics.AddOrUpdate(instrument.Name, measurement, (key, oldValue) => measurement);
            });

            listener.SetMeasurementEventCallback<int>((instrument, measurement, tags, state) =>
            {
                reportedMetrics.AddOrUpdate(instrument.Name, measurement, (key, oldValue) => measurement);
            });

            listener.Start();

            //Create pool instance with our meter.
            using var pool = new SensitiveMemoryPool<byte>(meter);

            //Rent buffers of different sizes to create slabs.
            using(pool.Rent(100))
            {
                using(pool.Rent(200))
                {
                    listener.RecordObservableInstruments();
                    await Task.Delay(TimeSpan.FromSeconds(1));

                    //Verify that total slabs metric was reported.
                    bool foundSlabs = reportedMetrics.TryGetValue(VerifiableMetrics.SensitiveMemoryPoolTotalSlabs, out long totalSlabs);
                    Assert.IsTrue(foundSlabs, "TotalSlabs metric should be reported.");
                    Assert.AreEqual(2, totalSlabs, "Should have created 2 slabs for different buffer sizes.");

                    //Verify that total memory allocated metric was reported.
                    bool foundMemory = reportedMetrics.TryGetValue(VerifiableMetrics.SensitiveMemoryPoolTotalMemoryAllocated, out long totalMemory);
                    Assert.IsTrue(foundMemory, "TotalMemoryAllocated metric should be reported.");

                    long expectedMemory = (100 + 200) * SensitiveMemoryPool<byte>.InitialSlabCapacity;
                    Assert.AreEqual(expectedMemory, totalMemory, "Total memory should match expected allocation.");
                }
            }

            listener.Dispose();
        }


        [TestMethod]
        public void TracingActivitiesAreProperlyCreated()
        {
            var activities = new List<Activity>();

            using var activityListener = new ActivityListener
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activities.Add
            };

            ActivitySource.AddActivityListener(activityListener);

            using var pool = new SensitiveMemoryPool<byte>();

            //Perform rent and dispose operations.
            using(var owner1 = pool.Rent(100))
            {
                //Rent operation should create an activity.
            }

            using(var owner2 = pool.Rent(200))
            {
                //Second rent operation should create another activity.
            }

            //Should have recorded rent and dispose activities.
            Assert.IsTrue(activities.Count >= 2, "Should have at least 2 activities (rent operations).");

            var rentActivities = activities.Where(a => a.OperationName == "Rent").ToList();
            Assert.AreEqual(2, rentActivities.Count, "Should have 2 rent activities.");

            //Verify activity tags contain buffer size information.
            var firstRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "100");
            var secondRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "200");

            Assert.IsNotNull(firstRent, "Should have rent activity for 100-byte buffer.");
            Assert.IsNotNull(secondRent, "Should have rent activity for 200-byte buffer.");
        }


        [TestMethod]
        public async Task TracingMaintainsParentChildRelationships()
        {
            var capturedActivities = new List<Activity>();

            using var listener = new ActivityListener
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = capturedActivities.Add
            };

            ActivitySource.AddActivityListener(listener);

            using var parentActivity = new Activity("ParentActivity");
            parentActivity.Start();

            using var pool = new SensitiveMemoryPool<byte>();

            using(var rentedMemory = pool.Rent(100))
            {
                await Task.Delay(100);
            }

            parentActivity.Stop();

            //Find our activities.
            var parentAct = capturedActivities.FirstOrDefault(a => a.OperationName == "ParentActivity");
            var rentAct = capturedActivities.FirstOrDefault(a => a.OperationName == "Rent");
            var disposeAct = capturedActivities.FirstOrDefault(a => a.OperationName == "Dispose");

            Assert.IsNotNull(parentAct, "Should have parent activity.");
            Assert.IsNotNull(rentAct, "Should have rent activity.");

            //Verify trace relationships.
            if(rentAct != null && parentAct != null)
            {
                Assert.AreEqual(parentAct.TraceId, rentAct.TraceId, "Rent should share trace ID with parent.");
                Assert.AreEqual(parentAct.SpanId, rentAct.ParentSpanId, "Rent should be child of parent.");
            }

            if(disposeAct != null && rentAct != null)
            {
                Assert.AreEqual(rentAct.TraceId, disposeAct.TraceId, "Dispose should share trace ID with rent.");
                Assert.AreEqual(rentAct.SpanId, disposeAct.ParentSpanId, "Dispose should be child of rent.");
            }
        }
    }
}