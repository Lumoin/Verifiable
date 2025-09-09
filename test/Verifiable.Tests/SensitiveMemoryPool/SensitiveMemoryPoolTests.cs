using CsCheck;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Verifiable.Core;
using Verifiable.Core.Cryptography;

namespace Verifiable.Tests.SensitiveMemoryPool
{
    [TestClass]
    public sealed class SensitiveMemoryPoolTests
    {
        public TestContext TestContext { get; set; }


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
                    await Task.Delay(TimeSpan.FromMilliseconds(10), TestContext.CancellationTokenSource.Token);

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
            //Clear any ambient activity state from other tests.
            Activity.Current = null;

            //Create a unique trace ID for this test to filter out activities from other tests.
            using var testRoot = new Activity("TestRoot").Start();
            var testTraceId = testRoot.TraceId;

            var activities = new List<Activity>();

            using var activityListener = new ActivityListener
            {
                //Only listen to SensitiveMemoryPool to avoid capturing unrelated activities.
                ShouldListenTo = source => source.Name == "SensitiveMemoryPool",
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity =>
                {
                    //Only capture activities that are part of this test's trace.
                    if(activity.TraceId == testTraceId)
                    {
                        activities.Add(activity);
                    }
                }
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

            testRoot.Stop();

            //Should have recorded rent and dispose activities (2 rents + 2 disposes = 4 total).
            Assert.IsGreaterThanOrEqualTo(4, activities.Count, "Should have at least 4 activities (2 rent + 2 dispose).");

            var rentActivities = activities.Where(a => a.OperationName == "Rent").ToList();
            Assert.HasCount(2, rentActivities, "Should have exactly 2 rent activities.");

            //Verify activity tags contain buffer size information.
            var firstRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "100");
            var secondRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "200");

            Assert.IsNotNull(firstRent, "Should have rent activity for 100-byte buffer.");
            Assert.IsNotNull(secondRent, "Should have rent activity for 200-byte buffer.");

            //Also verify we have dispose activities.
            var disposeActivities = activities.Where(a => a.OperationName == "Dispose").ToList();
            Assert.HasCount(2, disposeActivities, "Should have exactly 2 dispose activities.");
        }


        [TestMethod]
        public async Task TracingMaintainsParentChildRelationships()
        {
            //Clear any ambient activity state from other tests.
            Activity.Current = null;

            var capturedActivities = new ConcurrentBag<Activity>();

            using var listener = new ActivityListener
            {
                ShouldListenTo = source => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity => capturedActivities.Add(activity)
            };

            ActivitySource.AddActivityListener(listener);

            //Create a parent activity.
            using var parentSource = new ActivitySource("TestSource");
            using var parentActivity = parentSource.StartActivity("ParentActivity", ActivityKind.Internal);

            Assert.IsNotNull(parentActivity, "Parent activity should be created");

            //Record the parent's TraceId to filter activities from this specific test run.
            //This is critical because the listener may capture activities from other tests
            //that are still in flight or were run previously in the same test session.
            var expectedTraceId = parentActivity.TraceId;

            using var pool = new SensitiveMemoryPool<byte>();

            using(var rentedMemory = pool.Rent(100))
            {
                //Simulate async work to ensure activities flow correctly through async context.
                //This verifies that the parent-child relationship is maintained even when
                //the disposal happens after an async operation.
                await Task.Delay(TimeSpan.FromMilliseconds(10), TestContext.CancellationTokenSource.Token);
            }

            //Wait to ensure all activities are fully captured and stopped.
            //Without this delay, the Dispose activity might not be captured yet.
            await Task.Delay(TimeSpan.FromMilliseconds(50), TestContext.CancellationTokenSource.Token);

            //Filter to ONLY activities from this test run by TraceId.
            //This eliminates interference from other tests that may have run before.
            var activities = capturedActivities
                .Where(a => a.TraceId == expectedTraceId)
                .ToList();

            //Debug output to help diagnose issues if the test fails.
            TestContext.WriteLine($"Activities from this test run: {activities.Count}");
            foreach(var act in activities)
            {
                TestContext.WriteLine($"Activity: {act.OperationName}, TraceId: {act.TraceId}, SpanId: {act.SpanId}, ParentSpanId: {act.ParentSpanId}");
            }

            //Find our specific activities.
            var rentAct = activities.FirstOrDefault(a => a.OperationName == "Rent");
            var disposeAct = activities.FirstOrDefault(a => a.OperationName == "Dispose");

            Assert.IsNotNull(rentAct, "Should have captured Rent activity");
            Assert.IsNotNull(disposeAct, "Should have captured Dispose activity");

            //Verify parent-child relationships.
            //The Rent activity should be a child of our test's parent activity.
            Assert.AreEqual(parentActivity.SpanId, rentAct.ParentSpanId, "Rent should be child of parent");

            //The Dispose activity should be a child of the Rent activity.
            //This verifies that our fix to set Activity.Current = RentActivity works correctly.
            Assert.AreEqual(rentAct.SpanId, disposeAct.ParentSpanId, "Dispose should be child of Rent");
        }
    }
}