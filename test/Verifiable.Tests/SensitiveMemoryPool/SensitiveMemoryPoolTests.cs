using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using Verifiable.Core;
using Verifiable.Cryptography;

namespace Verifiable.Tests.SensitiveMemoryPool
{
    [TestClass]
    internal sealed class SensitiveMemoryPoolTests
    {
        public TestContext TestContext { get; set; } = null!;


        [TestMethod]
        public void RentReturnsExactBufferSize()
        {
            using var pool = new SensitiveMemoryPool<byte>();

            int[] testSizes = [1, 16, 32, 64, 128, 256, 512, 1024];

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
                for(int i = 0; i < rentCount; i++)
                {
                    buffers.Add(pool.Rent(bufferSize));
                }

                foreach(var buffer in buffers)
                {
                    Assert.AreEqual(bufferSize, buffer.Memory.Length);
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


        [TestMethod]
        public void DisposeClearsMemoryAndPreventsAccess()
        {
            using var pool = new SensitiveMemoryPool<byte>();
            var buffer = pool.Rent(32);

            buffer.Memory.Span.Fill(0xFF);
            buffer.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => _ = buffer.Memory);
        }


        [TestMethod]
        public void DoubleDisposeIsIdempotent()
        {
            using var pool = new SensitiveMemoryPool<byte>();
            var buffer = pool.Rent(32);

            buffer.Memory.Span.Fill(0xFF);
            buffer.Dispose();

            //Second dispose should not throw.
            buffer.Dispose();
        }


        [TestMethod]
        public void ReturnedMemoryIsZeroed()
        {
            using var meter = new Meter("Test", "1.0.0");
            using var pool = new SensitiveMemoryPool<byte>(
                meter,
                capacityStrategy: _ => 1);

            //Rent, fill with a recognizable pattern, and return.
            var first = pool.Rent(32);
            first.Memory.Span.Fill(0xDE);
            first.Dispose();

            //Rent again from the same slab and verify the memory is zeroed.
            using var second = pool.Rent(32);
            foreach(byte b in second.Memory.Span)
            {
                Assert.AreEqual(0, b, "Returned memory must be zeroed for security.");
            }
        }


        [TestMethod]
        public void RentHandlesEdgeCases()
        {
            using var pool = new SensitiveMemoryPool<byte>();

            using(var buffer = pool.Rent(1))
            {
                Assert.AreEqual(1, buffer.Memory.Length);
            }

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
        public void DisposingRentalAfterPoolDisposedDoesNotThrow()
        {
            var pool = new SensitiveMemoryPool<byte>();
            var owner = pool.Rent(32);
            owner.Memory.Span.Fill(0xCC);

            //Disposing the pool clears all slabs while a rental is still active.
            pool.Dispose();

            //The rental's Dispose calls Pool.Return on an already-disposed slab.
            //This must not throw — the error is caught internally and the lifecycle
            //activity records an error status instead.
            owner.Dispose();
        }


        [TestMethod]
        public void TrimExcessThrowsWhenPoolDisposed()
        {
            var pool = new SensitiveMemoryPool<byte>();
            pool.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => pool.TrimExcess());
        }


        [TestMethod]
        public void SharedReturnsSingletonInstance()
        {
            var first = SensitiveMemoryPool<byte>.Shared;
            var second = SensitiveMemoryPool<byte>.Shared;

            Assert.AreSame(first, second, "Shared should return the same instance.");

            using var buffer = first.Rent(64);
            Assert.AreEqual(64, buffer.Memory.Length);
        }


        [TestMethod]
        public void DefaultCapacityStrategyReturnsMoreSegmentsForSmallerSizes()
        {
            int smallCapacity = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(32);
            int mediumCapacity = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(128);
            int largeCapacity = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(8192);

            Assert.IsGreaterThan(mediumCapacity, smallCapacity,
                "Small buffers should get more segments per slab than medium buffers.");
            Assert.IsGreaterThan(largeCapacity, mediumCapacity,
                "Medium buffers should get more segments per slab than large buffers.");
        }


        [TestMethod]
        public void CustomCapacityStrategyIsUsed()
        {
            int strategyCallCount = 0;

            int customStrategy(int segmentSize)
            {
                Interlocked.Increment(ref strategyCallCount);
                return 2;
            }

            using var meter = new Meter("Test", "1.0.0");
            using var pool = new SensitiveMemoryPool<byte>(
                meter,
                capacityStrategy: customStrategy);

            //Rent three buffers of the same size to force slab creation and overflow.
            using var b1 = pool.Rent(32);
            using var b2 = pool.Rent(32);
            using var b3 = pool.Rent(32);

            //The strategy should have been invoked at least twice (first slab holds 2, second slab for the third rent).
            Assert.IsGreaterThanOrEqualTo(2, strategyCallCount,
                $"Custom strategy should have been called at least twice, was called {strategyCallCount} times.");
        }


        [TestMethod]
        public void TrimExcessReclaimsUnusedSlabs()
        {
            using var meter = new Meter("Test", "1.0.0");
            using var pool = new SensitiveMemoryPool<byte>(
                meter,
                capacityStrategy: _ => 2);

            //Hold three buffers simultaneously to force creation of a second slab (capacity 2 per slab).
            var b1 = pool.Rent(32);
            var b2 = pool.Rent(32);
            var b3 = pool.Rent(32);

            //Return all buffers so both slabs become fully available.
            b1.Dispose();
            b2.Dispose();
            b3.Dispose();

            int reclaimed = pool.TrimExcess();
            Assert.IsGreaterThan(0, reclaimed, "TrimExcess should reclaim at least one unused slab.");
        }


        [TestMethod]
        public void TrimExcessDoesNotReclaimSlabsWithActiveRentals()
        {
            using var meter = new Meter("Test", "1.0.0");
            using var pool = new SensitiveMemoryPool<byte>(
                meter,
                capacityStrategy: _ => 2);

            //Keep a rental alive so the slab cannot be reclaimed.
            using var active = pool.Rent(32);

            int reclaimed = pool.TrimExcess();
            Assert.AreEqual(0, reclaimed, "TrimExcess should not reclaim slabs with active rentals.");
        }


        [TestMethod]
        public void RentWorksAfterTrimExcess()
        {
            using var meter = new Meter("Test", "1.0.0");
            using var pool = new SensitiveMemoryPool<byte>(
                meter,
                capacityStrategy: _ => 2);

            //Create slabs, return everything, then trim.
            var b1 = pool.Rent(64);
            var b2 = pool.Rent(64);
            b1.Dispose();
            b2.Dispose();
            pool.TrimExcess();

            //Pool should create fresh slabs on demand after trimming.
            using var afterTrim = pool.Rent(64);
            Assert.AreEqual(64, afterTrim.Memory.Length, "Rent should work after TrimExcess reclaims slabs.");
        }


        [TestMethod]
        public void TracingCanBeDisabled()
        {
            var activities = new ConcurrentBag<Activity>();
            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == "SensitiveMemoryPool",
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity => activities.Add(activity)
            };
            ActivitySource.AddActivityListener(listener);

            using var meter = new Meter("Test", "1.0.0");
            using var pool = new SensitiveMemoryPool<byte>(
                meter,
                tracingEnabled: false);

            using(pool.Rent(32)) { }

            Assert.IsEmpty(activities,
                "No activities should be created when tracing is disabled.");
        }


        [TestMethod]
        public async Task MetricsAreReportedCorrectly()
        {
            using var meter = new Meter(VerifiableMetrics.CoreMeterName, "1.0.0");
            var reportedMetrics = new ConcurrentDictionary<string, long>();

            using var listener = new MeterListener();

            listener.InstrumentPublished = (instrument, meterListener) =>
            {
                if(instrument.Meter == meter)
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            };

            listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
            {
                reportedMetrics.AddOrUpdate(instrument.Name, measurement, (_, _) => measurement);
            });

            listener.SetMeasurementEventCallback<int>((instrument, measurement, tags, state) =>
            {
                reportedMetrics.AddOrUpdate(instrument.Name, measurement, (_, _) => measurement);
            });

            listener.Start();

            using var pool = new SensitiveMemoryPool<byte>(meter);

            using(pool.Rent(100))
            {
                using(pool.Rent(200))
                {
                    listener.RecordObservableInstruments();
                    await Task.Delay(TimeSpan.FromMilliseconds(10), TestContext.CancellationToken).ConfigureAwait(false);

                    bool foundSlabs = reportedMetrics.TryGetValue(CryptographyMetrics.SensitiveMemoryPoolTotalSlabs, out long totalSlabs);
                    Assert.IsTrue(foundSlabs, "TotalSlabs metric should be reported.");
                    Assert.AreEqual(2, totalSlabs, "Should have created two slabs for different buffer sizes.");

                    bool foundMemory = reportedMetrics.TryGetValue(CryptographyMetrics.SensitiveMemoryPoolTotalMemoryAllocated, out long totalMemory);
                    Assert.IsTrue(foundMemory, "TotalMemoryAllocated metric should be reported.");

                    //Expected memory uses the default capacity strategy.
                    int expectedCapacity100 = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(100);
                    int expectedCapacity200 = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(200);
                    long expectedMemory = (100 * expectedCapacity100) + (200 * expectedCapacity200);
                    Assert.AreEqual(expectedMemory, totalMemory, "Total memory should match expected allocation.");
                }
            }
        }


        [TestMethod]
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Analyzer false positive on testRoot.")]
        public void TracingRecordsSingleLifecycleActivityPerRental()
        {
            Activity.Current = null;

            using var testRoot = new Activity("TestRoot").Start();
            var testTraceId = testRoot.TraceId;

            var activities = new List<Activity>();

            using var activityListener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == "SensitiveMemoryPool",
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity =>
                {
                    if(activity.TraceId == testTraceId)
                    {
                        activities.Add(activity);
                    }
                }
            };

            ActivitySource.AddActivityListener(activityListener);

            using var pool = new SensitiveMemoryPool<byte>();

            using(pool.Rent(100)) { }
            using(pool.Rent(200)) { }

            testRoot.Stop();

            //Single-activity model: one "Rent" activity per rental lifecycle, no separate "Dispose" activity.
            var rentActivities = activities.Where(a => a.OperationName == "Rent").ToList();
            Assert.HasCount(2, rentActivities, "Should have exactly two lifecycle activities.");

            var firstRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "100");
            var secondRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "200");

            Assert.IsNotNull(firstRent, "Should have lifecycle activity for 100-byte buffer.");
            Assert.IsNotNull(secondRent, "Should have lifecycle activity for 200-byte buffer.");

            //No separate dispose activities should exist.
            var disposeActivities = activities.Where(a => a.OperationName == "Dispose").ToList();
            Assert.HasCount(0, disposeActivities,
                "Single-activity model should not create separate dispose activities.");
        }


        [TestMethod]
        public async Task TracingMaintainsParentChildRelationships()
        {
            Activity.Current = null;

            var capturedActivities = new ConcurrentBag<Activity>();

            using var listener = new ActivityListener
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity => capturedActivities.Add(activity)
            };

            ActivitySource.AddActivityListener(listener);

            using var parentSource = new ActivitySource("TestSource");
            using var parentActivity = parentSource.StartActivity("ParentActivity", ActivityKind.Internal);

            Assert.IsNotNull(parentActivity, "Parent activity should be created.");

            var expectedTraceId = parentActivity.TraceId;

            using var pool = new SensitiveMemoryPool<byte>();

            using(pool.Rent(100))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(10), TestContext.CancellationToken).ConfigureAwait(false);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50), TestContext.CancellationToken).ConfigureAwait(false);

            var activities = capturedActivities
                .Where(a => a.TraceId == expectedTraceId)
                .ToList();

            TestContext.WriteLine($"Activities from this test run: {activities.Count}.");
            foreach(var act in activities)
            {
                TestContext.WriteLine($"Activity: {act.OperationName}, SpanId: {act.SpanId}, ParentSpanId: {act.ParentSpanId}.");
            }

            var rentAct = activities.FirstOrDefault(a => a.OperationName == "Rent");
            Assert.IsNotNull(rentAct, "Should have captured the lifecycle activity.");

            Assert.AreEqual(parentActivity.SpanId, rentAct.ParentSpanId,
                "Lifecycle activity should be a child of the parent activity.");
        }


        [TestMethod]
        public async Task DisposeRestoresAmbientActivityToParent()
        {
            Activity.Current = null;

            using var listener = new ActivityListener
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded
            };

            ActivitySource.AddActivityListener(listener);

            using var parentSource = new ActivitySource("TestSource");
            using var parentActivity = parentSource.StartActivity("CallerActivity", ActivityKind.Internal);

            Assert.IsNotNull(parentActivity, "Parent activity should be created.");
            Assert.AreSame(parentActivity, Activity.Current,
                "Parent should be the ambient activity before rent.");

            using var pool = new SensitiveMemoryPool<byte>();

            //During the rental scope, Activity.Current is the lifecycle activity (child of parent).
            var owner = pool.Rent(64);
            Assert.AreEqual("Rent", Activity.Current?.OperationName,
                "During rental scope, Activity.Current should be the lifecycle activity.");
            Assert.AreEqual(parentActivity.SpanId, Activity.Current?.ParentSpanId,
                "Lifecycle activity should be a child of the caller's activity.");

            //Dispose stops the lifecycle activity, which restores Activity.Current to its parent.
            owner.Dispose();
            Assert.AreSame(parentActivity, Activity.Current,
                "After dispose, Activity.Current should be restored to the parent.");

            //Verify the same holds across an async boundary with ConfigureAwait(false).
            var owner2 = pool.Rent(64);
            await Task.Delay(TimeSpan.FromMilliseconds(5), TestContext.CancellationToken).ConfigureAwait(false);
            owner2.Dispose();

            //After ConfigureAwait(false), Activity.Current flows via AsyncLocal.
            //Activity.Stop restores it to the parent on whatever thread the continuation runs on.
            var afterAsync = Activity.Current;
            if(afterAsync is not null)
            {
                Assert.AreSame(parentActivity, afterAsync,
                    "After async dispose, ambient activity should be the caller's, not the pool's.");
            }
        }


        [TestMethod]
        public async Task RentOnOneThreadDisposeOnAnotherWithConfigureAwaitFalse()
        {
            using var pool = new SensitiveMemoryPool<byte>();

            //Rent on the current thread.
            var owner = pool.Rent(128);
            owner.Memory.Span.Fill(0xBB);

            //Force a thread switch via ConfigureAwait(false).
            await Task.Yield();
            await Task.Delay(TimeSpan.FromMilliseconds(5), TestContext.CancellationToken).ConfigureAwait(false);

            //Dispose may now execute on a thread pool thread.
            owner.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => _ = owner.Memory,
                "Buffer must be inaccessible after cross-thread dispose.");

            //Pool should still be functional after cross-thread return.
            using var subsequent = pool.Rent(128);
            Assert.AreEqual(128, subsequent.Memory.Length,
                "Pool must remain usable after cross-thread disposal.");
        }


        [TestMethod]
        public async Task ConfigureAwaitTruePreservesActivityContext()
        {
            Activity.Current = null;

            var capturedActivities = new ConcurrentBag<Activity>();

            using var listener = new ActivityListener
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity => capturedActivities.Add(activity)
            };

            ActivitySource.AddActivityListener(listener);

            using var parentSource = new ActivitySource("TestSource");
            using var parentActivity = parentSource.StartActivity("CallerContext", ActivityKind.Internal);

            Assert.IsNotNull(parentActivity, "Parent activity should be created.");

            var expectedTraceId = parentActivity.TraceId;

            using var pool = new SensitiveMemoryPool<byte>();

            //ConfigureAwait(true) preserves the synchronization context when available.
            using(pool.Rent(64))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(10), TestContext.CancellationToken).ConfigureAwait(true);
            }

            var rentAct = capturedActivities.FirstOrDefault(
                a => a.Source.Name == "SensitiveMemoryPool" && a.TraceId == expectedTraceId);

            Assert.IsNotNull(rentAct, "Lifecycle activity should share the parent trace.");
            Assert.AreEqual(parentActivity.SpanId, rentAct.ParentSpanId,
                "Lifecycle activity should be a child of the caller's activity.");
        }


        [TestMethod]
        public async Task ConcurrentRentAndDisposeAcrossThreads()
        {
            using var pool = new SensitiveMemoryPool<byte>();

            var tasks = Enumerable.Range(0, 50).Select(async i =>
            {
                var owner = pool.Rent((i % 8 + 1) * 16);
                owner.Memory.Span.Fill((byte)(i % 256));

                //Yield to force potential thread switches.
                await Task.Yield();

                int length = owner.Memory.Length;
                owner.Dispose();

                return length;
            }).ToArray();

            int[] results = await Task.WhenAll(tasks).ConfigureAwait(false);

            Assert.HasCount(50, results, "All concurrent rent-dispose cycles should complete.");
        }
    }
}