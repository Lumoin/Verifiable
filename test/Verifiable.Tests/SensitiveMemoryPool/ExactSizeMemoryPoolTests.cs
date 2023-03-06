using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Diagnostics.Tracing;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Core.Cryptography;
using Xunit;

namespace Verifiable.Core.SensitiveMemoryPool
{
    class MetricsEventListener: EventListener
    {
        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if(eventSource.Name == "System.Diagnostics.Metrics")
            {
                var args = new Dictionary<string, string?>
                {
                    ["Metrics"] = "ExactSizeMemoryPool\\SpecificInstrument"
                };
                EnableEvents(eventSource, EventLevel.LogAlways, EventKeywords.All, args);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if(eventData.EventName == "TotalSlabs")
            {
                Console.WriteLine($"{eventData.EventId}; {eventData.EventName}; {eventData?.Payload?[6]}");
                // TODO use eventData.PayloadNames and eventData.Payload to get the data
            }
            else
            {
                Console.WriteLine($"{eventData.EventId}; {eventData.EventName}");
                // TODO use eventData.PayloadNames and eventData.Payload to get the data
            }
        }
    }


    public class ExactSizeMemoryPoolTestsWitByte
    {
        [Fact]
        public void BuffersAreExactlyRequestedSize()
        {            
            var pool = new ExactSizeMemoryPool<byte>();
            for(int round = 0; round < 2; ++round)
            {
                for(int i = 1; i <= 256; ++i)
                {
                    var buffer = pool.Rent(i);
                    Assert.Equal(i, buffer.Memory.Length);
                    buffer.Dispose();
                }
            }
        }


        [Fact]
        public async Task MetricsAreReportedCorrectly()
        {
            var meter = new Meter("ExactSizeMemoryPool", "1.0.0");

            // Create a dictionary to store reported metrics
            var reportedMetrics = new ConcurrentDictionary<string, long>();

            // Create a MeterListener with a callback to store the reported metrics
            var listener = new MeterListener();
            var listener2 = new MetricsEventListener();

            listener.InstrumentPublished = (instrument, listener) =>
            {
                if(instrument.Meter == meter) // Only subscribe to instruments from the provided Meter
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

            // Create a new ExactSizeMemoryPool instance
            var pool = new ExactSizeMemoryPool<byte>(meter);

            // Rent buffers of different sizes
            using(pool.Rent(100))
            {
                using(pool.Rent(200))
                {
                    listener.RecordObservableInstruments();
                    // Allow some time for the metrics to be collected
                    await Task.Delay(TimeSpan.FromSeconds(1));

                    // Check that the metrics have the correct values
                    bool found = reportedMetrics.TryGetValue("TotalSlabs", out long totalSlabs);
                    Assert.True(found);
                    Assert.Equal(2, totalSlabs);

                    Assert.True(reportedMetrics.TryGetValue("TotalMemoryUsed", out long totalMemoryUsed));
                    Assert.Equal(100 * ExactSizeMemoryPool<byte>.InitialSlabCapacity + 200 * ExactSizeMemoryPool<byte>.InitialSlabCapacity, totalMemoryUsed);
                }
            }

            listener.Dispose();
        }


        [Fact(Skip = "Work in progress.")]
        public void TracingTest()
        {
            var activityListener = new ActivityListener
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity => { },
                ActivityStopped = activity => { }
            };

            ActivitySource.AddActivityListener(activityListener);

            var activities = new List<Activity>();

            activityListener.ActivityStarted = activity =>
            {
                lock(activities)
                {
                    activities.Add(activity);
                }
            };

            using var memoryPool = new ExactSizeMemoryPool<byte>();

            using(var owner1 = memoryPool.Rent(100))
            {
            }

            using(var owner2 = memoryPool.Rent(200))
            {
            }

            //ActivitySource.RemoveActivityListener(activityListener);

            Assert.Equal(4, activities.Count);
            Assert.Collection(activities,
                activity => Assert.Equal("Rent", activity.OperationName),
                activity => Assert.Equal("Dispose", activity.OperationName),
                activity => Assert.Equal("Rent", activity.OperationName),
                activity => Assert.Equal("Dispose", activity.OperationName)
            );

            Assert.Equal("100", activities[0].Tags.FirstOrDefault(tag => tag.Key == "bufferSize").Value);
            Assert.Equal("100", activities[1].Tags.FirstOrDefault(tag => tag.Key == "bufferSize").Value);
            Assert.Equal("200", activities[2].Tags.FirstOrDefault(tag => tag.Key == "bufferSize").Value);
            Assert.Equal("200", activities[3].Tags.FirstOrDefault(tag => tag.Key == "bufferSize").Value);
        }


        [Fact(Skip = "Work in progress.")]
        public async Task TracingTest2()
        {
            List<Activity> capturedActivities = new List<Activity>();

            using var listener = new ActivityListener
            {
                ShouldListenTo = _ => true,
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStarted = activity => { capturedActivities.Add(activity); }
            };

            ActivitySource.AddActivityListener(listener);

            using(var parentActivity = new Activity("ParentActivity"))
            {
                parentActivity.Start();
                var pool = new ExactSizeMemoryPool<byte>();

                using(var rentedMemory = pool.Rent(100))
                {
                    await Task.Delay(100);
                }
            }

            Assert.Equal(3, capturedActivities.Count);

            var rentActivity = capturedActivities.FirstOrDefault(a => a.OperationName == "Rent");
            var disposeActivity = capturedActivities.FirstOrDefault(a => a.OperationName == "Dispose");
            var parentActivity2 = capturedActivities.FirstOrDefault(a => a.OperationName == "ParentActivity");

            Assert.NotNull(rentActivity);
            Assert.NotNull(disposeActivity);
            Assert.NotNull(parentActivity2);

            Assert.Equal(parentActivity2.TraceId, rentActivity.TraceId);
            Assert.Equal(parentActivity2.TraceId, disposeActivity.TraceId);

            Assert.Equal(parentActivity2.SpanId, rentActivity.ParentSpanId);
            Assert.Equal(rentActivity.SpanId, disposeActivity.ParentSpanId);
        }
    }
}
