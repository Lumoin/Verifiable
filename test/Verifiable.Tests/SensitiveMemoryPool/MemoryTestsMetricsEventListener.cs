using System.Diagnostics.Tracing;
using Verifiable.Core;

namespace Verifiable.Tests.SensitiveMemoryPool
{
    /// <summary>
    /// Event listener for capturing metrics events during testing.
    /// </summary>
    class MemoryTestsMetricsEventListener: EventListener
    {
        private Dictionary<string, object> CapturedMetrics { get; } = [];

        public Dictionary<string, object> GetCapturedMetrics() => new(CapturedMetrics);


        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if(eventSource.Name.Equals("System.Diagnostics.Metrics", StringComparison.Ordinal))
            {
                var args = new Dictionary<string, string?>
                {
                    ["Metrics"] = VerifiableMetrics.CoreMeterName
                };

                EnableEvents(eventSource, EventLevel.LogAlways, EventKeywords.All, args);
            }
        }


        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if(eventData.EventName?.Contains("Counter", StringComparison.Ordinal) == true
                || eventData.EventName?.Contains("Histogram", StringComparison.Ordinal) == true)
            {
                //Capture metric events for verification.
                if(eventData.PayloadNames != null && eventData.Payload != null)
                {
                    for(int i = 0; i < eventData.PayloadNames.Count; i++)
                    {
                        CapturedMetrics[eventData.PayloadNames[i]] = eventData.Payload[i] ?? string.Empty;
                    }
                }
            }
        }
    }
}
