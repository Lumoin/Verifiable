using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;


namespace Verifiable.Assessment
{
    /// <summary>
    /// Provides utilities for generating tracing information.
    /// </summary>
    public static class TracingUtilities
    {
        /// <summary>
        /// Retrieves the current <see cref="Activity.TraceId"/> or generates a new one if none exists.
        /// </summary>
        /// <returns>A string representing the TraceId.</returns>
        public static string GetOrCreateTraceId()
        {
            return Activity.Current?.TraceId.ToString() ?? Guid.NewGuid().ToString();
        }


        /// <summary>
        /// Retrieves the current <see cref="Activity.SpanId"/> or generates a new one if none exists.
        /// </summary>
        /// <returns>A string representing the SpanId.</returns>
        public static string GetOrCreateSpanId()
        {
            return Activity.Current?.SpanId.ToString() ?? Guid.NewGuid().ToString();
        }

        /// <summary>
        /// Retrieves the current
        /// </summary>
        /// <returns></returns>
        public static IReadOnlyDictionary<string, string> GetOrCreateBaggage()
        {
            return Activity.Current?.Baggage?.ToDictionary(kv => kv.Key ?? string.Empty, kv => kv.Value ?? string.Empty) ?? [];
        }
    }
}
