using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;


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
            return Activity.Current?.TraceId.ToString() ?? Activity.TraceIdGenerator?.Invoke().ToHexString() ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

        }


        /// <summary>
        /// Retrieves the current <see cref="Activity.TraceFlags"/> or generates a new one if none exists.
        /// </summary>
        /// <returns>A string representing not sampled and produced in random flags <c>'02'</c>.</returns>
        public static string GetOrCreateTraceFlags()
        {
            //TODO: "02" can be depedent on Activity.TraceIdGenerator?
            const string NotSampledAndValuesProducesinRandom = "02";
            return Activity.Current?.ActivityTraceFlags.ToString() ?? NotSampledAndValuesProducesinRandom;
        }


        /// <summary>
        /// Retrieves the current <see cref="Activity.SpanId"/> or generates a new one if none exists.
        /// </summary>
        /// <returns>A string representing the SpanId.</returns>
        public static string GetOrCreateSpanId()
        {            
            return Activity.Current?.SpanId.ToString() ?? Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
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
