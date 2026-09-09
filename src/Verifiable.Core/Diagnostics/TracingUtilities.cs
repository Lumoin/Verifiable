using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;


namespace Verifiable.Core.Diagnostics
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
        /// <remarks>
        /// The fallback draw is <see cref="ActivityTraceId.CreateRandom"/> — the diagnostics framework's own
        /// W3C trace-context identifier minting, not a cryptographic key material draw, so it is the platform
        /// boundary itself rather than a caller-suppliable entropy seam: a trace id correlates log lines, it
        /// never gates access or authenticates anything.
        /// </remarks>
        public static string GetOrCreateTraceId()
        {
            return Activity.Current?.TraceId.ToString() ?? Activity.TraceIdGenerator?.Invoke().ToHexString() ?? ActivityTraceId.CreateRandom().ToHexString();

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
        /// <remarks>
        /// The fallback draw is <see cref="ActivitySpanId.CreateRandom"/> — the diagnostics framework's own
        /// span-identifier minting, not a cryptographic key material draw, so it is the platform boundary
        /// itself rather than a caller-suppliable entropy seam: a span id correlates log lines, it never
        /// gates access or authenticates anything.
        /// </remarks>
        public static string GetOrCreateSpanId()
        {
            return Activity.Current?.SpanId.ToString() ?? ActivitySpanId.CreateRandom().ToHexString();
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
