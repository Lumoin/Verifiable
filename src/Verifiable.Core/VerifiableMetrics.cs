namespace Verifiable.Core
{
    /// <summary>
    /// Centralized constants for all Verifiable library metrics and meter names.
    /// This class provides a single discoverable location for consumers who need to
    /// reference metric names for monitoring, alerting, or dashboard configuration.
    /// </summary>
    /// <remarks>
    /// Meter names are used by metrics collection infrastructure (like OpenTelemetry)
    /// to register which meters to collect from. When you register a meter name like
    /// "Verifiable.Core", the collector will gather ALL instruments (counters, histograms,
    /// gauges) created by ANY Meter instance with that exact name.
    ///
    /// Example usage in application startup:
    /// <code>
    /// services.AddOpenTelemetry()
    ///     .WithMetrics(builder => builder
    ///         .AddMeter(VerifiableMetrics.CoreMeterName)
    ///         .AddPrometheusExporter());
    /// </code>
    ///
    /// Individual metric names are used by monitoring dashboards, alert rules, and
    /// analysis tools to query specific metrics.
    /// </remarks>
    public static class VerifiableMetrics
    {
        /// <summary>
        /// Primary meter name for core Verifiable library components.
        /// Register this meter name in your metrics collection configuration to collect
        /// all core library metrics including memory pool, cryptographic operations, and
        /// performance counters.
        /// </summary>
        /// <remarks>
        /// When registered, this meter will collect metrics from all components that create
        /// Meter instances with this name, including SensitiveMemoryPool instances and
        /// future cryptographic operation metrics.
        /// </remarks>
        public static string CoreMeterName { get; } = "Verifiable.Core";

        /// <summary>
        /// Meter name specifically for DID (Decentralized Identifier) operations.
        /// Register this meter name to collect metrics related to DID resolution,
        /// validation, and document processing.
        /// </summary>
        public static string DidMeterName { get; } = "Verifiable.Did";

        /// <summary>
        /// Meter name specifically for VC (Verifiable Credential) operations.
        /// Register this meter name to collect metrics related to credential
        /// issuance, verification, and presentation.
        /// </summary>
        public static string VcMeterName { get; } = "Verifiable.VC";


        //SensitiveMemoryPool metrics - use these names for dashboard queries and alerts.

        /// <summary>
        /// Observable counter tracking total number of memory slabs across all buffer sizes.
        /// Higher values may indicate memory pressure or fragmentation.
        /// Unit: slabs (count)
        /// </summary>
        public static string SensitiveMemoryPoolTotalSlabs { get; } = "Verifiable.SensitiveMemoryPool.TotalSlabs";

        /// <summary>
        /// Observable counter tracking total memory allocated across all slabs.
        /// Includes both used and available segments.
        /// Unit: bytes
        /// </summary>
        public static string SensitiveMemoryPoolTotalMemoryAllocated { get; } = "Verifiable.SensitiveMemoryPool.TotalMemoryAllocated";

        /// <summary>
        /// Observable counter tracking number of currently rented memory segments.
        /// Indicates current memory pressure and active cryptographic operations.
        /// Unit: segments (count)
        /// </summary>
        public static string SensitiveMemoryPoolActiveRentals { get; } = "Verifiable.SensitiveMemoryPool.ActiveRentals";

        /// <summary>
        /// Observable counter tracking allocation efficiency as a percentage.
        /// Calculated as (active rentals / total allocated segments) * 100.
        /// Unit: percent (0-100)
        /// </summary>
        public static string SensitiveMemoryPoolAllocationEfficiency { get; } = "Verifiable.SensitiveMemoryPool.AllocationEfficiency";

        /// <summary>
        /// Histogram tracking distribution of requested buffer sizes.
        /// Helps identify optimization opportunities for common cryptographic buffer sizes.
        /// Unit: bytes
        /// </summary>
        public static string SensitiveMemoryPoolBufferSizeDistribution { get; } = "Verifiable.SensitiveMemoryPool.BufferSizeDistribution";

        /// <summary>
        /// Counter tracking total number of successful rent operations.
        /// Used for calculating allocation rates and throughput metrics.
        /// Unit: operations (cumulative count)
        /// </summary>
        public static string SensitiveMemoryPoolRentOperationsTotal { get; } = "Verifiable.SensitiveMemoryPool.RentOperationsTotal";

        /// <summary>
        /// Counter tracking total number of memory return operations.
        /// Should correlate with rent operations for proper resource management.
        /// Unit: operations (cumulative count)
        /// </summary>
        public static string SensitiveMemoryPoolReturnOperationsTotal { get; } = "Verifiable.SensitiveMemoryPool.ReturnOperationsTotal";

        //Future DID operation metrics.

        /// <summary>
        /// Histogram tracking time taken to resolve DID documents.
        /// Unit: milliseconds
        /// </summary>
        public static string DidResolutionDuration { get; } = "Verifiable.Did.ResolutionDuration";

        /// <summary>
        /// Counter tracking total number of DID resolution operations.
        /// Unit: operations (cumulative count)
        /// </summary>
        public static string DidResolutionOperationsTotal { get; } = "Verifiable.Did.ResolutionOperationsTotal";

        //Future VC operation metrics.

        /// <summary>
        /// Histogram tracking time taken to validate verifiable credentials.
        /// Unit: milliseconds
        /// </summary>
        public static string VcValidationDuration { get; } = "Verifiable.VC.ValidationDuration";

        /// <summary>
        /// Counter tracking total number of VC validation operations.
        /// Unit: operations (cumulative count)
        /// </summary>
        public static string VcValidationOperationsTotal { get; } = "Verifiable.VC.ValidationOperationsTotal";
    }
}
