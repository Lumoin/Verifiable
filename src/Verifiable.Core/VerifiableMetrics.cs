namespace Verifiable.Core
{
    /// <summary>
    /// Centralized constants for Verifiable.Core library metrics and meter names.
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
    ///         .AddMeter(VerifiableMetrics.DidMeterName)
    ///         .AddMeter(VerifiableMetrics.VcMeterName)
    ///         .AddPrometheusExporter());
    /// </code>
    ///
    /// Individual metric names are used by monitoring dashboards, alert rules, and
    /// analysis tools to query specific metrics.
    ///
    /// For cryptography-related metrics (such as SensitiveMemoryPool), see
    /// <see cref="Verifiable.Cryptography.CryptographyMetrics"/>.
    /// </remarks>
    public static class VerifiableMetrics
    {
        /// <summary>
        /// Primary meter name for core Verifiable library components.
        /// Register this meter name in your metrics collection configuration to collect
        /// core library metrics related to general operations and performance counters.
        /// </summary>
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


        //DID operation metrics.

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


        //VC operation metrics.

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