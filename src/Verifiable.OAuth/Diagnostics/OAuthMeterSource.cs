using System.Diagnostics.Metrics;

namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// The single <see cref="Meter"/> for all OAuth authorization server metrics.
/// The application wires the exporter via
/// <c>AddOpenTelemetry().WithMetrics(b => b.AddMeter(OAuthMeterSource.MeterName))</c>.
/// </summary>
public static class OAuthMeterSource
{
    /// <summary>
    /// The meter name registered with the .NET metrics infrastructure.
    /// Pass this to <c>AddMeter</c> in the application's OTel configuration.
    /// </summary>
    public static readonly string MeterName = "Verifiable.OAuth.Server";

    /// <summary>
    /// The shared <see cref="Meter"/> instance.
    /// </summary>
    public static Meter Meter { get; } = new(MeterName);
}
