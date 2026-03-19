using System.Diagnostics;

namespace Verifiable.OAuth.Diagnostics;

/// <summary>
/// The single <see cref="ActivitySource"/> for all OAuth authorization server
/// operations. Flow modules, endpoint handlers, and validation checks emit
/// activities and events through this source.
/// </summary>
/// <remarks>
/// <para>
/// The application wires the exporter via
/// <c>AddOpenTelemetry().WithTracing(b => b.AddSource(OAuthActivitySource.SourceName))</c>.
/// No OTel packages are referenced by the library — <see cref="ActivitySource"/>
/// is built into <c>System.Diagnostics</c>.
/// </para>
/// </remarks>
public static class OAuthActivitySource
{
    /// <summary>
    /// The source name registered with the .NET diagnostics infrastructure.
    /// Pass this to <c>AddSource</c> in the application's OTel configuration.
    /// </summary>
    public static readonly string SourceName = "Verifiable.OAuth.Server";

    /// <summary>
    /// The shared <see cref="ActivitySource"/> instance.
    /// </summary>
    public static ActivitySource Source { get; } = new(SourceName);
}
