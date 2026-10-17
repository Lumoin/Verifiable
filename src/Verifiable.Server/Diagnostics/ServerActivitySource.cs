using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.Server.Diagnostics;

/// <summary>
/// The single <see cref="ActivitySource"/> for all protocol-neutral endpoint host
/// operations. Flow dispatch, correlation resolution, state transitions, and flow
/// lifecycle events emit activities and events through this source.
/// </summary>
/// <remarks>
/// <para>
/// The application wires the exporter via
/// <c>AddOpenTelemetry().WithTracing(b => b.AddSource(ServerActivitySource.SourceName))</c>.
/// No OTel packages are referenced by the library — <see cref="ActivitySource"/>
/// is built into <c>System.Diagnostics</c>.
/// </para>
/// <para>
/// The dispatch span is started through <see cref="ServerIntegration.StartTraceActivity"/>, the application's
/// <see cref="StartTraceActivityDelegate"/>; with that slot unwired it is started by <see cref="StartActivity"/> on
/// <see cref="Source"/>.
/// </para>
/// </remarks>
public static class ServerActivitySource
{
    /// <summary>The UTF-8 source literal of <see cref="SourceName"/>.</summary>
    public static ReadOnlySpan<byte> SourceNameUtf8 => "Verifiable.Server"u8;

    /// <summary>
    /// The source name registered with the .NET diagnostics infrastructure.
    /// Pass this to <c>AddSource</c> in the application's OTel configuration.
    /// </summary>
    public static string SourceName { get; } = Utf8Constants.ToInternedString(SourceNameUtf8);

    /// <summary>
    /// The shared <see cref="ActivitySource"/> instance.
    /// </summary>
    public static ActivitySource Source { get; } = new(SourceName);


    /// <summary>
    /// The library's default <see cref="StartTraceActivityDelegate"/>: starts <paramref name="operationName"/> on
    /// <see cref="Source"/> with <paramref name="kind"/> and <paramref name="tags"/> under the ambient
    /// <see cref="Activity.Current"/>, reading nothing of <paramref name="context"/>. The dispatch reads it when
    /// <see cref="ServerIntegration.StartTraceActivity"/> is unwired, and an application names it as the method group when
    /// it wants the default explicitly. It answers <see langword="null"/> when no listener samples the source.
    /// </summary>
    /// <param name="operationName">The name of the operation.</param>
    /// <param name="kind">The kind of the span.</param>
    /// <param name="tags">The attributes the library holds when the operation begins.</param>
    /// <param name="context">The exchange's context; unread.</param>
    /// <returns>The started activity, or <see langword="null"/> when the source is not sampled.</returns>
    public static Activity? StartActivity(
        string operationName,
        ActivityKind kind,
        IReadOnlyList<KeyValuePair<string, object?>> tags,
        ExchangeContext context) =>
        Source.StartActivity(operationName, kind, parentContext: default, tags);
}
