using System.Diagnostics;
using Verifiable.Cryptography.Text;

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
    /// <summary>The UTF-8 source literal of <see cref="SourceName"/>.</summary>
    public static ReadOnlySpan<byte> SourceNameUtf8 => "Verifiable.OAuth.Server"u8;

    /// <summary>
    /// The source name registered with the .NET diagnostics infrastructure.
    /// Pass this to <c>AddSource</c> in the application's OTel configuration.
    /// </summary>
    public static readonly string SourceName = Utf8Constants.ToInternedString(SourceNameUtf8);

    /// <summary>
    /// The shared <see cref="ActivitySource"/> instance.
    /// </summary>
    public static ActivitySource Source { get; } = new(SourceName);
}
