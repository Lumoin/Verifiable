using System.Diagnostics;

namespace Verifiable.Cryptography;

/// <summary>
/// The shared <see cref="ActivitySource"/> for cryptographic lifetime spans emitted
/// by <see cref="SensitiveMemory"/> and its subtypes.
/// </summary>
/// <remarks>
/// <para>
/// Backend libraries start activities on this source before constructing
/// <see cref="SensitiveMemory"/> instances. If no OpenTelemetry listener is
/// configured, <see cref="ActivitySource.StartActivity"/> returns
/// <see langword="null"/> and the entire path is zero-cost.
/// </para>
/// <para>
/// Activity names follow the pattern <c>crypto.[type]</c> — for example
/// <c>crypto.nonce</c>, <c>crypto.salt</c>, <c>crypto.digest</c>. Attributes
/// are set by the backend at construction and by <see cref="SensitiveMemory"/>
/// at disposal.
/// </para>
/// <para>
/// Subscribe in your application startup to receive spans:
/// </para>
/// <code>
/// using var tracerProvider = Sdk.CreateTracerProviderBuilder()
///     .AddSource(CryptoActivitySource.Name)
///     .AddOtlpExporter()
///     .Build();
/// </code>
/// </remarks>
public static class CryptoActivitySource
{
    /// <summary>
    /// The name of the activity source. Use this value when configuring
    /// OpenTelemetry to subscribe to cryptographic lifetime spans.
    /// </summary>
    public const string Name = "Verifiable.Cryptography";

    /// <summary>
    /// The shared <see cref="ActivitySource"/> instance. All backends and
    /// <see cref="SensitiveMemory"/> subtypes use this source.
    /// </summary>
    public static readonly ActivitySource Source = new(Name);
}