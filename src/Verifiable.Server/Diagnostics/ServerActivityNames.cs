using Verifiable.Cryptography.Text;


namespace Verifiable.Server.Diagnostics;

/// <summary>
/// Activity (span) names for protocol-neutral endpoint host operations.
/// </summary>
/// <remarks>
/// <para>
/// Names follow the OTel semantic convention pattern: <c>{domain}.{operation}</c>.
/// Each name corresponds to one logical operation boundary in the host dispatch loop.
/// </para>
/// </remarks>
public static class ServerActivityNames
{
    /// <summary>The UTF-8 source literal of <see cref="Handle"/>.</summary>
    public static ReadOnlySpan<byte> HandleUtf8 => "server.handle"u8;

    /// <summary>
    /// The top-level span for <see cref="EndpointServer.DispatchAsync"/>.
    /// Covers the full request lifecycle: correlation resolution, state load,
    /// input building, PDA step, response building, and state save.
    /// </summary>
    public static readonly string Handle = Utf8Constants.ToInternedString(HandleUtf8);
}
