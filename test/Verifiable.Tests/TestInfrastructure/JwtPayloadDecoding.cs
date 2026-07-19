using System.Buffers;
using System.Text.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The shared JWT-payload decode helper every OAuth test category uses instead of reinventing a
/// private per-file copy — the shared-fixture counterpart of <see cref="SecurityEventTestJson"/>
/// for tests that only need the middle compact-JWS segment as parsed JSON claims.
/// </summary>
internal static class JwtPayloadDecoding
{
    /// <summary>
    /// Splits <paramref name="compactJws"/> into its three dot-separated segments,
    /// base64url-decodes the middle (payload) segment via <paramref name="pool"/>, and parses the
    /// decoded bytes as JSON. Caller owns the returned <see cref="JsonDocument"/> and must dispose
    /// it. Does not verify the signature — this is a wire-inspection helper for asserting what the
    /// AS actually emitted, not a validator.
    /// </summary>
    public static JsonDocument DecodePayload(string compactJws, MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJws);
        ArgumentNullException.ThrowIfNull(pool);

        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);

        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], pool);

        return JsonDocument.Parse(payloadBytes);
    }
}
