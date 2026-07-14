using System.Collections.Generic;
using System.Text;
using Verifiable.Foundation;
using Verifiable.Json;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared JWT header/payload JSON encoding for the Federation, JCose, and Jose test corpus — the
/// pre-base64url step every hand-assembled JWT part shares before <c>Base64Url</c> encoding.
/// </summary>
internal static class JwtWireFixtures
{
    /// <summary>
    /// JSON-serializes <paramref name="part"/> (a JWT header or payload) with
    /// <see cref="TestSetup.DefaultSerializationOptions"/> and wraps the UTF-8 bytes as
    /// <see cref="BufferTags.Json"/>-tagged memory, ready for base64url encoding into a JWT part.
    /// </summary>
    /// <param name="part">The header or payload claim map.</param>
    /// <returns>The UTF-8 JSON bytes, tagged <see cref="BufferTags.Json"/>.</returns>
    internal static TaggedMemory<byte> EncodeJwtPart(Dictionary<string, object> part)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializerExtensions.Serialize(part, TestSetup.DefaultSerializationOptions));

        return new TaggedMemory<byte>(bytes, BufferTags.Json);
    }
}
