using System.Text.Json.Serialization;
using Verifiable.JCose;
using Verifiable.OAuth;

namespace Verifiable.Json;

/// <summary>
/// Source-generated serialization metadata for <c>Verifiable.OAuth</c> server-side
/// response types whose JSON property names are snake_case per their respective RFCs.
/// </summary>
/// <remarks>
/// <para>
/// Covers <see cref="OidcDiscoveryDocument"/> (RFC 8414), <see cref="JwksDocument"/>
/// (RFC 7517 §5), <see cref="JsonWebKey"/> (RFC 7517 §4), <see cref="ParServerResponse"/>
/// (RFC 9126 §2.2), and <see cref="TokenServerResponse"/> (RFC 6749 §5.1).
/// </para>
/// <para>
/// A separate context is required because the OAuth wire format uses snake_case
/// (e.g. <c>request_uri</c>, <c>expires_in</c>, <c>access_token</c>) while the
/// main <see cref="VerifiableJsonContext"/> uses camelCase. Registered alongside
/// <see cref="VerifiableJsonContext"/> via
/// <see cref="JsonSerializerOptionsOAuthExtensions.ApplyOAuthDefaults"/>.
/// </para>
/// <para>
/// The <c>Verifiable.OAuth</c> types carry no STJ attributes — all serialization
/// knowledge lives exclusively here in <c>Verifiable.Json</c>.
/// </para>
/// </remarks>
[JsonSerializable(typeof(OidcDiscoveryDocument))]
[JsonSerializable(typeof(JwksDocument))]
[JsonSerializable(typeof(JsonWebKey))]
[JsonSerializable(typeof(ParServerResponse))]
[JsonSerializable(typeof(TokenServerResponse))]
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class VerifiableOAuthJsonContext: JsonSerializerContext
{
}
