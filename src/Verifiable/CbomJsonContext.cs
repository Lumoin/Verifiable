using System.Text.Json.Serialization;
using Verifiable.Cryptography.Cbom;

namespace Verifiable;

/// <summary>
/// Source-generated JSON serialization context for the CBOM model (AOT compatible).
/// </summary>
/// <remarks>
/// <para>
/// The CBOM record DTOs live in <c>Verifiable.Core</c> (the JSON firewall forbids the
/// serializer namespace there), so the CLI host owns this context, mirroring how the
/// library's <c>TpmInfo</c> is serialized by <see cref="TpmJsonContext"/>. CycloneDX
/// uses camelCase property names; the two keys that camelCase cannot express
/// (<c>bom-ref</c> and <c>$schema</c>) are rewritten by
/// <see cref="CbomJsonRenderer"/> after serialization.
/// </para>
/// </remarks>
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CbomDocument))]
internal partial class CbomJsonContext: JsonSerializerContext
{
}
