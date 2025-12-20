using System.Text.Json.Serialization;
using Verifiable.Tpm;

namespace Verifiable;

/// <summary>
/// Source-generated JSON serialization context for AOT/trimming compatibility.
/// The source generator walks the type graph from TpmInfo to handle all nested types.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,WriteIndented = true)]
[JsonSerializable(typeof(TpmInfo))]
internal partial class VerifiableJsonContext: JsonSerializerContext;