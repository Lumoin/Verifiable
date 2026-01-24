using System.Text.Json.Serialization;
using Verifiable.Tpm.Extensions.Info;

namespace Verifiable;

/// <summary>
/// JSON serialization context for TPM types (AOT compatible).
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(TpmInfo))]
internal partial class TpmJsonContext: JsonSerializerContext
{
}