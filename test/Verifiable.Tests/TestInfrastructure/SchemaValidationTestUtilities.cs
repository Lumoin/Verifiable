using Lumoin.Base;
using Lumoin.Veritas.Core;
using Lumoin.Veritas.Json.Stj;
using Lumoin.Veritas.JsonSchema;
using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Vcalm;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Schema-validation wiring for tests: the Lumoin.Veritas JSON Schema engine adapted onto the
/// <see cref="CredentialSchemaValidationDelegate"/> seam with the
/// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>
/// version gate, plus registry and embedded-schema-resolver factories.
/// </summary>
internal static class SchemaValidationTestUtilities
{
    /// <summary>
    /// The JSON Schema versions the wired engine evaluates. A schema declaring any other
    /// <c>$schema</c> evaluates as Indeterminate per §4.2 (implementers MUST return Indeterminate
    /// for a schema whose version they do not support).
    /// </summary>
    private static string[] SupportedSchemaVersions { get; } =
    [
        "https://json-schema.org/draft/2020-12/schema"
    ];


    /// <summary>
    /// Creates the Veritas-backed schema validator: the §4.2 version gate first, then
    /// <see cref="JsonSchemaValidator"/> evaluation with errors carried through as
    /// pointer-located <see cref="CredentialSchemaValidationError"/> entries.
    /// </summary>
    /// <returns>The validation delegate for the JSON Schema mechanism.</returns>
    public static CredentialSchemaValidationDelegate CreateVeritasSchemaValidator()
    {
        return (schemaJson, documentJson, cancellationToken) =>
        {
            //§4.2: a schema whose declared version is unsupported MUST evaluate Indeterminate.
            //A schema with no $schema declaration evaluates under the engine's default dialect.
            string? declaredVersion = ReadSchemaVersion(schemaJson);
            if(declaredVersion is not null && !IsSupportedVersion(declaredVersion))
            {
                return ValueTask.FromResult(CredentialSchemaValidationResult.Indeterminate);
            }

            ValidationResult result = JsonSchemaValidator.Validate(
                Utf8StringInterner.Shared.Intern(schemaJson),
                Utf8StringInterner.Shared.Intern(documentJson),
                StjJsonAdapter.Parse);
            if(result.IsValid)
            {
                return ValueTask.FromResult(CredentialSchemaValidationResult.Success);
            }

            var errors = new List<CredentialSchemaValidationError>(result.Errors.Count);
            foreach(ValidationError error in result.Errors)
            {
                errors.Add(new CredentialSchemaValidationError(
                    error.InstanceLocation.ToString(),
                    error.KeywordLocation.ToString(),
                    error.Message));
            }

            return ValueTask.FromResult(new CredentialSchemaValidationResult
            {
                Outcome = CredentialSchemaValidationOutcome.Failure,
                Errors = errors
            });
        };
    }


    /// <summary>
    /// Creates a registry with the Veritas-backed validator registered for the
    /// <see cref="VcalmSchemaValidatorRegistry.JsonSchemaType"/> mechanism.
    /// </summary>
    /// <returns>The registry.</returns>
    public static VcalmSchemaValidatorRegistry CreateSchemaRegistry()
    {
        var registry = new VcalmSchemaValidatorRegistry();
        registry.Register(VcalmSchemaValidatorRegistry.JsonSchemaType, CreateVeritasSchemaValidator());

        return registry;
    }


    /// <summary>
    /// Creates a schema-document resolver over an embedded id → schema-text map, for deterministic
    /// offline tests; an id absent from the map resolves to <see langword="null"/> (Indeterminate).
    /// </summary>
    /// <param name="schemas">The embedded schema documents by their <c>credentialSchema.id</c> URL.</param>
    /// <returns>The resolver delegate.</returns>
    public static ResolveVcalmSchemaDocumentDelegate CreateEmbeddedSchemaResolver(IReadOnlyDictionary<string, string> schemas)
    {
        return (schemaId, context, cancellationToken) =>
            ValueTask.FromResult(schemas.TryGetValue(schemaId, out string? schemaJson) ? schemaJson : null);
    }


    //Reads the schema document's declared $schema dialect, or null when absent or unreadable
    //(an unreadable schema document fails evaluation in the engine rather than the gate).
    private static string? ReadSchemaVersion(string schemaJson)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(schemaJson);

            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("$schema", out JsonElement version)
                && version.ValueKind == JsonValueKind.String
                    ? version.GetString()
                    : null;
        }
        catch(JsonException)
        {
            return null;
        }
    }


    //The declared dialect matches a supported version, ignoring an empty fragment.
    private static bool IsSupportedVersion(string declaredVersion)
    {
        string normalized = declaredVersion.EndsWith('#') ? declaredVersion[..^1] : declaredVersion;

        return SupportedSchemaVersions.Contains(normalized, StringComparer.Ordinal);
    }
}
