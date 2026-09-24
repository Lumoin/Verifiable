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
    /// A validation outcome the <see cref="CredentialSchemaValidationOutcome"/> enumeration does not define, one past its
    /// largest defined value, which a validator that answers with no verdict of the three
    /// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see> outcomes stands in for.
    /// </summary>
    public static CredentialSchemaValidationOutcome UndefinedValidationOutcome { get; } =
        Enum.GetValues<CredentialSchemaValidationOutcome>().Max() + 1;


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
    public static VcalmSchemaValidatorRegistry CreateSchemaRegistry() => CreateSchemaRegistry(CreateVeritasSchemaValidator());


    /// <summary>
    /// Creates a registry with <paramref name="validator"/> registered for the
    /// <see cref="VcalmSchemaValidatorRegistry.JsonSchemaType"/> mechanism, for a test that stands a validator of its own
    /// in for the engine.
    /// </summary>
    /// <param name="validator">The validator the JSON Schema mechanism dispatches to.</param>
    /// <returns>The registry.</returns>
    public static VcalmSchemaValidatorRegistry CreateSchemaRegistry(CredentialSchemaValidationDelegate validator)
    {
        var registry = new VcalmSchemaValidatorRegistry();
        registry.Register(VcalmSchemaValidatorRegistry.JsonSchemaType, validator);

        return registry;
    }


    /// <summary>
    /// Creates a schema-document resolver over an embedded id → schema-text map, for deterministic
    /// offline tests; an id absent from the map resolves to <see langword="null"/>, a schema document the resolver did
    /// not return.
    /// </summary>
    /// <param name="schemas">The embedded schema documents by their <c>credentialSchema.id</c> URL.</param>
    /// <returns>The resolver delegate.</returns>
    public static ResolveVcalmSchemaDocumentDelegate CreateEmbeddedSchemaResolver(IReadOnlyDictionary<string, string> schemas)
    {
        return (schemaId, context, cancellationToken) =>
            ValueTask.FromResult(schemas.TryGetValue(schemaId, out string? schemaJson) ? schemaJson : null);
    }


    /// <summary>
    /// Reads the schema document's declared <c>$schema</c> dialect, or <see langword="null"/> when absent or unreadable
    /// (an unreadable schema document fails evaluation in the engine rather than the gate).
    /// </summary>
    /// <param name="schemaJson">The schema document.</param>
    /// <returns>The declared dialect, or <see langword="null"/>.</returns>
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


    /// <summary>Whether the declared dialect matches a supported version, ignoring an empty fragment.</summary>
    /// <param name="declaredVersion">The schema document's declared <c>$schema</c> dialect.</param>
    /// <returns><see langword="true"/> when the dialect is one of <see cref="SupportedSchemaVersions"/>.</returns>
    private static bool IsSupportedVersion(string declaredVersion)
    {
        string normalized = declaredVersion.EndsWith('#', StringComparison.Ordinal) ? declaredVersion[..^1] : declaredVersion;

        return SupportedSchemaVersions.Contains(normalized, StringComparer.Ordinal);
    }
}
