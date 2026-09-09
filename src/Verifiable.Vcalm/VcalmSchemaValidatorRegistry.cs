using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Vcalm;

/// <summary>
/// Resolves the JSON Schema document a VCALM 1.0 §3.3.1 <c>credentialSchema.id</c> URL identifies,
/// returning its text or <see langword="null"/> when the schema cannot be resolved. The application
/// composes its own retrieval (typically the SSRF-policed outbound fetch riding
/// <paramref name="context"/>, or a pre-seeded local set); an unresolved schema evaluates as
/// <see cref="CredentialSchemaValidationOutcome.Indeterminate"/>.
/// </summary>
/// <param name="schemaId">The <c>credentialSchema.id</c> URL identifying the schema document.</param>
/// <param name="context">The per-call exchange context carrying the outbound-fetch policy.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The schema document text, or <see langword="null"/> when unresolvable.</returns>
public delegate ValueTask<string?> ResolveVcalmSchemaDocumentDelegate(
    string schemaId,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// The schema-validation mechanism seam: a registry that selects a
/// <see cref="CredentialSchemaValidationDelegate"/> by the schema mechanism's <c>type</c> — the
/// VCALM 1.0 §3.6.1 <c>presentationSchema.type</c> and the VC Data Model 2.0 §4.11
/// <c>credentialSchema.type</c> discriminator. Per
/// <see href="https://www.w3.org/TR/vc-json-schema/">VC JSON Schema §2.1</see> the JSON Schema
/// mechanism's type is exactly <see cref="JsonSchemaType"/>; VCALM §3.6.1 additionally admits
/// alternate mechanism types whose semantics are beyond the specification's scope, which register
/// under their own type strings.
/// </summary>
/// <remarks>
/// The registry ships EMPTY: the library carries no JSON Schema engine, so a deployment registers
/// one (e.g. the validator from <c>Lumoin.Veritas</c>) for <see cref="JsonSchemaType"/>. Validation
/// sites treat an unregistered mechanism as
/// <see cref="CredentialSchemaValidationOutcome.Indeterminate"/> where a result is reported, and
/// fail closed where a workflow step demands validation (§3.6.1 <c>presentationSchema</c>): a step
/// that declares a schema is the workflow author requiring the check, and an instance that cannot
/// run it refuses the presentation rather than skipping the check.
/// </remarks>
public sealed class VcalmSchemaValidatorRegistry
{
    /// <summary>
    /// The <see href="https://www.w3.org/TR/vc-json-schema/">VC JSON Schema</see> mechanism type:
    /// <c>JsonSchema</c>. Both VCALM §3.6.1 (<c>presentationSchema.type</c>) and VC Data Model 2.0
    /// §4.11 (<c>credentialSchema.type</c>) name this value for the JSON Schema mechanism.
    /// </summary>
    public const string JsonSchemaType = "JsonSchema";


    private Dictionary<string, CredentialSchemaValidationDelegate> Validators { get; } = new(StringComparer.Ordinal);


    /// <summary>
    /// Registers (or supersedes) the validator for a schema mechanism type. A deployment calls this
    /// with a JSON Schema engine (e.g. the one from <c>Lumoin.Veritas</c>) for
    /// <see cref="JsonSchemaType"/>.
    /// </summary>
    /// <param name="schemaType">The mechanism <c>type</c> the validator handles.</param>
    /// <param name="validator">The validator to register for the type.</param>
    public void Register(string schemaType, CredentialSchemaValidationDelegate validator)
    {
        ArgumentException.ThrowIfNullOrEmpty(schemaType);
        ArgumentNullException.ThrowIfNull(validator);

        Validators[schemaType] = validator;
    }


    /// <summary>
    /// Whether a validator is registered for a schema mechanism type.
    /// </summary>
    /// <param name="schemaType">The mechanism <c>type</c>.</param>
    /// <returns><see langword="true"/> when a validator is registered for the type.</returns>
    public bool IsRegistered(string schemaType)
    {
        ArgumentNullException.ThrowIfNull(schemaType);

        return Validators.ContainsKey(schemaType);
    }


    /// <summary>
    /// Validates a document against a schema, selecting the validator by the mechanism type.
    /// </summary>
    /// <param name="schemaType">The mechanism <c>type</c> selecting the validator.</param>
    /// <param name="schemaJson">The schema document text.</param>
    /// <param name="documentJson">The document text to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The tri-state validation result.</returns>
    /// <exception cref="KeyNotFoundException">When no validator is registered for the type.</exception>
    public ValueTask<CredentialSchemaValidationResult> ValidateAsync(
        string schemaType,
        string schemaJson,
        string documentJson,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(schemaType);

        if(!Validators.TryGetValue(schemaType, out CredentialSchemaValidationDelegate? validator))
        {
            throw new KeyNotFoundException($"No schema validator is registered for the schema mechanism type '{schemaType}'.");
        }

        return validator(schemaJson, documentJson, cancellationToken);
    }
}
