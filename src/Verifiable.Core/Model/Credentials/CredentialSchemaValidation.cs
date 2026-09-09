using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// The outcome of evaluating a credential or presentation document against a credential schema,
/// per <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>:
/// validation MUST result in exactly one of these three outcomes.
/// </summary>
public enum CredentialSchemaValidationOutcome
{
    /// <summary>The document is valid against the given schema.</summary>
    Success,

    /// <summary>The document is not valid against the given schema.</summary>
    Failure,

    /// <summary>
    /// The document could not be validated. Per
    /// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>
    /// implementers MUST return this outcome for a schema whose version they do not support;
    /// an unresolvable schema document or an unavailable validation mechanism also lands here.
    /// </summary>
    Indeterminate
}


/// <summary>
/// One schema-validation error, located by JSON Pointers into the instance and into the schema,
/// matching the JSON Schema output-unit shape.
/// </summary>
/// <param name="InstanceLocation">The JSON Pointer to the failing location in the validated document.</param>
/// <param name="KeywordLocation">The JSON Pointer to the schema keyword that failed.</param>
/// <param name="Message">The human-readable error description.</param>
public sealed record CredentialSchemaValidationError(string InstanceLocation, string KeywordLocation, string Message);


/// <summary>
/// The result of one schema evaluation: the
/// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>
/// tri-state outcome plus the located errors for a <see cref="CredentialSchemaValidationOutcome.Failure"/>.
/// </summary>
public sealed record CredentialSchemaValidationResult
{
    /// <summary>The §4.2 evaluation outcome.</summary>
    public required CredentialSchemaValidationOutcome Outcome { get; init; }

    /// <summary>The located errors; empty unless <see cref="Outcome"/> is <see cref="CredentialSchemaValidationOutcome.Failure"/>.</summary>
    public IReadOnlyList<CredentialSchemaValidationError> Errors { get; init; } = Array.Empty<CredentialSchemaValidationError>();

    /// <summary>The shared successful result.</summary>
    public static CredentialSchemaValidationResult Success { get; } = new() { Outcome = CredentialSchemaValidationOutcome.Success };

    /// <summary>The shared indeterminate result.</summary>
    public static CredentialSchemaValidationResult Indeterminate { get; } = new() { Outcome = CredentialSchemaValidationOutcome.Indeterminate };
}


/// <summary>
/// Evaluates a JSON document against a JSON Schema document, returning the
/// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see> tri-state
/// result. The application wires the schema engine (e.g. the one from <c>Lumoin.Veritas</c>);
/// the library dispatches to it by the schema mechanism's <c>type</c> and never hardcodes an engine.
/// </summary>
/// <param name="schemaJson">The JSON Schema document text.</param>
/// <param name="documentJson">The document text to validate.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The tri-state validation result.</returns>
public delegate ValueTask<CredentialSchemaValidationResult> CredentialSchemaValidationDelegate(
    string schemaJson,
    string documentJson,
    CancellationToken cancellationToken);
