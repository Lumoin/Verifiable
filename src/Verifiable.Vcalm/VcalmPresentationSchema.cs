using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The parsed VCALM 1.0 §3.6.1 <c>presentationSchema</c> envelope: the schema mechanism
/// <see cref="Type"/> (the specification names <c>JsonSchema</c>; alternate mechanism types are
/// admitted with semantics beyond the specification's scope) and, for the JSON Schema mechanism,
/// the inline <c>jsonSchema</c> object's text.
/// </summary>
[DebuggerDisplay("VcalmPresentationSchema Type={Type}")]
public sealed record VcalmPresentationSchema
{
    /// <summary>The §3.6.1 schema mechanism <c>type</c>; <c>JsonSchema</c> for the JSON Schema mechanism.</summary>
    public required string Type { get; init; }

    /// <summary>
    /// The inline <c>jsonSchema</c> object's JSON text, or <see langword="null"/> when the envelope
    /// carries an alternate mechanism whose payload this library does not interpret.
    /// </summary>
    public string? SchemaJson { get; init; }
}


/// <summary>
/// Parses a §3.6.1 <c>presentationSchema</c> envelope's verbatim JSON into the neutral
/// <see cref="VcalmPresentationSchema"/>, or <see langword="null"/> when the envelope is not a JSON
/// object carrying a string <c>type</c>. The default JSON implementation lives in
/// <c>Verifiable.Json</c>; the delegate keeps <c>System.Text.Json</c> out of this library.
/// </summary>
/// <param name="presentationSchemaJson">The verbatim <c>presentationSchema</c> JSON.</param>
/// <returns>The parsed envelope, or <see langword="null"/> when malformed.</returns>
public delegate VcalmPresentationSchema? ParseVcalmPresentationSchemaDelegate(string presentationSchemaJson);
