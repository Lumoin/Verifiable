using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="Context"/> to and from JSON. Handles the JSON-LD <c>@context</c>
/// property in every shape VC Data Model 2.0 §4.3 and DID Core allow: a single string, a single
/// inline object, or an array combining strings and objects.
/// </summary>
/// <remarks>
/// <para>
/// Per <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
/// Contexts</see>, array items "MUST be composed of any combination of URLs and objects" — a
/// number, boolean, null, or nested array is therefore rejected with a <see cref="JsonException"/>
/// rather than silently coerced or dropped.
/// </para>
/// <para>
/// An inline object entry is materialized through <see cref="ManualJsonReader"/> into the plain
/// <see cref="Dictionary{TKey, TValue}"/> shape <see cref="ContextEntry.FromDefinition"/> expects
/// (<see cref="Verifiable.Core"/> never references a JSON serialization library, so the entry
/// cannot carry a <c>JsonElement</c>), and written back through <see cref="ManualJsonWriter"/>. A
/// <see langword="null"/>-valued member inside that object — for example <c>{"@vocab": null}</c>,
/// JSON-LD 1.1's way to clear <c>@vocab</c>/<c>@base</c> or remove a term — is data, not absence,
/// and both readers/writers preserve it.
/// </para>
/// <para>
/// The read side records which wire shape was seen (<see cref="ContextForm.Scalar"/> for a bare
/// string/object, <see cref="ContextForm.Array"/> for an array of any length) on the produced
/// <see cref="Context"/>, and the write side reproduces that shape, so a re-serialized document's
/// <c>@context</c> bytes are unchanged from what was read — which matters to JCS-based Data
/// Integrity proofs, where those bytes are exactly what is signed.
/// </para>
/// </remarks>
public class JsonLdContextConverter: JsonConverter<Context>
{
    /// <inheritdoc/>
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(Context);
    }


    /// <inheritdoc/>
    public override Context Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.TokenType switch
        {
            JsonTokenType.String => new Context([ContextEntry.FromIri(ReadIri(ref reader))], ContextForm.Scalar),
            JsonTokenType.StartObject => new Context([ContextEntry.FromDefinition(ReadDefinition(ref reader))], ContextForm.Scalar),
            JsonTokenType.StartArray => ReadArray(ref reader),
            _ => throw new JsonException(
                $"VC Data Model 2.0 §4.3: @context MUST be a URL, an object, or an array of URLs and objects; "
                + $"got '{reader.TokenType}'.")
        };
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, Context value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        //Context's constructor checks the entry count against its own copied storage, not the caller's list, before allowing ContextForm.Scalar, so the array fallback below is unreachable for a Scalar-form value.
        if(value.Form == ContextForm.Scalar && value.Entries.Count == 1)
        {
            WriteEntry(writer, value.Entries[0]);

            return;
        }

        writer.WriteStartArray();
        for(int i = 0; i < value.Entries.Count; ++i)
        {
            WriteEntry(writer, value.Entries[i]);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads the scalar string <c>@context</c> value the reader is positioned on.
    /// </summary>
    private static string ReadIri(ref Utf8JsonReader reader)
    {
        return reader.GetString() ?? throw new JsonException(
            "VC Data Model 2.0 §4.3: a scalar @context value MUST be a URL.");
    }


    /// <summary>
    /// Reads the array the reader is positioned on (<see cref="JsonTokenType.StartArray"/>) into
    /// ordered <see cref="ContextEntry"/> instances.
    /// </summary>
    private static Context ReadArray(ref Utf8JsonReader reader)
    {
        var entries = new List<ContextEntry>();
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            ContextEntry entry = reader.TokenType switch
            {
                JsonTokenType.String => ContextEntry.FromIri(reader.GetString()!),
                JsonTokenType.StartObject => ContextEntry.FromDefinition(ReadDefinition(ref reader)),
                _ => throw new JsonException(
                    $"VC Data Model 2.0 §4.3: each @context array item MUST be a URL or an object "
                    + $"processable as a JSON-LD Context; got '{reader.TokenType}'.")
            };

            entries.Add(entry);
        }

        return new Context(entries, ContextForm.Array);
    }


    /// <summary>
    /// Reads the object the reader is positioned on (<see cref="JsonTokenType.StartObject"/>) into
    /// the plain <see cref="Dictionary{TKey, TValue}"/> shape <see cref="ContextEntry.FromDefinition"/>
    /// expects.
    /// </summary>
    private static Dictionary<string, object> ReadDefinition(ref Utf8JsonReader reader)
    {
        object? value = ManualJsonReader.ReadValue(ref reader);
        if(value is not Dictionary<string, object> definition)
        {
            throw new JsonException("VC Data Model 2.0 §4.3: an inline @context entry MUST be a JSON object.");
        }

        return definition;
    }


    /// <summary>
    /// Writes one entry as its IRI string or its inline definition object. A degenerate entry (from
    /// <see cref="ContextEntry"/>'s struct zero value, never from <see cref="ContextEntry.FromIri"/>
    /// or <see cref="ContextEntry.FromDefinition"/>) has no wire form to write.
    /// </summary>
    private static void WriteEntry(Utf8JsonWriter writer, ContextEntry entry)
    {
        if(entry.IsIri)
        {
            writer.WriteStringValue(entry.Iri);

            return;
        }

        if(entry.IsDefinition)
        {
            ManualJsonWriter.WriteValue(writer, entry.Definition);

            return;
        }

        throw new InvalidOperationException(
            "A ContextEntry that is neither an IRI nor a definition has no wire form to write.");
    }
}
