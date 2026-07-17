using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Core.SecurityEvents;

namespace Verifiable.Json;

/// <summary>
/// Shared faithful, strict <see cref="JsonElement"/> readers for the Shared
/// Signals JSON parsers (discovery metadata, stream configuration, stream
/// status). Strings stay strings (no date coercion); a present-but-wrong-typed
/// member throws a <see cref="JsonException"/> the parser catches via
/// <see cref="IsParseFailure"/> and turns into a <see langword="null"/> result.
/// </summary>
internal static class SsfJsonReadHelpers
{
    /// <summary>
    /// Parse options for all Shared Signals JSON documents, with an explicit, modest
    /// <see cref="JsonDocumentOptions.MaxDepth"/>. SETs, discovery, stream-management, and
    /// poll bodies are shallow, so 32 is generous; making the bound explicit (rather than
    /// relying on the global STJ default of 64) caps nesting at parse time and keeps the
    /// downstream recursive materialization safely bounded for untrusted input.
    /// </summary>
    internal static JsonDocumentOptions DocumentOptions { get; } = new() { MaxDepth = 32 };


    internal static string? ReadOptionalString(JsonElement parent, string name)
    {
        if(!parent.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.String)
        {
            throw new JsonException($"Field '{name}' must be a string.");
        }

        return value.GetString();
    }


    internal static int? ReadOptionalInt(JsonElement parent, string name)
    {
        if(!parent.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int number))
        {
            throw new JsonException($"Field '{name}' must be an integer.");
        }

        return number;
    }


    internal static List<string>? ReadStringArray(JsonElement parent, string name)
    {
        if(!parent.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException($"Field '{name}' must be an array.");
        }

        var items = new List<string>(value.GetArrayLength());
        foreach(JsonElement item in value.EnumerateArray())
        {
            if(item.ValueKind != JsonValueKind.String)
            {
                throw new JsonException($"Field '{name}' must contain only strings.");
            }

            items.Add(item.GetString()!);
        }

        return items;
    }


    //Reads an "aud"-style member that may be a single string or an array of strings.
    internal static List<string>? ReadAudiences(JsonElement parent, string name)
    {
        if(!parent.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind == JsonValueKind.String)
        {
            return [value.GetString()!];
        }

        return ReadStringArray(parent, name);
    }


    internal static bool? ReadOptionalBool(JsonElement parent, string name)
    {
        if(!parent.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new JsonException($"Field '{name}' must be a boolean.");
        }

        return value.GetBoolean();
    }


    //Reads a Subject Identifier object faithfully (strings stay strings; nested
    //complex members recurse) and projects it via SubjectIdentifier.FromWireObject.
    //Throws when the member is present but not a well-formed Subject Identifier.
    internal static SubjectIdentifier? ReadSubject(JsonElement parent, string name)
    {
        if(!parent.TryGetProperty(name, out JsonElement value))
        {
            return null;
        }

        if(value.ValueKind != JsonValueKind.Object)
        {
            throw new JsonException($"Field '{name}' must be a JSON object.");
        }

        var members = (Dictionary<string, object>)JsonElementConversion.Convert(value)!;
        SubjectIdentifier? subject = SubjectIdentifier.FromWireObject(members);
        if(subject is null)
        {
            throw new JsonException($"Field '{name}' is not a valid Subject Identifier (missing 'format').");
        }

        return subject;
    }


    internal static bool IsParseFailure(Exception ex) =>
        ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or NotSupportedException;
}