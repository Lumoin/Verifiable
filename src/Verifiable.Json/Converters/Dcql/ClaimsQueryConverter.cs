using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Json.Converters.Dcql;

/// <summary>
/// Converts a <see cref="ClaimsQuery"/> to and from JSON.
/// </summary>
/// <remarks>
/// <para>
/// This converter handles the critical translation between the JSON wire format
/// and the domain model:
/// </para>
/// <list type="bullet">
///   <item><description>
///     The JSON <c>path</c> array (containing strings, integers, and nulls) is
///     converted to a <see cref="DcqlClaimPattern"/> with typed
///     <see cref="PatternSegment"/> values.
///   </description></item>
///   <item><description>
///     The JSON <c>values</c> array is converted to <c>IReadOnlyList&lt;object&gt;</c>
///     with unboxed primitives (string, long, bool).
///   </description></item>
/// </list>
/// </remarks>
public sealed class ClaimsQueryConverter: JsonConverter<ClaimsQuery>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override ClaimsQuery Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        string? id = null;
        DcqlClaimPattern? path = null;
        List<object>? values = null;
        bool? intentToRetain = null;

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                JsonThrowHelper.ThrowJsonException();
            }

            string propertyName = reader.GetString()!;
            reader.Read();

            switch(propertyName)
            {
                case ClaimsQuery.IdPropertyName:
                {
                    id = reader.GetString();
                    break;
                }
                case ClaimsQuery.PathPropertyName:
                {
                    path = ReadClaimPattern(ref reader);
                    break;
                }
                case ClaimsQuery.ValuesPropertyName:
                {
                    values = ReadValues(ref reader);
                    break;
                }
                case ClaimsQuery.IntentToRetainPropertyName:
                {
                    intentToRetain = reader.GetBoolean();
                    break;
                }
                default:
                {
                    reader.Skip();
                    break;
                }
            }
        }

        if(path is null)
        {
            throw new JsonException("The 'path' property is required and must not be empty.");
        }

        return new ClaimsQuery
        {
            Id = id,
            Path = path,
            Values = values,
            IntentToRetain = intentToRetain
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, ClaimsQuery value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        if(value.Id is not null)
        {
            writer.WriteString(ClaimsQuery.IdPropertyName, value.Id);
        }

        if(value.Path is not null)
        {
            writer.WritePropertyName(ClaimsQuery.PathPropertyName);
            WriteClaimPattern(writer, value.Path);
        }

        if(value.Values is not null)
        {
            writer.WritePropertyName(ClaimsQuery.ValuesPropertyName);
            WriteValues(writer, value.Values);
        }

        if(value.IntentToRetain is not null)
        {
            writer.WriteBoolean(ClaimsQuery.IntentToRetainPropertyName, value.IntentToRetain.Value);
        }

        writer.WriteEndObject();
    }

    /// <summary>
    /// Reads a JSON array of mixed types (string, integer, null) into a <see cref="DcqlClaimPattern"/>.
    /// </summary>
    private static DcqlClaimPattern ReadClaimPattern(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("The 'path' property must be an array.");
        }

        var segments = new List<PatternSegment>();
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            PatternSegment segment = reader.TokenType switch
            {
                JsonTokenType.String => PatternSegment.Key(reader.GetString()!),
                JsonTokenType.Number => PatternSegment.Index(reader.GetInt32()),
                JsonTokenType.Null => PatternSegment.Wildcard(),
                _ => throw new JsonException($"Unexpected token type '{reader.TokenType}' in claim path array.")
            };

            segments.Add(segment);
        }

        if(segments.Count == 0)
        {
            throw new JsonException("The 'path' array must not be empty.");
        }

        return new DcqlClaimPattern([.. segments]);
    }

    /// <summary>
    /// Writes a <see cref="DcqlClaimPattern"/> as a JSON array of strings, integers, and nulls.
    /// </summary>
    private static void WriteClaimPattern(Utf8JsonWriter writer, DcqlClaimPattern pattern)
    {
        writer.WriteStartArray();
        for(int i = 0; i < pattern.Count; i++)
        {
            var segment = pattern[i];
            if(segment.IsKey)
            {
                writer.WriteStringValue(segment.KeyValue);
            }
            else if(segment.IsIndex)
            {
                writer.WriteNumberValue(segment.IndexValue!.Value);
            }
            else
            {
                writer.WriteNullValue();
            }
        }

        writer.WriteEndArray();
    }

    /// <summary>
    /// Reads a JSON array of mixed primitive values into a list of boxed objects.
    /// </summary>
    private static List<object> ReadValues(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("The 'values' property must be an array.");
        }

        var result = new List<object>();
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            object value = reader.TokenType switch
            {
                JsonTokenType.String => reader.GetString()!,
                JsonTokenType.Number => reader.GetInt64(),
                JsonTokenType.True => true,
                JsonTokenType.False => false,
                _ => throw new JsonException($"Unexpected token type '{reader.TokenType}' in values array.")
            };

            result.Add(value);
        }

        return result;
    }

    /// <summary>
    /// Writes a list of boxed primitive values as a JSON array.
    /// </summary>
    private static void WriteValues(Utf8JsonWriter writer, IReadOnlyList<object> values)
    {
        writer.WriteStartArray();
        foreach(var value in values)
        {
            switch(value)
            {
                case string s:
                {
                    writer.WriteStringValue(s);
                    break;
                }
                case long l:
                {
                    writer.WriteNumberValue(l);
                    break;
                }
                case int i:
                {
                    writer.WriteNumberValue(i);
                    break;
                }
                case bool b:
                {
                    writer.WriteBooleanValue(b);
                    break;
                }
                default:
                {
                    throw new JsonException($"Unsupported value type '{value.GetType().Name}' in values array.");
                }
            }
        }

        writer.WriteEndArray();
    }
}