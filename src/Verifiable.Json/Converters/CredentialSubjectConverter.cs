using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Credentials;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="CredentialSubject"/> lists to and from JSON, handling both
/// single object and array forms.
/// </summary>
/// <remarks>
/// <para>
/// In the VC Data Model, <c>credentialSubject</c> can be expressed as either:
/// </para>
/// <list type="bullet">
/// <item><description>A single object with claims about one subject.</description></item>
/// <item><description>An array of objects with claims about multiple subjects.</description></item>
/// </list>
/// <para>
/// This converter handles both forms transparently, always deserializing to a list.
/// </para>
/// </remarks>
public class CredentialSubjectConverter: JsonConverter<List<CredentialSubject>>
{
    /// <inheritdoc/>
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(List<CredentialSubject>);
    }


    /// <inheritdoc/>
    public override List<CredentialSubject>? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        var list = new List<CredentialSubject>();

        if(reader.TokenType == JsonTokenType.StartArray)
        {
            while(reader.Read())
            {
                if(reader.TokenType == JsonTokenType.EndArray)
                {
                    break;
                }

                var subject = ReadSingleSubject(ref reader);
                if(subject is not null)
                {
                    list.Add(subject);
                }
            }
        }
        else if(reader.TokenType == JsonTokenType.StartObject)
        {
            var subject = ReadSingleSubject(ref reader);
            if(subject is not null)
            {
                list.Add(subject);
            }
        }
        else
        {
            throw new JsonException($"Unexpected token type '{reader.TokenType}' when parsing credentialSubject.");
        }

        return list;
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, List<CredentialSubject> value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if(value is null)
        {
            writer.WriteNullValue();
            return;
        }

        if(value.Count == 1)
        {
            WriteSingleSubject(writer, value[0]);
        }
        else
        {
            writer.WriteStartArray();
            for(int i = 0; i < value.Count; ++i)
            {
                WriteSingleSubject(writer, value[i]);
            }

            writer.WriteEndArray();
        }
    }


    /// <summary>
    /// Reads one JSON object into a <see cref="CredentialSubject"/>: a string-valued <c>id</c>
    /// maps to <see cref="CredentialSubject.Id"/>; every other member, and an <c>id</c> whose
    /// value is JSON <see langword="null"/>, is captured verbatim in
    /// <see cref="CredentialSubject.AdditionalData"/> under its property name - the null is
    /// data belonging to the member, not an absent member, so it is stored rather than
    /// dropped. A <see langword="null"/>-valued <c>id</c> cannot be told apart from an absent
    /// <c>id</c> on the string-typed <see cref="CredentialSubject.Id"/> property alone, which
    /// is why it is routed into the bucket instead.
    /// </summary>
    /// <param name="reader">The reader positioned on the object's <c>StartObject</c> token.</param>
    /// <returns>The parsed <see cref="CredentialSubject"/>.</returns>
    private static CredentialSubject? ReadSingleSubject(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject, got '{reader.TokenType}'.");
        }

        string? id = null;
        var additionalData = new Dictionary<string, object>();

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndObject)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException("Expected property name.");
            }

            string? propertyName = reader.GetString();
            reader.Read();

            if(propertyName == "id")
            {
                if(reader.TokenType == JsonTokenType.Null)
                {
                    //A JSON null "id" is data, not an absent member; there is no separate
                    //"explicitly null" state on the string-typed Id property to carry it, so
                    //it is kept in the additional-data bucket instead, where WriteSingleSubject
                    //re-emits it as the null literal.
                    additionalData["id"] = null!;
                }
                else
                {
                    id = reader.GetString();
                }
            }
            else if(propertyName is not null)
            {
                additionalData[propertyName] = ManualJsonReader.ReadValue(ref reader)!;
            }
        }

        return new CredentialSubject
        {
            Id = id,
            AdditionalData = additionalData.Count > 0 ? additionalData : null
        };
    }


    /// <summary>
    /// Writes one <see cref="CredentialSubject"/> as a JSON object: <see cref="CredentialSubject.Id"/>
    /// first when present, then every <see cref="CredentialSubject.AdditionalData"/> entry,
    /// including one whose value is <see langword="null"/>, which round-trips as the JSON
    /// <c>null</c> literal via <see cref="ManualJsonWriter.WriteValue"/>.
    /// </summary>
    /// <param name="writer">The writer to write to.</param>
    /// <param name="subject">The subject to write.</param>
    private static void WriteSingleSubject(Utf8JsonWriter writer, CredentialSubject subject)
    {
        writer.WriteStartObject();

        if(subject.Id is not null)
        {
            writer.WriteString("id"u8, subject.Id);
        }

        if(subject.AdditionalData is not null)
        {
            foreach(var kvp in subject.AdditionalData)
            {
                writer.WritePropertyName(kvp.Key);
                ManualJsonWriter.WriteValue(writer, kvp.Value);
            }
        }

        writer.WriteEndObject();
    }
}
