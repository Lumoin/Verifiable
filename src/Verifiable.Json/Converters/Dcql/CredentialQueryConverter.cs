using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Json.Converters.Dcql;

/// <summary>
/// Converts a <see cref="CredentialQuery"/> to and from JSON, mapping between
/// the snake_case JSON properties and PascalCase C# properties.
/// </summary>
public sealed class CredentialQueryConverter: JsonConverter<CredentialQuery>
{
    /// <inheritdoc/>
    [return: NotNull]
    public override CredentialQuery Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        string? id = null;
        string? format = null;
        CredentialQueryMeta? meta = null;
        List<ClaimsQuery>? claims = null;
        List<ClaimSetQuery>? claimSets = null;
        List<TrustedAuthoritiesQuery>? trustedAuthorities = null;

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
                case CredentialQuery.IdPropertyName:
                {
                    id = reader.GetString();
                    break;
                }
                case CredentialQuery.FormatPropertyName:
                {
                    format = reader.GetString();
                    break;
                }
                case CredentialQuery.MetaPropertyName:
                {
                    meta = JsonSerializer.Deserialize<CredentialQueryMeta>(ref reader, options);
                    break;
                }
                case CredentialQuery.ClaimsPropertyName:
                {
                    claims = JsonSerializer.Deserialize<List<ClaimsQuery>>(ref reader, options);
                    break;
                }
                case CredentialQuery.ClaimSetsPropertyName:
                {
                    claimSets = ReadClaimSets(ref reader, options);
                    break;
                }
                case CredentialQuery.TrustedAuthoritiesPropertyName:
                {
                    trustedAuthorities = JsonSerializer.Deserialize<List<TrustedAuthoritiesQuery>>(ref reader, options);
                    break;
                }
                default:
                {
                    reader.Skip();
                    break;
                }
            }
        }

        if(id is null)
        {
            throw new JsonException("The 'id' property is required.");
        }

        if(format is null)
        {
            throw new JsonException("The 'format' property is required.");
        }

        return new CredentialQuery
        {
            Id = id,
            Format = format,
            Meta = meta,
            Claims = claims,
            ClaimSets = claimSets,
            TrustedAuthorities = trustedAuthorities
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CredentialQuery value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        writer.WriteString(CredentialQuery.IdPropertyName, value.Id);
        writer.WriteString(CredentialQuery.FormatPropertyName, value.Format);

        if(value.Meta is not null)
        {
            writer.WritePropertyName(CredentialQuery.MetaPropertyName);
            JsonSerializer.Serialize(writer, value.Meta, options);
        }

        if(value.Claims is not null)
        {
            writer.WritePropertyName(CredentialQuery.ClaimsPropertyName);
            JsonSerializer.Serialize(writer, value.Claims, options);
        }

        if(value.ClaimSets is not null)
        {
            writer.WritePropertyName(CredentialQuery.ClaimSetsPropertyName);
            WriteClaimSets(writer, value.ClaimSets, options);
        }

        if(value.TrustedAuthorities is not null)
        {
            writer.WritePropertyName(CredentialQuery.TrustedAuthoritiesPropertyName);
            JsonSerializer.Serialize(writer, value.TrustedAuthorities, options);
        }

        writer.WriteEndObject();
    }

    /// <summary>
    /// Reads the wire-format <c>claim_sets</c> (an array of string arrays) and wraps
    /// it as a single <see cref="ClaimSetQuery"/> whose <see cref="ClaimSetQuery.Options"/>
    /// are the deserialized alternatives.
    /// </summary>
    private static List<ClaimSetQuery> ReadClaimSets(ref Utf8JsonReader reader, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("Expected an array for 'claim_sets'.");
        }

        var optionSets = new List<IReadOnlyList<string>>();
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            var innerList = JsonSerializer.Deserialize<List<string>>(ref reader, options);
            if(innerList is not null)
            {
                optionSets.Add(innerList);
            }
        }

        return [new ClaimSetQuery { Options = optionSets }];
    }

    /// <summary>
    /// Writes claim sets back to the wire format: a flat array of string arrays
    /// representing all options across all claim set queries.
    /// </summary>
    private static void WriteClaimSets(Utf8JsonWriter writer, IReadOnlyList<ClaimSetQuery> claimSets, JsonSerializerOptions options)
    {
        writer.WriteStartArray();
        foreach(var claimSet in claimSets)
        {
            if(claimSet.Options is null)
            {
                continue;
            }

            foreach(var option in claimSet.Options)
            {
                JsonSerializer.Serialize(writer, option, options);
            }
        }

        writer.WriteEndArray();
    }
}