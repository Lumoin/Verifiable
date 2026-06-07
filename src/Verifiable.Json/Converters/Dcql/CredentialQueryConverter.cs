using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.Json.Converters.Dcql;

/// <summary>
/// Converts a <see cref="CredentialQuery"/> to and from JSON, mapping between
/// the snake_case JSON properties and PascalCase C# properties.
/// </summary>
public sealed class CredentialQueryConverter: JsonConverter<CredentialQuery>
{
    private readonly bool requireMeta;


    /// <summary>
    /// Creates a <see cref="CredentialQueryConverter"/>.
    /// </summary>
    /// <param name="requireMeta">
    /// When <see langword="true"/> — the default and the OID4VP 1.0 §6.1-conformant
    /// behaviour — a Credential Query lacking the <c>meta</c> member is rejected on read.
    /// Set <see langword="false"/> only to interoperate with the (widely-seen but
    /// non-conformant) Verifiers that omit <c>meta</c>.
    /// </param>
    public CredentialQueryConverter(bool requireMeta = true)
    {
        this.requireMeta = requireMeta;
    }


    /// <inheritdoc/>
    [return: NotNull]
    public override CredentialQuery Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

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
        bool? multiple = null;
        bool? requireCryptographicHolderBinding = null;

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
                case var name when DcqlParameterNames.IsId(name):
                {
                    id = reader.GetString();
                    break;
                }
                case var name when DcqlParameterNames.IsFormat(name):
                {
                    format = reader.GetString();
                    break;
                }
                case var name when DcqlParameterNames.IsMeta(name):
                {
                    var typeInfo = (JsonTypeInfo<CredentialQueryMeta>)options.GetTypeInfo(typeof(CredentialQueryMeta));
                    meta = JsonSerializer.Deserialize(ref reader, typeInfo);
                    break;
                }
                case var name when DcqlParameterNames.IsClaims(name):
                {
                    claims = ReadArray<ClaimsQuery>(ref reader, options);
                    break;
                }
                case var name when DcqlParameterNames.IsClaimSets(name):
                {
                    claimSets = ReadClaimSets(ref reader);
                    break;
                }
                case var name when DcqlParameterNames.IsTrustedAuthorities(name):
                {
                    trustedAuthorities = ReadArray<TrustedAuthoritiesQuery>(ref reader, options);
                    break;
                }
                case var name when DcqlParameterNames.IsMultiple(name):
                {
                    multiple = reader.GetBoolean();
                    break;
                }
                case var name when DcqlParameterNames.IsRequireCryptographicHolderBinding(name):
                {
                    requireCryptographicHolderBinding = reader.GetBoolean();
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

        //OID4VP 1.0 §6.1: 'meta' is REQUIRED (may be empty). Configurable via requireMeta
        //to tolerate non-conformant Verifiers that omit it.
        if(requireMeta && meta is null)
        {
            throw new JsonException("The 'meta' property is required (OID4VP 1.0 §6.1).");
        }

        //OID4VP 1.0 §6.3: a Claims Query 'id' is REQUIRED when 'claim_sets' is present,
        //because claim_sets references claims by their id.
        if(claimSets is not null && claims is not null && claims.Exists(static claim => claim.Id is null))
        {
            throw new JsonException(
                "Each Claims Query requires an 'id' when 'claim_sets' is present (OID4VP 1.0 §6.3).");
        }

        return new CredentialQuery
        {
            Id = id,
            Format = format,
            Meta = meta,
            Claims = claims,
            ClaimSets = claimSets,
            TrustedAuthorities = trustedAuthorities,
            Multiple = multiple,
            RequireCryptographicHolderBinding = requireCryptographicHolderBinding
        };
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CredentialQuery value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        writer.WriteString(DcqlParameterNames.Id, value.Id);
        writer.WriteString(DcqlParameterNames.Format, value.Format);

        if(value.Meta is not null)
        {
            writer.WritePropertyName(DcqlParameterNames.Meta);
            var typeInfo = (JsonTypeInfo<CredentialQueryMeta>)options.GetTypeInfo(typeof(CredentialQueryMeta));
            JsonSerializer.Serialize(writer, value.Meta, typeInfo);
        }

        if(value.Claims is not null)
        {
            writer.WritePropertyName(DcqlParameterNames.Claims);
            WriteArray(writer, value.Claims, options);
        }

        if(value.ClaimSets is not null)
        {
            writer.WritePropertyName(DcqlParameterNames.ClaimSets);
            WriteClaimSets(writer, value.ClaimSets);
        }

        if(value.TrustedAuthorities is not null)
        {
            writer.WritePropertyName(DcqlParameterNames.TrustedAuthorities);
            WriteArray(writer, value.TrustedAuthorities, options);
        }

        if(value.Multiple is not null)
        {
            writer.WriteBoolean(DcqlParameterNames.Multiple, value.Multiple.Value);
        }

        if(value.RequireCryptographicHolderBinding is not null)
        {
            writer.WriteBoolean(
                DcqlParameterNames.RequireCryptographicHolderBinding,
                value.RequireCryptographicHolderBinding.Value);
        }

        writer.WriteEndObject();
    }


    /// <summary>
    /// Reads a JSON array by deserializing each element individually via
    /// <see cref="JsonSerializerOptions.GetTypeInfo"/>.
    /// </summary>
    private static List<T> ReadArray<T>(ref Utf8JsonReader reader, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException($"Expected StartArray but got {reader.TokenType}.");
        }

        var typeInfo = (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));
        var list = new List<T>();

        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            var item = JsonSerializer.Deserialize(ref reader, typeInfo);
            if(item is not null)
            {
                list.Add(item);
            }
        }

        return list;
    }


    /// <summary>
    /// Writes a list as a JSON array by serializing each element individually via
    /// <see cref="JsonSerializerOptions.GetTypeInfo"/>.
    /// </summary>
    private static void WriteArray<T>(Utf8JsonWriter writer, IReadOnlyList<T> items, JsonSerializerOptions options)
    {
        var typeInfo = (JsonTypeInfo<T>)options.GetTypeInfo(typeof(T));

        writer.WriteStartArray();
        foreach(var item in items)
        {
            JsonSerializer.Serialize(writer, item, typeInfo);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads the wire-format <c>claim_sets</c> (an array of string arrays) and wraps
    /// it as a single <see cref="ClaimSetQuery"/> whose <see cref="ClaimSetQuery.Options"/>
    /// are the deserialized alternatives.
    /// </summary>
    private static List<ClaimSetQuery> ReadClaimSets(ref Utf8JsonReader reader)
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

            var innerList = ReadStringArray(ref reader);
            optionSets.Add(innerList);
        }

        return [new ClaimSetQuery { Options = optionSets }];
    }


    /// <summary>
    /// Writes claim sets back to the wire format: a flat array of string arrays
    /// representing all options across all claim set queries.
    /// </summary>
    private static void WriteClaimSets(Utf8JsonWriter writer, IReadOnlyList<ClaimSetQuery> claimSets)
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
                writer.WriteStartArray();
                foreach(var item in option)
                {
                    writer.WriteStringValue(item);
                }

                writer.WriteEndArray();
            }
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Reads a JSON array of strings manually without calling into <see cref="JsonSerializer"/>.
    /// </summary>
    private static List<string> ReadStringArray(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException("Expected StartArray for string array.");
        }

        var list = new List<string>();
        while(reader.Read())
        {
            if(reader.TokenType == JsonTokenType.EndArray)
            {
                break;
            }

            if(reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException($"Expected String but got {reader.TokenType}.");
            }

            list.Add(reader.GetString()!);
        }

        return list;
    }
}
