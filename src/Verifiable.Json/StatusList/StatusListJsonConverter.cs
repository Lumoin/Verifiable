using System;
using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.StatusList;

namespace Verifiable.Json.StatusList;

/// <summary>
/// System.Text.Json converter for <see cref="Core.StatusList.StatusList"/> handling
/// the JSON representation defined in Section 4.2 of the specification.
/// </summary>
/// <remarks>
/// <para>
/// Reads and writes the following JSON structure:
/// </para>
/// <code>
/// {
///   "bits": 1,
///   "lst": "eNrbuRgAAhcBXQ",
///   "aggregation_uri": "https://example.com/aggregation"
/// }
/// </code>
/// </remarks>
public sealed class StatusListJsonConverter: JsonConverter<Core.StatusList.StatusList>
{
    private readonly MemoryPool<byte> pool;

    /// <summary>
    /// Creates a new converter using the specified memory pool.
    /// </summary>
    /// <param name="pool">The memory pool for allocating decompressed data.</param>
    public StatusListJsonConverter(MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        this.pool = pool;
    }

    /// <inheritdoc/>
    public override Core.StatusList.StatusList Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected start of JSON object for StatusList.");
        }

        int? bits = null;
        string? lst = null;
        string? aggregationUri = null;

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

            string propertyName = reader.GetString()!;
            reader.Read();

            switch(propertyName)
            {
                case StatusListJsonConstants.Bits:
                    bits = reader.GetInt32();
                    break;
                case StatusListJsonConstants.List:
                    lst = reader.GetString();
                    break;
                case StatusListJsonConstants.AggregationUri:
                    aggregationUri = reader.GetString();
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        if(!bits.HasValue)
        {
            throw new JsonException("Missing required property 'bits'.");
        }

        if(lst is null)
        {
            throw new JsonException("Missing required property 'lst'.");
        }

        StatusListBitSize bitSize = (StatusListBitSize)bits.Value;
        byte[] compressedData = Base64UrlDecode(lst);

        var statusList = Core.StatusList.StatusList.FromCompressed(compressedData, bitSize, pool);

        if(aggregationUri is not null)
        {
            statusList.AggregationUri = aggregationUri;
        }

        return statusList;
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, Core.StatusList.StatusList value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();
        writer.WriteNumber(StatusListJsonConstants.Bits, (int)value.BitSize);
        writer.WriteString(StatusListJsonConstants.List, Base64UrlEncode(value.Compress()));

        if(value.AggregationUri is not null)
        {
            writer.WriteString(StatusListJsonConstants.AggregationUri, value.AggregationUri);
        }

        writer.WriteEndObject();
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        string padded = base64Url.Replace('-', '+').Replace('_', '/');
        switch(padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
        }

        return Convert.FromBase64String(padded);
    }

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}


/// <summary>
/// System.Text.Json converter for <see cref="StatusListReference"/> values.
/// </summary>
public sealed class StatusListReferenceJsonConverter: JsonConverter<StatusListReference>
{
    /// <inheritdoc/>
    public override StatusListReference Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected start of JSON object for StatusListReference.");
        }

        int? idx = null;
        string? uri = null;

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

            string propertyName = reader.GetString()!;
            reader.Read();

            switch(propertyName)
            {
                case StatusListJsonConstants.Index:
                    idx = reader.GetInt32();
                    break;
                case StatusListJsonConstants.Uri:
                    uri = reader.GetString();
                    break;
                default:
                    reader.Skip();
                    break;
            }
        }

        if(!idx.HasValue)
        {
            throw new JsonException("Missing required property 'idx'.");
        }

        if(uri is null)
        {
            throw new JsonException("Missing required property 'uri'.");
        }

        return new StatusListReference(idx.Value, uri);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, StatusListReference value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);

        writer.WriteStartObject();
        writer.WriteNumber(StatusListJsonConstants.Index, value.Index);
        writer.WriteString(StatusListJsonConstants.Uri, value.Uri);
        writer.WriteEndObject();
    }
}


/// <summary>
/// System.Text.Json converter for <see cref="StatusClaim"/> values.
/// </summary>
public sealed class StatusClaimJsonConverter: JsonConverter<StatusClaim>
{
    private readonly StatusListReferenceJsonConverter referenceConverter = new();

    /// <inheritdoc/>
    public override StatusClaim Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected start of JSON object for StatusClaim.");
        }

        StatusListReference? statusList = null;

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

            string propertyName = reader.GetString()!;
            reader.Read();

            if(propertyName == StatusListJsonConstants.StatusList)
            {
                statusList = referenceConverter.Read(ref reader, typeof(StatusListReference), options);
            }
            else
            {
                reader.Skip();
            }
        }

        if(!statusList.HasValue)
        {
            throw new JsonException("Missing required property 'status_list'.");
        }

        return new StatusClaim(statusList.Value);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, StatusClaim value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();

        if(value.HasStatusList)
        {
            writer.WritePropertyName(StatusListJsonConstants.StatusList);
            referenceConverter.Write(writer, value.StatusList!.Value, options);
        }

        writer.WriteEndObject();
    }
}


/// <summary>
/// System.Text.Json converter for <see cref="StatusListAggregation"/> values.
/// </summary>
public sealed class StatusListAggregationJsonConverter: JsonConverter<StatusListAggregation>
{
    /// <inheritdoc/>
    public override StatusListAggregation Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected start of JSON object for StatusListAggregation.");
        }

        string[]? statusLists = null;

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

            string propertyName = reader.GetString()!;
            reader.Read();

            if(propertyName == StatusListJsonConstants.StatusLists)
            {
                statusLists = JsonSerializer.Deserialize<string[]>(ref reader, options);
            }
            else
            {
                reader.Skip();
            }
        }

        if(statusLists is null)
        {
            throw new JsonException("Missing required property 'status_lists'.");
        }

        return new StatusListAggregation(statusLists);
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, StatusListAggregation value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        writer.WriteStartObject();
        writer.WriteStartArray(StatusListJsonConstants.StatusLists);

        foreach(string uri in value.StatusLists)
        {
            writer.WriteStringValue(uri);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }
}