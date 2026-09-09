using System;
using System.Buffers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.StatusList;
using Verifiable.Json;

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
    private BaseMemoryPool Pool { get; }

    /// <summary>
    /// Creates a new converter using the specified memory pool.
    /// </summary>
    /// <param name="pool">The memory pool for allocating decompressed data.</param>
    public StatusListJsonConverter(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        this.Pool = pool;
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

        var statusList = Core.StatusList.StatusList.FromCompressed(
            compressedData, bitSize, Pool, Core.StatusList.BitOrder.LeastSignificantFirst);

        if(aggregationUri is not null)
        {
            statusList.AggregationUri = aggregationUri;
        }

        return statusList;
    }

    /// <summary>
    /// Writes <paramref name="value"/> as the Section 4.2 JSON structure.
    /// </summary>
    /// <param name="writer">The JSON writer.</param>
    /// <param name="value">The Status List to write. Must be packed <c>LeastSignificantFirst</c>.</param>
    /// <param name="options">The serializer options.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="writer"/> or <paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="value"/> is packed <c>MostSignificantFirst</c> (the W3C Bitstring
    /// Status List's order) rather than the <c>LeastSignificantFirst</c> order Section 4.1 requires —
    /// see <see cref="Core.StatusList.StatusList.EnsureIetfBitOrder"/>.
    /// </exception>
    public override void Write(Utf8JsonWriter writer, Core.StatusList.StatusList value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        Core.StatusList.StatusList.EnsureIetfBitOrder(value, nameof(value));

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
/// System.Text.Json converter for <see cref="StatusClaim"/> values — the serializer-tier twin of the
/// span reader <see cref="Verifiable.Core.StatusList.StatusClaimReader"/> and of the COSE-tier
/// Status-structure reader.
/// </summary>
/// <remarks>
/// <para>
/// Reading records every member name as a status mechanism, per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">
/// Token Status List, Section 6.1</see>: "The status (status) claim MUST specify a JSON Object that
/// contains at least one reference to a status mechanism." An object with no member is therefore
/// refused; an object naming a mechanism this library does not model is valid, its value skipped and
/// its name kept.
/// </para>
/// <para>
/// Writing refuses a mechanism it cannot encode, the same posture the CBOR writer takes for the same
/// structure: a claim written back must say what the claim said, and dropping an unmodelled
/// mechanism's name would silently change the issuer's statement.
/// </para>
/// </remarks>
public sealed class StatusClaimJsonConverter: JsonConverter<StatusClaim>
{
    /// <summary>The nested <c>status_list</c> value's own converter, per Section 6.2.</summary>
    private StatusListReferenceJsonConverter ReferenceConverter { get; } = new();

    /// <inheritdoc/>
    /// <exception cref="JsonException">
    /// Thrown when the value is not an object, when a member name is missing, when a member name
    /// repeats, or when the object carries no member at all (Section 6.1's "at least one reference to
    /// a status mechanism"). A repeated member name lets one producer show one reader one mechanism
    /// and another reader a different one, so it is refused rather than collapsed — the same posture
    /// the span reader and the CBOR reader of this claim take.
    /// </exception>
    public override StatusClaim Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected start of JSON object for StatusClaim.");
        }

        StatusListReference? statusList = null;
        var mechanisms = new HashSet<string>(StringComparer.Ordinal);

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
            if(!mechanisms.Add(propertyName))
            {
                throw new JsonException(
                    $"The status claim repeats the status-mechanism member '{propertyName}'; " +
                    "Token Status List Section 6.1's members each name one status mechanism.");
            }

            reader.Read();

            if(propertyName == StatusListJsonConstants.StatusList)
            {
                statusList = ReferenceConverter.Read(ref reader, typeof(StatusListReference), options);
            }
            else
            {
                reader.Skip();
            }
        }

        if(mechanisms.Count == 0)
        {
            throw new JsonException(
                "The status claim must contain at least one status mechanism per Token Status List Section 6.1.");
        }

        return new StatusClaim(statusList, mechanisms);
    }

    /// <inheritdoc/>
    /// <exception cref="NotSupportedException">
    /// Thrown when the claim names a mechanism other than <c>status_list</c> — the only mechanism this
    /// library models for encoding.
    /// </exception>
    public override void Write(Utf8JsonWriter writer, StatusClaim value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        foreach(string mechanism in value.Mechanisms)
        {
            if(!string.Equals(mechanism, StatusListJsonConstants.StatusList, StringComparison.Ordinal))
            {
                throw new NotSupportedException(
                    $"Status mechanism '{mechanism}' cannot be written: only " +
                    $"'{StatusListJsonConstants.StatusList}' is modelled for encoding per Token Status List Section 6.1.");
            }
        }

        writer.WriteStartObject();

        if(value.StatusList is StatusListReference statusList)
        {
            writer.WritePropertyName(StatusListJsonConstants.StatusList);
            ReferenceConverter.Write(writer, statusList, options);
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
                statusLists = JsonSerializer.Deserialize(ref reader, VerifiableJsonContext.Default.StringArray);
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