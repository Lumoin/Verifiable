using System;
using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.StatusList;

namespace Verifiable.Cbor.StatusList;

/// <summary>
/// CBOR converter for <see cref="Core.StatusList.StatusList"/> handling the
/// CBOR map structure defined in Section 4.3 of the specification.
/// </summary>
/// <remarks>
/// <para>
/// Reads and writes the following CBOR structure:
/// </para>
/// <code>
/// StatusList = {
///     bits: 1 / 2 / 4 / 8,
///     lst: bstr,
///     ? aggregation_uri: tstr
/// }
/// </code>
/// </remarks>
public sealed class StatusListCborConverter: CborConverter<Core.StatusList.StatusList>
{
    private readonly MemoryPool<byte> pool;

    /// <summary>
    /// Creates a new converter using the specified memory pool.
    /// </summary>
    /// <param name="pool">The memory pool for allocating decompressed data.</param>
    public StatusListCborConverter(MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        this.pool = pool;
    }

    /// <inheritdoc/>
    public override Core.StatusList.StatusList Read(ref CborReader reader, Type typeToConvert, CborSerializerOptions options)
    {
        int? mapLength = reader.ReadStartMap();

        int? bits = null;
        byte[]? lst = null;
        string? aggregationUri = null;

        int count = mapLength ?? int.MaxValue;
        for(int i = 0; i < count; i++)
        {
            if(mapLength is null && reader.PeekState() == CborReaderState.EndMap)
            {
                break;
            }

            string key = reader.ReadTextString();

            switch(key)
            {
                case StatusListCborConstants.Bits:
                    bits = reader.ReadInt32();
                    break;
                case StatusListCborConstants.List:
                    lst = reader.ReadByteString();
                    break;
                case StatusListCborConstants.AggregationUri:
                    aggregationUri = reader.ReadTextString();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if(!bits.HasValue)
        {
            CborThrowHelper.ThrowMissingRequiredProperty(StatusListCborConstants.Bits);
        }

        if(lst is null)
        {
            CborThrowHelper.ThrowMissingRequiredProperty(StatusListCborConstants.List);
        }

        StatusListBitSize bitSize = (StatusListBitSize)bits.Value;
        var statusList = Core.StatusList.StatusList.FromCompressed(lst, bitSize, pool);

        if(aggregationUri is not null)
        {
            statusList.AggregationUri = aggregationUri;
        }

        return statusList;
    }

    /// <inheritdoc/>
    public override void Write(CborWriter writer, Core.StatusList.StatusList value, CborSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);

        int mapSize = value.AggregationUri is not null ? 3 : 2;
        writer.WriteStartMap(mapSize);

        writer.WriteTextString(StatusListCborConstants.Bits);
        writer.WriteInt32((int)value.BitSize);

        writer.WriteTextString(StatusListCborConstants.List);
        writer.WriteByteString(value.Compress());

        if(value.AggregationUri is not null)
        {
            writer.WriteTextString(StatusListCborConstants.AggregationUri);
            writer.WriteTextString(value.AggregationUri);
        }

        writer.WriteEndMap();
    }
}


/// <summary>
/// CBOR converter for <see cref="StatusListReference"/> handling the CBOR map
/// with <c>idx</c> and <c>uri</c> text string keys.
/// </summary>
public sealed class StatusListReferenceCborConverter: CborConverter<StatusListReference>
{
    /// <inheritdoc/>
    public override StatusListReference Read(ref CborReader reader, Type typeToConvert, CborSerializerOptions options)
    {
        int? mapLength = reader.ReadStartMap();

        int? idx = null;
        string? uri = null;

        int count = mapLength ?? int.MaxValue;
        for(int i = 0; i < count; i++)
        {
            if(mapLength is null && reader.PeekState() == CborReaderState.EndMap)
            {
                break;
            }

            string key = reader.ReadTextString();

            switch(key)
            {
                case StatusListCborConstants.Index:
                    idx = reader.ReadInt32();
                    break;
                case StatusListCborConstants.Uri:
                    uri = reader.ReadTextString();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if(!idx.HasValue)
        {
            CborThrowHelper.ThrowMissingRequiredProperty(StatusListCborConstants.Index);
        }

        if(uri is null)
        {
            CborThrowHelper.ThrowMissingRequiredProperty(StatusListCborConstants.Uri);
        }

        return new StatusListReference(idx.Value, uri);
    }

    /// <inheritdoc/>
    public override void Write(CborWriter writer, StatusListReference value, CborSerializerOptions options)
    {
        writer.WriteStartMap(2);
        writer.WriteTextString(StatusListCborConstants.Index);
        writer.WriteInt32(value.Index);
        writer.WriteTextString(StatusListCborConstants.Uri);
        writer.WriteTextString(value.Uri);
        writer.WriteEndMap();
    }
}


/// <summary>
/// CBOR converter for <see cref="StatusListToken"/> handling the CWT Claims Set
/// with integer claim keys as defined in Section 5.2 of the specification.
/// </summary>
public sealed class StatusListTokenCborConverter: CborConverter<StatusListToken>
{
    private readonly StatusListCborConverter statusListConverter;

    /// <summary>
    /// Creates a new converter using the specified memory pool.
    /// </summary>
    /// <param name="pool">The memory pool for the nested Status List converter.</param>
    public StatusListTokenCborConverter(MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        statusListConverter = new StatusListCborConverter(pool);
    }

    /// <inheritdoc/>
    public override StatusListToken Read(ref CborReader reader, Type typeToConvert, CborSerializerOptions options)
    {
        int? mapLength = reader.ReadStartMap();

        string? subject = null;
        long? issuedAt = null;
        long? expirationTime = null;
        long? timeToLive = null;
        Core.StatusList.StatusList? statusList = null;

        int count = mapLength ?? int.MaxValue;
        for(int i = 0; i < count; i++)
        {
            if(mapLength is null && reader.PeekState() == CborReaderState.EndMap)
            {
                break;
            }

            int claimKey = reader.ReadInt32();

            switch(claimKey)
            {
                case StatusListCborConstants.Subject:
                    subject = reader.ReadTextString();
                    break;
                case StatusListCborConstants.IssuedAt:
                    issuedAt = reader.ReadInt64();
                    break;
                case StatusListCborConstants.ExpirationTime:
                    expirationTime = reader.ReadInt64();
                    break;
                case StatusListCborConstants.TimeToLive:
                    timeToLive = reader.ReadInt64();
                    break;
                case StatusListCborConstants.StatusList:
                    statusList = statusListConverter.Read(ref reader, typeof(Core.StatusList.StatusList), options);
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if(subject is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(StatusListCborConstants.Subject);
        }

        if(!issuedAt.HasValue)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(StatusListCborConstants.IssuedAt);
        }

        if(statusList is null)
        {
            CborThrowHelper.ThrowMissingRequiredMapKey(StatusListCborConstants.StatusList);
        }

        return new StatusListToken(subject, DateTimeOffset.FromUnixTimeSeconds(issuedAt.Value), statusList)
        {
            TimeToLive = timeToLive,
            ExpirationTime = expirationTime.HasValue
                ? DateTimeOffset.FromUnixTimeSeconds(expirationTime.Value)
                : null
        };
    }

    /// <inheritdoc/>
    public override void Write(CborWriter writer, StatusListToken value, CborSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(value);

        int mapSize = 3;
        if(value.ExpirationTime.HasValue) { mapSize++; }
        if(value.TimeToLive.HasValue) { mapSize++; }

        writer.WriteStartMap(mapSize);

        writer.WriteInt32(StatusListCborConstants.Subject);
        writer.WriteTextString(value.Subject);

        writer.WriteInt32(StatusListCborConstants.IssuedAt);
        writer.WriteInt64(value.IssuedAt.ToUnixTimeSeconds());

        if(value.ExpirationTime.HasValue)
        {
            writer.WriteInt32(StatusListCborConstants.ExpirationTime);
            writer.WriteInt64(value.ExpirationTime.Value.ToUnixTimeSeconds());
        }

        if(value.TimeToLive.HasValue)
        {
            writer.WriteInt32(StatusListCborConstants.TimeToLive);
            writer.WriteInt64(value.TimeToLive.Value);
        }

        writer.WriteInt32(StatusListCborConstants.StatusList);
        statusListConverter.Write(writer, value.StatusList, options);

        writer.WriteEndMap();
    }
}