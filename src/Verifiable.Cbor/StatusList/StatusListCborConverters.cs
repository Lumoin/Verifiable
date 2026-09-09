using System;
using System.Buffers;
using Lumoin.Veritas.Cbor;
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
    private BaseMemoryPool Pool { get; }

    /// <summary>
    /// Creates a new converter using the specified memory pool.
    /// </summary>
    /// <param name="pool">The memory pool for allocating decompressed data.</param>
    public StatusListCborConverter(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        this.Pool = pool;
    }

    /// <inheritdoc/>
    public override Core.StatusList.StatusList Read(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

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
        var statusList = Core.StatusList.StatusList.FromCompressed(
            lst, bitSize, Pool, Core.StatusList.BitOrder.LeastSignificantFirst);

        if(aggregationUri is not null)
        {
            statusList.AggregationUri = aggregationUri;
        }

        return statusList;
    }

    /// <summary>
    /// Writes <paramref name="value"/> as the Section 4.3 CBOR map.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="value">The Status List to write. Must be packed <c>LeastSignificantFirst</c>.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="value"/> is packed <c>MostSignificantFirst</c> (the W3C Bitstring
    /// Status List's order) rather than the <c>LeastSignificantFirst</c> order Section 4.1 requires —
    /// see <see cref="Core.StatusList.StatusList.EnsureIetfBitOrder"/>.
    /// </exception>
    public override void Write(CborWriter writer, Core.StatusList.StatusList value)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        Core.StatusList.StatusList.EnsureIetfBitOrder(value, nameof(value));

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
    public override StatusListReference Read(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

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
    public override void Write(CborWriter writer, StatusListReference value)
    {
        ArgumentNullException.ThrowIfNull(writer);

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
    private StatusListCborConverter StatusListConverter { get; }

    /// <summary>
    /// Creates a new converter using the specified memory pool.
    /// </summary>
    /// <param name="pool">The memory pool for the nested Status List converter.</param>
    public StatusListTokenCborConverter(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        StatusListConverter = new StatusListCborConverter(pool);
    }

    /// <inheritdoc/>
    public override StatusListToken Read(CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);

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
                    statusList = StatusListConverter.Read(reader);
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

        //"ttl: RECOMMENDED. … The value of the claim MUST be a positive number encoded in JSON as a
        //number." — the same rule the JSON tier's StatusListTokenJsonConverter refuses on, applied here
        //for symmetry so a CWT-carried non-positive ttl is not silently accepted where a JWT-carried one
        //would be refused.
        if(timeToLive.HasValue && timeToLive.Value <= 0)
        {
            CborThrowHelper.ThrowCborContentException(
                $"Map key {StatusListCborConstants.TimeToLive} ('ttl') MUST be a positive number.");
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
    public override void Write(CborWriter writer, StatusListToken value)
    {
        ArgumentNullException.ThrowIfNull(writer);
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
        StatusListConverter.Write(writer, value.StatusList);

        writer.WriteEndMap();
    }
}
