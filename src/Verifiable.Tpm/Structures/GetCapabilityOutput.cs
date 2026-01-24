using System;
using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Output for the TPM2_GetCapability command.
/// </summary>
/// <remarks>
/// <para>
/// Contains the capability data returned by the TPM. The format depends on
/// the capability category that was queried.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3: Commands, Section 30.2 - TPM2_GetCapability.
/// </para>
/// </remarks>
public readonly struct GetCapabilityOutput: ITpmCommandOutput<GetCapabilityOutput>, IEquatable<GetCapabilityOutput>
{
    /// <summary>
    /// Gets a value indicating whether more data is available.
    /// </summary>
    public bool MoreData { get; }

    /// <summary>
    /// Gets the capability category that was queried.
    /// </summary>
    public Tpm2CapConstants Capability { get; }

    /// <summary>
    /// Gets the TPM properties (for TPM_CAP_TPM_PROPERTIES queries).
    /// </summary>
    public IReadOnlyList<TpmProperty> Properties { get; }

    /// <summary>
    /// Gets the raw capability data for non-property queries.
    /// </summary>
    public ReadOnlyMemory<byte> RawData { get; }

    /// <inheritdoc/>
    public int SerializedSize
    {
        get
        {
            int size = sizeof(byte) + sizeof(uint);
            if(Capability == Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES)
            {
                size += sizeof(uint) + Properties.Count * 8;
            }
            else
            {
                size += RawData.Length;
            }
            return size;
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GetCapabilityOutput"/> struct for property queries.
    /// </summary>
    /// <param name="moreData">Whether more data is available.</param>
    /// <param name="capability">The capability category.</param>
    /// <param name="properties">The property list.</param>
    public GetCapabilityOutput(bool moreData, Tpm2CapConstants capability, IReadOnlyList<TpmProperty> properties)
    {
        MoreData = moreData;
        Capability = capability;
        Properties = properties;
        RawData = ReadOnlyMemory<byte>.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GetCapabilityOutput"/> struct for raw data.
    /// </summary>
    /// <param name="moreData">Whether more data is available.</param>
    /// <param name="capability">The capability category.</param>
    /// <param name="rawData">The raw capability data.</param>
    public GetCapabilityOutput(bool moreData, Tpm2CapConstants capability, byte[] rawData)
    {
        MoreData = moreData;
        Capability = capability;
        Properties = [];
        RawData = rawData;
    }

    /// <inheritdoc/>
    public static TpmParseResult<GetCapabilityOutput> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);

        bool moreData = reader.ReadByte() != 0;
        uint capability = reader.ReadUInt32();

        if((Tpm2CapConstants)capability == Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES)
        {
            uint count = reader.ReadUInt32();
            var properties = new List<TpmProperty>((int)count);

            for(int i = 0; i < count; i++)
            {
                uint property = reader.ReadUInt32();
                uint value = reader.ReadUInt32();
                properties.Add(new TpmProperty(property, value));
            }

            return new TpmParseResult<GetCapabilityOutput>(
                new GetCapabilityOutput(moreData, (Tpm2CapConstants)capability, properties),
                reader.Consumed);
        }
        else
        {
            //For other capability types, read remaining as raw data.
            int remaining = source.Length - reader.Consumed;
            byte[] rawData = remaining > 0 ? source.Slice(reader.Consumed, remaining).ToArray() : [];

            return new TpmParseResult<GetCapabilityOutput>(
                new GetCapabilityOutput(moreData, (Tpm2CapConstants)capability, rawData),
                source.Length);
        }
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);

        writer.WriteByte(MoreData ? (byte)1 : (byte)0);
        writer.WriteUInt32((uint)Capability);

        if(Capability == Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES)
        {
            writer.WriteUInt32((uint)Properties.Count);
            foreach(TpmProperty prop in Properties)
            {
                writer.WriteUInt32(prop.Property);
                writer.WriteUInt32(prop.Value);
            }
        }
        else
        {
            writer.WriteBytes(RawData.Span);
        }
    }

    /// <inheritdoc/>
    public bool Equals(GetCapabilityOutput other)
    {
        if(MoreData != other.MoreData || Capability != other.Capability)
        {
            return false;
        }

        if(Capability == Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES)
        {
            if(Properties.Count != other.Properties.Count)
            {
                return false;
            }

            for(int i = 0; i < Properties.Count; i++)
            {
                if(!Properties[i].Equals(other.Properties[i]))
                {
                    return false;
                }
            }

            return true;
        }

        return RawData.Span.SequenceEqual(other.RawData.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is GetCapabilityOutput other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(MoreData);
        hash.Add(Capability);

        if(Capability == Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES)
        {
            foreach(TpmProperty prop in Properties)
            {
                hash.Add(prop.GetHashCode());
            }
        }
        else
        {
            hash.AddBytes(RawData.Span);
        }

        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(GetCapabilityOutput left, GetCapabilityOutput right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(GetCapabilityOutput left, GetCapabilityOutput right) => !left.Equals(right);
}

/// <summary>
/// A TPM property tag/value pair.
/// </summary>
/// <param name="Property">The property tag.</param>
/// <param name="Value">The property value.</param>
public readonly record struct TpmProperty(uint Property, uint Value);