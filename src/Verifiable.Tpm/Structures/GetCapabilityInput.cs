using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Commands;

/// <summary>
/// Input for the TPM2_GetCapability command.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_GetCapability returns information about the TPM and its current state.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 3: Commands, Section 30.2 - TPM2_GetCapability.
/// </para>
/// </remarks>
public readonly struct GetCapabilityInput: ITpmCommandInput<GetCapabilityInput>, IEquatable<GetCapabilityInput>
{
    /// <summary>
    /// Gets the capability category to query.
    /// </summary>
    public Tpm2CapConstants Capability { get; }

    /// <summary>
    /// Gets the first property value to return.
    /// </summary>
    public uint Property { get; }

    /// <summary>
    /// Gets the maximum number of properties to return.
    /// </summary>
    public uint PropertyCount { get; }

    /// <inheritdoc/>
    public static Tpm2CcConstants CommandCode => Tpm2CcConstants.TPM2_CC_GetCapability;

    /// <inheritdoc/>
    public int SerializedSize => sizeof(uint) + sizeof(uint) + sizeof(uint);

    /// <summary>
    /// Initializes a new instance of the <see cref="GetCapabilityInput"/> struct.
    /// </summary>
    /// <param name="capability">The capability category.</param>
    /// <param name="property">The first property.</param>
    /// <param name="propertyCount">The maximum number of properties.</param>
    public GetCapabilityInput(Tpm2CapConstants capability, uint property, uint propertyCount)
    {
        Capability = capability;
        Property = property;
        PropertyCount = propertyCount;
    }

    /// <inheritdoc/>
    public static TpmParseResult<GetCapabilityInput> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);

        uint capability = reader.ReadUInt32();
        uint property = reader.ReadUInt32();
        uint propertyCount = reader.ReadUInt32();

        return new TpmParseResult<GetCapabilityInput>(
            new GetCapabilityInput((Tpm2CapConstants)capability, property, propertyCount),
            reader.Consumed);
    }

    /// <inheritdoc/>
    public void WriteTo(Span<byte> destination)
    {
        var writer = new TpmWriter(destination);

        writer.WriteUInt32((uint)Capability);
        writer.WriteUInt32(Property);
        writer.WriteUInt32(PropertyCount);
    }

    /// <inheritdoc/>
    public bool Equals(GetCapabilityInput other)
    {
        return Capability == other.Capability &&
               Property == other.Property &&
               PropertyCount == other.PropertyCount;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is GetCapabilityInput other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Capability, Property, PropertyCount);

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(GetCapabilityInput left, GetCapabilityInput right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(GetCapabilityInput left, GetCapabilityInput right) => !left.Equals(right);
}