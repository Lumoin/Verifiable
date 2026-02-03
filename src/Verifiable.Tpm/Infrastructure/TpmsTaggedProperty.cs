using System;
using System.Buffers.Binary;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPMS_TAGGED_PROPERTY - a property value with its identifying tag.
/// </summary>
/// <remarks>
/// <para>
/// This structure is returned in the capability data from TPM2_GetCapability
/// when querying TPM properties (<see cref="Tpm2CapConstants.TPM_CAP_TPM_PROPERTIES"/>).
/// </para>
/// <para>
/// Wire format (big-endian, 8 bytes total):
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-3: Property (TPM_PT) - the property identifier from <see cref="Tpm2PtConstants"/>.</description></item>
///   <item><description>Bytes 4-7: Value (uint32) - the property value.</description></item>
/// </list>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 10.6.1 - TPMS_TAGGED_PROPERTY.
/// </para>
/// </remarks>
/// <seealso cref="Tpm2PtConstants"/>
/// <seealso cref="Tpm2CapConstants"/>
public readonly struct TpmsTaggedProperty: IEquatable<TpmsTaggedProperty>
{
    /// <summary>
    /// Size in bytes when serialized (property: 4 + value: 4 = 8).
    /// </summary>
    public const int Size = sizeof(uint) + sizeof(uint);

    /// <summary>
    /// Gets the property identifier (TPM_PT value).
    /// </summary>
    /// <remarks>
    /// See <see cref="Tpm2PtConstants"/> for defined property values such as
    /// <see cref="Tpm2PtConstants.TPM2_PT_MANUFACTURER"/> and <see cref="Tpm2PtConstants.TPM2_PT_MODES"/>.
    /// </remarks>
    /// <seealso cref="Tpm2PtConstants"/>
    public uint Property { get; }

    /// <summary>
    /// Gets the property value.
    /// </summary>
    /// <remarks>
    /// The interpretation of this value depends on the property type. For example,
    /// <see cref="Tpm2PtConstants.TPM2_PT_MODES"/> returns a <see cref="TpmaModes"/> bitmask.
    /// </remarks>
    public uint Value { get; }

    /// <summary>
    /// Initializes a tagged property with the specified identifier and value.
    /// </summary>
    /// <param name="property">Property identifier from <see cref="Tpm2PtConstants"/>.</param>
    /// <param name="value">Property value.</param>
    public TpmsTaggedProperty(uint property, uint value)
    {
        Property = property;
        Value = value;
    }

    /// <summary>
    /// Reads a tagged property from a byte span.
    /// </summary>
    /// <param name="source">Source bytes, must be at least <see cref="Size"/> bytes.</param>
    /// <returns>The parsed tagged property.</returns>
    public static TpmsTaggedProperty ReadFrom(ReadOnlySpan<byte> source)
    {
        return new TpmsTaggedProperty(BinaryPrimitives.ReadUInt32BigEndian(source), BinaryPrimitives.ReadUInt32BigEndian(source[sizeof(uint)..]));
    }

    /// <inheritdoc/>
    public bool Equals(TpmsTaggedProperty other)
    {
        return Property == other.Property && Value == other.Value;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmsTaggedProperty other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Property, Value);
    }

    /// <summary>
    /// Determines whether two <see cref="TpmsTaggedProperty"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
    public static bool operator ==(TpmsTaggedProperty left, TpmsTaggedProperty right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="TpmsTaggedProperty"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><c>true</c> if not equal; otherwise, <c>false</c>.</returns>
    public static bool operator !=(TpmsTaggedProperty left, TpmsTaggedProperty right)
    {
        return !left.Equals(right);
    }
}