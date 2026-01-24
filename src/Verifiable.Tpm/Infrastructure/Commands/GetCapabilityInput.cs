using System;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_GetCapability command.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_GetCapability returns information about the TPM and its current state.
/// This command has no handles - only parameters.
/// </para>
/// <para>
/// <b>Command parameters:</b>
/// </para>
/// <list type="bullet">
///   <item><description>capability (TPM_CAP) - the capability category to query.</description></item>
///   <item><description>property (UINT32) - the first property value to return.</description></item>
///   <item><description>propertyCount (UINT32) - the maximum number of properties to return.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, Section 30.2.
/// </para>
/// </remarks>
public readonly struct GetCapabilityInput: ITpmCommandInput, IEquatable<GetCapabilityInput>
{
    /// <summary>
    /// Gets the capability category to query.
    /// </summary>
    public TpmCapConstants Capability { get; }

    /// <summary>
    /// Gets the starting value for the property query.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The interpretation of this value depends on <see cref="Capability"/>:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>TPM_CAP_ALGS: TPM_ALG_ID (first algorithm).</description></item>
    ///   <item><description>TPM_CAP_HANDLES: TPM_HANDLE (first handle).</description></item>
    ///   <item><description>TPM_CAP_COMMANDS: TPM_CC (first command code).</description></item>
    ///   <item><description>TPM_CAP_TPM_PROPERTIES: TPM_PT (first property tag).</description></item>
    ///   <item><description>TPM_CAP_ECC_CURVES: TPM_ECC_CURVE (first curve).</description></item>
    ///   <item><description>TPM_CAP_PCRS: reserved (should be 0).</description></item>
    /// </list>
    /// </remarks>
    public uint Property { get; }

    /// <summary>
    /// Gets the maximum number of properties to return.
    /// </summary>
    public uint PropertyCount { get; }

    /// <summary>
    /// Initializes a new GetCapability input.
    /// </summary>
    /// <param name="capability">The capability category.</param>
    /// <param name="property">The first property value.</param>
    /// <param name="propertyCount">The maximum number of properties.</param>
    public GetCapabilityInput(TpmCapConstants capability, uint property, uint propertyCount)
    {
        Capability = capability;
        Property = property;
        PropertyCount = propertyCount;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_GetCapability;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //No handles, only parameters.
        return sizeof(uint) +  //capability
               sizeof(uint) +  //property
               sizeof(uint);   //propertyCount
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //No handles for GetCapability.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)Capability);
        writer.WriteUInt32(Property);
        writer.WriteUInt32(PropertyCount);
    }

    /// <summary>
    /// Creates input to query fixed TPM properties (PT_FIXED).
    /// </summary>
    /// <remarks>
    /// Fixed properties are values that only change due to firmware updates.
    /// Includes manufacturer, firmware version, specification revision, etc.
    /// </remarks>
    /// <param name="count">Maximum properties to return.</param>
    /// <returns>The input.</returns>
    public static GetCapabilityInput ForFixedProperties(uint count = 64)
    {
        return new GetCapabilityInput(TpmCapConstants.TPM_CAP_TPM_PROPERTIES, TpmPtConstants.PT_FIXED, count);
    }

    /// <summary>
    /// Creates input to query variable TPM properties (PT_VAR).
    /// </summary>
    /// <remarks>
    /// Variable properties change due to TPM operations (not firmware updates).
    /// Includes session counts, NV usage, lockout state, etc.
    /// </remarks>
    /// <param name="count">Maximum properties to return.</param>
    /// <returns>The input.</returns>
    public static GetCapabilityInput ForVariableProperties(uint count = 64)
    {
        return new GetCapabilityInput(TpmCapConstants.TPM_CAP_TPM_PROPERTIES, TpmPtConstants.PT_VAR, count);
    }

    /// <summary>
    /// Creates input to query TPM properties starting at a specific property.
    /// </summary>
    /// <param name="startProperty">The first property (use <see cref="TpmPtConstants"/>).</param>
    /// <param name="count">Maximum properties to return.</param>
    /// <returns>The input.</returns>
    public static GetCapabilityInput ForTpmProperties(uint startProperty, uint count = 64)
    {
        return new GetCapabilityInput(TpmCapConstants.TPM_CAP_TPM_PROPERTIES, startProperty, count);
    }

    /// <summary>
    /// Creates input to query supported algorithms.
    /// </summary>
    /// <param name="count">Maximum algorithms to return.</param>
    /// <returns>The input.</returns>
    public static GetCapabilityInput ForAlgorithms(uint count = 64)
    {
        return new GetCapabilityInput(TpmCapConstants.TPM_CAP_ALGS, 0, count);
    }

    /// <summary>
    /// Creates input to query supported ECC curves.
    /// </summary>
    /// <param name="count">Maximum curves to return.</param>
    /// <returns>The input.</returns>
    public static GetCapabilityInput ForEccCurves(uint count = 64)
    {
        return new GetCapabilityInput(TpmCapConstants.TPM_CAP_ECC_CURVES, 0, count);
    }

    /// <summary>
    /// Creates input to query supported commands.
    /// </summary>
    /// <param name="startCommand">The first command code.</param>
    /// <param name="count">Maximum commands to return.</param>
    /// <returns>The input.</returns>
    public static GetCapabilityInput ForCommands(uint startCommand = 0, uint count = 64)
    {
        return new GetCapabilityInput(TpmCapConstants.TPM_CAP_COMMANDS, startCommand, count);
    }

    /// <summary>
    /// Creates input to query PCR allocation (which banks are active).
    /// </summary>
    /// <param name="count">Maximum selections to return.</param>
    /// <returns>The input.</returns>
    public static GetCapabilityInput ForPcrs(uint count = 64)
    {
        return new GetCapabilityInput(TpmCapConstants.TPM_CAP_PCRS, 0, count);
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