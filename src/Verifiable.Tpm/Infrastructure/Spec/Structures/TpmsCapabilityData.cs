using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPMS_CAPABILITY_DATA - capability data returned by TPM2_GetCapability.
/// </summary>
/// <remarks>
/// <para>
/// This is a discriminated union where the capability type determines which
/// data field is populated.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <list type="bullet">
///   <item><description>capability (TPM_CAP) - the capability type.</description></item>
///   <item><description>data (TPMU_CAPABILITIES) - the union data.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.11.1.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsCapabilityData: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the capability type.
    /// </summary>
    public TpmCapConstants Capability { get; }

    /// <summary>
    /// Gets the algorithm properties (when Capability is TPM_CAP_ALGS).
    /// </summary>
    public IReadOnlyList<TpmsAlgProperty>? Algorithms { get; }

    /// <summary>
    /// Gets the handles (when Capability is TPM_CAP_HANDLES).
    /// </summary>
    public IReadOnlyList<uint>? Handles { get; }

    /// <summary>
    /// Gets the command attributes (when Capability is TPM_CAP_COMMANDS).
    /// </summary>
    public IReadOnlyList<uint>? Commands { get; }

    /// <summary>
    /// Gets the PCR selections (when Capability is TPM_CAP_PCRS).
    /// </summary>
    public TpmlPcrSelection? PcrSelection { get; }

    /// <summary>
    /// Gets the TPM properties (when Capability is TPM_CAP_TPM_PROPERTIES).
    /// </summary>
    public IReadOnlyList<TpmsTaggedProperty>? TpmProperties { get; }

    /// <summary>
    /// Gets the ECC curves (when Capability is TPM_CAP_ECC_CURVES).
    /// </summary>
    public IReadOnlyList<TpmEccCurveConstants>? EccCurves { get; }

    private TpmsCapabilityData(TpmCapConstants capability)
    {
        Capability = capability;
    }

    private TpmsCapabilityData(TpmCapConstants capability, IReadOnlyList<TpmsAlgProperty> algorithms)
        : this(capability)
    {
        Algorithms = algorithms;
    }

    private TpmsCapabilityData(TpmCapConstants capability, IReadOnlyList<uint> handles, bool isHandles)
        : this(capability)
    {
        if(isHandles)
        {
            Handles = handles;
        }
        else
        {
            Commands = handles;
        }
    }

    private TpmsCapabilityData(TpmCapConstants capability, TpmlPcrSelection pcrSelection)
        : this(capability)
    {
        PcrSelection = pcrSelection;
    }

    private TpmsCapabilityData(TpmCapConstants capability, IReadOnlyList<TpmsTaggedProperty> tpmProperties)
        : this(capability)
    {
        TpmProperties = tpmProperties;
    }

    private TpmsCapabilityData(TpmCapConstants capability, IReadOnlyList<TpmEccCurveConstants> eccCurves)
        : this(capability)
    {
        EccCurves = eccCurves;
    }

    /// <summary>
    /// Creates capability data for the <c>TPM_CAP_TPM_PROPERTIES</c> arm from a list of tagged
    /// properties. This is the server-side counterpart to <see cref="Parse"/>, used when producing a
    /// <c>TPM2_GetCapability()</c> response.
    /// </summary>
    /// <param name="properties">The tagged properties, in ascending property order.</param>
    /// <returns>The capability data.</returns>
    public static TpmsCapabilityData CreateTpmProperties(IReadOnlyList<TpmsTaggedProperty> properties)
    {
        ArgumentNullException.ThrowIfNull(properties);

        return new TpmsCapabilityData(TpmCapConstants.TPM_CAP_TPM_PROPERTIES, properties);
    }

    /// <summary>
    /// Writes this capability data to a TPM writer (capability selector followed by the union arm).
    /// Only the <c>TPM_CAP_TPM_PROPERTIES</c> arm is supported; other arms are written as they are
    /// modelled.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <exception cref="NotSupportedException">Thrown for an arm without write support.</exception>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)Capability);

        switch(Capability)
        {
            case TpmCapConstants.TPM_CAP_TPM_PROPERTIES:
            {
                IReadOnlyList<TpmsTaggedProperty> properties = TpmProperties ?? Array.Empty<TpmsTaggedProperty>();
                writer.WriteUInt32((uint)properties.Count);
                for(int i = 0; i < properties.Count; i++)
                {
                    writer.WriteUInt32(properties[i].Property);
                    writer.WriteUInt32(properties[i].Value);
                }

                break;
            }
            default:
            {
                throw new NotSupportedException($"Writing TPMS_CAPABILITY_DATA for capability '{Capability}' is not supported.");
            }
        }
    }

    /// <summary>
    /// Gets the serialized size in octets of this capability data (capability selector plus the union
    /// arm), for sizing a response buffer before framing.
    /// </summary>
    /// <returns>The serialized size in octets.</returns>
    /// <exception cref="NotSupportedException">Thrown for an arm without write support.</exception>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate",
        Justification = "Mirrors the WriteTo serialization and throws NotSupportedException for unmodelled arms, so a method rather than a property is appropriate.")]
    public int GetSerializedSize() => Capability switch
    {
        TpmCapConstants.TPM_CAP_TPM_PROPERTIES =>
            sizeof(uint) + sizeof(uint) + ((TpmProperties?.Count ?? 0) * (sizeof(uint) + sizeof(uint))),
        _ => throw new NotSupportedException($"Serialized size for capability '{Capability}' is not supported.")
    };

    /// <summary>
    /// Parses capability data from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed capability data.</returns>
    public static TpmsCapabilityData Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        uint capabilityValue = reader.ReadUInt32();
        var capability = (TpmCapConstants)capabilityValue;

        return capability switch
        {
            TpmCapConstants.TPM_CAP_ALGS => ParseAlgorithms(ref reader, capability),
            TpmCapConstants.TPM_CAP_HANDLES => ParseHandles(ref reader, capability, isHandles: true),
            TpmCapConstants.TPM_CAP_COMMANDS => ParseHandles(ref reader, capability, isHandles: false),
            TpmCapConstants.TPM_CAP_PP_COMMANDS => ParseCommandCodes(ref reader, capability),
            TpmCapConstants.TPM_CAP_AUDIT_COMMANDS => ParseCommandCodes(ref reader, capability),
            TpmCapConstants.TPM_CAP_PCRS => ParsePcrSelection(ref reader, capability, pool),
            TpmCapConstants.TPM_CAP_TPM_PROPERTIES => ParseTpmProperties(ref reader, capability),
            TpmCapConstants.TPM_CAP_ECC_CURVES => ParseEccCurves(ref reader, capability),
            _ => throw new NotSupportedException($"Capability '{capability}' is not supported.")
        };
    }

    private static TpmsCapabilityData ParseAlgorithms(ref TpmReader reader, TpmCapConstants capability)
    {
        uint count = reader.ReadUInt32();
        var algorithms = new TpmsAlgProperty[count];

        for(int i = 0; i < count; i++)
        {
            algorithms[i] = TpmsAlgProperty.Parse(ref reader);
        }

        return new TpmsCapabilityData(capability, algorithms);
    }

    private static TpmsCapabilityData ParseHandles(ref TpmReader reader, TpmCapConstants capability, bool isHandles)
    {
        uint count = reader.ReadUInt32();
        var handles = new uint[count];

        for(int i = 0; i < count; i++)
        {
            handles[i] = reader.ReadUInt32();
        }

        return new TpmsCapabilityData(capability, handles, isHandles);
    }

    private static TpmsCapabilityData ParseCommandCodes(ref TpmReader reader, TpmCapConstants capability)
    {
        uint count = reader.ReadUInt32();
        var commands = new uint[count];

        for(int i = 0; i < count; i++)
        {
            commands[i] = reader.ReadUInt32();
        }

        return new TpmsCapabilityData(capability, commands, isHandles: false);
    }

    private static TpmsCapabilityData ParsePcrSelection(ref TpmReader reader, TpmCapConstants capability, MemoryPool<byte> pool)
    {
        TpmlPcrSelection pcrSelection = TpmlPcrSelection.Parse(ref reader, pool);
        return new TpmsCapabilityData(capability, pcrSelection);
    }

    private static TpmsCapabilityData ParseTpmProperties(ref TpmReader reader, TpmCapConstants capability)
    {
        uint count = reader.ReadUInt32();
        var properties = new TpmsTaggedProperty[count];

        for(int i = 0; i < count; i++)
        {
            //TpmsTaggedProperty is a record struct - parse inline.
            uint property = reader.ReadUInt32();
            uint value = reader.ReadUInt32();
            properties[i] = new TpmsTaggedProperty(property, value);
        }

        return new TpmsCapabilityData(capability, properties);
    }

    private static TpmsCapabilityData ParseEccCurves(ref TpmReader reader, TpmCapConstants capability)
    {
        uint count = reader.ReadUInt32();
        var curves = new TpmEccCurveConstants[count];

        for(int i = 0; i < count; i++)
        {
            curves[i] = (TpmEccCurveConstants)reader.ReadUInt16();
        }

        return new TpmsCapabilityData(capability, curves);
    }

    /// <summary>
    /// Releases resources owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            PcrSelection?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_CAPABILITY_DATA({Capability})";
}
