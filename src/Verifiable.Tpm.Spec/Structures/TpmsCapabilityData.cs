using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, Section 10.9.2, Table 139 (Definition of TPMS_CAPABILITY_DATA Structure).
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
    /// Gets the handles (when Capability is TPM_CAP_HANDLES), the <c>TPML_HANDLE</c> arm of Table 138.
    /// </summary>
    public TpmlHandle? Handles { get; }

    /// <summary>
    /// Gets the command attributes (when Capability is TPM_CAP_COMMANDS), the <c>TPML_CCA</c> arm of Table 138.
    /// </summary>
    /// <remarks>
    /// Table 138 selects <c>TPML_CCA</c> for <c>TPM_CAP_COMMANDS</c> alone: its elements are <c>TPMA_CC</c>
    /// attribute words whose low 16 bits are the command index, not the bare <c>TPM_CC</c> command codes
    /// <see cref="PhysicalPresenceCommands"/> and <see cref="AuditCommands"/> carry.
    /// </remarks>
    public TpmlCca? CommandAttributes { get; }

    /// <summary>
    /// Gets the commands requiring physical presence (when Capability is TPM_CAP_PP_COMMANDS), the
    /// <c>ppCommands</c> <c>TPML_CC</c> arm of Table 138.
    /// </summary>
    public TpmlCc? PhysicalPresenceCommands { get; }

    /// <summary>
    /// Gets the audited commands (when Capability is TPM_CAP_AUDIT_COMMANDS), the <c>auditCommands</c>
    /// <c>TPML_CC</c> arm of Table 138.
    /// </summary>
    public TpmlCc? AuditCommands { get; }

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

    /// <summary>
    /// Initializes capability data that carries the selector alone, with every union arm left unset.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector of Table 138.</param>
    private TpmsCapabilityData(TpmCapConstants capability)
    {
        Capability = capability;
    }

    /// <summary>
    /// Initializes capability data holding Table 138's <c>algorithms</c> arm.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector, <c>TPM_CAP_ALGS</c>.</param>
    /// <param name="algorithms">The algorithm properties.</param>
    private TpmsCapabilityData(TpmCapConstants capability, IReadOnlyList<TpmsAlgProperty> algorithms)
        : this(capability)
    {
        Algorithms = algorithms;
    }

    /// <summary>
    /// Initializes capability data holding Table 138's <c>handles</c> arm.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector, <c>TPM_CAP_HANDLES</c>.</param>
    /// <param name="handles">The handle list. Ownership transfers to this instance.</param>
    private TpmsCapabilityData(TpmCapConstants capability, TpmlHandle handles)
        : this(capability)
    {
        Handles = handles;
    }

    /// <summary>
    /// Initializes capability data holding Table 138's <c>command</c> arm, the <c>TPML_CCA</c> attribute words.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector, <c>TPM_CAP_COMMANDS</c>.</param>
    /// <param name="commandAttributes">The command attribute list. Ownership transfers to this instance.</param>
    private TpmsCapabilityData(TpmCapConstants capability, TpmlCca commandAttributes)
        : this(capability)
    {
        CommandAttributes = commandAttributes;
    }

    /// <summary>
    /// Initializes capability data holding one of Table 138's two <c>TPML_CC</c> arms, chosen by
    /// <paramref name="capability"/>: <c>ppCommands</c> for <c>TPM_CAP_PP_COMMANDS</c>, <c>auditCommands</c>
    /// otherwise.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector, <c>TPM_CAP_PP_COMMANDS</c> or <c>TPM_CAP_AUDIT_COMMANDS</c>.</param>
    /// <param name="commandCodes">The command code list. Ownership transfers to this instance.</param>
    private TpmsCapabilityData(TpmCapConstants capability, TpmlCc commandCodes)
        : this(capability)
    {
        if(capability == TpmCapConstants.TPM_CAP_PP_COMMANDS)
        {
            PhysicalPresenceCommands = commandCodes;
        }
        else
        {
            AuditCommands = commandCodes;
        }
    }

    /// <summary>
    /// Initializes capability data holding Table 138's <c>assignedPCR</c> arm.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector, <c>TPM_CAP_PCRS</c>.</param>
    /// <param name="pcrSelection">The PCR selection list.</param>
    private TpmsCapabilityData(TpmCapConstants capability, TpmlPcrSelection pcrSelection)
        : this(capability)
    {
        PcrSelection = pcrSelection;
    }

    /// <summary>
    /// Initializes capability data holding Table 138's <c>tpmProperties</c> arm.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector, <c>TPM_CAP_TPM_PROPERTIES</c>.</param>
    /// <param name="tpmProperties">The tagged properties.</param>
    private TpmsCapabilityData(TpmCapConstants capability, IReadOnlyList<TpmsTaggedProperty> tpmProperties)
        : this(capability)
    {
        TpmProperties = tpmProperties;
    }

    /// <summary>
    /// Initializes capability data holding Table 138's <c>eccCurves</c> arm.
    /// </summary>
    /// <param name="capability">The <c>TPM_CAP</c> selector, <c>TPM_CAP_ECC_CURVES</c>.</param>
    /// <param name="eccCurves">The supported curve identifiers.</param>
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
    public static TpmsCapabilityData Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        uint capabilityValue = reader.ReadUInt32();
        var capability = (TpmCapConstants)capabilityValue;

        return capability switch
        {
            TpmCapConstants.TPM_CAP_ALGS => ParseAlgorithms(ref reader, capability),
            TpmCapConstants.TPM_CAP_HANDLES => ParseHandles(ref reader, capability),
            TpmCapConstants.TPM_CAP_COMMANDS => ParseCommandAttributes(ref reader, capability),
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

        //Each TPMS_ALG_PROPERTY is algId(2) + attributes(4); reject a count the buffer cannot hold before
        //sizing the array, so a lying count cannot force an unbounded allocation (Part 2, §10.7).
        reader.EnsureCount(count, sizeof(ushort) + sizeof(uint));

        var algorithms = new TpmsAlgProperty[count];

        for(int i = 0; i < count; i++)
        {
            algorithms[i] = TpmsAlgProperty.Parse(ref reader);
        }

        return new TpmsCapabilityData(capability, algorithms);
    }

    /// <summary>
    /// Parses the <c>TPM_CAP_HANDLES</c> arm: a <c>TPML_HANDLE</c> of loaded, persistent, or NV Index handles
    /// (Part 2, clause 10.8.4, Table 125; Table 138's <c>handles</c> member).
    /// </summary>
    /// <param name="reader">The reader positioned at the list's count field.</param>
    /// <param name="capability">The capability selector already read.</param>
    /// <returns>The parsed capability data.</returns>
    private static TpmsCapabilityData ParseHandles(ref TpmReader reader, TpmCapConstants capability) =>
        new(capability, TpmlHandle.Parse(ref reader));

    /// <summary>
    /// Parses the <c>TPM_CAP_COMMANDS</c> arm: a <c>TPML_CCA</c> of <c>TPMA_CC</c> attribute words, the only
    /// capability that returns command ATTRIBUTES rather than bare command codes (Part 2, clause 10.8.2,
    /// Table 123; Table 138's <c>command</c> member).
    /// </summary>
    /// <param name="reader">The reader positioned at the list's count field.</param>
    /// <param name="capability">The capability selector already read.</param>
    /// <returns>The parsed capability data.</returns>
    private static TpmsCapabilityData ParseCommandAttributes(ref TpmReader reader, TpmCapConstants capability) =>
        new(capability, TpmlCca.Parse(ref reader));

    /// <summary>
    /// Parses the <c>TPM_CAP_PP_COMMANDS</c> and <c>TPM_CAP_AUDIT_COMMANDS</c> arms: a <c>TPML_CC</c> of bare
    /// command codes (Part 2, clause 10.8.1, Table 122; Table 138's <c>ppCommands</c> and <c>auditCommands</c>
    /// members).
    /// </summary>
    /// <param name="reader">The reader positioned at the list's count field.</param>
    /// <param name="capability">The capability selector already read, which selects which member is populated.</param>
    /// <returns>The parsed capability data.</returns>
    private static TpmsCapabilityData ParseCommandCodes(ref TpmReader reader, TpmCapConstants capability) =>
        new(capability, TpmlCc.Parse(ref reader));

    private static TpmsCapabilityData ParsePcrSelection(ref TpmReader reader, TpmCapConstants capability, BaseMemoryPool pool)
    {
        TpmlPcrSelection pcrSelection = TpmlPcrSelection.Parse(ref reader, pool);
        return new TpmsCapabilityData(capability, pcrSelection);
    }

    private static TpmsCapabilityData ParseTpmProperties(ref TpmReader reader, TpmCapConstants capability)
    {
        uint count = reader.ReadUInt32();

        //Each TPMS_TAGGED_PROPERTY is property(4) + value(4); reject a count the buffer cannot hold before
        //sizing the array so a lying count cannot force an unbounded allocation (Part 2, §10.7).
        reader.EnsureCount(count, sizeof(uint) + sizeof(uint));

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

        //Each TPM_ECC_CURVE is a 2-byte selector; reject a count the buffer cannot hold before sizing the
        //array so a lying count cannot force an unbounded allocation (Part 2, §10.7).
        reader.EnsureCount(count, sizeof(ushort));

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
