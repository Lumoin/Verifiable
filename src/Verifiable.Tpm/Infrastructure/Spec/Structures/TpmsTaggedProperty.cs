using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Reports properties that are UINT32 values (TPMS_TAGGED_PROPERTY).
/// </summary>
/// <remarks>
/// <para>
/// Returned in response to <c>TPM2_GetCapability(capability == TPM_CAP_TPM_PROPERTIES)</c>.
/// Each property is a key-value pair where the key identifies the property type
/// and the value is a 32-bit unsigned integer whose interpretation depends on
/// the property.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_PT property;   // A property identifier.
///     UINT32 value;      // The value of the property.
/// } TPMS_TAGGED_PROPERTY;
/// </code>
/// <para>
/// <b>Property categories:</b>
/// </para>
/// <list type="bullet">
///   <item><description><b>Fixed properties</b> (PT_FIXED, 0x100-0x1FF): Immutable values
///   like manufacturer ID, firmware version, specification level. These only change
///   with firmware updates.</description></item>
///   <item><description><b>Variable properties</b> (PT_VAR, 0x200-0x2FF): Mutable values
///   like startup clear flags, lockout counter, audit counter. These change during
///   TPM operation.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.8.2, Table 114.
/// </para>
/// </remarks>
/// <param name="Property">A property identifier (TPM_PT).</param>
/// <param name="Value">The value of the property.</param>
/// <seealso cref="TpmsTaggedPropertyExtensions"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsTaggedProperty(uint Property, uint Value)
{
    private string DebuggerDisplay
    {
        get
        {
            return Property switch
            {
                //Fixed properties with special formatting.
                TpmPtConstants.TPM_PT_FAMILY_INDICATOR => $"TPM_PT_FAMILY_INDICATOR: {TpmValueConversions.ToAscii4(Value)}",
                TpmPtConstants.TPM_PT_MANUFACTURER => $"TPM_PT_MANUFACTURER: {TpmValueConversions.ToAscii4(Value)}",
                TpmPtConstants.TPM_PT_VENDOR_STRING_1 => $"TPM_PT_VENDOR_STRING_1: {TpmValueConversions.ToAscii4(Value)}",
                TpmPtConstants.TPM_PT_VENDOR_STRING_2 => $"TPM_PT_VENDOR_STRING_2: {TpmValueConversions.ToAscii4(Value)}",
                TpmPtConstants.TPM_PT_VENDOR_STRING_3 => $"TPM_PT_VENDOR_STRING_3: {TpmValueConversions.ToAscii4(Value)}",
                TpmPtConstants.TPM_PT_VENDOR_STRING_4 => $"TPM_PT_VENDOR_STRING_4: {TpmValueConversions.ToAscii4(Value)}",
                TpmPtConstants.TPM_PT_FIRMWARE_VERSION_1 => $"TPM_PT_FIRMWARE_VERSION_1: {TpmValueConversions.ToVersion(Value)}",
                TpmPtConstants.TPM_PT_FIRMWARE_VERSION_2 => $"TPM_PT_FIRMWARE_VERSION_2: {TpmValueConversions.ToVersion(Value)}",

                //Size/count properties.
                TpmPtConstants.TPM_PT_MEMORY => $"TPM_PT_MEMORY: {TpmValueConversions.ToByteSize(Value)}",
                TpmPtConstants.TPM_PT_INPUT_BUFFER => $"TPM_PT_INPUT_BUFFER: {TpmValueConversions.ToByteSize(Value)}",
                TpmPtConstants.TPM_PT_NV_BUFFER_MAX => $"TPM_PT_NV_BUFFER_MAX: {TpmValueConversions.ToByteSize(Value)}",

                //Count properties.
                TpmPtConstants.TPM_PT_HR_LOADED => $"TPM_PT_HR_LOADED: {TpmValueConversions.ToCount(Value, "handle")}",
                TpmPtConstants.TPM_PT_HR_ACTIVE => $"TPM_PT_HR_ACTIVE: {TpmValueConversions.ToCount(Value, "session")}",
                TpmPtConstants.TPM_PT_PCR_COUNT => $"TPM_PT_PCR_COUNT: {TpmValueConversions.ToCount(Value, "PCR")}",

                //Default: show raw value with hex.
                _ => $"TPM_PT_0x{Property:X}: {Value} (0x{Value:X8})"
            };
        }
    }
}