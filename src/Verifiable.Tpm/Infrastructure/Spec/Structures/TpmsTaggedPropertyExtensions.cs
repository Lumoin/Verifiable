using System;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Extension methods for <see cref="TpmsTaggedProperty"/>.
/// </summary>
/// <remarks>
/// <para>
/// Provides interpretation and formatting methods for tagged TPM properties.
/// These methods expose the same logic used in <see cref="System.Diagnostics.DebuggerDisplayAttribute"/>
/// as public API for callers.
/// </para>
/// </remarks>
public static class TpmsTaggedPropertyExtensions
{
    /// <summary>
    /// Gets a human-readable description of the property and its value.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Interprets the property value based on its type. For example:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>TPM_PT_MANUFACTURER → "Intel" (manufacturer name lookup).</description></item>
    ///   <item><description>TPM_PT_FIRMWARE_VERSION_1 → "7.85" (version formatting).</description></item>
    ///   <item><description>TPM_PT_FAMILY_INDICATOR → "2.0" (ASCII conversion).</description></item>
    /// </list>
    /// </remarks>
    /// <param name="property">The tagged property to describe.</param>
    /// <returns>A human-readable description of the property.</returns>
    public static string GetDescription(this TpmsTaggedProperty property)
    {
        string valuePart = property.Property switch
        {
            //Fixed properties with special formatting.
            TpmPtConstants.TPM_PT_FAMILY_INDICATOR => TpmValueConversions.ToAscii4(property.Value),
            TpmPtConstants.TPM_PT_MANUFACTURER => TpmValueConversions.ToAscii4(property.Value),
            TpmPtConstants.TPM_PT_VENDOR_STRING_1 => TpmValueConversions.ToAscii4(property.Value),
            TpmPtConstants.TPM_PT_VENDOR_STRING_2 => TpmValueConversions.ToAscii4(property.Value),
            TpmPtConstants.TPM_PT_VENDOR_STRING_3 => TpmValueConversions.ToAscii4(property.Value),
            TpmPtConstants.TPM_PT_VENDOR_STRING_4 => TpmValueConversions.ToAscii4(property.Value),
            TpmPtConstants.TPM_PT_FIRMWARE_VERSION_1 => TpmValueConversions.ToVersion(property.Value),
            TpmPtConstants.TPM_PT_FIRMWARE_VERSION_2 => TpmValueConversions.ToVersion(property.Value),

            //Size/count properties.
            TpmPtConstants.TPM_PT_MEMORY => TpmValueConversions.ToByteSize(property.Value),
            TpmPtConstants.TPM_PT_INPUT_BUFFER => TpmValueConversions.ToByteSize(property.Value),
            TpmPtConstants.TPM_PT_NV_BUFFER_MAX => TpmValueConversions.ToByteSize(property.Value),

            //Count properties.
            TpmPtConstants.TPM_PT_HR_LOADED => TpmValueConversions.ToCount(property.Value, "handle"),
            TpmPtConstants.TPM_PT_HR_ACTIVE => TpmValueConversions.ToCount(property.Value, "session"),
            TpmPtConstants.TPM_PT_PCR_COUNT => TpmValueConversions.ToCount(property.Value, "PCR"),

            //Default: show raw value.
            _ => $"{property.Value} (0x{property.Value:X8})"
        };

        return $"{GetPropertyName(property.Property)}: {valuePart}";
    }

    /// <summary>
    /// Gets a friendly name for the property identifier.
    /// </summary>
    /// <param name="property">The property identifier value.</param>
    /// <returns>A friendly name for known properties, or hex representation if unknown.</returns>
    public static string GetPropertyName(uint property)
    {
        return property switch
        {
            TpmPtConstants.TPM_PT_FAMILY_INDICATOR => "FAMILY_INDICATOR",
            TpmPtConstants.TPM_PT_LEVEL => "LEVEL",
            TpmPtConstants.TPM_PT_REVISION => "REVISION",
            TpmPtConstants.TPM_PT_DAY_OF_YEAR => "DAY_OF_YEAR",
            TpmPtConstants.TPM_PT_YEAR => "YEAR",
            TpmPtConstants.TPM_PT_MANUFACTURER => "MANUFACTURER",
            TpmPtConstants.TPM_PT_VENDOR_STRING_1 => "VENDOR_STRING_1",
            TpmPtConstants.TPM_PT_VENDOR_STRING_2 => "VENDOR_STRING_2",
            TpmPtConstants.TPM_PT_VENDOR_STRING_3 => "VENDOR_STRING_3",
            TpmPtConstants.TPM_PT_VENDOR_STRING_4 => "VENDOR_STRING_4",
            TpmPtConstants.TPM_PT_VENDOR_TPM_TYPE => "VENDOR_TPM_TYPE",
            TpmPtConstants.TPM_PT_FIRMWARE_VERSION_1 => "FIRMWARE_VERSION_1",
            TpmPtConstants.TPM_PT_FIRMWARE_VERSION_2 => "FIRMWARE_VERSION_2",
            TpmPtConstants.TPM_PT_INPUT_BUFFER => "INPUT_BUFFER",
            TpmPtConstants.TPM_PT_MEMORY => "MEMORY",
            TpmPtConstants.TPM_PT_PCR_COUNT => "PCR_COUNT",
            TpmPtConstants.TPM_PT_HR_LOADED => "HR_LOADED",
            TpmPtConstants.TPM_PT_HR_ACTIVE => "HR_ACTIVE",
            TpmPtConstants.TPM_PT_NV_BUFFER_MAX => "NV_BUFFER_MAX",
            TpmPtConstants.TPM_PT_PERMANENT => "PERMANENT",
            TpmPtConstants.TPM_PT_STARTUP_CLEAR => "STARTUP_CLEAR",
            TpmPtConstants.TPM_PT_LOCKOUT_COUNTER => "LOCKOUT_COUNTER",
            TpmPtConstants.TPM_PT_MAX_AUTH_FAIL => "MAX_AUTH_FAIL",
            TpmPtConstants.TPM_PT_LOCKOUT_INTERVAL => "LOCKOUT_INTERVAL",
            TpmPtConstants.TPM_PT_LOCKOUT_RECOVERY => "LOCKOUT_RECOVERY",
            _ => $"TPM_PT_0x{property:X}"
        };
    }

    /// <summary>
    /// Gets the raw value interpreted as a 4-character ASCII string.
    /// </summary>
    /// <param name="property">The tagged property.</param>
    /// <returns>The ASCII string representation, or hex if non-printable.</returns>
    public static string GetValueAsAscii(this TpmsTaggedProperty property)
    {
        return TpmValueConversions.ToAscii4(property.Value);
    }

    /// <summary>
    /// Gets the raw value interpreted as a version (major.minor).
    /// </summary>
    /// <param name="property">The tagged property.</param>
    /// <returns>The version string.</returns>
    public static string GetValueAsVersion(this TpmsTaggedProperty property)
    {
        return TpmValueConversions.ToVersion(property.Value);
    }

    /// <summary>
    /// Gets the raw value interpreted as a byte size.
    /// </summary>
    /// <param name="property">The tagged property.</param>
    /// <returns>The formatted byte size string.</returns>
    public static string GetValueAsByteSize(this TpmsTaggedProperty property)
    {
        return TpmValueConversions.ToByteSize(property.Value);
    }

    /// <summary>
    /// Determines if this is a fixed property (immutable, only changes with firmware update).
    /// </summary>
    /// <param name="property">The tagged property.</param>
    /// <returns><c>true</c> if this is a fixed property; otherwise, <c>false</c>.</returns>
    public static bool IsFixedProperty(this TpmsTaggedProperty property)
    {
        return property.Property >= TpmPtConstants.PT_FIXED && property.Property < TpmPtConstants.PT_VAR;
    }

    /// <summary>
    /// Determines if this is a variable property (mutable during TPM operation).
    /// </summary>
    /// <param name="property">The tagged property.</param>
    /// <returns><c>true</c> if this is a variable property; otherwise, <c>false</c>.</returns>
    public static bool IsVariableProperty(this TpmsTaggedProperty property)
    {
        return property.Property >= TpmPtConstants.PT_VAR && property.Property < TpmPtConstants.PT_VAR + TpmPtConstants.PT_GROUP;
    }
}