using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_ENABLES — a handle constrained to a hierarchy-enable or NV-enable selector.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the handle is required to be one of the hierarchy or NV
/// enables.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_OWNER</c> (storage hierarchy), <c>TPM_RH_PLATFORM</c> (platform
/// hierarchy), <c>TPM_RH_ENDORSEMENT</c> (endorsement hierarchy), <c>TPM_RH_PLATFORM_NV</c> (platform NV),
/// and, where the caller admits it, <c>TPM_RH_NULL</c> (the null hierarchy). Unmarshaling any other value
/// is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.14, Table 60.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhEnables
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes an enables handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhEnables(uint value)
    {
        Value = value;
    }

    /// <summary>The storage hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhEnables Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhEnables Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>The endorsement hierarchy (<c>TPM_RH_ENDORSEMENT</c>).</summary>
    public static TpmiRhEnables Endorsement => new((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>The platform NV enable (<c>TPM_RH_PLATFORM_NV</c>).</summary>
    public static TpmiRhEnables PlatformNv => new((uint)TpmRh.TPM_RH_PLATFORM_NV);

    /// <summary>The NULL hierarchy (<c>TPM_RH_NULL</c>).</summary>
    public static TpmiRhEnables Null => new((uint)TpmRh.TPM_RH_NULL);

    /// <summary>
    /// Whether a raw handle value is one of the four named enable selectors this type admits, optionally
    /// also admitting the NULL hierarchy where the table's <c>+TPM_RH_NULL</c> form applies.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsEnables(uint value, bool isNullAdmitted = false) => value switch
    {
        (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_ENDORSEMENT or (uint)TpmRh.TPM_RH_PLATFORM_NV => true,
        (uint)TpmRh.TPM_RH_NULL => isNullAdmitted,
        _ => false
    };

    /// <summary>
    /// Parses an enables handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns>The parsed enables handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not an enables selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhEnables Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        uint value = reader.ReadUInt32();
        if(!IsEnables(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid enables handle 0x{value:X8}. Expected a TPMI_RH_ENABLES selector.");
        }

        return new TpmiRhEnables(value);
    }

    /// <summary>
    /// Creates an enables handle from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhEnables FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The enables handle.</param>
    public static implicit operator TpmHandle(TpmiRhEnables handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_ENABLES(OWNER)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_ENABLES(PLATFORM)",
        (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPMI_RH_ENABLES(ENDORSEMENT)",
        (uint)TpmRh.TPM_RH_PLATFORM_NV => "TPMI_RH_ENABLES(PLATFORM_NV)",
        (uint)TpmRh.TPM_RH_NULL => "TPMI_RH_ENABLES(NULL)",
        _ => $"TPMI_RH_ENABLES(0x{Value:X8})"
    };
}
