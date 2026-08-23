using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_NV_LEGACY_INDEX — a handle constrained to an NV index with 32-bit attributes.
/// </summary>
/// <remarks>
/// <para>
/// Used to identify an NV index in the <c>TPM2_NV_DefineSpace()</c> and <c>TPM2_NV_ReadPublic()</c>
/// commands, and as the <c>nvIndex</c> field of the legacy <c>TPMS_NV_PUBLIC</c> structure (Part 2,
/// Section 13.6, Table 235), which only supports regular NV indexes.
/// </para>
/// <para>
/// <b>Valid values:</b> the ordinary NV index range. Unmarshaling a value outside it — an external or a
/// permanent NV index included — is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.27, Table 74.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhNvLegacyIndex(uint Value)
{
    /// <summary>
    /// Gets the handle type (MSO).
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Whether a raw handle value falls within the single NV index range this type admits — the ordinary NV
    /// index range. The external and permanent NV index ranges are excluded: the legacy public area carries
    /// 32-bit attributes, which only a regular NV index has.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is an ordinary NV index.</returns>
    public static bool IsLegacyIndex(uint value)
    {
        return TpmHandleRanges.GetHandleType(value) == TpmHt.TPM_HT_NV_INDEX;
    }

    /// <summary>
    /// Parses a legacy NV index handle from a TPM reader, validating the range.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed NV index handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not an ordinary NV index (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhNvLegacyIndex Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsLegacyIndex(value))
        {
            throw new InvalidOperationException($"Invalid NV index handle 0x{value:X8}. Expected a TPMI_RH_NV_LEGACY_INDEX value.");
        }

        return new TpmiRhNvLegacyIndex(value);
    }

    /// <summary>
    /// Creates a legacy NV index handle from a raw value without validation — for a value already known good
    /// (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhNvLegacyIndex FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The NV index handle.</param>
    public static implicit operator TpmHandle(TpmiRhNvLegacyIndex handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_RH_NV_LEGACY_INDEX(0x{Value:X8})";
}
