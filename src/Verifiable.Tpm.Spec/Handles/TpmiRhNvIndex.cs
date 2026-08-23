using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_NV_INDEX — a handle constrained to an NV index.
/// </summary>
/// <remarks>
/// <para>
/// Used to identify an NV index. This type is used in all NV commands except those that define or undefine
/// an index and <c>TPM2_NV_ReadPublic()</c>.
/// </para>
/// <para>
/// <b>Valid values:</b> the ordinary NV index range, the external NV index range, and the permanent NV index
/// range. Unmarshaling a value outside these ranges is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.25, Table 72.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhNvIndex(uint Value)
{
    /// <summary>
    /// Gets the handle type (MSO).
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Whether a raw handle value falls within an NV index range this type admits — the ordinary, external,
    /// or permanent NV index range.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is an NV index.</returns>
    public static bool IsNvIndex(uint value)
    {
        TpmHt type = TpmHandleRanges.GetHandleType(value);

        return type is TpmHt.TPM_HT_NV_INDEX or TpmHt.TPM_HT_EXTERNAL_NV or TpmHt.TPM_HT_PERMANENT_NV;
    }

    /// <summary>
    /// Parses an NV index handle from a TPM reader, validating the range.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed NV index handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not an NV index (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhNvIndex Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsNvIndex(value))
        {
            throw new InvalidOperationException($"Invalid NV index handle 0x{value:X8}. Expected a TPMI_RH_NV_INDEX value.");
        }

        return new TpmiRhNvIndex(value);
    }

    /// <summary>
    /// Creates an NV index handle from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhNvIndex FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The NV index handle.</param>
    public static implicit operator TpmHandle(TpmiRhNvIndex handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_RH_NV_INDEX(0x{Value:X8})";
}
