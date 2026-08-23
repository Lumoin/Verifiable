using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_NV_DEFINED_INDEX — a handle constrained to an NV index that can be defined or undefined.
/// </summary>
/// <remarks>
/// <para>
/// Used to identify an NV index in the NV commands that define or undefine an index, except for
/// <c>TPM2_NV_DefineSpace()</c>. It does not apply to permanent NV indexes, which are architecturally
/// defined and therefore never created or removed by a command.
/// </para>
/// <para>
/// <b>Valid values:</b> the ordinary NV index range and the external NV index range. Unmarshaling a value
/// outside these ranges — a permanent NV index included — is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.26, Table 73.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhNvDefinedIndex(uint Value)
{
    /// <summary>
    /// Gets the handle type (MSO).
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Whether a raw handle value falls within an NV index range this type admits — the ordinary or the
    /// external NV index range. The permanent NV index range is excluded: a permanent index is
    /// architecturally defined and cannot be the subject of a define or undefine command.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a definable NV index.</returns>
    public static bool IsDefinedIndex(uint value)
    {
        TpmHt type = TpmHandleRanges.GetHandleType(value);

        return type is TpmHt.TPM_HT_NV_INDEX or TpmHt.TPM_HT_EXTERNAL_NV;
    }

    /// <summary>
    /// Parses a definable NV index handle from a TPM reader, validating the range.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed NV index handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not a definable NV index (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhNvDefinedIndex Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsDefinedIndex(value))
        {
            throw new InvalidOperationException($"Invalid NV index handle 0x{value:X8}. Expected a TPMI_RH_NV_DEFINED_INDEX value.");
        }

        return new TpmiRhNvDefinedIndex(value);
    }

    /// <summary>
    /// Creates a definable NV index handle from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhNvDefinedIndex FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The NV index handle.</param>
    public static implicit operator TpmHandle(TpmiRhNvDefinedIndex handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_RH_NV_DEFINED_INDEX(0x{Value:X8})";
}
