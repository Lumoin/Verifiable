using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_DH_PCR — a handle constrained to the set of Platform Configuration Register (PCR) references.
/// </summary>
/// <remarks>
/// <para>
/// Used wherever a command requires a PCR handle, for example <c>TPM2_PCR_Extend()</c>, <c>TPM2_PCR_Event()</c>,
/// and <c>TPM2_PCR_Reset()</c>. PCR 0 is architecturally defined to have a handle value of zero.
/// </para>
/// <para>
/// <b>Valid values:</b> the PCR range <c>{PCR_FIRST:PCR_LAST}</c> (<see cref="TpmHandleRanges.PCR_FIRST"/>..
/// <see cref="TpmHandleRanges.PCR_LAST"/>), plus the conditional <c>TPM_RH_NULL</c> where the caller admits it
/// (<c>isNullAdmitted</c>). Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.7, Table 53.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiDhPcr
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a PCR handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiDhPcr(uint value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets the PCR index (equal to <see cref="Value"/>, since the PCR range base is zero).
    /// </summary>
    public uint Index => TpmHandleRanges.GetHandleIndex(Value);

    /// <summary>
    /// Gets whether this is the NULL PCR reference (<c>TPM_RH_NULL</c>).
    /// </summary>
    public bool IsNull => Value == (uint)TpmRh.TPM_RH_NULL;

    /// <summary>
    /// Whether a raw handle value is a PCR reference this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> (the <c>+</c> form) is admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a PCR reference this type admits.</returns>
    public static bool IsPcr(uint value, bool isNullAdmitted = false)
    {
        if(isNullAdmitted && value == (uint)TpmRh.TPM_RH_NULL)
        {
            return true;
        }

        //PCR_FIRST is zero, so the lower bound of the range is unconditionally satisfied by every uint.
        return value <= TpmHandleRanges.PCR_LAST;
    }

    /// <summary>
    /// Parses a PCR handle from a TPM reader, validating the range.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> (the <c>+</c> form) is admitted.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">The value is neither a PCR reference nor an admitted NULL (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiDhPcr Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        uint value = reader.ReadUInt32();
        if(!IsPcr(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid PCR handle 0x{value:X8}. Expected the range {TpmHandleRanges.PCR_FIRST:X8}-{TpmHandleRanges.PCR_LAST:X8}{(isNullAdmitted ? " or TPM_RH_NULL" : string.Empty)}.");
        }

        return new TpmiDhPcr(value);
    }

    /// <summary>
    /// Creates a PCR handle from a raw value without validation — for a value already known good.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiDhPcr FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The PCR handle.</param>
    public static implicit operator TpmHandle(TpmiDhPcr handle) => new(handle.Value);

    private string DebuggerDisplay => IsNull
        ? "TPMI_DH_PCR(NULL)"
        : $"TPMI_DH_PCR(PCR{Value})";
}
