using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_DH_PERSISTENT — a handle constrained to the persistent-object range, used to indicate the handle to be
/// assigned to a persistent object.
/// </summary>
/// <remarks>
/// <para>
/// Used as the input handle type of <c>TPM2_EvictControl()</c>'s <c>persistentHandle</c> parameter, naming the
/// slot a transient object is to be made persistent under.
/// </para>
/// <para>
/// <b>Valid values:</b> the persistent-object range <c>{PERSISTENT_FIRST:PERSISTENT_LAST}</c>
/// (<see cref="TpmHandleRanges.PERSISTENT_FIRST"/>..<see cref="TpmHandleRanges.PERSISTENT_LAST"/>). Unmarshaling a
/// value outside the range is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.5, Table 52.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiDhPersistent
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a persistent-object handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiDhPersistent(uint value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets the handle type (MSO), always <see cref="TpmHt.TPM_HT_PERSISTENT"/> for a value this type admits.
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Gets the 24-bit handle index.
    /// </summary>
    public uint Index => TpmHandleRanges.GetHandleIndex(Value);

    /// <summary>
    /// Whether a raw handle value falls within the persistent-object range this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is within the persistent-object range.</returns>
    public static bool IsPersistent(uint value) => value is >= TpmHandleRanges.PERSISTENT_FIRST and <= TpmHandleRanges.PERSISTENT_LAST;

    /// <summary>
    /// Parses a persistent-object handle from a TPM reader, validating the range.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">The value is outside the persistent-object range (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiDhPersistent Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsPersistent(value))
        {
            throw new InvalidOperationException($"Invalid persistent-object handle 0x{value:X8}. Expected the range {TpmHandleRanges.PERSISTENT_FIRST:X8}-{TpmHandleRanges.PERSISTENT_LAST:X8}.");
        }

        return new TpmiDhPersistent(value);
    }

    /// <summary>
    /// Creates a persistent-object handle from a raw value without validation — for a value already known good.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiDhPersistent FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The persistent-object handle.</param>
    public static implicit operator TpmHandle(TpmiDhPersistent handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_DH_PERSISTENT(0x{Value:X8})";
}
