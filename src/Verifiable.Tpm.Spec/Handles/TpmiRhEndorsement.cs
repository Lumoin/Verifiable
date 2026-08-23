using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_ENDORSEMENT — a handle constrained to the endorsement hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the only allowed handle is <c>TPM_RH_ENDORSEMENT</c>,
/// indicating that Endorsement Authorization is required.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_ENDORSEMENT</c> (endorsement hierarchy), and, where the caller admits it,
/// <c>TPM_RH_NULL</c> (the null handle). Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.20, Table 67.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhEndorsement
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes an endorsement handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhEndorsement(uint value)
    {
        Value = value;
    }

    /// <summary>The endorsement hierarchy (<c>TPM_RH_ENDORSEMENT</c>).</summary>
    public static TpmiRhEndorsement Endorsement => new((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>The NULL hierarchy (<c>TPM_RH_NULL</c>).</summary>
    public static TpmiRhEndorsement Null => new((uint)TpmRh.TPM_RH_NULL);

    /// <summary>
    /// Whether a raw handle value is the endorsement selector this type admits, optionally also admitting the
    /// NULL hierarchy where the table's <c>+TPM_RH_NULL</c> form applies.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsEndorsement(uint value, bool isNullAdmitted = false) => value switch
    {
        (uint)TpmRh.TPM_RH_ENDORSEMENT => true,
        (uint)TpmRh.TPM_RH_NULL => isNullAdmitted,
        _ => false
    };

    /// <summary>
    /// Parses an endorsement handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns>The parsed endorsement handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not an endorsement selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhEndorsement Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        uint value = reader.ReadUInt32();
        if(!IsEndorsement(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid endorsement handle 0x{value:X8}. Expected a TPMI_RH_ENDORSEMENT selector.");
        }

        return new TpmiRhEndorsement(value);
    }

    /// <summary>
    /// Creates an endorsement handle from a raw value without validation — for a value already known good
    /// (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhEndorsement FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The endorsement handle.</param>
    public static implicit operator TpmHandle(TpmiRhEndorsement handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPMI_RH_ENDORSEMENT(ENDORSEMENT)",
        (uint)TpmRh.TPM_RH_NULL => "TPMI_RH_ENDORSEMENT(NULL)",
        _ => $"TPMI_RH_ENDORSEMENT(0x{Value:X8})"
    };
}
