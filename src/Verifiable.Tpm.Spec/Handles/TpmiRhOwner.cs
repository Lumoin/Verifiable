using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_OWNER — a handle constrained to the owner hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the only allowed handle is <c>TPM_RH_OWNER</c>,
/// indicating that Owner Authorization is required.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_OWNER</c> (owner hierarchy), and, where the caller admits it,
/// <c>TPM_RH_NULL</c> (the null handle). Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.19, Table 65.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhOwner
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes an owner handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhOwner(uint value)
    {
        Value = value;
    }

    /// <summary>The owner hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhOwner Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The NULL hierarchy (<c>TPM_RH_NULL</c>).</summary>
    public static TpmiRhOwner Null => new((uint)TpmRh.TPM_RH_NULL);

    /// <summary>
    /// Whether a raw handle value is the owner selector this type admits, optionally also admitting the NULL
    /// hierarchy where the table's <c>+TPM_RH_NULL</c> form applies.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsOwner(uint value, bool isNullAdmitted = false) => value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => true,
        (uint)TpmRh.TPM_RH_NULL => isNullAdmitted,
        _ => false
    };

    /// <summary>
    /// Parses an owner handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns>The parsed owner handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not an owner selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhOwner Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        uint value = reader.ReadUInt32();
        if(!IsOwner(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid owner handle 0x{value:X8}. Expected a TPMI_RH_OWNER selector.");
        }

        return new TpmiRhOwner(value);
    }

    /// <summary>
    /// Creates an owner handle from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhOwner FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The owner handle.</param>
    public static implicit operator TpmHandle(TpmiRhOwner handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_OWNER(OWNER)",
        (uint)TpmRh.TPM_RH_NULL => "TPMI_RH_OWNER(NULL)",
        _ => $"TPMI_RH_OWNER(0x{Value:X8})"
    };
}
