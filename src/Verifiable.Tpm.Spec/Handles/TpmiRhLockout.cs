using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_LOCKOUT — a handle constrained to the lockout authorization.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the only allowed handle is <c>TPM_RH_LOCKOUT</c>,
/// indicating that Lockout Authorization is required.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_LOCKOUT</c> (lockout authorization). Unmarshaling any other value is
/// <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.24, Table 70.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhLockout
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a lockout handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhLockout(uint value)
    {
        Value = value;
    }

    /// <summary>The lockout authorization (<c>TPM_RH_LOCKOUT</c>).</summary>
    public static TpmiRhLockout Lockout => new((uint)TpmRh.TPM_RH_LOCKOUT);

    /// <summary>
    /// Whether a raw handle value is the lockout selector this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is <c>TPM_RH_LOCKOUT</c>.</returns>
    public static bool IsLockout(uint value) => value == (uint)TpmRh.TPM_RH_LOCKOUT;

    /// <summary>
    /// Parses a lockout handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed lockout handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not <c>TPM_RH_LOCKOUT</c> (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhLockout Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsLockout(value))
        {
            throw new InvalidOperationException($"Invalid lockout handle 0x{value:X8}. Expected TPMI_RH_LOCKOUT (TPM_RH_LOCKOUT).");
        }

        return new TpmiRhLockout(value);
    }

    /// <summary>
    /// Creates a lockout handle from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhLockout FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The lockout handle.</param>
    public static implicit operator TpmHandle(TpmiRhLockout handle) => new(handle.Value);

    private string DebuggerDisplay => Value == (uint)TpmRh.TPM_RH_LOCKOUT
        ? "TPMI_RH_LOCKOUT(LOCKOUT)"
        : $"TPMI_RH_LOCKOUT(0x{Value:X8})";
}
