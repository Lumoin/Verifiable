using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_CLEAR — a handle constrained to the lockout or platform hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of the handle in a command when the only allowed handles are either
/// <c>TPM_RH_LOCKOUT</c> or <c>TPM_RH_PLATFORM</c>, indicating that either Platform Authorization or
/// Lockout Authorization is allowed. Normally used for performing or controlling <c>TPM2_Clear()</c>.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_LOCKOUT</c> (Lockout Authorization) and <c>TPM_RH_PLATFORM</c> (Platform
/// Authorization). Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.22, Table 69.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhClear
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a clear-authorization handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhClear(uint value)
    {
        Value = value;
    }

    /// <summary>The lockout authorization (<c>TPM_RH_LOCKOUT</c>).</summary>
    public static TpmiRhClear Lockout => new((uint)TpmRh.TPM_RH_LOCKOUT);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhClear Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>
    /// Whether a raw handle value is one of the two clear-authorization selectors this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a clear-authorization selector.</returns>
    public static bool IsClear(uint value) => value switch
    {
        (uint)TpmRh.TPM_RH_LOCKOUT or (uint)TpmRh.TPM_RH_PLATFORM => true,
        _ => false
    };

    /// <summary>
    /// Parses a clear-authorization handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed clear-authorization handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not a clear-authorization selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhClear Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsClear(value))
        {
            throw new InvalidOperationException($"Invalid clear-authorization handle 0x{value:X8}. Expected a TPMI_RH_CLEAR selector.");
        }

        return new TpmiRhClear(value);
    }

    /// <summary>
    /// Creates a clear-authorization handle from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhClear FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The clear-authorization handle.</param>
    public static implicit operator TpmHandle(TpmiRhClear handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_LOCKOUT => "TPMI_RH_CLEAR(LOCKOUT)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_CLEAR(PLATFORM)",
        _ => $"TPMI_RH_CLEAR(0x{Value:X8})"
    };
}
