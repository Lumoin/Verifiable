using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_PLATFORM — a handle constrained to the platform hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the only allowed handle is <c>TPM_RH_PLATFORM</c>,
/// indicating that Platform Authorization is required.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_PLATFORM</c> (platform hierarchy). Unmarshaling any other value is
/// <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.18, Table 65.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhPlatform
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a platform handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhPlatform(uint value)
    {
        Value = value;
    }

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhPlatform Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>
    /// Whether a raw handle value is the platform selector this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is <c>TPM_RH_PLATFORM</c>.</returns>
    public static bool IsPlatform(uint value) => value == (uint)TpmRh.TPM_RH_PLATFORM;

    /// <summary>
    /// Parses a platform handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed platform handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not <c>TPM_RH_PLATFORM</c> (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhPlatform Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsPlatform(value))
        {
            throw new InvalidOperationException($"Invalid platform handle 0x{value:X8}. Expected TPMI_RH_PLATFORM (TPM_RH_PLATFORM).");
        }

        return new TpmiRhPlatform(value);
    }

    /// <summary>
    /// Creates a platform handle from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhPlatform FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The platform handle.</param>
    public static implicit operator TpmHandle(TpmiRhPlatform handle) => new(handle.Value);

    private string DebuggerDisplay => Value == (uint)TpmRh.TPM_RH_PLATFORM
        ? "TPMI_RH_PLATFORM(PLATFORM)"
        : $"TPMI_RH_PLATFORM(0x{Value:X8})";
}
