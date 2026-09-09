using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_PROVISION — a handle constrained to the owner or platform hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of the handle in a command when the only allowed handles are either
/// <c>TPM_RH_OWNER</c> or <c>TPM_RH_PLATFORM</c>, indicating that either Platform Authorization or Owner
/// Authorization is allowed. In most cases, either authorization may be used for management of TPM
/// resources, and this interface type is used.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_OWNER</c> (Owner Authorization) and <c>TPM_RH_PLATFORM</c> (Platform
/// Authorization). Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.21, Table 67.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhProvision
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a provisioning handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhProvision(uint value)
    {
        Value = value;
    }

    /// <summary>The owner hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhProvision Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhProvision Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>
    /// Whether a raw handle value is one of the two provisioning selectors this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a provisioning selector.</returns>
    public static bool IsProvision(uint value) => value switch
    {
        (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_PLATFORM => true,
        _ => false
    };

    /// <summary>
    /// Parses a provisioning handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed provisioning handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not a provisioning selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhProvision Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsProvision(value))
        {
            throw new InvalidOperationException($"Invalid provisioning handle 0x{value:X8}. Expected a TPMI_RH_PROVISION selector.");
        }

        return new TpmiRhProvision(value);
    }

    /// <summary>
    /// Creates a provisioning handle from a raw value without validation — for a value already known good
    /// (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhProvision FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The provisioning handle.</param>
    public static implicit operator TpmHandle(TpmiRhProvision handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_PROVISION(OWNER)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_PROVISION(PLATFORM)",
        _ => $"TPMI_RH_PROVISION(0x{Value:X8})"
    };
}
