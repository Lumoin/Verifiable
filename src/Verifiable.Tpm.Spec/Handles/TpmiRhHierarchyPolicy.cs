using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_HIERARCHY_POLICY — a handle constrained to a hierarchy selector, the Lockout Authorization, or an
/// ACT.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the handle is required to be one of the hierarchy
/// selectors, the Lockout Authorization, or an ACT. Used in <c>TPM2_SetPrimaryPolicy()</c>.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_OWNER</c> (storage hierarchy), <c>TPM_RH_PLATFORM</c> (platform
/// hierarchy), <c>TPM_RH_ENDORSEMENT</c> (endorsement hierarchy), <c>TPM_RH_LOCKOUT</c> (Lockout
/// Authorization), and the Authenticated Countdown Timer handle range <c>{TPM_RH_ACT_0:TPM_RH_ACT_F}</c>.
/// Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.16, Table 63.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhHierarchyPolicy
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a hierarchy-policy handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhHierarchyPolicy(uint value)
    {
        Value = value;
    }

    /// <summary>The storage hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhHierarchyPolicy Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhHierarchyPolicy Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>The endorsement hierarchy (<c>TPM_RH_ENDORSEMENT</c>).</summary>
    public static TpmiRhHierarchyPolicy Endorsement => new((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>The lockout authorization (<c>TPM_RH_LOCKOUT</c>).</summary>
    public static TpmiRhHierarchyPolicy Lockout => new((uint)TpmRh.TPM_RH_LOCKOUT);

    /// <summary>
    /// Whether a raw handle value is one of the four named selectors this type admits or falls within the
    /// Authenticated Countdown Timer handle range (<c>{TPM_RH_ACT_0:TPM_RH_ACT_F}</c>).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsHierarchyPolicy(uint value) => value switch
    {
        (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_ENDORSEMENT or (uint)TpmRh.TPM_RH_LOCKOUT => true,
        _ => value is >= (uint)TpmRh.TPM_RH_ACT_0 and <= (uint)TpmRh.TPM_RH_ACT_F
    };

    /// <summary>
    /// Parses a hierarchy-policy handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed hierarchy-policy handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not a hierarchy-policy selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhHierarchyPolicy Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsHierarchyPolicy(value))
        {
            throw new InvalidOperationException($"Invalid hierarchy-policy handle 0x{value:X8}. Expected a TPMI_RH_HIERARCHY_POLICY selector.");
        }

        return new TpmiRhHierarchyPolicy(value);
    }

    /// <summary>
    /// Creates a hierarchy-policy handle from a raw value without validation — for a value already known good
    /// (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhHierarchyPolicy FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The hierarchy-policy handle.</param>
    public static implicit operator TpmHandle(TpmiRhHierarchyPolicy handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_HIERARCHY_POLICY(OWNER)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_HIERARCHY_POLICY(PLATFORM)",
        (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPMI_RH_HIERARCHY_POLICY(ENDORSEMENT)",
        (uint)TpmRh.TPM_RH_LOCKOUT => "TPMI_RH_HIERARCHY_POLICY(LOCKOUT)",
        _ when Value is >= (uint)TpmRh.TPM_RH_ACT_0 and <= (uint)TpmRh.TPM_RH_ACT_F => $"TPMI_RH_HIERARCHY_POLICY(ACT_0x{Value - (uint)TpmRh.TPM_RH_ACT_0:X1})",
        _ => $"TPMI_RH_HIERARCHY_POLICY(0x{Value:X8})"
    };
}
