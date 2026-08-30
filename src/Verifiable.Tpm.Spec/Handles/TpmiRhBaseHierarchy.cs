using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_BASE_HIERARCHY — a handle constrained to a base hierarchy selector.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the handle is required to be one of the base hierarchy
/// selectors. Used in <c>TPM2_HierarchyControl()</c>.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_OWNER</c> (storage hierarchy), <c>TPM_RH_PLATFORM</c> (platform
/// hierarchy), and <c>TPM_RH_ENDORSEMENT</c> (endorsement hierarchy). Unmarshaling any other value is
/// <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.17, Table 63.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhBaseHierarchy
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a base-hierarchy handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhBaseHierarchy(uint value)
    {
        Value = value;
    }

    /// <summary>The storage hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhBaseHierarchy Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhBaseHierarchy Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>The endorsement hierarchy (<c>TPM_RH_ENDORSEMENT</c>).</summary>
    public static TpmiRhBaseHierarchy Endorsement => new((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>
    /// Whether a raw handle value is one of the three base hierarchy selectors this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a base hierarchy selector.</returns>
    public static bool IsBaseHierarchy(uint value) => value switch
    {
        (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_ENDORSEMENT => true,
        _ => false
    };

    /// <summary>
    /// Parses a base-hierarchy handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed base-hierarchy handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not a base hierarchy selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhBaseHierarchy Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsBaseHierarchy(value))
        {
            throw new InvalidOperationException($"Invalid base hierarchy handle 0x{value:X8}. Expected a TPMI_RH_BASE_HIERARCHY selector.");
        }

        return new TpmiRhBaseHierarchy(value);
    }

    /// <summary>
    /// Creates a base-hierarchy handle from a raw value without validation — for a value already known good
    /// (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhBaseHierarchy FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The base-hierarchy handle.</param>
    public static implicit operator TpmHandle(TpmiRhBaseHierarchy handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_BASE_HIERARCHY(OWNER)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_BASE_HIERARCHY(PLATFORM)",
        (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPMI_RH_BASE_HIERARCHY(ENDORSEMENT)",
        _ => $"TPMI_RH_BASE_HIERARCHY(0x{Value:X8})"
    };
}
