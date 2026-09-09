using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_HIERARCHY — a handle constrained to a hierarchy selector.
/// </summary>
/// <remarks>
/// <para>
/// Used as a handle type wherever a command requires one of the hierarchy selectors — for example the hierarchy
/// an object is created under, or the privacy administrator of an attestation.
/// </para>
/// <para>
/// <b>Admitted values:</b> <c>TPM_RH_OWNER</c> (storage), <c>TPM_RH_PLATFORM</c> (platform),
/// <c>TPM_RH_ENDORSEMENT</c> (endorsement), and <c>TPM_RH_NULL</c> (the NULL hierarchy). Unmarshaling a value
/// outside that set is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Table 59 additionally lists the firmware-limited hierarchies (<c>TPM_RH_FW_OWNER</c>,
/// <c>TPM_RH_FW_PLATFORM</c>, <c>TPM_RH_FW_ENDORSEMENT</c>, <c>TPM_RH_FW_NULL</c>) and the SVN-limited
/// hierarchy ranges. This library models neither — no such handle constant exists, no command accepts one, and
/// no hierarchy proof is derived for one — so <see cref="IsHierarchy"/> admits the four base selectors alone
/// and this type's admitted set is narrower than the table's by exactly those variants.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.13, Table 59.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhHierarchy
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a hierarchy handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhHierarchy(uint value)
    {
        Value = value;
    }

    /// <summary>The storage hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhHierarchy Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhHierarchy Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>The endorsement hierarchy (<c>TPM_RH_ENDORSEMENT</c>).</summary>
    public static TpmiRhHierarchy Endorsement => new((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>The NULL hierarchy (<c>TPM_RH_NULL</c>).</summary>
    public static TpmiRhHierarchy Null => new((uint)TpmRh.TPM_RH_NULL);

    /// <summary>
    /// Gets whether this is the NULL hierarchy — the one selector whose objects are non-persistable and whose
    /// Qualified Name derives from no permanent proof.
    /// </summary>
    public bool IsNull => Value == (uint)TpmRh.TPM_RH_NULL;

    /// <summary>
    /// Whether a raw handle value is one of the four base hierarchy selectors this type admits
    /// (<c>TPM_RH_OWNER</c>, <c>TPM_RH_PLATFORM</c>, <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_NULL</c>) — Table 59's
    /// firmware-limited and SVN-limited variants are not modelled by this library and are not admitted.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a hierarchy selector.</returns>
    public static bool IsHierarchy(uint value) => value switch
    {
        (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_ENDORSEMENT or (uint)TpmRh.TPM_RH_NULL => true,
        _ => false
    };

    /// <summary>
    /// Parses a hierarchy handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed hierarchy handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not a hierarchy selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhHierarchy Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsHierarchy(value))
        {
            throw new InvalidOperationException($"Invalid hierarchy handle 0x{value:X8}. Expected a TPMI_RH_HIERARCHY selector.");
        }

        return new TpmiRhHierarchy(value);
    }

    /// <summary>
    /// Creates a hierarchy handle from a raw value without validation — for a value already known good (for
    /// example one retained from a validated command or drawn from <see cref="TpmRh"/>).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhHierarchy FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="hierarchy">The hierarchy handle.</param>
    public static implicit operator TpmHandle(TpmiRhHierarchy hierarchy) => new(hierarchy.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_HIERARCHY(OWNER)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_HIERARCHY(PLATFORM)",
        (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPMI_RH_HIERARCHY(ENDORSEMENT)",
        (uint)TpmRh.TPM_RH_NULL => "TPMI_RH_HIERARCHY(NULL)",
        _ => $"TPMI_RH_HIERARCHY(0x{Value:X8})"
    };
}
