using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_HIERARCHY_AUTH — a handle constrained to a hierarchy selector or the Lockout Authorization.
/// </summary>
/// <remarks>
/// <para>
/// Used as the type of a handle in a command when the handle is required to be one of the hierarchy
/// selectors or the Lockout Authorization.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_OWNER</c> (storage hierarchy), <c>TPM_RH_PLATFORM</c> (platform
/// hierarchy), <c>TPM_RH_ENDORSEMENT</c> (endorsement hierarchy), <c>TPM_RH_LOCKOUT</c> (Lockout
/// Authorization), and, where the caller admits it, <c>TPM_RH_NULL</c> (the null hierarchy). Unmarshaling
/// any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.15, Table 61.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhHierarchyAuth
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a hierarchy-authorization handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhHierarchyAuth(uint value)
    {
        Value = value;
    }

    /// <summary>The storage hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhHierarchyAuth Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhHierarchyAuth Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>The endorsement hierarchy (<c>TPM_RH_ENDORSEMENT</c>).</summary>
    public static TpmiRhHierarchyAuth Endorsement => new((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>The lockout authorization (<c>TPM_RH_LOCKOUT</c>).</summary>
    public static TpmiRhHierarchyAuth Lockout => new((uint)TpmRh.TPM_RH_LOCKOUT);

    /// <summary>The NULL hierarchy (<c>TPM_RH_NULL</c>).</summary>
    public static TpmiRhHierarchyAuth Null => new((uint)TpmRh.TPM_RH_NULL);

    /// <summary>
    /// Whether a raw handle value is one of the four named selectors this type admits, optionally also
    /// admitting the NULL hierarchy where the table's <c>+TPM_RH_NULL</c> form applies.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsHierarchyAuth(uint value, bool isNullAdmitted = false) => value switch
    {
        (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_ENDORSEMENT or (uint)TpmRh.TPM_RH_LOCKOUT => true,
        (uint)TpmRh.TPM_RH_NULL => isNullAdmitted,
        _ => false
    };

    /// <summary>
    /// Parses a hierarchy-authorization handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> is an admitted value.</param>
    /// <returns>The parsed hierarchy-authorization handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not a hierarchy-authorization selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhHierarchyAuth Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        uint value = reader.ReadUInt32();
        if(!IsHierarchyAuth(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid hierarchy-authorization handle 0x{value:X8}. Expected a TPMI_RH_HIERARCHY_AUTH selector.");
        }

        return new TpmiRhHierarchyAuth(value);
    }

    /// <summary>
    /// Creates a hierarchy-authorization handle from a raw value without validation — for a value already
    /// known good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhHierarchyAuth FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The hierarchy-authorization handle.</param>
    public static implicit operator TpmHandle(TpmiRhHierarchyAuth handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_HIERARCHY_AUTH(OWNER)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_HIERARCHY_AUTH(PLATFORM)",
        (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPMI_RH_HIERARCHY_AUTH(ENDORSEMENT)",
        (uint)TpmRh.TPM_RH_LOCKOUT => "TPMI_RH_HIERARCHY_AUTH(LOCKOUT)",
        (uint)TpmRh.TPM_RH_NULL => "TPMI_RH_HIERARCHY_AUTH(NULL)",
        _ => $"TPMI_RH_HIERARCHY_AUTH(0x{Value:X8})"
    };
}
