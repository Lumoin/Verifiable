using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_DH_ENTITY — a handle constrained to the values that indicate the handle refers to an authValue.
/// </summary>
/// <remarks>
/// <para>
/// A mixed closed-set-plus-range interface type: three permanent hierarchies and the lockout handle, unioned
/// with the object, NV Index, and PCR ranges, and with the vendor-specific authorization-value range
/// <c>TPM_RH_AUTH_00</c>..<c>TPM_RH_AUTH_FF</c>. The range of values would change according to the TPM
/// implementation.
/// </para>
/// <para>
/// <b>Valid values:</b>
/// </para>
/// <list type="bullet">
///   <item><description><c>TPM_RH_OWNER</c>, <c>TPM_RH_ENDORSEMENT</c>, <c>TPM_RH_PLATFORM</c>, <c>TPM_RH_LOCKOUT</c>.</description></item>
///   <item><description>The transient-object range <c>{TRANSIENT_FIRST:TRANSIENT_LAST}</c>.</description></item>
///   <item><description>The persistent-object range <c>{PERSISTENT_FIRST:PERSISTENT_LAST}</c>.</description></item>
///   <item><description>The NV Index range <c>{NV_INDEX_FIRST:NV_INDEX_LAST}</c>.</description></item>
///   <item><description>The PCR range <c>{PCR_FIRST:PCR_LAST}</c>.</description></item>
///   <item><description>The vendor-specific authorization range <c>{TPM_RH_AUTH_00:TPM_RH_AUTH_FF}</c>.</description></item>
///   <item><description><c>TPM_RH_NULL</c>, the conditional value, where the caller admits it (<c>isNullAdmitted</c>).</description></item>
/// </list>
/// <para>
/// Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.6, Table 52.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiDhEntity
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes an entity handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiDhEntity(uint value)
    {
        Value = value;
    }

    /// <summary>The owner hierarchy (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiDhEntity Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>The endorsement hierarchy (<c>TPM_RH_ENDORSEMENT</c>).</summary>
    public static TpmiDhEntity Endorsement => new((uint)TpmRh.TPM_RH_ENDORSEMENT);

    /// <summary>The platform hierarchy (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiDhEntity Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>The lockout handle (<c>TPM_RH_LOCKOUT</c>).</summary>
    public static TpmiDhEntity Lockout => new((uint)TpmRh.TPM_RH_LOCKOUT);

    /// <summary>The NULL entity (<c>TPM_RH_NULL</c>), admitted only where the caller opts in.</summary>
    public static TpmiDhEntity Null => new((uint)TpmRh.TPM_RH_NULL);

    /// <summary>
    /// Gets whether this is the NULL entity.
    /// </summary>
    public bool IsNull => Value == (uint)TpmRh.TPM_RH_NULL;

    /// <summary>
    /// Whether a raw handle value is an entity this type admits: one of the four permanent handles, an object,
    /// NV Index, or PCR handle, a vendor-specific authorization handle, or (conditionally) <c>TPM_RH_NULL</c>.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> (the <c>+</c> form) is admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is an entity this type admits.</returns>
    public static bool IsEntity(uint value, bool isNullAdmitted = false)
    {
        if(isNullAdmitted && value == (uint)TpmRh.TPM_RH_NULL)
        {
            return true;
        }

        //PCR_FIRST is zero, so the lower bound of the PCR range is unconditionally satisfied by every uint.
        return value
            is (uint)TpmRh.TPM_RH_OWNER
            or (uint)TpmRh.TPM_RH_ENDORSEMENT
            or (uint)TpmRh.TPM_RH_PLATFORM
            or (uint)TpmRh.TPM_RH_LOCKOUT
            or >= TpmHandleRanges.TRANSIENT_FIRST and <= TpmHandleRanges.TRANSIENT_LAST
            or >= TpmHandleRanges.PERSISTENT_FIRST and <= TpmHandleRanges.PERSISTENT_LAST
            or >= TpmHandleRanges.NV_INDEX_FIRST and <= TpmHandleRanges.NV_INDEX_LAST
            or <= TpmHandleRanges.PCR_LAST
            or >= (uint)TpmRh.TPM_RH_AUTH_00 and <= (uint)TpmRh.TPM_RH_AUTH_FF;
    }

    /// <summary>
    /// Parses an entity handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_RH_NULL</c> (the <c>+</c> form) is admitted.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not an entity this type admits (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiDhEntity Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        uint value = reader.ReadUInt32();
        if(!IsEntity(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid entity handle 0x{value:X8}. Expected a hierarchy, lockout, object, NV Index, PCR, or vendor authorization handle{(isNullAdmitted ? ", or TPM_RH_NULL" : string.Empty)}.");
        }

        return new TpmiDhEntity(value);
    }

    /// <summary>
    /// Creates an entity handle from a raw value without validation — for a value already known good.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiDhEntity FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The entity handle.</param>
    public static implicit operator TpmHandle(TpmiDhEntity handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_DH_ENTITY(OWNER)",
        (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPMI_DH_ENTITY(ENDORSEMENT)",
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_DH_ENTITY(PLATFORM)",
        (uint)TpmRh.TPM_RH_LOCKOUT => "TPMI_DH_ENTITY(LOCKOUT)",
        (uint)TpmRh.TPM_RH_NULL => "TPMI_DH_ENTITY(NULL)",
        _ => $"TPMI_DH_ENTITY(0x{Value:X8}, {TpmHandleRanges.GetHandleType(Value)})"
    };
}
