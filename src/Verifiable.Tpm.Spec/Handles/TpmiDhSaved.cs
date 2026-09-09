using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_DH_SAVED — a handle constrained to the values <see cref="Structures.TpmsContext.SavedHandle"/> carries:
/// an HMAC session, a policy session, or one of the three fixed values that stand in for an object's own handle
/// in a saved context.
/// </summary>
/// <remarks>
/// <para>
/// Table 58 admits five arms: the HMAC session range, the policy session range, and three fixed single values
/// distinguishing an ordinary transient object, a sequence object, and a transient object whose <c>stClear</c>
/// attribute is SET — "an HMAC session context", "a policy session context", "an ordinary transient object", "a
/// sequence object", "a transient object with the stClear attribute SET" (TPM 2.0 Library Part 2, clause 9.12,
/// Table 58). A session's own handle already lies in one of the two session ranges (the same handle a loaded
/// session carries), so a session context needs no fixed stand-in; an object's real handle is never reused
/// across a save/load round trip (a reload draws a new one), so Table 58 substitutes the fixed values instead.
/// </para>
/// <para>
/// Consumed by <c>TPM2_ContextSave()</c> and <c>TPM2_ContextLoad()</c> alone, as the <see
/// cref="Structures.TpmsContext.SavedHandle"/> field of the <c>TPMS_CONTEXT</c> both commands exchange.
/// </para>
/// <para>
/// <b>Valid values:</b>
/// </para>
/// <list type="bullet">
///   <item><description>The HMAC session range <c>{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}</c>.</description></item>
///   <item><description>The policy session range <c>{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}</c>.</description></item>
///   <item><description><see cref="OrdinaryTransientObject"/> (<c>0x80000000</c>).</description></item>
///   <item><description><see cref="SequenceObject"/> (<c>0x80000001</c>).</description></item>
///   <item><description><see cref="StClearTransientObject"/> (<c>0x80000002</c>).</description></item>
/// </list>
/// <para>
/// Unmarshaling a value outside these five arms is <c>TPM_RC_VALUE</c>: "If an input value for handle is
/// outside of the range of values used by the TPM, the TPM shall return an error (TPM_RC_VALUE) and do no
/// additional processing of the context." (TPM 2.0 Library Part 2, clause 14.6.2).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.12, Table 58.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiDhSaved
{
    /// <summary>
    /// The fixed <c>savedHandle</c> value standing in for an ordinary transient object — one whose own
    /// <c>stClear</c> attribute is not SET (TPM 2.0 Library Part 2, clause 9.12, Table 58).
    /// </summary>
    public const uint OrdinaryTransientObject = 0x8000_0000u;

    /// <summary>
    /// The fixed <c>savedHandle</c> value standing in for a sequence object (TPM 2.0 Library Part 2, clause
    /// 9.12, Table 58).
    /// </summary>
    public const uint SequenceObject = 0x8000_0001u;

    /// <summary>
    /// The fixed <c>savedHandle</c> value standing in for a transient object whose <c>stClear</c> attribute is
    /// SET (TPM 2.0 Library Part 2, clause 9.12, Table 58).
    /// </summary>
    public const uint StClearTransientObject = 0x8000_0002u;

    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a saved-context handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiDhSaved(uint value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets the handle type (MSO).
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Gets the 24-bit handle index.
    /// </summary>
    public uint Index => TpmHandleRanges.GetHandleIndex(Value);

    /// <summary>
    /// Gets whether this value names an HMAC session context.
    /// </summary>
    public bool IsHmacSession => Value is >= TpmHandleRanges.HMAC_SESSION_FIRST and <= TpmHandleRanges.HMAC_SESSION_LAST;

    /// <summary>
    /// Gets whether this value names a policy session context.
    /// </summary>
    public bool IsPolicySession => Value is >= TpmHandleRanges.POLICY_SESSION_FIRST and <= TpmHandleRanges.POLICY_SESSION_LAST;

    /// <summary>
    /// Gets whether this value names a session context of either kind.
    /// </summary>
    public bool IsSession => IsHmacSession || IsPolicySession;

    /// <summary>
    /// Gets whether this value is <see cref="OrdinaryTransientObject"/>.
    /// </summary>
    public bool IsOrdinaryObject => Value == OrdinaryTransientObject;

    /// <summary>
    /// Gets whether this value is <see cref="SequenceObject"/>.
    /// </summary>
    public bool IsSequenceObject => Value == SequenceObject;

    /// <summary>
    /// Gets whether this value is <see cref="StClearTransientObject"/>.
    /// </summary>
    public bool IsStClearObject => Value == StClearTransientObject;

    /// <summary>
    /// Gets whether this value names an object context of any of the three fixed kinds.
    /// </summary>
    public bool IsObject => IsOrdinaryObject || IsSequenceObject || IsStClearObject;

    /// <summary>
    /// Whether a raw handle value is one of Table 58's five admitted arms.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a saved-context handle this type admits.</returns>
    public static bool IsSaved(uint value) =>
        value is >= TpmHandleRanges.HMAC_SESSION_FIRST and <= TpmHandleRanges.HMAC_SESSION_LAST
            or >= TpmHandleRanges.POLICY_SESSION_FIRST and <= TpmHandleRanges.POLICY_SESSION_LAST
            or OrdinaryTransientObject
            or SequenceObject
            or StClearTransientObject;

    /// <summary>
    /// Parses a saved-context handle from a TPM reader, validating that it names one of Table 58's five arms.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">The value is outside Table 58's admitted set (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiDhSaved Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsSaved(value))
        {
            throw new InvalidOperationException($"Invalid saved-context handle 0x{value:X8}. Expected an HMAC session, a policy session, or one of the three fixed object values from Table 58.");
        }

        return new TpmiDhSaved(value);
    }

    /// <summary>
    /// Creates a saved-context handle from a raw value without validation — for a value already known good.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiDhSaved FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The saved-context handle.</param>
    public static implicit operator TpmHandle(TpmiDhSaved handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_DH_SAVED(0x{Value:X8}, {HandleType})";
}
