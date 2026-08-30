using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_DH_CONTEXT — a handle constrained to the values that may be used in <c>TPM2_ContextSave()</c> or
/// <c>TPM2_FlushContext()</c>: a saved or loaded session, or a loaded transient object.
/// </summary>
/// <remarks>
/// <para>
/// The union of the HMAC session range, the policy session range, and the transient-object range — the three
/// resource kinds a context can be saved from or flushed. Unlike <see cref="TpmiDhPcr"/> or
/// <see cref="TpmiDhEntity"/>, this type admits no NULL form: the table carries no <c>+</c> row.
/// </para>
/// <para>
/// <b>Valid values:</b>
/// </para>
/// <list type="bullet">
///   <item><description>The HMAC session range <c>{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}</c>.</description></item>
///   <item><description>The policy session range <c>{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}</c>.</description></item>
///   <item><description>The transient-object range <c>{TRANSIENT_FIRST:TRANSIENT_LAST}</c>.</description></item>
/// </list>
/// <para>
/// Unmarshaling a value outside these ranges is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.11, Table 57.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiDhContext
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a context handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiDhContext(uint value)
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
    /// Whether a raw handle value is a saved-context-eligible resource: an HMAC session, a policy session, or a
    /// transient object.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a context handle this type admits.</returns>
    public static bool IsContext(uint value) =>
        value is >= TpmHandleRanges.HMAC_SESSION_FIRST and <= TpmHandleRanges.HMAC_SESSION_LAST
            or >= TpmHandleRanges.POLICY_SESSION_FIRST and <= TpmHandleRanges.POLICY_SESSION_LAST
            or >= TpmHandleRanges.TRANSIENT_FIRST and <= TpmHandleRanges.TRANSIENT_LAST;

    /// <summary>
    /// Parses a context handle from a TPM reader, validating that it names a session or a transient object.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">The value is neither a session nor a transient-object handle (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiDhContext Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsContext(value))
        {
            throw new InvalidOperationException($"Invalid context handle 0x{value:X8}. Expected an HMAC session, a policy session, or a transient object.");
        }

        return new TpmiDhContext(value);
    }

    /// <summary>
    /// Creates a context handle from a raw value without validation — for a value already known good.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiDhContext FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The context handle.</param>
    public static implicit operator TpmHandle(TpmiDhContext handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_DH_CONTEXT(0x{Value:X8}, {HandleType})";
}
