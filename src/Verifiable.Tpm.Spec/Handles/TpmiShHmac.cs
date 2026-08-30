using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_SH_HMAC — a handle constrained to an HMAC authorization session, used when the authorization session at
/// a slot must use an HMAC rather than a policy.
/// </summary>
/// <remarks>
/// <para>
/// Used for the session handle in commands that require the session to be an HMAC session specifically (for
/// example <c>TPM2_PolicyAuthorize()</c>'s <c>policySession</c> is a policy session, while a handful of session
/// management commands require the narrower HMAC form).
/// </para>
/// <para>
/// <b>Valid values:</b> the HMAC session range <c>{HMAC_SESSION_FIRST:HMAC_SESSION_LAST}</c>
/// (<see cref="TpmHandleRanges.HMAC_SESSION_FIRST"/>..<see cref="TpmHandleRanges.HMAC_SESSION_LAST"/>).
/// Unmarshaling a value outside the range is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.9, Table 55.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiShHmac
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes an HMAC session handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiShHmac(uint value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets the handle type (MSO), always <see cref="TpmHt.TPM_HT_HMAC_SESSION"/> for a value this type admits.
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Gets the 24-bit handle index.
    /// </summary>
    public uint Index => TpmHandleRanges.GetHandleIndex(Value);

    /// <summary>
    /// Whether a raw handle value falls within the HMAC session range this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is within the HMAC session range.</returns>
    public static bool IsHmacSession(uint value) => value is >= TpmHandleRanges.HMAC_SESSION_FIRST and <= TpmHandleRanges.HMAC_SESSION_LAST;

    /// <summary>
    /// Parses an HMAC session handle from a TPM reader, validating the range.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">The value is outside the HMAC session range (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiShHmac Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsHmacSession(value))
        {
            throw new InvalidOperationException($"Invalid HMAC session handle 0x{value:X8}. Expected the range {TpmHandleRanges.HMAC_SESSION_FIRST:X8}-{TpmHandleRanges.HMAC_SESSION_LAST:X8}.");
        }

        return new TpmiShHmac(value);
    }

    /// <summary>
    /// Creates an HMAC session handle from a raw value without validation — for a value already known good.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiShHmac FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The HMAC session handle.</param>
    public static implicit operator TpmHandle(TpmiShHmac handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_SH_HMAC(0x{Value:X8})";
}
