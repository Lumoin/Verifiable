using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Handles;

/// <summary>
/// TPMI_SH_AUTH_SESSION - authorization session handle interface type.
/// </summary>
/// <remarks>
/// <para>
/// This interface type constrains handles to those that reference authorization
/// sessions: HMAC sessions or policy sessions.
/// </para>
/// <para>
/// <b>Valid handle types:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_HT_HMAC_SESSION (0x02) - HMAC authorization sessions.</description></item>
///   <item><description>TPM_HT_POLICY_SESSION (0x03) - policy authorization sessions.</description></item>
/// </list>
/// <para>
/// <b>Special value:</b> TPM_RH_PW (0x40000009) is a password session pseudo-handle
/// that may also be valid in contexts expecting a session handle.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.8.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiShAuthSession(uint Value)
{
    /// <summary>
    /// Gets the handle type (MSO).
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Gets the 24-bit handle index.
    /// </summary>
    public uint Index => TpmHandleRanges.GetHandleIndex(Value);

    /// <summary>
    /// Gets whether this is an HMAC session handle.
    /// </summary>
    public bool IsHmacSession => HandleType == TpmHt.TPM_HT_HMAC_SESSION;

    /// <summary>
    /// Gets whether this is a policy session handle.
    /// </summary>
    public bool IsPolicySession => HandleType == TpmHt.TPM_HT_POLICY_SESSION;

    /// <summary>
    /// Gets whether this is the password session pseudo-handle (TPM_RH_PW).
    /// </summary>
    public bool IsPasswordSession => Value == (uint)TpmRh.TPM_RH_PW;

    /// <summary>
    /// Parses a session handle from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the handle type is not valid for sessions.</exception>
    public static TpmiShAuthSession Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();

        if(!IsValidSessionHandle(value))
        {
            var type = TpmHandleRanges.GetHandleType(value);
            throw new InvalidOperationException($"Invalid session handle type: {type}. Expected HMAC session, policy session, or password session.");
        }

        return new TpmiShAuthSession(value);
    }

    /// <summary>
    /// Creates a session handle from a raw value without validation.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    /// <remarks>
    /// Use this when you know the value is valid (e.g., from a TPM response).
    /// For untrusted input, use <see cref="Parse"/>.
    /// </remarks>
    public static TpmiShAuthSession FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    public static implicit operator TpmHandle(TpmiShAuthSession handle) => new(handle.Value);

    private static bool IsValidSessionHandle(uint value)
    {
        if(value == (uint)TpmRh.TPM_RH_PW)
        {
            return true;
        }

        var type = TpmHandleRanges.GetHandleType(value);
        return type is TpmHt.TPM_HT_HMAC_SESSION or TpmHt.TPM_HT_POLICY_SESSION;
    }

    private string DebuggerDisplay => Value == (uint)TpmRh.TPM_RH_PW
        ? "TPMI_SH_AUTH_SESSION(TPM_RH_PW)"
        : $"TPMI_SH_AUTH_SESSION(0x{Value:X8}, {HandleType})";
}