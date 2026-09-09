using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_SH_POLICY — a handle constrained to a policy authorization session, used for the policy handle argument
/// of a policy command.
/// </summary>
/// <remarks>
/// <para>
/// Used for the <c>policySession</c> parameter of the <c>TPM2_Policy*()</c> commands (for example
/// <c>TPM2_PolicySigned()</c>, <c>TPM2_PolicySecret()</c>, <c>TPM2_PolicyPCR()</c>), which require the session
/// building the policy digest to be a policy session specifically, never a plain HMAC session.
/// </para>
/// <para>
/// <b>Valid values:</b> the policy session range <c>{POLICY_SESSION_FIRST:POLICY_SESSION_LAST}</c>
/// (<see cref="TpmHandleRanges.POLICY_SESSION_FIRST"/>..<see cref="TpmHandleRanges.POLICY_SESSION_LAST"/>).
/// Unmarshaling a value outside the range is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.10, Table 56.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiShPolicy
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes a policy session handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiShPolicy(uint value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets the handle type (MSO), always <see cref="TpmHt.TPM_HT_POLICY_SESSION"/> for a value this type admits.
    /// </summary>
    public TpmHt HandleType => TpmHandleRanges.GetHandleType(Value);

    /// <summary>
    /// Gets the 24-bit handle index.
    /// </summary>
    public uint Index => TpmHandleRanges.GetHandleIndex(Value);

    /// <summary>
    /// Whether a raw handle value falls within the policy session range this type admits.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is within the policy session range.</returns>
    public static bool IsPolicySession(uint value) => value is >= TpmHandleRanges.POLICY_SESSION_FIRST and <= TpmHandleRanges.POLICY_SESSION_LAST;

    /// <summary>
    /// Parses a policy session handle from a TPM reader, validating the range.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">The value is outside the policy session range (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiShPolicy Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsPolicySession(value))
        {
            throw new InvalidOperationException($"Invalid policy session handle 0x{value:X8}. Expected the range {TpmHandleRanges.POLICY_SESSION_FIRST:X8}-{TpmHandleRanges.POLICY_SESSION_LAST:X8}.");
        }

        return new TpmiShPolicy(value);
    }

    /// <summary>
    /// Creates a policy session handle from a raw value without validation — for a value already known good.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiShPolicy FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The policy session handle.</param>
    public static implicit operator TpmHandle(TpmiShPolicy handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_SH_POLICY(0x{Value:X8})";
}
