using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// TPMI_RH_NV_AUTH — a handle identifying the source of authorization for access to an NV location.
/// </summary>
/// <remarks>
/// <para>
/// The handle value shall indicate that the authorization value is either Platform Authorization, Owner
/// Authorization, or the NV index's own <c>authValue</c>. Used in the commands that access an NV Index
/// (<c>TPM2_NV_xxx</c>) other than <c>TPM2_NV_DefineSpace()</c> and <c>TPM2_NV_UndefineSpace()</c>.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_RH_PLATFORM</c> (Platform Authorization is allowed), <c>TPM_RH_OWNER</c>
/// (Owner Authorization is allowed), and the NV index range (the index's own authorization applies).
/// Unmarshaling any other value is <c>TPM_RC_VALUE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.23, Table 69.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiRhNvAuth
{
    /// <summary>
    /// Gets the raw handle value.
    /// </summary>
    public uint Value { get; }

    /// <summary>
    /// Initializes an NV authorization handle from a raw value.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    public TpmiRhNvAuth(uint value)
    {
        Value = value;
    }

    /// <summary>Platform Authorization (<c>TPM_RH_PLATFORM</c>).</summary>
    public static TpmiRhNvAuth Platform => new((uint)TpmRh.TPM_RH_PLATFORM);

    /// <summary>Owner Authorization (<c>TPM_RH_OWNER</c>).</summary>
    public static TpmiRhNvAuth Owner => new((uint)TpmRh.TPM_RH_OWNER);

    /// <summary>
    /// Whether a raw handle value is one of the named authorization selectors or falls within the NV index
    /// range (the index's own <c>authValue</c> applies).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsNvAuth(uint value) => value switch
    {
        (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_OWNER => true,
        _ => value is >= TpmHandleRanges.NV_INDEX_FIRST and <= TpmHandleRanges.NV_INDEX_LAST
    };

    /// <summary>
    /// Parses an NV authorization handle from a TPM reader, validating the selector.
    /// </summary>
    /// <param name="reader">The reader positioned at the 4-octet handle.</param>
    /// <returns>The parsed NV authorization handle.</returns>
    /// <exception cref="InvalidOperationException">The value is not an NV authorization selector (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiRhNvAuth Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        if(!IsNvAuth(value))
        {
            throw new InvalidOperationException($"Invalid NV authorization handle 0x{value:X8}. Expected a TPMI_RH_NV_AUTH selector.");
        }

        return new TpmiRhNvAuth(value);
    }

    /// <summary>
    /// Creates an NV authorization handle from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    public static TpmiRhNvAuth FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    /// <param name="handle">The NV authorization handle.</param>
    public static implicit operator TpmHandle(TpmiRhNvAuth handle) => new(handle.Value);

    private string DebuggerDisplay => Value switch
    {
        (uint)TpmRh.TPM_RH_PLATFORM => "TPMI_RH_NV_AUTH(PLATFORM)",
        (uint)TpmRh.TPM_RH_OWNER => "TPMI_RH_NV_AUTH(OWNER)",
        _ => $"TPMI_RH_NV_AUTH(0x{Value:X8})"
    };
}
