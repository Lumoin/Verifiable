using System;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Handles;

/// <summary>
/// TPMI_DH_OBJECT - object handle interface type.
/// </summary>
/// <remarks>
/// <para>
/// This interface type constrains handles to those that reference objects:
/// transient objects or persistent objects.
/// </para>
/// <para>
/// <b>Valid handle types:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_HT_TRANSIENT (0x80) - transient objects loaded into TPM.</description></item>
///   <item><description>TPM_HT_PERSISTENT (0x81) - persistent objects stored in NV.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 9.3.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiDhObject(uint Value)
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
    /// Gets whether this is a transient object handle.
    /// </summary>
    public bool IsTransient => HandleType == TpmHt.TPM_HT_TRANSIENT;

    /// <summary>
    /// Gets whether this is a persistent object handle.
    /// </summary>
    public bool IsPersistent => HandleType == TpmHt.TPM_HT_PERSISTENT;

    /// <summary>
    /// Parses an object handle from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed handle.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the handle type is not valid for objects.</exception>
    public static TpmiDhObject Parse(ref TpmReader reader)
    {
        uint value = reader.ReadUInt32();
        var type = TpmHandleRanges.GetHandleType(value);

        if(type is not (TpmHt.TPM_HT_TRANSIENT or TpmHt.TPM_HT_PERSISTENT))
        {
            throw new InvalidOperationException($"Invalid object handle type: {type}. Expected transient or persistent.");
        }

        return new TpmiDhObject(value);
    }

    /// <summary>
    /// Creates an object handle from a raw value without validation.
    /// </summary>
    /// <param name="value">The raw handle value.</param>
    /// <returns>The handle.</returns>
    /// <remarks>
    /// Use this when you know the value is valid (e.g., from a TPM response).
    /// For untrusted input, use <see cref="Parse"/>.
    /// </remarks>
    public static TpmiDhObject FromValue(uint value) => new(value);

    /// <summary>
    /// Writes this handle to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt32(Value);

    /// <summary>
    /// Implicit conversion to <see cref="TpmHandle"/>.
    /// </summary>
    public static implicit operator TpmHandle(TpmiDhObject handle) => new(handle.Value);

    private string DebuggerDisplay => $"TPMI_DH_OBJECT(0x{Value:X8}, {HandleType})";
}