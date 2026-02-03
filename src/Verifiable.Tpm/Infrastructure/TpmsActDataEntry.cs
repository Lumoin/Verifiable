using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// ACT (Authenticated Countdown Timer) data entry (TPMS_ACT_DATA).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_HANDLE handle;    // ACT handle (4 bytes).
///     UINT32 timeout;       // Current timeout value in seconds (4 bytes).
///     TPMA_ACT attributes;  // ACT attributes (4 bytes).
/// } TPMS_ACT_DATA;
/// </code>
/// <para>
/// <b>Size:</b> 12 bytes total.
/// </para>
/// <para>
/// <b>Note:</b> ACT support was added in TPM 2.0 revision 1.59.
/// </para>
/// </remarks>
/// <seealso cref="TpmActData"/>
[DebuggerDisplay("Handle=0x{Handle:X8}, Timeout={Timeout}s")]
public readonly struct TpmsActDataEntry: IEquatable<TpmsActDataEntry>
{
    /// <summary>
    /// Size of this structure when serialized.
    /// </summary>
    public const int SerializedSize = 12;

    /// <summary>
    /// Gets the ACT handle.
    /// </summary>
    public uint Handle { get; }

    /// <summary>
    /// Gets the current timeout value in seconds.
    /// </summary>
    /// <remarks>
    /// A value of 0 indicates the timer is not running.
    /// </remarks>
    public uint Timeout { get; }

    /// <summary>
    /// Gets the ACT attributes.
    /// </summary>
    public TpmaAct Attributes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TpmsActDataEntry"/> struct.
    /// </summary>
    /// <param name="handle">The ACT handle.</param>
    /// <param name="timeout">The timeout value in seconds.</param>
    /// <param name="attributes">The ACT attributes.</param>
    public TpmsActDataEntry(uint handle, uint timeout, TpmaAct attributes)
    {
        Handle = handle;
        Timeout = timeout;
        Attributes = attributes;
    }

    /// <summary>
    /// Parses an instance from a byte buffer.
    /// </summary>
    /// <param name="source">The source bytes.</param>
    /// <returns>The parsed value and number of bytes consumed.</returns>
    public static TpmParseResult<TpmsActDataEntry> Parse(ReadOnlySpan<byte> source)
    {
        var reader = new TpmReader(source);
        uint handle = reader.ReadUInt32();
        uint timeout = reader.ReadUInt32();
        uint attributes = reader.ReadUInt32();

        return new TpmParseResult<TpmsActDataEntry>(
            new TpmsActDataEntry(handle, timeout, (TpmaAct)attributes),
            reader.Consumed);
    }

    /// <inheritdoc/>
    public bool Equals(TpmsActDataEntry other)
    {
        return Handle == other.Handle &&
               Timeout == other.Timeout &&
               Attributes == other.Attributes;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is TpmsActDataEntry other && Equals(other);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Handle, Timeout, Attributes);
    }

    /// <summary>
    /// Determines whether two instances are equal.
    /// </summary>
    public static bool operator ==(TpmsActDataEntry left, TpmsActDataEntry right) => left.Equals(right);

    /// <summary>
    /// Determines whether two instances are not equal.
    /// </summary>
    public static bool operator !=(TpmsActDataEntry left, TpmsActDataEntry right) => !left.Equals(right);
}

/// <summary>
/// ACT attribute flags (TPMA_ACT).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format:</b> A 32-bit value with the following bit assignments:
/// </para>
/// <code>
/// Bit 0     - signaled: ACT has signaled (timeout reached zero).
/// Bit 1     - preserveSignaled: Do not clear signaled on TPM2_ACT_SetTimeout.
/// Bits 31:2 - Reserved.
/// </code>
/// </remarks>
[Flags]
public enum TpmaAct: uint
{
    /// <summary>
    /// No attributes set.
    /// </summary>
    None = 0,

    /// <summary>
    /// ACT has signaled (timeout reached zero).
    /// </summary>
    Signaled = 1u << 0,

    /// <summary>
    /// Do not clear signaled state on TPM2_ACT_SetTimeout.
    /// </summary>
    PreserveSignaled = 1u << 1
}