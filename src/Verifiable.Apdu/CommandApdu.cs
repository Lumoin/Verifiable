using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Apdu;

/// <summary>
/// The encoded wire bytes of an ISO/IEC 7816-4 command APDU, with static factories for the four
/// command cases. A tracked carrier rather than a naked buffer: it owns its pooled memory and clears
/// it on disposal, and carries <see cref="ApduTags.CommandApdu"/> for provenance.
/// </summary>
/// <remarks>
/// <para>
/// ISO 7816-4 defines four command APDU cases based on the presence of command data and expected
/// response data:
/// </para>
/// <list type="bullet">
///   <item><description><strong>Case 1:</strong> No data, no response expected. Header only (4 bytes).</description></item>
///   <item><description><strong>Case 2:</strong> No data, response expected. Header + Le.</description></item>
///   <item><description><strong>Case 3:</strong> Data present, no response expected. Header + Lc + data.</description></item>
///   <item><description><strong>Case 4:</strong> Data present, response expected. Header + Lc + data + Le.</description></item>
/// </list>
/// <para>
/// Both short-length (Lc/Le as single byte) and extended-length (Lc/Le as 3 bytes) encodings are
/// supported. Short-length is used by default; extended-length is used when the data exceeds 255
/// bytes or when Le exceeds 256.
/// </para>
/// </remarks>
[DebuggerDisplay("CommandApdu({Length} bytes)")]
public sealed class CommandApdu: SensitiveMemory
{
    private CommandApdu(IMemoryOwner<byte> storage)
        : base(storage, ApduTags.CommandApdu)
    {
    }


    /// <summary>Gets the length of the command APDU in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Builds a Case 1 command (no data, no response).
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="pool">Memory pool for the command buffer.</param>
    /// <returns>The command APDU. The caller must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned CommandApdu, which the caller disposes.")]
    public static CommandApdu BuildCase1(
        byte cla, byte ins, byte p1, byte p2,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(ApduConstants.CommandHeaderSize);
        var writer = new ApduWriter(owner.Memory.Span);
        writer.WriteHeader(cla, ins, p1, p2);

        return new CommandApdu(owner);
    }

    /// <summary>
    /// Builds a Case 2 command (no data, response expected).
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="le">Expected response length. 0 means 256 (short) or 65536 (extended).</param>
    /// <param name="useExtended">Use extended-length encoding.</param>
    /// <param name="pool">Memory pool for the command buffer.</param>
    /// <returns>The command APDU. The caller must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned CommandApdu, which the caller disposes.")]
    public static CommandApdu BuildCase2(
        byte cla, byte ins, byte p1, byte p2,
        int le, bool useExtended,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(useExtended)
        {
            //Extended: header(4) + 0x00(1) + Le(2) = 7 bytes.
            IMemoryOwner<byte> owner = pool.Rent(7);
            var writer = new ApduWriter(owner.Memory.Span);
            writer.WriteHeader(cla, ins, p1, p2);
            writer.WriteByte(0x00);
            writer.WriteUInt16((ushort)le);
            return new CommandApdu(owner);
        }
        else
        {
            //Short: header(4) + Le(1) = 5 bytes.
            IMemoryOwner<byte> owner = pool.Rent(5);
            var writer = new ApduWriter(owner.Memory.Span);
            writer.WriteHeader(cla, ins, p1, p2);
            writer.WriteByte((byte)le);
            return new CommandApdu(owner);
        }
    }

    /// <summary>
    /// Builds a Case 3 command (data present, no response expected).
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="data">Command data field.</param>
    /// <param name="pool">Memory pool for the command buffer.</param>
    /// <returns>The command APDU. The caller must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned CommandApdu, which the caller disposes.")]
    public static CommandApdu BuildCase3(
        byte cla, byte ins, byte p1, byte p2,
        ReadOnlySpan<byte> data,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        bool useExtended = data.Length > 255;

        if(useExtended)
        {
            //Extended: header(4) + 0x00(1) + Lc(2) + data.
            int totalSize = 4 + 1 + 2 + data.Length;
            IMemoryOwner<byte> owner = pool.Rent(totalSize);
            var writer = new ApduWriter(owner.Memory.Span);
            writer.WriteHeader(cla, ins, p1, p2);
            writer.WriteByte(0x00);
            writer.WriteUInt16((ushort)data.Length);
            writer.WriteBytes(data);
            return new CommandApdu(owner);
        }
        else
        {
            //Short: header(4) + Lc(1) + data.
            int totalSize = 4 + 1 + data.Length;
            IMemoryOwner<byte> owner = pool.Rent(totalSize);
            var writer = new ApduWriter(owner.Memory.Span);
            writer.WriteHeader(cla, ins, p1, p2);
            writer.WriteByte((byte)data.Length);
            writer.WriteBytes(data);
            return new CommandApdu(owner);
        }
    }

    /// <summary>
    /// Builds a Case 4 command (data present, response expected).
    /// </summary>
    /// <param name="cla">Class byte.</param>
    /// <param name="ins">Instruction byte.</param>
    /// <param name="p1">Parameter 1.</param>
    /// <param name="p2">Parameter 2.</param>
    /// <param name="data">Command data field.</param>
    /// <param name="le">Expected response length. 0 means maximum.</param>
    /// <param name="pool">Memory pool for the command buffer.</param>
    /// <returns>The command APDU. The caller must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned CommandApdu, which the caller disposes.")]
    public static CommandApdu BuildCase4(
        byte cla, byte ins, byte p1, byte p2,
        ReadOnlySpan<byte> data, int le,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        bool useExtended = data.Length > 255 || le > 256;

        if(useExtended)
        {
            //Extended: header(4) + 0x00(1) + Lc(2) + data + Le(2).
            int totalSize = 4 + 1 + 2 + data.Length + 2;
            IMemoryOwner<byte> owner = pool.Rent(totalSize);
            var writer = new ApduWriter(owner.Memory.Span);
            writer.WriteHeader(cla, ins, p1, p2);
            writer.WriteByte(0x00);
            writer.WriteUInt16((ushort)data.Length);
            writer.WriteBytes(data);
            writer.WriteUInt16((ushort)le);
            return new CommandApdu(owner);
        }
        else
        {
            //Short: header(4) + Lc(1) + data + Le(1).
            int totalSize = 4 + 1 + data.Length + 1;
            IMemoryOwner<byte> owner = pool.Rent(totalSize);
            var writer = new ApduWriter(owner.Memory.Span);
            writer.WriteHeader(cla, ins, p1, p2);
            writer.WriteByte((byte)data.Length);
            writer.WriteBytes(data);
            writer.WriteByte((byte)le);
            return new CommandApdu(owner);
        }
    }
}
