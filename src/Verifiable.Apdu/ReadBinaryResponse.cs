using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// Parsed response to a READ BINARY command: the bytes the card returns from the addressed
/// region of a transparent file.
/// </summary>
/// <remarks>
/// <para>
/// READ BINARY (INS <c>0xB0</c>) reads from a transparent (byte-oriented) elementary file at an
/// offset encoded in P1-P2, requesting up to Le bytes. The card answers with the data field
/// followed by a status word; this type carries the raw data field. The card may return fewer
/// bytes than requested when the read reaches end of file, in which case it pairs the data with a
/// <c>62 82</c> warning that higher layers inspect on the result.
/// </para>
/// <para>
/// It inherits from <see cref="SensitiveMemory"/> so the bytes are cleared and returned to the
/// pool on disposal.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ReadBinaryResponse : SensitiveMemory, IApduWireType
{
    internal ReadBinaryResponse(IMemoryOwner<byte> storage, int length)
        : base(storage, ApduTags.Response)
    {
        Length = length;
    }

    /// <summary>
    /// Gets the length of the data read in bytes. Zero when the card returned no data
    /// (a bare <c>9000</c> response).
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the raw data the card read from the file.
    /// </summary>
    public ReadOnlySpan<byte> Data => MemoryOwner.Memory.Span[..Length];

    /// <summary>
    /// Parses a READ BINARY response from its data field (the status word is already stripped).
    /// </summary>
    /// <param name="reader">The reader positioned at the response data.</param>
    /// <param name="pool">The memory pool for the data buffer.</param>
    /// <returns>The parsed response. The caller owns it and must dispose it.</returns>
    public static ReadBinaryResponse Parse(ref ApduReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlySpan<byte> data = reader.ReadRemainingBytes();
        IMemoryOwner<byte> owner = pool.Rent(data.Length);
        data.CopyTo(owner.Memory.Span);

        return new ReadBinaryResponse(owner, data.Length);
    }

    private string DebuggerDisplay => $"ReadBinaryResponse(Data {Length}B)";
}
