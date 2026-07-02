using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu;

/// <summary>
/// An APDU response containing data and a status word.
/// </summary>
/// <remarks>
/// <para>
/// This type wraps the complete response bytes returned by the card, including
/// both the data field and the two-byte status word trailer. It inherits from
/// <see cref="SensitiveMemory"/> because response data may contain sensitive
/// material (keys, certificates, authentication tokens) that must be cleared
/// on disposal.
/// </para>
/// <para>
/// <strong>Ownership:</strong> The caller owns this response and must dispose it.
/// Disposing clears the memory and returns it to the pool.
/// </para>
/// <para>
/// <strong>Layout:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0..(Length-3): Response data field.</description></item>
///   <item><description>Bytes (Length-2)..(Length-1): Status word (SW1, SW2).</description></item>
/// </list>
/// <para>
/// <strong>Usage:</strong>
/// </para>
/// <code>
/// using ApduResponse response = await device.TransceiveAsync(command, pool, ct);
///
/// StatusWord sw = response.StatusWord;
/// ReadOnlySpan&lt;byte&gt; data = response.Data;
/// </code>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ApduResponse : SensitiveMemory
{
    /// <summary>
    /// Initializes a new APDU response with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the complete response bytes (data + SW).</param>
    /// <param name="length">The actual number of valid bytes in the response.</param>
    internal ApduResponse(IMemoryOwner<byte> storage, int length)
        : base(storage, ApduTags.Response)
    {
        Length = length;
    }

    /// <summary>
    /// Creates an <see cref="ApduResponse"/> from the complete response bytes a platform transport returned (the
    /// data field followed by the two-byte status word). The bytes are copied into a buffer rented from
    /// <paramref name="pool"/>; the returned response owns that buffer and must be disposed by the caller.
    /// </summary>
    /// <remarks>
    /// This is the construction seam a <see cref="TransceiveDelegate"/> implementation uses to wrap a raw transceive
    /// result — for example the bytes returned by PC/SC <c>SCardTransmit</c>, Android <c>IsoDep.Transceive</c>, or
    /// iOS <c>NFCISO7816Tag.SendCommand</c> — into the response the protocol engine consumes.
    /// </remarks>
    /// <param name="responseBytes">The complete response APDU bytes (data, then SW1 and SW2).</param>
    /// <param name="pool">The memory pool the response buffer is rented from.</param>
    /// <returns>An <see cref="ApduResponse"/> wrapping a pooled copy of <paramref name="responseBytes"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static ApduResponse FromResponseBytes(ReadOnlySpan<byte> responseBytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> storage = pool.Rent(responseBytes.Length);
        try
        {
            responseBytes.CopyTo(storage.Memory.Span);

            return new ApduResponse(storage, responseBytes.Length);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Gets the total length of the response in bytes (data + status word).
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the status word from the last two bytes of the response.
    /// </summary>
    public StatusWord StatusWord
    {
        get
        {
            if(Length < ApduConstants.StatusWordSize)
            {
                throw new InvalidOperationException(
                    $"Response length {Length} is shorter than the {ApduConstants.StatusWordSize}-byte status word.");
            }

            ReadOnlySpan<byte> span = MemoryOwner.Memory.Span;
            byte sw1 = span[Length - 2];
            byte sw2 = span[Length - 1];

            return StatusWord.FromBytes(sw1, sw2);
        }
    }

    /// <summary>
    /// Gets the length of the data field (total length minus the two-byte status word).
    /// </summary>
    public int DataLength => Math.Max(0, Length - ApduConstants.StatusWordSize);

    /// <summary>
    /// Gets the response data field without the status word.
    /// </summary>
    /// <returns>A read-only span over the data portion of the response.</returns>
    public ReadOnlySpan<byte> Data => MemoryOwner.Memory.Span[..DataLength];

    /// <summary>
    /// Gets the complete response bytes including the status word.
    /// </summary>
    /// <returns>A read-only span over the entire response.</returns>
    public new ReadOnlySpan<byte> AsReadOnlySpan() => MemoryOwner.Memory.Span[..Length];

    /// <summary>
    /// Gets the complete response bytes as memory, including the status word.
    /// </summary>
    /// <returns>A read-only memory over the entire response.</returns>
    public new ReadOnlyMemory<byte> AsReadOnlyMemory() => MemoryOwner.Memory[..Length];

    /// <summary>
    /// Gets a value indicating whether this response has a data field
    /// (i.e., the response is longer than just the status word).
    /// </summary>
    public bool HasData => DataLength > 0;

    private string DebuggerDisplay
    {
        get
        {
            if(Length < ApduConstants.StatusWordSize)
            {
                return $"ApduResponse(truncated, {Length}B)";
            }

            StatusWord sw = StatusWord;
            if(!HasData)
            {
                return $"ApduResponse(SW=0x{sw.Value:X4}, no data)";
            }

            ReadOnlySpan<byte> data = Data;
            int previewLength = Math.Min(data.Length, 8);
            string hexPreview = Convert.ToHexStringLower(data[..previewLength]);
            string ellipsis = data.Length > 8 ? "..." : string.Empty;

            return $"ApduResponse(SW=0x{sw.Value:X4}, {data.Length}B, {hexPreview}{ellipsis})";
        }
    }
}
