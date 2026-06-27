using System;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// ISO/IEC 9797-1 padding method 2 (equivalently ISO/IEC 7816-4 padding): append a single
/// <c>0x80</c> byte followed by as many <c>0x00</c> bytes as needed to reach a block boundary.
/// </summary>
/// <remarks>
/// <para>
/// This padding is unambiguous because the <c>0x80</c> marker is always present — a padded
/// message that is already a multiple of the block size still gains a full block of padding.
/// ICAO Doc 9303 Secure Messaging applies it to both the plaintext before encryption and the
/// message before the Retail MAC, and the padding is kept here (in the protocol layer) rather
/// than inside the cipher / MAC primitives so it is visible and independently testable.
/// </para>
/// </remarks>
public static class Iso9797Padding
{
    /// <summary>The mandatory leading padding byte.</summary>
    private const byte Marker = 0x80;


    /// <summary>
    /// Computes the length, in bytes, of <paramref name="dataLength"/> bytes after method 2 padding
    /// to a multiple of <paramref name="blockSize"/>. Always strictly greater than
    /// <paramref name="dataLength"/> — a block-aligned input gains a whole extra block.
    /// </summary>
    /// <param name="dataLength">The unpadded length in bytes.</param>
    /// <param name="blockSize">The cipher block size in bytes.</param>
    /// <returns>The padded length in bytes.</returns>
    public static int PaddedLength(int dataLength, int blockSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(dataLength);
        ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);

        return dataLength + blockSize - (dataLength % blockSize);
    }


    /// <summary>
    /// Writes <paramref name="data"/> followed by method 2 padding into <paramref name="destination"/>.
    /// </summary>
    /// <param name="data">The bytes to pad.</param>
    /// <param name="blockSize">The cipher block size in bytes.</param>
    /// <param name="destination">
    /// The buffer to write into. Must be at least <see cref="PaddedLength(int, int)"/> bytes.
    /// </param>
    /// <returns>The number of bytes written (the padded length).</returns>
    public static int Pad(ReadOnlySpan<byte> data, int blockSize, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);

        int paddedLength = PaddedLength(data.Length, blockSize);
        if(destination.Length < paddedLength)
        {
            throw new ArgumentException(
                $"The destination needs {paddedLength} bytes but has {destination.Length}.", nameof(destination));
        }

        data.CopyTo(destination);
        destination[data.Length] = Marker;
        destination.Slice(data.Length + 1, paddedLength - data.Length - 1).Clear();

        return paddedLength;
    }


    /// <summary>
    /// Returns the length of the data within <paramref name="padded"/> with the method 2 padding
    /// removed: the bytes up to (but not including) the final <c>0x80</c> marker.
    /// </summary>
    /// <param name="padded">The padded bytes — trailing <c>0x00</c> bytes then a <c>0x80</c> marker.</param>
    /// <returns>The unpadded length in bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when no valid method 2 padding is present.</exception>
    public static int UnpaddedLength(ReadOnlySpan<byte> padded)
    {
        for(int i = padded.Length - 1; i >= 0; i--)
        {
            if(padded[i] == Marker)
            {
                return i;
            }

            if(padded[i] != 0x00)
            {
                break;
            }
        }

        throw new ArgumentException("The input does not carry valid ISO 9797-1 method 2 padding.", nameof(padded));
    }
}
