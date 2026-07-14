using System;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared BER/DER TLV wire fixtures for the CV certificate and eMRTD DataGroup 14/15 test corpus.
/// </summary>
/// <remarks>
/// <c>TpmBackedTerminalAuthenticationTests</c>'s own uncompressed-point builder is not folded
/// in here: it constructs the point from a TPM-returned <c>TpmsEccPoint</c>'s big-endian, possibly
/// short, coordinates (left-padding each to a fixed width), rather than from a single fill byte, so it
/// is a different operation shaped like this family's name rather than a duplicate of its body.
/// </remarks>
internal static class ApduWireFixtures
{
    /// <summary>The uncompressed SEC1 point's fixed byte length for a P-256 (32-byte coordinate) key.</summary>
    private const int P256UncompressedPointLength = 65;


    /// <summary>
    /// Builds an uncompressed SEC1 EC point (<c>0x04 || X || Y</c>) with both coordinates filled with
    /// <paramref name="fill"/>, sized for a P-256 (32-byte coordinate) key.
    /// </summary>
    /// <param name="fill">The byte value both coordinates are filled with.</param>
    /// <returns>The 65-byte uncompressed point encoding.</returns>
    internal static byte[] BuildUncompressedPoint(byte fill)
    {
        byte[] point = new byte[P256UncompressedPointLength];
        point[0] = 0x04;
        point.AsSpan(1).Fill(fill);

        return point;
    }


    /// <summary>
    /// Builds an uncompressed SEC1 EC point (<c>0x04 || X || Y</c>) with both <paramref name="coordinateSize"/>-byte
    /// coordinates filled with <paramref name="fill"/>.
    /// </summary>
    /// <param name="coordinateSize">The byte length of each coordinate.</param>
    /// <param name="fill">The byte value both coordinates are filled with.</param>
    /// <returns>The <c>1 + 2 * coordinateSize</c>-byte uncompressed point encoding.</returns>
    internal static byte[] BuildUncompressedPoint(int coordinateSize, byte fill)
    {
        byte[] point = new byte[1 + (2 * coordinateSize)];
        point[0] = 0x04;
        point.AsSpan(1).Fill(fill);

        return point;
    }


    /// <summary>
    /// Encodes <paramref name="length"/> as a BER/DER TLV length field: short form for 0-127, and the
    /// long form (0x81 or 0x82 prefix) for larger values up to 16 bits.
    /// </summary>
    /// <param name="length">The length value to encode.</param>
    /// <returns>The encoded length field bytes.</returns>
    internal static byte[] EncodeLength(int length)
    {
        if(length <= 0x7F) { return [(byte)length]; }
        if(length <= 0xFF) { return [0x81, (byte)length]; }

        return [0x82, (byte)(length >> 8), (byte)length];
    }
}
