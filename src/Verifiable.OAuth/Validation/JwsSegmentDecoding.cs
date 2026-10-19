using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// The one decoding of a compact JWS segment (RFC 7515 section 7.1) every validator of wire input shares before it reads the
/// part: the decoder's refusal of a segment as no base64url text, its <see cref="FormatException"/>, is the established failure
/// of decoding wire input, answered as no reading; any other exception is a fault of the decoder or of the reading and surfaces
/// as one.
/// </summary>
internal static class JwsSegmentDecoding
{
    /// <summary>
    /// The reading of one segment, its bytes decoded and handed to the part's reading and released after it, or
    /// <see langword="null"/> when the decoder refuses the segment as no base64url text.
    /// </summary>
    /// <typeparam name="TReading">The reading the part's reader answers.</typeparam>
    /// <param name="segment">The segment.</param>
    /// <param name="read">The part's reading, which never keeps the bytes it is handed.</param>
    /// <param name="base64UrlDecoder">The decoder.</param>
    /// <param name="memoryPool">The pool the bytes are rented from.</param>
    /// <returns>The reading, or <see langword="null"/>.</returns>
    internal static TReading? ReadOrNone<TReading>(
        string segment,
        Func<ReadOnlyMemory<byte>, TReading> read,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool memoryPool) where TReading : class
    {
        using var bytes = DecodedOrNone(segment, base64UrlDecoder, memoryPool);

        return bytes is null ? null : read(bytes.Memory);
    }


    /// <summary>The decoded bytes of one segment, or <see langword="null"/> when the decoder refuses it as no base64url text.</summary>
    /// <param name="segment">The segment.</param>
    /// <param name="base64UrlDecoder">The decoder.</param>
    /// <param name="memoryPool">The pool the bytes are rented from.</param>
    /// <returns>The bytes, which the caller disposes, or <see langword="null"/>.</returns>
    internal static IMemoryOwner<byte>? DecodedOrNone(string segment, DecodeDelegate base64UrlDecoder, BaseMemoryPool memoryPool)
    {
        try
        {
            return base64UrlDecoder(segment, memoryPool);
        }
        catch(FormatException)
        {
            return null;
        }
    }
}
