using System.Buffers;
using System.Buffers.Text;

namespace Verifiable.Cesr.Text;

/// <summary>
/// The shared CESR text-domain operations the primitive, indexed-signature, and count-code codecs are all
/// built on: converting between Base64URL text and integers, packing a code into and reading it back from the
/// binary (qb2) domain, and the value-framing helpers (pad/lead handling and validation). These are the
/// genus-independent mechanics of the 24-bit composable encoding, factored out of the individual codecs.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#concrete-domain-representations">
/// Concrete Domain representations</see>. The character/sextet bijection itself lives in
/// <see cref="Base64UrlAlphabet"/>; these operations build on it.
/// </para>
/// </remarks>
public static class CesrTextCodec
{
    /// <summary>
    /// The Base64URL pad character used as the extra (prepad) character within the soft part of certain
    /// special codes.
    /// </summary>
    public const char Pad = '_';


    /// <summary>
    /// Converts a non-negative integer to a fixed-width Base64URL string, most significant sextet first.
    /// </summary>
    /// <param name="value">The non-negative value to convert.</param>
    /// <param name="length">The number of characters to produce.</param>
    /// <returns>The Base64URL representation of <paramref name="value"/> padded to <paramref name="length"/> characters.</returns>
    public static string IntToBase64(long value, int length)
    {
        return string.Create(length, value, static (span, state) =>
        {
            long remaining = state;
            for(int i = span.Length - 1; i >= 0; i--)
            {
                span[i] = Base64UrlAlphabet.CharOf((int)(remaining & 0x3F));
                remaining >>= 6;
            }
        });
    }


    /// <summary>
    /// Converts a Base64URL string to a non-negative integer, most significant sextet first.
    /// </summary>
    /// <param name="text">The Base64URL characters to convert.</param>
    /// <returns>The integer value the characters encode.</returns>
    public static long Base64ToInt(ReadOnlySpan<char> text)
    {
        long value = 0;
        for(int i = 0; i < text.Length; i++)
        {
            value = (value << 6) | (uint)Base64UrlAlphabet.SextetOf(text[i]);
        }

        return value;
    }


    /// <summary>
    /// Writes the sextets of a code's text characters into the leading bits of a destination buffer,
    /// most significant bit first, leaving the trailing pad bits zero. This packs the code part of a
    /// primitive into its binary (qb2) domain form.
    /// </summary>
    /// <param name="code">The full code text (hard plus soft) to pack.</param>
    /// <param name="destination">The destination buffer; its length must be <c>ceil(code.Length * 3 / 4)</c> bytes.</param>
    public static void PackCodeBits(ReadOnlySpan<char> code, Span<byte> destination)
    {
        destination.Clear();
        for(int i = 0; i < code.Length; i++)
        {
            int sextet = Base64UrlAlphabet.SextetOf(code[i]);
            int bitOffset = i * 6;
            for(int k = 0; k < 6; k++)
            {
                int bit = (sextet >> (5 - k)) & 1;
                if(bit != 0)
                {
                    int absoluteBit = bitOffset + k;
                    destination[absoluteBit >> 3] |= (byte)(1 << (7 - (absoluteBit & 7)));
                }
            }
        }
    }


    /// <summary>
    /// Reads a single sextet (six bits, most significant bit first) at the given sextet index from a binary
    /// (qb2) buffer.
    /// </summary>
    /// <param name="source">The binary domain buffer.</param>
    /// <param name="sextetIndex">The zero-based sextet index to read.</param>
    /// <returns>The sextet value in the range 0-63.</returns>
    public static int ReadSextet(ReadOnlySpan<byte> source, int sextetIndex)
    {
        int bitOffset = sextetIndex * 6;
        int value = 0;
        for(int k = 0; k < 6; k++)
        {
            int absoluteBit = bitOffset + k;
            int bit = (source[absoluteBit >> 3] >> (7 - (absoluteBit & 7))) & 1;
            value = (value << 1) | bit;
        }

        return value;
    }


    /// <summary>
    /// Reads the leading <paramref name="characterCount"/> code characters from a binary (qb2) buffer and
    /// returns them as Base64URL text.
    /// </summary>
    /// <param name="source">The binary domain buffer.</param>
    /// <param name="characterCount">The number of code characters (sextets) to read.</param>
    /// <returns>The decoded code text.</returns>
    public static string ReadCodeText(ReadOnlySpan<byte> source, int characterCount)
    {
        Span<char> characters = characterCount <= 16 ? stackalloc char[characterCount] : new char[characterCount];
        for(int i = 0; i < characterCount; i++)
        {
            characters[i] = Base64UrlAlphabet.CharOf(ReadSextet(source, i));
        }

        return new string(characters);
    }


    /// <summary>
    /// Converts a code character count to the number of binary-domain bytes that hold those sextets,
    /// <c>ceil(characters * 3 / 4)</c>.
    /// </summary>
    /// <param name="characters">The number of code characters.</param>
    /// <returns>The number of bytes.</returns>
    public static int CodeBinaryLength(int characters) => ((characters * 3) + 3) / 4;


    /// <summary>
    /// Base64URL-encodes a raw value prefixed by zero bytes, then drops the leading characters those prefix
    /// bytes produced. This renders the value part of a primitive: the prepad and lead bytes prepend zeros to
    /// align on a 24-bit boundary, and the resulting leading Base64URL characters are stripped because the code
    /// itself already conveys them.
    /// </summary>
    /// <param name="raw">The raw value bytes.</param>
    /// <param name="prefixZeros">The number of zero bytes to prepend (net pad plus lead bytes).</param>
    /// <param name="skip">The number of leading encoded characters to drop.</param>
    /// <returns>The encoded value characters.</returns>
    public static string EncodeValue(ReadOnlySpan<byte> raw, int prefixZeros, int skip)
    {
        int total = prefixZeros + raw.Length;
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(total, 1));
        try
        {
            Span<byte> buffer = rented.AsSpan(0, total);
            buffer[..prefixZeros].Clear();
            raw.CopyTo(buffer[prefixZeros..]);
            string encoded = Base64Url.EncodeToString(buffer);

            return skip == 0 ? encoded : encoded[skip..];
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    /// <summary>
    /// Verifies that the leading prefix bytes of a decoded value (the net pad and lead bytes) are all zero, as
    /// the composable encoding requires.
    /// </summary>
    /// <param name="prefix">The prefix bytes to check.</param>
    /// <exception cref="CesrFormatException">A prefix byte is non-zero.</exception>
    public static void VerifyZeroPrefix(ReadOnlySpan<byte> prefix)
    {
        for(int i = 0; i < prefix.Length; i++)
        {
            if(prefix[i] != 0)
            {
                throw new CesrFormatException("Non-zero pad or lead bytes in CESR material.");
            }
        }
    }


    /// <summary>
    /// Verifies that the unused low bits at the end of a code's binary (qb2) packing are zero. When a code's
    /// character count is not a multiple of four its sextets do not fill a whole number of bytes, so the last
    /// code byte carries mid-pad bits that the composable encoding requires to be zero; a non-canonical encoding
    /// that sets them decodes to the same code and so must be rejected to keep the domain a bijection (otherwise
    /// two distinct byte strings decode to the same primitive — a malleability that content addressing cannot
    /// tolerate). Shared by the primitive and indexed-signature binary decoders.
    /// </summary>
    /// <param name="qb2">The binary domain buffer.</param>
    /// <param name="codeSize">The number of code characters (hard plus soft sextets).</param>
    /// <param name="codeBytes">The number of bytes those code characters pack into.</param>
    /// <exception cref="CesrFormatException">A mid-pad bit is non-zero.</exception>
    public static void VerifyCodeMidpadBits(ReadOnlySpan<byte> qb2, int codeSize, int codeBytes)
    {
        int padBits = 2 * (codeSize % 4);
        if(padBits == 0)
        {
            return;
        }

        int mask = (1 << padBits) - 1;
        if((qb2[codeBytes - 1] & mask) != 0)
        {
            throw new CesrFormatException("Non-zero code mid-pad bits in CESR binary primitive.");
        }
    }
}
