using System.Buffers;
using System.Buffers.Text;

namespace Verifiable.Cesr;

/// <summary>
/// Transcodes a Base64URL-only text string to and from its compact CESR string primitive (the codes <c>4A</c>/
/// <c>5A</c>/<c>6A</c>). A Base64URL string is carried as its own characters packed into the primitive's value with
/// mid-pad bits, which is more compact than encoding the string's raw bytes; this is what a field-map label or text
/// value longer than a compact tag uses.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// Master code table</see> string codes. A string that is not a multiple of four characters is left-padded with the
/// Base64URL zero character to a 24-bit boundary, and the lead bytes the padding implies select the lead-sized code.
/// A one-character leading pad is ambiguous with a leading <c>A</c> in the string itself, and a leading <c>-</c> is
/// the escape character, so both are resolved by prepending an escape <c>-</c>: a string whose first character is
/// <c>-</c>, or is <c>A</c> at a length where the pad would be one character or none, is escaped, and the decode
/// strips the escape. This lets a string carry any Base64URL content, including a leading <c>A</c> or <c>-</c>.
/// </para>
/// </remarks>
public static class CesrBase64Text
{
    /// <summary>The Base64URL zero character used as the left pad and, doubled, in the encode's value.</summary>
    private const char PadCharacter = 'A';

    /// <summary>The escape character prepended to resolve the leading-pad ambiguity.</summary>
    private const char EscapeCharacter = '-';

    /// <summary>The greatest quadlet count the two-character count of a small string code can carry.</summary>
    private const int SmallCountCapacity = (64 * 64) - 1;


    /// <summary>
    /// Encodes a Base64URL-only text string as its compact CESR string primitive.
    /// </summary>
    /// <param name="text">The Base64URL-only text to encode.</param>
    /// <returns>The qb64 string primitive.</returns>
    /// <exception cref="CesrFormatException">The text is too long for a small string code (a big string code is a later slice), or is not valid Base64URL.</exception>
    public static string Encode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        int wad = (4 - (text.Length % 4)) % 4;
        bool escape = text.Length > 0 && (text[0] == EscapeCharacter || (text[0] == PadCharacter && (wad == 0 || wad == 1)));
        int escapedLength = escape ? text.Length + 1 : text.Length;
        int escapedWad = (4 - (escapedLength % 4)) % 4;
        int leadSize = (3 - (escapedLength % 4)) % 3;
        int baseLength = escapedWad + escapedLength;
        if(baseLength / 4 > SmallCountCapacity)
        {
            throw new CesrFormatException("A CESR field-map Base64 string longer than a small string code holds is a later slice.");
        }

        char[] rentedChars = ArrayPool<char>.Shared.Rent(Math.Max(baseLength, 1));
        byte[] rentedBytes = ArrayPool<byte>.Shared.Rent(Base64Url.GetMaxDecodedLength(baseLength));
        try
        {
            Span<char> padded = rentedChars.AsSpan(0, baseLength);
            padded[..escapedWad].Fill(PadCharacter);
            int at = escapedWad;
            if(escape)
            {
                padded[at++] = EscapeCharacter;
            }

            text.AsSpan().CopyTo(padded[at..]);

            if(Base64Url.DecodeFromChars(padded, rentedBytes, out _, out int decoded) != OperationStatus.Done)
            {
                throw new CesrFormatException("Invalid Base64URL text for a CESR field-map string value.");
            }

            ReadOnlySpan<byte> raw = rentedBytes.AsSpan(leadSize, decoded - leadSize);

            return CesrPrimitiveCodec.EncodeText(LeadCode(leadSize), raw);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rentedChars);
            ArrayPool<byte>.Shared.Return(rentedBytes, clearArray: true);
        }
    }


    /// <summary>
    /// Decodes a CESR string primitive's raw value back to its Base64URL text.
    /// </summary>
    /// <param name="code">The string primitive's stable code (a small string code).</param>
    /// <param name="raw">The primitive's raw value.</param>
    /// <returns>The decoded Base64URL text.</returns>
    public static string Decode(string code, ReadOnlySpan<byte> raw)
    {
        ArgumentNullException.ThrowIfNull(code);

        int leadSize = CesrCodeTables.Sizes[code].LeadSize;
        int total = leadSize + raw.Length;

        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(total, 1));
        try
        {
            Span<byte> buffer = rented.AsSpan(0, total);
            buffer[..leadSize].Clear();
            raw.CopyTo(buffer[leadSize..]);
            string padded = Base64Url.EncodeToString(buffer);

            int wad = leadSize == 0
                ? (padded.Length > 0 && padded[0] == PadCharacter ? 1 : 0)
                : (leadSize + 1) % 4;
            ReadOnlySpan<char> text = padded.AsSpan(wad);
            if(text.Length > 0 && text[0] == EscapeCharacter)
            {
                text = text[1..];
            }

            return new string(text);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    //Maps a lead size to the lead-sized small string code.
    private static string LeadCode(int leadSize) => leadSize switch
    {
        0 => "4A",
        1 => "5A",
        2 => "6A",
        _ => throw new CesrFormatException($"Invalid string lead size {leadSize}.")
    };
}
