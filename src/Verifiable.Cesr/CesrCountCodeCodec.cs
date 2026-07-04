using System.Buffers;
using Verifiable.Cesr.Text;

namespace Verifiable.Cesr;

/// <summary>
/// Transcodes a CESR count (group/framing) code between its text (qb64) and binary (qb2) domains. A count
/// code frames a group of primitives or groups: its soft part holds the number of quadlets/triplets in the
/// group that follows so that a parser can offload the group without parsing its contents. The genus/version
/// code is encoded by the same mechanism but its soft part holds a protocol version rather than a count.
/// </summary>
/// <remarks>
/// <para>
/// A count code carries no raw value and is always aligned on a 24-bit boundary, so its whole code is a
/// multiple of four characters with a pad size of zero. Encoding is therefore just the hard code followed by
/// the count as a fixed-width Base64URL integer; the binary form packs those characters into bits exactly as
/// for the code part of a primitive. Anchored on the CESR specification's
/// <see href="https://trustoverip.github.io/kswg-cesr-specification/#count-code-tables">Count Code tables</see>.
/// </para>
/// </remarks>
public static class CesrCountCodeCodec
{
    /// <summary>
    /// Encodes a count code into the text domain (qb64).
    /// </summary>
    /// <param name="code">The stable (hard) count code, for example <c>-V</c>, <c>--V</c>, or <c>-_AAA</c>.</param>
    /// <param name="count">The quadlet/triplet count, or the packed version for a genus/version code.</param>
    /// <returns>The fully qualified Base64URL text.</returns>
    public static string EncodeText(string code, int count)
    {
        ArgumentNullException.ThrowIfNull(code);

        CesrCountCodeSizing sizing = LookupSizing(code);
        ValidateCount(code, count, sizing.SoftSize);

        return code + CesrTextCodec.IntToBase64(count, sizing.SoftSize);
    }


    /// <summary>
    /// Encodes a count code into the binary domain (qb2).
    /// </summary>
    /// <param name="code">The stable (hard) count code.</param>
    /// <param name="count">The quadlet/triplet count, or the packed version for a genus/version code.</param>
    /// <param name="pool">The memory pool from which to allocate the result.</param>
    /// <returns>Pooled memory holding the qb2 bytes; the caller must dispose it. The length is the full code size.</returns>
    public static IMemoryOwner<byte> EncodeBinary(string code, int count, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(pool);

        int totalBytes = CesrTextCodec.CodeBinaryLength(LookupSizing(code).FullSize);
        IMemoryOwner<byte> owner = pool.Rent(totalBytes);
        EncodeBinary(code, count, owner.Memory.Span[..totalBytes]);

        return owner;
    }


    /// <summary>
    /// Encodes a count code into the binary domain (qb2) directly into a destination span, for example a buffer
    /// rented from a <see cref="System.IO.Pipelines.PipeWriter"/>.
    /// </summary>
    /// <param name="code">The stable (hard) count code.</param>
    /// <param name="count">The quadlet/triplet count, or the packed version for a genus/version code.</param>
    /// <param name="destination">The destination buffer; it must be at least the full code size in bytes.</param>
    /// <returns>The number of bytes written (the full code size).</returns>
    public static int EncodeBinary(string code, int count, Span<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(code);

        CesrCountCodeSizing sizing = LookupSizing(code);
        ValidateCount(code, count, sizing.SoftSize);
        int totalBytes = CesrTextCodec.CodeBinaryLength(sizing.FullSize);
        if(destination.Length < totalBytes)
        {
            throw new ArgumentException($"The destination is too small for CESR count code '{code}' ({destination.Length} < {totalBytes} bytes).", nameof(destination));
        }

        string both = code + CesrTextCodec.IntToBase64(count, sizing.SoftSize);
        Span<byte> target = destination[..totalBytes];
        target.Clear();
        CesrTextCodec.PackCodeBits(both, target);

        return totalBytes;
    }


    /// <summary>
    /// Decodes a count code from the text domain (qb64).
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading count code is consumed.</param>
    /// <returns>The decoded code and count.</returns>
    public static CesrParsedCountCode DecodeText(ReadOnlySpan<char> qb64)
    {
        if(qb64.Length < 2)
        {
            throw new CesrFormatException("Truncated CESR count code.");
        }

        CesrCountCodeSizing sizing = CesrCountCodeTables.SizingForSelector(qb64[0], qb64[1]);
        if(qb64.Length < sizing.FullSize)
        {
            throw new CesrFormatException("Truncated CESR count code.");
        }

        string code = new string(qb64[..sizing.HardSize]);
        ValidateHardCharacters(code);
        int count = (int)CesrTextCodec.Base64ToInt(qb64.Slice(sizing.HardSize, sizing.SoftSize));

        return new CesrParsedCountCode(code, count);
    }


    /// <summary>
    /// Decodes a count code from the binary domain (qb2).
    /// </summary>
    /// <param name="qb2">The fully qualified binary bytes; only the leading count code is consumed.</param>
    /// <returns>The decoded code and count.</returns>
    public static CesrParsedCountCode DecodeBinary(ReadOnlySpan<byte> qb2)
    {
        //Two selector sextets (twelve bits) are needed to determine the count code table.
        if(qb2.Length < 2)
        {
            throw new CesrFormatException("Truncated CESR count code.");
        }

        char first = Base64UrlAlphabet.CharOf(CesrTextCodec.ReadSextet(qb2, 0));
        char second = Base64UrlAlphabet.CharOf(CesrTextCodec.ReadSextet(qb2, 1));
        CesrCountCodeSizing sizing = CesrCountCodeTables.SizingForSelector(first, second);
        int fullBytes = CesrTextCodec.CodeBinaryLength(sizing.FullSize);
        if(qb2.Length < fullBytes)
        {
            throw new CesrFormatException("Truncated CESR count code.");
        }

        string both = CesrTextCodec.ReadCodeText(qb2, sizing.FullSize);
        string code = both[..sizing.HardSize];
        int count = (int)CesrTextCodec.Base64ToInt(both.AsSpan(sizing.HardSize, sizing.SoftSize));

        return new CesrParsedCountCode(code, count);
    }


    private static CesrCountCodeSizing LookupSizing(string code)
    {
        if(code.Length < 2)
        {
            throw new CesrFormatException("Truncated CESR count code.");
        }

        CesrCountCodeSizing sizing = CesrCountCodeTables.SizingForSelector(code[0], code[1]);
        if(code.Length != sizing.HardSize)
        {
            throw new CesrFormatException($"CESR count code '{code}' has {code.Length} hard characters; expected {sizing.HardSize}.");
        }

        ValidateHardCharacters(code);

        return sizing;
    }


    private static void ValidateHardCharacters(string code)
    {
        //The first two characters are the selectors, already validated by SizingForSelector; the remaining
        //hard characters (the large-code type or the genus) must be valid Base64URL characters.
        for(int i = 2; i < code.Length; i++)
        {
            Base64UrlAlphabet.SextetOf(code[i]);
        }
    }


    private static void ValidateCount(string code, int count, int softSize)
    {
        long max = CesrCountCodeTables.MaxCount(softSize);
        if(count < 0 || count > max)
        {
            throw new CesrFormatException($"Count {count} is out of the range 0 to {max} for CESR count code '{code}'.");
        }
    }
}
