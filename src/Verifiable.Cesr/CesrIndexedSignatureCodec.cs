using System.Buffers;
using System.Buffers.Text;
using Verifiable.Cesr.Text;

namespace Verifiable.Cesr;

/// <summary>
/// Transcodes a CESR indexed signature between its raw, text (qb64) and binary (qb2) domains. An indexed
/// signature carries, in the soft part of its code, the index of the signing key in a key list (and, for
/// dual-indexed codes, an other-index into a prior key list), followed by the raw signature value.
/// </summary>
/// <remarks>
/// <para>
/// The framing follows the same 24-bit-aligned scheme as <see cref="CesrPrimitiveCodec"/>; the only
/// difference is that the soft part holds the index and other-index rather than a length or special value.
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#indexed-codes">
/// Indexed codes</see> section.
/// </para>
/// </remarks>
public static class CesrIndexedSignatureCodec
{
    /// <summary>
    /// Encodes a raw signature under an indexed code into the text domain (qb64).
    /// </summary>
    /// <param name="code">The stable (hard) indexed code, for example <c>A</c>.</param>
    /// <param name="raw">The raw signature value.</param>
    /// <param name="index">The signature index into the key list.</param>
    /// <param name="ondex">The other-index for a dual-indexed signature, or <see langword="null"/> when single-indexed.</param>
    /// <returns>The fully qualified Base64URL text.</returns>
    public static string EncodeText(string code, ReadOnlySpan<byte> raw, int index, int? ondex = null)
    {
        ArgumentNullException.ThrowIfNull(code);

        CesrIndexedCodeSizing sizing = LookupSizing(code);
        ValidateRawSize(code, sizing, raw.Length);
        string both = ComposeCode(code, sizing, index, ondex);
        int leadSize = sizing.LeadSize;
        int padSize = (3 - ((raw.Length + leadSize) % 3)) % 3;

        string value = CesrTextCodec.EncodeValue(raw, padSize + leadSize, skip: padSize);

        return both + value;
    }


    /// <summary>
    /// Encodes a raw signature under an indexed code into the binary domain (qb2).
    /// </summary>
    /// <param name="code">The stable (hard) indexed code.</param>
    /// <param name="raw">The raw signature value.</param>
    /// <param name="index">The signature index into the key list.</param>
    /// <param name="pool">The memory pool from which to allocate the result.</param>
    /// <param name="ondex">The other-index for a dual-indexed signature, or <see langword="null"/> when single-indexed.</param>
    /// <returns>Pooled memory holding the qb2 bytes; the caller must dispose it.</returns>
    public static IMemoryOwner<byte> EncodeBinary(string code, ReadOnlySpan<byte> raw, int index, MemoryPool<byte> pool, int? ondex = null)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(pool);

        CesrIndexedCodeSizing sizing = LookupSizing(code);
        ValidateRawSize(code, sizing, raw.Length);
        string both = ComposeCode(code, sizing, index, ondex);
        int leadSize = sizing.LeadSize;
        int codeBytes = CesrTextCodec.CodeBinaryLength(sizing.CodeSize);
        int total = codeBytes + leadSize + raw.Length;

        IMemoryOwner<byte> owner = pool.Rent(total);
        Span<byte> span = owner.Memory.Span[..total];
        span.Clear();
        CesrTextCodec.PackCodeBits(both, span[..codeBytes]);
        raw.CopyTo(span[(codeBytes + leadSize)..]);

        return owner;
    }


    /// <summary>
    /// Decodes a CESR indexed signature from the text domain (qb64).
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw signature.</param>
    /// <returns>The decoded code, index, other-index, and raw signature. The caller must dispose the result.</returns>
    public static CesrParsedIndexedSignature DecodeText(ReadOnlySpan<char> qb64, MemoryPool<byte> pool) =>
        DecodeText(qb64, pool, out _);


    /// <summary>
    /// Decodes a CESR indexed signature from the text domain (qb64), also reporting how many characters the
    /// signature occupied so a caller can advance to the next signature in a group.
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw signature.</param>
    /// <param name="consumedChars">The number of leading characters the decoded signature occupied.</param>
    /// <returns>The decoded code, index, other-index, and raw signature. The caller must dispose the result.</returns>
    public static CesrParsedIndexedSignature DecodeText(ReadOnlySpan<char> qb64, MemoryPool<byte> pool, out int consumedChars)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(qb64.IsEmpty)
        {
            throw new CesrFormatException("Empty CESR text material.");
        }

        int hardSize = HardSizeOf(qb64[0]);
        if(qb64.Length < hardSize)
        {
            throw new CesrFormatException("Truncated CESR indexed code.");
        }

        string hard = new string(qb64[..hardSize]);
        CesrIndexedCodeSizing sizing = LookupSizing(hard);
        int codeSize = sizing.CodeSize;
        int mainIndexSize = sizing.MainIndexSize;
        int ondexSize = sizing.OndexSize;
        int leadSize = sizing.LeadSize;

        if(qb64.Length < codeSize)
        {
            throw new CesrFormatException("Truncated CESR indexed code.");
        }

        int index = (int)CesrTextCodec.Base64ToInt(qb64.Slice(hardSize, mainIndexSize));
        int? ondex = ResolveOndex(hard, sizing, qb64.Slice(hardSize + mainIndexSize, ondexSize), index);

        int fullSize = sizing.FullSize ?? (index * 4 + codeSize);
        if(qb64.Length < fullSize)
        {
            throw new CesrFormatException("Truncated CESR indexed signature.");
        }

        consumedChars = fullSize;
        int padSize = codeSize % 4;
        int valueChars = fullSize - codeSize;
        int paddedChars = padSize + valueChars;

        char[] rentedChars = ArrayPool<char>.Shared.Rent(paddedChars);
        byte[] rentedBytes = ArrayPool<byte>.Shared.Rent(Base64Url.GetMaxDecodedLength(paddedChars));
        try
        {
            Span<char> padded = rentedChars.AsSpan(0, paddedChars);
            padded[..padSize].Fill('A');
            qb64.Slice(codeSize, valueChars).CopyTo(padded[padSize..]);

            if(Base64Url.DecodeFromChars(padded, rentedBytes, out _, out int decodedBytes) != OperationStatus.Done)
            {
                throw new CesrFormatException("Invalid Base64URL in CESR indexed signature.");
            }

            int prefix = padSize + leadSize;
            if(decodedBytes < prefix)
            {
                throw new CesrFormatException("A CESR indexed signature declares a size too small to hold its pad and lead bytes.");
            }

            CesrTextCodec.VerifyZeroPrefix(rentedBytes.AsSpan(0, prefix));
            int rawLength = decodedBytes - prefix;

            return BuildParsed(hard, index, ondex, rentedBytes.AsSpan(prefix, rawLength), pool);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rentedChars);
            ArrayPool<byte>.Shared.Return(rentedBytes, clearArray: true);
        }
    }


    /// <summary>
    /// Decodes a CESR indexed signature from the binary domain (qb2).
    /// </summary>
    /// <param name="qb2">The fully qualified binary bytes; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw signature.</param>
    /// <returns>The decoded code, index, other-index, and raw signature. The caller must dispose the result.</returns>
    public static CesrParsedIndexedSignature DecodeBinary(ReadOnlySpan<byte> qb2, MemoryPool<byte> pool) =>
        DecodeBinary(qb2, pool, out _);


    /// <summary>
    /// Decodes a CESR indexed signature from the binary domain (qb2), also reporting how many bytes the
    /// signature occupied so a caller can advance to the next signature in a group.
    /// </summary>
    /// <param name="qb2">The fully qualified binary bytes; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw signature.</param>
    /// <param name="consumedBytes">The number of leading bytes the decoded signature occupied.</param>
    /// <returns>The decoded code, index, other-index, and raw signature. The caller must dispose the result.</returns>
    public static CesrParsedIndexedSignature DecodeBinary(ReadOnlySpan<byte> qb2, MemoryPool<byte> pool, out int consumedBytes)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(qb2.IsEmpty)
        {
            throw new CesrFormatException("Empty CESR binary material.");
        }

        char selector = Base64UrlAlphabet.CharOf(CesrTextCodec.ReadSextet(qb2, 0));
        int hardSize = HardSizeOf(selector);
        int hardBytes = CesrTextCodec.CodeBinaryLength(hardSize);
        if(qb2.Length < hardBytes)
        {
            throw new CesrFormatException("Truncated CESR indexed code.");
        }

        string hard = CesrTextCodec.ReadCodeText(qb2, hardSize);
        CesrIndexedCodeSizing sizing = LookupSizing(hard);
        int codeSize = sizing.CodeSize;
        int mainIndexSize = sizing.MainIndexSize;
        int ondexSize = sizing.OndexSize;
        int leadSize = sizing.LeadSize;
        int codeBytes = CesrTextCodec.CodeBinaryLength(codeSize);

        if(qb2.Length < codeBytes)
        {
            throw new CesrFormatException("Truncated CESR indexed code.");
        }

        string both = CesrTextCodec.ReadCodeText(qb2, codeSize);
        int index = (int)CesrTextCodec.Base64ToInt(both.AsSpan(sizing.HardSize, mainIndexSize));
        int? ondex = ResolveOndex(hard, sizing, both.AsSpan(sizing.HardSize + mainIndexSize, ondexSize), index);

        int fullSize = sizing.FullSize ?? (index * 4 + codeSize);
        int fullBytes = CesrTextCodec.CodeBinaryLength(fullSize);
        if(qb2.Length < fullBytes)
        {
            throw new CesrFormatException("Truncated CESR indexed signature.");
        }

        int rawLength = fullBytes - codeBytes - leadSize;
        if(rawLength < 0)
        {
            throw new CesrFormatException("A CESR indexed signature declares a size too small to hold its pad and lead bytes.");
        }

        //Reject a non-canonical code packing (the same check the primitive decoder makes): without it two qb2 byte
        //strings differing only in the code's unused mid-pad bits decode to the same signature — a malleability.
        CesrTextCodec.VerifyCodeMidpadBits(qb2, codeSize, codeBytes);
        CesrTextCodec.VerifyZeroPrefix(qb2.Slice(codeBytes, leadSize));
        consumedBytes = fullBytes;

        return BuildParsed(hard, index, ondex, qb2.Slice(codeBytes + leadSize, rawLength), pool);
    }


    private static CesrParsedIndexedSignature BuildParsed(string code, int index, int? ondex, ReadOnlySpan<byte> raw, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(raw.Length, 1));
        raw.CopyTo(owner.Memory.Span);

        return new CesrParsedIndexedSignature(code, index, ondex, owner, raw.Length);
    }


    private static int? ResolveOndex(string code, CesrIndexedCodeSizing sizing, ReadOnlySpan<char> ondexChars, int index)
    {
        if(sizing.IsVariable)
        {
            return null;
        }

        if(CesrIndexedCodeTables.CurrentOnlyCodes.Contains(code))
        {
            if(sizing.OndexSize > 0 && CesrTextCodec.Base64ToInt(ondexChars) != 0)
            {
                throw new CesrFormatException($"Code '{code}' is current-list only but carries a non-zero other-index.");
            }

            return null;
        }

        return sizing.OndexSize > 0 ? (int)CesrTextCodec.Base64ToInt(ondexChars) : index;
    }


    private static string ComposeCode(string code, CesrIndexedCodeSizing sizing, int index, int? ondex)
    {
        ValidateIndex(code, "index", index, sizing.MainIndexSize);
        string indexPart = CesrTextCodec.IntToBase64(index, sizing.MainIndexSize);
        if(sizing.OndexSize == 0)
        {
            return code + indexPart;
        }

        long ondexValue = CesrIndexedCodeTables.CurrentOnlyCodes.Contains(code) ? 0 : (ondex ?? index);
        ValidateIndex(code, "other-index", ondexValue, sizing.OndexSize);

        return code + indexPart + CesrTextCodec.IntToBase64(ondexValue, sizing.OndexSize);
    }


    /// <summary>
    /// Rejects an index or other-index that does not fit its soft field, so a value beyond the field's capacity is
    /// never silently truncated to an aliased position (<see cref="CesrTextCodec.IntToBase64"/> discards high bits).
    /// The capacity of a soft field of the given character width is the same <c>64^width - 1</c> bound a count
    /// code's soft part has.
    /// </summary>
    private static void ValidateIndex(string code, string name, long value, int size)
    {
        long max = CesrCountCodeTables.MaxCount(size);
        if(value < 0 || value > max)
        {
            throw new CesrFormatException($"CESR indexed code '{code}' {name} {value} is out of the range 0 to {max}.");
        }
    }


    /// <summary>
    /// Rejects a raw signature whose length does not match the code: a fixed code implies an exact raw size (derived
    /// from its full size, code size, and lead size), and a variable code requires 24-bit alignment. Without this the
    /// encoders silently emit a wrong-length or truncated signature.
    /// </summary>
    private static void ValidateRawSize(string code, CesrIndexedCodeSizing sizing, int rawSize)
    {
        int leadSize = sizing.LeadSize;
        if(sizing.FullSize is int fullSize)
        {
            int codeBytes = CesrTextCodec.CodeBinaryLength(sizing.CodeSize);
            int fullBytes = CesrTextCodec.CodeBinaryLength(fullSize);
            int expected = fullBytes - codeBytes - leadSize;
            if(rawSize != expected)
            {
                throw new CesrFormatException($"Signature raw size {rawSize} is invalid for indexed code '{code}' (expected {expected}).");
            }
        }
        else if((rawSize + leadSize) % 3 != 0)
        {
            throw new CesrFormatException($"Variable indexed signature raw size {rawSize} with lead {leadSize} is not 24-bit aligned for code '{code}'.");
        }
    }


    private static CesrIndexedCodeSizing LookupSizing(string code)
    {
        if(!CesrIndexedCodeTables.Sizes.TryGetValue(code, out CesrIndexedCodeSizing sizing))
        {
            throw new CesrFormatException($"Unsupported CESR indexed code '{code}'.");
        }

        return sizing;
    }


    private static int HardSizeOf(char selector)
    {
        if(!CesrIndexedCodeTables.HardSizes.TryGetValue(selector, out int hardSize))
        {
            throw new CesrFormatException($"Unsupported CESR indexed code selector '{selector}'.");
        }

        return hardSize;
    }
}
