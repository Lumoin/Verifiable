using System.Buffers;
using System.Buffers.Text;
using Verifiable.Cesr.Text;

namespace Verifiable.Cesr;

/// <summary>
/// Transcodes a single CESR primitive between its three representation domains: the raw value, the text
/// domain (qualified Base64URL, "qb64"), and the binary domain ("qb2"). This is the foundational operation
/// of the codec; count codes, indexed signatures, and groups compose over it.
/// </summary>
/// <remarks>
/// <para>
/// The conversions implement the framing scheme of the CESR specification's
/// <see href="https://trustoverip.github.io/kswg-cesr-specification/#concrete-domain-representations">
/// Concrete Domain representations</see>: the code is sized so that the whole primitive aligns on a 24-bit
/// boundary, with the net pad bits prepended into the value (CESR never appends Base64 <c>=</c> padding) and
/// zero-valued lead bytes prepended to the raw value as needed for binary-domain alignment.
/// </para>
/// </remarks>
public static class CesrPrimitiveCodec
{
    /// <summary>
    /// Encodes a raw value under a code into the text domain (qb64).
    /// </summary>
    /// <param name="code">The stable (hard) code, for example <c>0B</c>.</param>
    /// <param name="raw">The raw value to encode.</param>
    /// <param name="soft">The soft value for a special fixed code, exclusive of extra prepad; ignored otherwise.</param>
    /// <returns>The fully qualified Base64URL text.</returns>
    public static string EncodeText(string code, ReadOnlySpan<byte> raw, string soft = "")
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(soft);

        CesrCodeSizing sizing = LookupSizing(code);
        string both = ComposeCode(code, sizing, soft, raw.Length);
        int codeSize = sizing.CodeSize;
        int leadSize = sizing.LeadSize;
        int rawSize = raw.Length;

        if(sizing.IsVariable)
        {
            if((leadSize + rawSize) % 3 != 0)
            {
                throw new CesrFormatException($"Variable raw size {rawSize} with lead {leadSize} is not 24-bit aligned for code '{code}'.");
            }

            string variableValue = CesrTextCodec.EncodeValue(raw, leadSize, skip: 0);

            return both + variableValue;
        }

        int padSize = (3 - ((rawSize + leadSize) % 3)) % 3;
        if(padSize != codeSize % 4)
        {
            throw new CesrFormatException($"Fixed raw size {rawSize} is invalid for code '{code}' (net pad {padSize} != code pad {codeSize % 4}).");
        }

        string fixedValue = CesrTextCodec.EncodeValue(raw, padSize + leadSize, skip: padSize);

        return both + fixedValue;
    }


    /// <summary>
    /// Encodes a raw value under a code into the binary domain (qb2).
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <param name="raw">The raw value to encode.</param>
    /// <param name="pool">The memory pool from which to allocate the result.</param>
    /// <param name="soft">The soft value for a special fixed code, exclusive of extra prepad; ignored otherwise.</param>
    /// <returns>Pooled memory holding the qb2 bytes; the caller must dispose it. The length is the full primitive size.</returns>
    public static IMemoryOwner<byte> EncodeBinary(string code, ReadOnlySpan<byte> raw, MemoryPool<byte> pool, string soft = "")
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(soft);

        CesrCodeSizing sizing = LookupSizing(code);
        string both = ComposeCode(code, sizing, soft, raw.Length);
        int codeSize = sizing.CodeSize;
        int leadSize = sizing.LeadSize;
        int codeBytes = CesrTextCodec.CodeBinaryLength(codeSize);
        int total = codeBytes + leadSize + raw.Length;

        IMemoryOwner<byte> owner = pool.Rent(total);
        Span<byte> span = owner.Memory.Span[..total];
        span.Clear();
        CesrTextCodec.PackCodeBits(both, span[..codeBytes]);
        raw.CopyTo(span[(codeBytes + leadSize)..]);

        return owner;
    }


    /// <summary>
    /// Decodes a single CESR primitive from the text domain (qb64).
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw value.</param>
    /// <returns>The decoded code, soft value, and raw value. The caller must dispose the result.</returns>
    public static CesrParsedPrimitive DecodeText(ReadOnlySpan<char> qb64, MemoryPool<byte> pool) =>
        DecodeText(qb64, pool, out _);


    /// <summary>
    /// Decodes a single CESR primitive from the text domain (qb64), also reporting how many characters the
    /// primitive occupied so a caller can advance to the next element in a group.
    /// </summary>
    /// <param name="qb64">The fully qualified Base64URL text; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw value.</param>
    /// <param name="consumedChars">The number of leading characters the decoded primitive occupied.</param>
    /// <returns>The decoded code, soft value, and raw value. The caller must dispose the result.</returns>
    public static CesrParsedPrimitive DecodeText(ReadOnlySpan<char> qb64, MemoryPool<byte> pool, out int consumedChars)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(qb64.IsEmpty)
        {
            throw new CesrFormatException("Empty CESR text material.");
        }

        int hardSize = HardSizeOf(qb64[0]);
        if(qb64.Length < hardSize)
        {
            throw new CesrFormatException("Truncated CESR code.");
        }

        string hard = new string(qb64[..hardSize]);
        CesrCodeSizing sizing = LookupSizing(hard);
        int codeSize = sizing.CodeSize;
        int softSize = sizing.SoftSize;
        int extraSize = sizing.ExtraSize;
        int leadSize = sizing.LeadSize;

        if(qb64.Length < codeSize)
        {
            throw new CesrFormatException("Truncated CESR code.");
        }

        ReadOnlySpan<char> softSpan = qb64.Slice(hardSize, softSize);
        VerifyExtraPad(softSpan[..extraSize]);
        string soft = new string(softSpan[extraSize..]);

        int fullSize = sizing.FullSize ?? (int)(CesrTextCodec.Base64ToInt(soft) * 4 + codeSize);
        if(qb64.Length < fullSize)
        {
            throw new CesrFormatException("Truncated CESR primitive.");
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
            padded[..padSize].Fill(Base64UrlAlphabet.Zero);
            qb64.Slice(codeSize, valueChars).CopyTo(padded[padSize..]);

            if(Base64Url.DecodeFromChars(padded, rentedBytes, out _, out int decodedBytes) != OperationStatus.Done)
            {
                throw new CesrFormatException("Invalid Base64URL in CESR primitive.");
            }

            int prefix = padSize + leadSize;
            if(decodedBytes < prefix)
            {
                throw new CesrFormatException("A CESR primitive declares a size too small to hold its pad and lead bytes.");
            }

            CesrTextCodec.VerifyZeroPrefix(rentedBytes.AsSpan(0, prefix));
            int rawLength = decodedBytes - prefix;

            return BuildParsed(hard, soft, rentedBytes.AsSpan(prefix, rawLength), pool);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rentedChars);
            ArrayPool<byte>.Shared.Return(rentedBytes, clearArray: true);
        }
    }


    /// <summary>
    /// Decodes a single CESR primitive from the binary domain (qb2).
    /// </summary>
    /// <param name="qb2">The fully qualified binary bytes; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw value.</param>
    /// <returns>The decoded code, soft value, and raw value. The caller must dispose the result.</returns>
    public static CesrParsedPrimitive DecodeBinary(ReadOnlySpan<byte> qb2, MemoryPool<byte> pool) =>
        DecodeBinary(qb2, pool, out _);


    /// <summary>
    /// Decodes a single CESR primitive from the binary domain (qb2), also reporting how many bytes the
    /// primitive occupied so a caller can advance to the next element in a group.
    /// </summary>
    /// <param name="qb2">The fully qualified binary bytes; only the leading primitive is consumed.</param>
    /// <param name="pool">The memory pool from which to allocate the recovered raw value.</param>
    /// <param name="consumedBytes">The number of leading bytes the decoded primitive occupied.</param>
    /// <returns>The decoded code, soft value, and raw value. The caller must dispose the result.</returns>
    public static CesrParsedPrimitive DecodeBinary(ReadOnlySpan<byte> qb2, MemoryPool<byte> pool, out int consumedBytes)
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
            throw new CesrFormatException("Truncated CESR code.");
        }

        string hard = CesrTextCodec.ReadCodeText(qb2, hardSize);
        CesrCodeSizing sizing = LookupSizing(hard);
        int codeSize = sizing.CodeSize;
        int extraSize = sizing.ExtraSize;
        int leadSize = sizing.LeadSize;
        int codeBytes = CesrTextCodec.CodeBinaryLength(codeSize);

        if(qb2.Length < codeBytes)
        {
            throw new CesrFormatException("Truncated CESR code.");
        }

        string both = CesrTextCodec.ReadCodeText(qb2, codeSize);
        ReadOnlySpan<char> softSpan = both.AsSpan(sizing.HardSize, sizing.SoftSize);
        VerifyExtraPad(softSpan[..extraSize]);
        string soft = new string(softSpan[extraSize..]);

        int fullSize = sizing.FullSize ?? (int)(CesrTextCodec.Base64ToInt(soft) * 4 + codeSize);
        int fullBytes = CesrTextCodec.CodeBinaryLength(fullSize);
        if(qb2.Length < fullBytes)
        {
            throw new CesrFormatException("Truncated CESR primitive.");
        }

        int rawLength = fullBytes - codeBytes - leadSize;
        if(rawLength < 0)
        {
            throw new CesrFormatException("A CESR primitive declares a size too small to hold its pad and lead bytes.");
        }

        CesrTextCodec.VerifyCodeMidpadBits(qb2, codeSize, codeBytes);
        CesrTextCodec.VerifyZeroPrefix(qb2.Slice(codeBytes, leadSize));
        consumedBytes = fullBytes;

        return BuildParsed(hard, soft, qb2.Slice(codeBytes + leadSize, rawLength), pool);
    }


    private static CesrParsedPrimitive BuildParsed(string code, string soft, ReadOnlySpan<byte> raw, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(raw.Length, 1));
        raw.CopyTo(owner.Memory.Span);

        return new CesrParsedPrimitive(code, soft, owner, raw.Length);
    }


    private static string ComposeCode(string code, CesrCodeSizing sizing, string soft, int rawLength)
    {
        if(sizing.IsVariable)
        {
            int leadSize = sizing.LeadSize;
            if((rawLength + leadSize) % 3 != 0)
            {
                throw new CesrFormatException($"Variable raw size {rawLength} with lead {leadSize} is not 24-bit aligned for code '{code}'.");
            }

            long size = (rawLength + leadSize) / 3;

            return code + CesrTextCodec.IntToBase64(size, sizing.SoftSize);
        }

        //A fixed code implies an exact raw size; reject a mismatch here so both the text and binary encoders
        //(which share this) refuse to emit a wrong-length primitive, rather than only the text encoder's partial
        //net-pad check catching some mismatches.
        if(sizing.RawSize is int expectedRaw && rawLength != expectedRaw)
        {
            throw new CesrFormatException($"Raw size {rawLength} is invalid for fixed CESR code '{code}' (expected {expectedRaw}).");
        }

        if(sizing.SoftSize > 0)
        {
            int conveyed = sizing.SoftSize - sizing.ExtraSize;
            if(soft.Length != conveyed)
            {
                throw new CesrFormatException($"Soft value '{soft}' has {soft.Length} characters; code '{code}' expects {conveyed}.");
            }

            return code + new string(CesrTextCodec.Pad, sizing.ExtraSize) + soft;
        }

        return code;
    }


    private static CesrCodeSizing LookupSizing(string code)
    {
        if(!CesrCodeTables.Sizes.TryGetValue(code, out CesrCodeSizing sizing))
        {
            throw new CesrFormatException($"Unsupported CESR code '{code}'.");
        }

        return sizing;
    }


    private static int HardSizeOf(char selector)
    {
        if(!CesrCodeTables.HardSizes.TryGetValue(selector, out int hardSize))
        {
            if(selector == '-')
            {
                throw new CesrFormatException("Unexpected count code where a primitive was expected.");
            }

            if(selector == '_')
            {
                throw new CesrFormatException("Unexpected op code where a primitive was expected.");
            }

            throw new CesrFormatException($"Unsupported CESR code selector '{selector}'.");
        }

        return hardSize;
    }


    private static void VerifyExtraPad(ReadOnlySpan<char> extra)
    {
        for(int i = 0; i < extra.Length; i++)
        {
            if(extra[i] != CesrTextCodec.Pad)
            {
                throw new CesrFormatException("Invalid prepad in CESR soft value.");
            }
        }
    }
}
