using System.Linq;
using System.Buffers;
using CsCheck;
using Lumoin.Base;
using Verifiable.Cesr;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Property-based tests (CsCheck) for the CESR codec. Two classes of invariant: valid-input round-trips (a value
/// encoded and decoded again recovers itself, in and across both concrete domains), and arbitrary/near-valid-input
/// robustness (decoding either succeeds or throws only a <see cref="CesrFormatException"/> — never another exception
/// type, and the count arithmetic never overflows). The robustness generators mutate known-valid material one edit
/// at a time rather than sampling blindly, because a codec of this shape rejects almost all blind-random input at
/// the first selector but a near-valid neighbour reaches the size and slice arithmetic where the defects live.
/// These run in every build, unlike the external conformance-vector corpus, which is present only when its
/// environment variable points at it (see <see cref="CesrConformanceVectors"/>).
/// </summary>
[TestClass]
internal sealed class CesrCodecPropertyTests
{
    /// <summary>The largest count a five-character large-count-code soft field carries (<c>64^5 - 1</c>).</summary>
    private const int MaxLargeCount = (64 * 64 * 64 * 64 * 64) - 1;


    /// <summary>Valid fixed-code (code, raw) pairs: a code paired with a raw value of exactly the length it carries.</summary>
    private static Gen<(string Code, byte[] Raw)> GenFixedPrimitive { get; } =
        Gen.OneOf(
            Gen.Byte.Array[32].Select(raw => ("D", raw)),
            Gen.Byte.Array[16].Select(raw => ("0A", raw)),
            Gen.Byte.Array[64].Select(raw => ("0B", raw)),
            Gen.Byte.Array[2].Select(raw => ("M", raw)));

    /// <summary>Known-valid qb64 primitives spanning the code shapes, used as the seeds for mutation.</summary>
    private static string[] ValidPrimitivesQb64 { get; } =
    [
        "DA_52v7lAkIJVUuruh40GvMsY3_K7J4-ZdVo7NoD2xzm",
        "0AA_Az7vckaE383AHOsW1J1N",
        "MAAA",
        "4AAA",
        "Xabc"
    ];

    /// <summary>A character drawn from the Base64URL alphabet plus off-alphabet octets that a decoder must reject.</summary>
    private static Gen<char> GenAnyChar { get; } =
        Gen.OneOf(
            Gen.Char['A', 'Z'],
            Gen.Char['a', 'z'],
            Gen.Char['0', '9'],
            Gen.Const('-'),
            Gen.Const('_'),
            Gen.Const('='),
            Gen.Const('!'),
            Gen.Const(' '),
            Gen.Const('\0'));

    /// <summary>A one-edit mutation (substitute, truncate, or append) of a known-valid qb64 primitive.</summary>
    private static Gen<string> GenMutatedPrimitive { get; } =
        from seed in Gen.Int[0, ValidPrimitivesQb64.Length - 1]
        from mutation in Gen.Int[0, 2]
        from position in Gen.Int[0, ValidPrimitivesQb64[seed].Length]
        from character in GenAnyChar
        select Mutate(ValidPrimitivesQb64[seed], mutation, position, character);


    /// <summary>
    /// A valid fixed primitive round-trips in the text domain, in the binary domain, and consistently between them:
    /// decoding either encoding recovers the original code and raw value.
    /// </summary>
    [TestMethod]
    public void FixedPrimitiveRoundTripsInAndAcrossBothDomains() =>
        GenFixedPrimitive.Sample(pair =>
        {
            string qb64 = CesrPrimitiveCodec.EncodeText(pair.Code, pair.Raw);
            using(CesrParsedPrimitive fromText = CesrPrimitiveCodec.DecodeText(qb64, BaseMemoryPool.Shared))
            {
                if(fromText.Code != pair.Code || !fromText.Raw.SequenceEqual(pair.Raw))
                {
                    return false;
                }
            }

            int qb2Length = qb64.Length * 3 / 4;
            using IMemoryOwner<byte> binary = CesrPrimitiveCodec.EncodeBinary(pair.Code, pair.Raw, BaseMemoryPool.Shared);
            using CesrParsedPrimitive fromBinary = CesrPrimitiveCodec.DecodeBinary(binary.Memory.Span[..qb2Length], BaseMemoryPool.Shared);

            return fromBinary.Code == pair.Code && fromBinary.Raw.SequenceEqual(pair.Raw);
        });


    /// <summary>
    /// Decoding a one-edit mutation of a valid qb64 primitive either succeeds or is rejected with a
    /// <see cref="CesrFormatException"/>; it never escapes with another exception type (an overflow, an
    /// out-of-range slice, a raw Base64 format error). Any other escaping exception fails the property with its
    /// shrunk seed.
    /// </summary>
    [TestMethod]
    public void DecodeTextRejectsMutatedPrimitivesOnlyWithCesrFormatException() =>
        GenMutatedPrimitive.Sample(text => DecodesOrThrowsCesrFormat(() =>
        {
            using CesrParsedPrimitive _ = CesrPrimitiveCodec.DecodeText(text, BaseMemoryPool.Shared);
        }));


    /// <summary>
    /// Decoding an arbitrary byte span as a binary-domain primitive either succeeds or is rejected with a
    /// <see cref="CesrFormatException"/>, never another exception type. Blind bytes exercise the selector and code
    /// tables; the mutation property above exercises the size arithmetic that blind bytes rarely reach.
    /// </summary>
    [TestMethod]
    public void DecodeBinaryRejectsArbitraryBytesOnlyWithCesrFormatException() =>
        Gen.Byte.Array[0, 24].Sample(bytes => DecodesOrThrowsCesrFormat(() =>
        {
            using CesrParsedPrimitive _ = CesrPrimitiveCodec.DecodeBinary(bytes, BaseMemoryPool.Shared);
        }));


    /// <summary>
    /// A large count code round-trips its count, and its framed byte and character counts are the exact,
    /// never-negative <see cref="long"/> products across the whole count range, including the range where an
    /// <see cref="int"/> computation of <c>count * 4</c> would overflow to a negative value.
    /// </summary>
    [TestMethod]
    public void LargeCountCodeSpanArithmeticNeverOverflows() =>
        Gen.Int[0, MaxLargeCount].Sample(count =>
        {
            string qb64 = CesrCountCodeCodec.EncodeText("--A", count);
            CesrParsedCountCode parsed = CesrCountCodeCodec.DecodeText(qb64);

            return parsed.Count == count
                && parsed.BinaryByteCount == (long)count * 3
                && parsed.TextCharCount == (long)count * 4
                && parsed.BinaryByteCount >= 0
                && parsed.TextCharCount >= 0;
        });


    //Applies a single edit to a known-valid string: substitute the character at a position, truncate to a position,
    //or append a character. A substitution past the end degenerates to an append.
    private static string Mutate(string text, int mutation, int position, char character) => mutation switch
    {
        0 => position < text.Length ? string.Concat(text.AsSpan(0, position), character.ToString(), text.AsSpan(position + 1)) : text + character,
        1 => text[..System.Math.Min(position, text.Length)],
        _ => text + character
    };


    //Runs a decode and reports whether it either completed or threw the contracted CesrFormatException; any other
    //exception propagates so CsCheck fails the property with the offending exception and its shrunk seed.
    private static bool DecodesOrThrowsCesrFormat(System.Action decode)
    {
        try
        {
            decode();

            return true;
        }
        catch(CesrFormatException)
        {
            return true;
        }
    }
}
