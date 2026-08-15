using System.Buffers;
using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Cesr;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrIndexedSignatureCodec"/>: round-tripping a CESR indexed signature between the
/// raw, text (qb64) and binary (qb2) domains. The known-answer vectors cover a single-indexed code
/// (other-index equal to the index), a dual-indexed code (distinct other-index), and a variable indexed
/// code (no other-index). Anchored on the CESR specification's
/// <see href="https://trustoverip.github.io/kswg-cesr-specification/#indexed-codes">Indexed codes</see> section.
/// </summary>
[TestClass]
internal sealed class CesrIndexedSignatureCodecTests
{
    /// <summary>
    /// Known-answer vectors: code, raw (hex), index, other-index (null when absent), expected qb64, expected qb2 (hex).
    /// </summary>
    /// <returns>The known-answer vectors.</returns>
    private static IEnumerable<object?[]> KnownAnswerVectors()
    {
        //Single-indexed Ed25519 signature: other-index equals the index for a both-lists code (no ondex chars).
        yield return ["A", "3f13ac360430d54a73044f307f6a15f4f3dbaba177fe50e1dd50dcdf58c372e3b54ad3fbfe0f98ff6a1e28dd637a10e030314e7318445b6abd1d5cb4c628e006", 0, (int?)0,
            "AAA_E6w2BDDVSnMETzB_ahX089uroXf-UOHdUNzfWMNy47VK0_v-D5j_ah4o3WN6EOAwMU5zGERbar0dXLTGKOAG",
            "00003f13ac360430d54a73044f307f6a15f4f3dbaba177fe50e1dd50dcdf58c372e3b54ad3fbfe0f98ff6a1e28dd637a10e030314e7318445b6abd1d5cb4c628e006"];

        //Dual-indexed big Ed25519 signature: distinct other-index.
        yield return ["2A", "0a5f1a7b23654ba314cdd5d45c1b37d924d822335fe818c2ed0a29ad9c5f57ac9a7c3e3a7b51858550fc08db33a4bd7241664c7f5e3c2e0a54106446abbe9a0a", 0, (int?)1,
            "2AAAABAKXxp7I2VLoxTN1dRcGzfZJNgiM1_oGMLtCimtnF9XrJp8Pjp7UYWFUPwI2zOkvXJBZkx_XjwuClQQZEarvpoK",
            "d8000000100a5f1a7b23654ba314cdd5d45c1b37d924d822335fe818c2ed0a29ad9c5f57ac9a7c3e3a7b51858550fc08db33a4bd7241664c7f5e3c2e0a54106446abbe9a0a"];

        //Variable indexed code with an empty value and no other-index.
        yield return ["0z", "", 0, (int?)null, "0zAA", "d33000"];
    }


    [TestMethod]
    [DynamicData(nameof(KnownAnswerVectors))]
    public void RoundTripsKnownAnswerVector(string code, string rawHex, int index, int? ondex, string expectedQb64, string expectedQb2Hex)
    {
        byte[] raw = rawHex.Length == 0 ? [] : Convert.FromHexString(rawHex);
        byte[] expectedQb2 = Convert.FromHexString(expectedQb2Hex);

        string actualQb64 = CesrIndexedSignatureCodec.EncodeText(code, raw, index, ondex);
        Assert.AreEqual(expectedQb64, actualQb64, $"Encoding indexed code '{code}' to the text domain must match the known answer.");

        using(CesrParsedIndexedSignature parsed = CesrIndexedSignatureCodec.DecodeText(expectedQb64, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(code, parsed.Code, "Decoding qb64 must recover the code.");
            Assert.AreEqual(index, parsed.Index, "Decoding qb64 must recover the index.");
            Assert.AreEqual(ondex, parsed.Ondex, "Decoding qb64 must recover the other-index.");
            Assert.AreEqual(rawHex, Convert.ToHexStringLower(parsed.Raw), "Decoding qb64 must recover the raw signature.");
        }

        using(IMemoryOwner<byte> binary = CesrIndexedSignatureCodec.EncodeBinary(code, raw, index, BaseMemoryPool.Shared, ondex))
        {
            Assert.AreEqual(expectedQb2Hex, Convert.ToHexStringLower(binary.Memory.Span[..expectedQb2.Length]), $"Encoding indexed code '{code}' to the binary domain must match the known answer.");
        }

        using(CesrParsedIndexedSignature parsed = CesrIndexedSignatureCodec.DecodeBinary(expectedQb2, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(code, parsed.Code, "Decoding qb2 must recover the code.");
            Assert.AreEqual(index, parsed.Index, "Decoding qb2 must recover the index.");
            Assert.AreEqual(ondex, parsed.Ondex, "Decoding qb2 must recover the other-index.");
            Assert.AreEqual(rawHex, Convert.ToHexStringLower(parsed.Raw), "Decoding qb2 must recover the raw signature.");
        }
    }
}
