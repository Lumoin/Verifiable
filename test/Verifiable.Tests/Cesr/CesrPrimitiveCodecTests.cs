using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Lumoin.Base;
using Verifiable.Cesr;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrPrimitiveCodec"/>: round-tripping a single CESR primitive between the raw, text
/// (qb64) and binary (qb2) domains. The always-on cases are known-answer vectors covering each code shape
/// (one- and two-character fixed codes, a small fixed code, a special soft code, and a variable-length code),
/// anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#concrete-domain-representations">
/// Concrete Domain representations</see> and master code table. The corpus-driven case exercises the full
/// published conformance vector set when it is available (see <see cref="CesrConformanceVectors"/>).
/// </summary>
[TestClass]
internal sealed class CesrPrimitiveCodecTests
{
    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Known-answer vectors: code, raw (hex), expected soft, expected qb64, expected qb2 (hex).
    /// </summary>
    /// <returns>The known-answer vectors.</returns>
    private static IEnumerable<object[]> KnownAnswerVectors()
    {
        //One-character fixed code (Ed25519 public verification key, 32-byte raw, pad size 1).
        yield return ["D", "0ff9dafee5024209554babba1e341af32c637fcaec9e3e65d568ecda03db1ce6", "",
            "DA_52v7lAkIJVUuruh40GvMsY3_K7J4-ZdVo7NoD2xzm",
            "0c0ff9dafee5024209554babba1e341af32c637fcaec9e3e65d568ecda03db1ce6"];

        //Two-character fixed code (128-bit salt/nonce, 16-byte raw, pad size 2).
        yield return ["0A", "3f033eef724684dfcdc01ceb16d49d4d", "",
            "0AA_Az7vckaE383AHOsW1J1N",
            "d0003f033eef724684dfcdc01ceb16d49d4d"];

        //Two-character fixed code (Ed25519 signature, 64-byte raw, pad size 2).
        yield return ["0B", "3f0760325617f4e4d38e49c6290f5f3000acd2a6a0abe0a20873a447ed78c5ecc9dc85b466eef5bbc0909f6bf542082b70e13f0f70aa4fccf6ea83f1d2c8930d", "",
            "0BA_B2AyVhf05NOOScYpD18wAKzSpqCr4KIIc6RH7XjF7MnchbRm7vW7wJCfa_VCCCtw4T8PcKpPzPbqg_HSyJMN",
            "d0103f0760325617f4e4d38e49c6290f5f3000acd2a6a0abe0a20873a447ed78c5ecc9dc85b466eef5bbc0909f6bf542082b70e13f0f70aa4fccf6ea83f1d2c8930d"];

        //One-character fixed small number code (2-byte raw).
        yield return ["M", "0000", "", "MAAA", "300000"];

        //Small variable-length code (Base64 string) with an empty value.
        yield return ["4A", "", "AA", "4AAA", "e00000"];

        //Special fixed code carrying a three-character Base64 value in the code itself (empty raw).
        yield return ["X", "", "abc", "Xabc", "5da6dc"];
    }


    [TestMethod]
    [DynamicData(nameof(KnownAnswerVectors))]
    public void RoundTripsKnownAnswerVector(string code, string rawHex, string soft, string expectedQb64, string expectedQb2Hex)
    {
        byte[] raw = rawHex.Length == 0 ? [] : Convert.FromHexString(rawHex);
        byte[] expectedQb2 = Convert.FromHexString(expectedQb2Hex);

        //Text domain: encode raw -> qb64 and decode qb64 -> raw.
        string actualQb64 = CesrPrimitiveCodec.EncodeText(code, raw, soft);
        Assert.AreEqual(expectedQb64, actualQb64, $"Encoding code '{code}' to the text domain must match the known answer.");

        using(CesrParsedPrimitive parsed = CesrPrimitiveCodec.DecodeText(expectedQb64, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(code, parsed.Code, "Decoding qb64 must recover the code.");
            Assert.AreEqual(soft, parsed.Soft, "Decoding qb64 must recover the soft value.");
            Assert.AreEqual(rawHex, Convert.ToHexStringLower(parsed.Raw), "Decoding qb64 must recover the raw value.");
        }

        //Binary domain: encode raw -> qb2 and decode qb2 -> raw.
        using(IMemoryOwner<byte> binary = CesrPrimitiveCodec.EncodeBinary(code, raw, BaseMemoryPool.Shared, soft))
        {
            Assert.AreEqual(expectedQb2Hex, Convert.ToHexStringLower(binary.Memory.Span[..expectedQb2.Length]), $"Encoding code '{code}' to the binary domain must match the known answer.");
        }

        using(CesrParsedPrimitive parsed = CesrPrimitiveCodec.DecodeBinary(expectedQb2, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(code, parsed.Code, "Decoding qb2 must recover the code.");
            Assert.AreEqual(soft, parsed.Soft, "Decoding qb2 must recover the soft value.");
            Assert.AreEqual(rawHex, Convert.ToHexStringLower(parsed.Raw), "Decoding qb2 must recover the raw value.");
        }
    }


    [TestMethod]
    public void RoundTripsEveryPrimitiveConformanceVector()
    {
        if(!CesrConformanceVectors.TryGetCorpusRoot(out string root))
        {
            Assert.Inconclusive($"The CESR conformance vector corpus is not available; set {CesrConformanceVectors.CorpusVariable} to run this test.");
        }

        int verified = 0;
        int skipped = 0;
        var failures = new StringBuilder();
        foreach(CesrConformanceVector vector in CesrConformanceVectors.EnumeratePrimitives(root))
        {
            if(vector.Malformed)
            {
                skipped++;
                continue;
            }

            try
            {
                VerifyPrimitive(vector);
                verified++;
            }
            catch(Exception exception)
            {
                if(failures.Length < 8192)
                {
                    failures.Append(vector.Name).Append(" (").Append(vector.Code).Append("): ").AppendLine(exception.Message);
                }
            }
        }

        TestContext.WriteLine($"Verified {verified} CESR primitive conformance vectors ({skipped} malformed corpus files skipped).");
        Assert.IsGreaterThan(0, verified, "The corpus was located but contained no primitive vectors to verify.");
        Assert.AreEqual(0, failures.Length, $"All CESR primitive conformance vectors must round-trip.\n{failures}");
    }


    private static void VerifyPrimitive(CesrConformanceVector vector)
    {
        //Decode the wire text first so the recovered soft value can drive re-encoding (special codes carry
        //their value in the soft part of the code, which the vector files do not list separately).
        string soft;
        using(CesrParsedPrimitive fromText = CesrPrimitiveCodec.DecodeText(vector.Text, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(vector.Code, fromText.Code, "qb64 decode code mismatch");
            Assert.AreEqual(Convert.ToHexStringLower(vector.Raw), Convert.ToHexStringLower(fromText.Raw), "qb64 decode raw mismatch");
            soft = fromText.Soft;
        }

        Assert.AreEqual(vector.Text, CesrPrimitiveCodec.EncodeText(vector.Code, vector.Raw, soft), "qb64 mismatch");

        using(IMemoryOwner<byte> binary = CesrPrimitiveCodec.EncodeBinary(vector.Code, vector.Raw, BaseMemoryPool.Shared, soft))
        {
            Assert.AreEqual(
                Convert.ToHexStringLower(vector.Binary),
                Convert.ToHexStringLower(binary.Memory.Span[..vector.Binary.Length]),
                "qb2 mismatch");
        }

        using(CesrParsedPrimitive fromBinary = CesrPrimitiveCodec.DecodeBinary(vector.Binary, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(vector.Code, fromBinary.Code, "qb2 decode code mismatch");
            Assert.AreEqual(Convert.ToHexStringLower(vector.Raw), Convert.ToHexStringLower(fromBinary.Raw), "qb2 decode raw mismatch");
            Assert.AreEqual(soft, fromBinary.Soft, "qb2 decode soft mismatch");
        }
    }
}
