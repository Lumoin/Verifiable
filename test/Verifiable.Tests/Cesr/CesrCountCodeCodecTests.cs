using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Lumoin.Base;
using Verifiable.Cesr;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrCountCodeCodec"/>: round-tripping a CESR count (group/framing) code between the
/// text (qb64) and binary (qb2) domains, and using a count code to frame a group of primitives. The
/// known-answer vectors cover each count code table (small, large, and the protocol genus/version code),
/// anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#count-code-tables">
/// Count Code tables</see>. The published conformance corpus has no standalone count code vectors, so the
/// end-to-end coverage instead frames the corpus primitive vectors and verifies the count describes their
/// span exactly (see <see cref="CesrConformanceVectors"/>).
/// </summary>
[TestClass]
internal sealed class CesrCountCodeCodecTests
{
    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Known-answer vectors: code, count, expected qb64, expected qb2 (hex).
    /// </summary>
    /// <returns>The known-answer vectors.</returns>
    private static IEnumerable<object[]> KnownAnswerVectors()
    {
        //Small count code, count 1: selector '-', type 'A', two-character count "AB".
        yield return ["-A", 1, "-AAB", "f80001"];

        //Small count code at its maximum count (64^2 - 1 = 4095): count "__".
        yield return ["-A", 4095, "-A__", "f80fff"];

        //Large count code, count 1: selectors '--', type 'A', five-character count "AAAAB".
        yield return ["--A", 1, "--AAAAAB", "fbe000000001"];

        //Protocol genus/version code for the KERI/ACDC genus at version 2.00: hard "-_AAA", soft "CAA".
        yield return ["-_AAA", 8192, "-_AAACAA", "fbf000002000"];
    }


    [TestMethod]
    [DynamicData(nameof(KnownAnswerVectors))]
    public void RoundTripsKnownAnswerVector(string code, int count, string expectedQb64, string expectedQb2Hex)
    {
        byte[] expectedQb2 = Convert.FromHexString(expectedQb2Hex);

        //Text domain: encode (code, count) -> qb64 and decode qb64 -> (code, count).
        Assert.AreEqual(expectedQb64, CesrCountCodeCodec.EncodeText(code, count), $"Encoding count code '{code}' to the text domain must match the known answer.");

        CesrParsedCountCode fromText = CesrCountCodeCodec.DecodeText(expectedQb64);
        Assert.AreEqual(code, fromText.Code, "Decoding qb64 must recover the code.");
        Assert.AreEqual(count, fromText.Count, "Decoding qb64 must recover the count.");

        //Binary domain: encode (code, count) -> qb2 and decode qb2 -> (code, count).
        using(IMemoryOwner<byte> binary = CesrCountCodeCodec.EncodeBinary(code, count, BaseMemoryPool.Shared))
        {
            Assert.AreEqual(expectedQb2Hex, Convert.ToHexStringLower(binary.Memory.Span[..expectedQb2.Length]), $"Encoding count code '{code}' to the binary domain must match the known answer.");
        }

        CesrParsedCountCode fromBinary = CesrCountCodeCodec.DecodeBinary(expectedQb2);
        Assert.AreEqual(code, fromBinary.Code, "Decoding qb2 must recover the code.");
        Assert.AreEqual(count, fromBinary.Count, "Decoding qb2 must recover the count.");
    }


    [TestMethod]
    public void DecodesGenusVersionSemantics()
    {
        CesrParsedCountCode parsed = CesrCountCodeCodec.DecodeText("-_AAACAA");

        Assert.IsTrue(parsed.IsGenusVersion, "A '-_' code must be recognized as a genus/version code.");
        Assert.AreEqual("AAA", parsed.Genus, "The genus is the three hard characters after the '-_' prefix.");
        Assert.AreEqual((2, 0), parsed.Version, "Version 'CAA' decodes to major 2, minor 0.");
    }


    [TestMethod]
    public void OrdinaryCountCodeIsNotGenusVersion()
    {
        CesrParsedCountCode parsed = CesrCountCodeCodec.DecodeText("-AAB");

        Assert.IsFalse(parsed.IsGenusVersion, "A small count code is not a genus/version code.");
        Assert.IsNull(parsed.Genus, "An ordinary count code has no genus.");
        Assert.IsNull(parsed.Version, "An ordinary count code has no version.");
        Assert.AreEqual(4, parsed.TextCharCount, "A count of 1 frames one quadlet of four text characters.");
        Assert.AreEqual(3, parsed.BinaryByteCount, "A count of 1 frames one triplet of three binary bytes.");
    }


    [TestMethod]
    public void RejectsCountAboveTableMaximum()
    {
        //The small count code soft size is two characters, so its maximum count is 64^2 - 1 = 4095.
        Assert.ThrowsExactly<CesrFormatException>(() => CesrCountCodeCodec.EncodeText("-A", 4096));
    }


    [TestMethod]
    public void RejectsReservedAndOpCodeSelectors()
    {
        //A numeral second character selects an as-yet-unspecified count code table.
        Assert.ThrowsExactly<CesrFormatException>(() => CesrCountCodeCodec.DecodeText("-0AB"));

        //The '_' first character is the op code selector, not a count code.
        Assert.ThrowsExactly<CesrFormatException>(() => CesrCountCodeCodec.DecodeText("_AAB"));
    }


    [TestMethod]
    public void RejectsTruncatedCountCode()
    {
        //A large count code is eight characters; a shorter span must be rejected rather than misread.
        Assert.ThrowsExactly<CesrFormatException>(() => CesrCountCodeCodec.DecodeText("--AAA"));
    }


    [TestMethod]
    public void FramesPrimitiveGroupInBothDomains()
    {
        //Two real primitive known-answer vectors (an Ed25519 verification key and a 128-bit salt), each
        //already 24-bit aligned, concatenated into an attachment group framed by a '-V' count code.
        string first = "DA_52v7lAkIJVUuruh40GvMsY3_K7J4-ZdVo7NoD2xzm";
        string second = "0AA_Az7vckaE383AHOsW1J1N";
        string body = first + second;
        int quadlets = body.Length / 4;

        string stream = CesrCountCodeCodec.EncodeText("-V", quadlets) + body;
        CesrParsedCountCode counter = CesrCountCodeCodec.DecodeText(stream);

        Assert.AreEqual("-V", counter.Code, "The framed stream must begin with the attachment count code.");
        Assert.AreEqual(quadlets, counter.Count, "The count must be the number of quadlets in the framed group.");
        Assert.AreEqual(body.Length, counter.TextCharCount, "The count must describe the exact text span of the group.");
        Assert.AreEqual(body, stream.Substring(4, (int)counter.TextCharCount), "Slicing the stream by the count must recover the group body.");

        //The same count is invariant across domains: it is the triplet count in the binary domain.
        using(IMemoryOwner<byte> firstBinary = CesrPrimitiveCodec.EncodeBinary("D", Convert.FromHexString("0ff9dafee5024209554babba1e341af32c637fcaec9e3e65d568ecda03db1ce6"), BaseMemoryPool.Shared))
        using(IMemoryOwner<byte> secondBinary = CesrPrimitiveCodec.EncodeBinary("0A", Convert.FromHexString("3f033eef724684dfcdc01ceb16d49d4d"), BaseMemoryPool.Shared))
        {
            int bodyBytes = (first.Length / 4 * 3) + (second.Length / 4 * 3);
            Assert.AreEqual(bodyBytes, counter.BinaryByteCount, "The count must describe the exact binary span of the same group.");

            //Sanity: the binary primitive lengths equal the per-primitive triplet spans implied by their qb64.
            Assert.AreEqual(first.Length / 4 * 3, firstBinary.Memory.Span[..(first.Length / 4 * 3)].Length);
            Assert.AreEqual(second.Length / 4 * 3, secondBinary.Memory.Span[..(second.Length / 4 * 3)].Length);
        }
    }


    [TestMethod]
    public void FramesEveryPrimitiveConformanceVectorGroup()
    {
        if(!CesrConformanceVectors.TryGetCorpusRoot(out string root))
        {
            Assert.Inconclusive($"The CESR conformance vector corpus is not available; set {CesrConformanceVectors.CorpusVariable} to run this test.");
        }

        int verified = 0;
        var failures = new StringBuilder();
        foreach(CesrConformanceVector vector in CesrConformanceVectors.EnumeratePrimitives(root))
        {
            if(vector.Malformed || vector.Text.Length == 0)
            {
                continue;
            }

            try
            {
                //Frame the single primitive as an attachment group and verify the count code describes its
                //span exactly in both domains, then recover the body by slicing. A group larger than the
                //small count code's maximum (4095 quadlets) must use the large attachment count code.
                int quadlets = vector.Text.Length / 4;
                bool big = quadlets > 4095;
                string code = big ? "--V" : "-V";
                int codeChars = big ? 8 : 4;
                string stream = CesrCountCodeCodec.EncodeText(code, quadlets) + vector.Text;
                CesrParsedCountCode counter = CesrCountCodeCodec.DecodeText(stream);

                Assert.AreEqual(code, counter.Code, "code");
                Assert.AreEqual(quadlets, counter.Count, "count");
                Assert.AreEqual(vector.Text.Length, counter.TextCharCount, "text span");
                Assert.AreEqual(vector.Binary.Length, counter.BinaryByteCount, "binary span");
                Assert.AreEqual(vector.Text, stream.Substring(codeChars, (int)counter.TextCharCount), "body");
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

        TestContext.WriteLine($"Framed and verified the span of {verified} CESR primitive conformance vectors.");
        Assert.IsGreaterThan(0, verified, "The corpus was located but contained no primitive vectors to frame.");
        Assert.AreEqual(0, failures.Length, $"Every framed primitive's count code must describe its span exactly.\n{failures}");
    }
}
