using System.Collections.Generic;
using System.Text;
using Lumoin.Base;
using Verifiable.BouncyCastle;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrSaid"/> — the Self-Addressing IDentifier primitive (dummy-fill, digest, CESR
/// encode). The dummied serializations are the two worked examples from the SAID specification
/// (draft-ssmith-said): the fixed-field record and the <c>{"said":…,"first":"Sue",…}</c> JSON body. The
/// expected SAIDs are each computed by an independent digest oracle (the reference Blake3 implementation and
/// the .NET SHA implementations), exercising every supported derivation code over those serializations.
/// </summary>
/// <remarks>
/// The specification's printed SAID values for its two Blake3-256 examples (<c>E8wYu…</c> and <c>EnKa0…</c>)
/// are NOT used: both are inconsistent with the Blake3-256 digest of the very serializations the examples
/// show (a known erratum in the draft). The expected values here are the canonical digests of those exact
/// serializations from the independent oracle, so the vectors validate the whole pipeline rather than
/// reproduce the draft's printed text.
/// </remarks>
[TestClass]
internal sealed class CesrSaidTests
{
    //The fixed-field worked example from the specification: field1 (44 chars) replaced by the dummy run.
    private const string FixedFieldDummied = "field0______############################################field2______";

    //A field-map serialization with its SAID field set to the 44-character dummy (the specification's JSON example body).
    private const string JsonDummied = """{"said":"############################################","first":"Sue","last":"Smith","role":"Founder"}""";


    /// <summary>
    /// The test context.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An algorithm-agile digest: a BLAKE3-tagged request routes to the BouncyCastle backend, every other
    /// (SHA) request to the Microsoft backend. This is an independent oracle constructed in the test, not the
    /// production registry.
    /// </summary>
    private static readonly ComputeDigestDelegate AgileDigest = (input, outputByteLength, tag, pool, context, cancellationToken) =>
        tag.TryGet<CryptoAlgorithm>(out CryptoAlgorithm algorithm) && algorithm == CryptoAlgorithm.Blake3
            ? BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, context, cancellationToken)
            : MicrosoftEntropyFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, context, cancellationToken);


    /// <summary>
    /// Known-answer vectors: derivation code, dummied serialization, expected SAID.
    /// </summary>
    /// <returns>The known-answer vectors.</returns>
    private static IEnumerable<object[]> KnownAnswerVectors()
    {
        //Blake3-256 of the fixed-field example body, from the independent reference oracle.
        yield return [CesrDigestCodes.Blake3Bits256, FixedFieldDummied, "EPMGLgY4bJRE2Gi2XMTJFq4VWzHAPEUtaSmJe5ye-57Q"];

        //SHA2-256 of the JSON field-map body, from the independent oracle.
        yield return [CesrDigestCodes.Sha2Bits256, JsonDummied, "IO8IW8DhVYgn-ItF0TY2VHBPXRz0pgUnHoOMzRbgJRWW"];

        //SHA2-512 (88-character SAID) of a field map whose id field is the 88-character dummy, from the independent oracle.
        yield return [CesrDigestCodes.Sha2Bits512, """{"id":"########################################################################################","v":"x"}""", "0GBqUGvOlHBc5jFosNsdCRRWOGxgjlpQAx9wCgeBqZ-NEBkhf_XonjcZFO-OlRuda4Xk9_8kwqGsLD9Xqd_xtiyI"];
    }


    [TestMethod]
    [DynamicData(nameof(KnownAnswerVectors))]
    public async Task ComputesAndVerifiesKnownAnswerVector(string code, string dummied, string expectedSaid)
    {
        byte[] serialization = Encoding.UTF8.GetBytes(dummied);

        Assert.AreEqual(expectedSaid, await CesrSaid.ComputeAsync(serialization, code, AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken), $"The {code} SAID must match the known answer.");
        Assert.AreEqual(code, CesrSaid.DigestCodeOf(expectedSaid), "The derivation code must be recoverable from the SAID.");
        Assert.IsTrue(await CesrSaid.VerifyAsync(serialization, expectedSaid, AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken), "The SAID must verify against its dummied serialization.");
    }


    [TestMethod]
    public async Task RejectsTamperedSerialization()
    {
        const string said = "IO8IW8DhVYgn-ItF0TY2VHBPXRz0pgUnHoOMzRbgJRWW";

        //Flip one character of the dummied serialization ("Sue" -> "Sve"); the SAID must no longer verify.
        string tampered = JsonDummied.Replace("Sue", "Sve", StringComparison.Ordinal);

        Assert.IsFalse(
            await CesrSaid.VerifyAsync(Encoding.UTF8.GetBytes(tampered), said, AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken),
            "A SAID must not verify against a mutated serialization.");
    }


    [TestMethod]
    public async Task RejectsWrongClaimedSaid()
    {
        const string said = "IO8IW8DhVYgn-ItF0TY2VHBPXRz0pgUnHoOMzRbgJRWW";

        //The serialization is correct but the claimed SAID differs (last character changed).
        string wrongSaid = said[..^1] + (said[^1] == 'A' ? 'B' : 'A');

        Assert.IsFalse(
            await CesrSaid.VerifyAsync(Encoding.UTF8.GetBytes(JsonDummied), wrongSaid, AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken),
            "A claimed SAID that differs from the recomputed value must not verify.");
    }


    [TestMethod]
    public void PlaceholderLengthsMatchTheDerivationCode()
    {
        //The specification fixes the SAID length per digest: a 256-bit digest is 44 Base64URL characters and
        //a 512-bit digest is 88.
        const int Bits256SaidLength = 44;
        const int Bits512SaidLength = 88;

        Assert.AreEqual(Bits256SaidLength, CesrSaid.PlaceholderLength(CesrDigestCodes.Blake3Bits256), "Blake3-256 SAIDs are 44 characters.");
        Assert.AreEqual(Bits256SaidLength, CesrSaid.PlaceholderLength(CesrDigestCodes.Sha2Bits256), "SHA2-256 SAIDs are 44 characters.");
        Assert.AreEqual(Bits512SaidLength, CesrSaid.PlaceholderLength(CesrDigestCodes.Sha2Bits512), "SHA2-512 SAIDs are 88 characters.");

        Assert.AreEqual(new string('#', Bits256SaidLength), CesrSaid.Placeholder(CesrDigestCodes.Blake3Bits256), "The placeholder is a run of the '#' dummy character of the SAID's length.");
    }


    [TestMethod]
    public void RecognizesEveryMasterTableDigestCode()
    {
        //All nine CESR digest codes are admissible SAID codes; a verification-key code is not.
        foreach(string code in new[]
        {
            CesrDigestCodes.Blake3Bits256, CesrDigestCodes.Blake2bBits256, CesrDigestCodes.Blake2sBits256,
            CesrDigestCodes.Sha3Bits256, CesrDigestCodes.Sha2Bits256, CesrDigestCodes.Blake3Bits512,
            CesrDigestCodes.Blake2bBits512, CesrDigestCodes.Sha3Bits512, CesrDigestCodes.Sha2Bits512
        })
        {
            Assert.IsTrue(CesrDigestCodes.IsDigestCode(code), $"'{code}' is a CESR digest code.");
        }

        Assert.IsFalse(CesrDigestCodes.IsDigestCode("D"), "The Ed25519 verification-key code is not a digest code.");
    }


    [TestMethod]
    public async Task RejectsNonDigestDerivationCode()
    {
        //'D' is the Ed25519 verification-key code, not a digest code, so it cannot derive a SAID.
        await Assert.ThrowsExactlyAsync<CesrFormatException>(async () => await CesrSaid.ComputeAsync("data"u8.ToArray(), "D", AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken));
        Assert.ThrowsExactly<CesrFormatException>(() => CesrSaid.PlaceholderLength("D"));
        Assert.ThrowsExactly<CesrFormatException>(() => CesrSaid.DigestCodeOf("DA_52v7lAkIJVUuruh40GvMsY3_K7J4-ZdVo7NoD2xzm"));
    }


    [TestMethod]
    public void IsWellFormedSaidAcceptsEveryDigestCodeShape()
    {
        //The shape check spans the FULL master-table digest-code set, not only the seam-computable subset the
        //compute and verify methods narrow to: a well-formed 256-bit SAID is its one-character code plus 43
        //Base64URL characters (44 total), a 512-bit SAID its two-character code plus 86 (88 total).
        foreach(string code in new[]
        {
            CesrDigestCodes.Blake3Bits256, CesrDigestCodes.Blake2bBits256, CesrDigestCodes.Blake2sBits256,
            CesrDigestCodes.Sha3Bits256, CesrDigestCodes.Sha2Bits256, CesrDigestCodes.Blake3Bits512,
            CesrDigestCodes.Blake2bBits512, CesrDigestCodes.Sha3Bits512, CesrDigestCodes.Sha2Bits512
        })
        {
            int fullSize = code.Length == 1 ? 44 : 88;
            string said = code + new string('A', fullSize - code.Length);

            Assert.IsTrue(CesrSaid.IsWellFormedSaid(said), $"A shape-valid '{code}' SAID must be recognized.");
        }
    }


    [TestMethod]
    [DataRow("", DisplayName = "Empty string.")]
    [DataRow("E", DisplayName = "Digest code with no body.")]
    [DataRow("EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jin", DisplayName = "Blake3-256 code but 42 characters, too short.")]
    [DataRow("EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jinGRxx", DisplayName = "Blake3-256 code but too long.")]
    [DataRow("EKTh4PkRBiNWHQd263Eueu39gWmg7AfIfnEmNy6jin+R", DisplayName = "Correct length but a non-Base64URL character.")]
    [DataRow("DA_52v7lAkIJVUuruh40GvMsY3_K7J4-ZdVo7NoD2xzm", DisplayName = "A 44-character CESR primitive whose code is a verification key, not a digest.")]
    public void IsWellFormedSaidRejectsMalformedShapes(string candidate)
    {
        Assert.IsFalse(CesrSaid.IsWellFormedSaid(candidate), "A string that is not a shape-valid SAID must be rejected.");
    }


    /// <summary>
    /// A claimed SAID whose length is not its code's fixed full size is rejected as malformed rather than used to
    /// size the embedded reset's scratch buffer. A value with a valid leading digest code followed by an arbitrarily
    /// long run of Base64URL characters — delivered as an ACDC, KERI event, or aggregate block's <c>d</c> — is the
    /// hostile case: the reset once sized a stack buffer to the claimed SAID's own length, so such a value grew the
    /// stack without bound (an uncatchable crash). It is now a rejected input, and the reset buffer is stack-bound
    /// for well-formed SAIDs and heaps above the bound regardless.
    /// </summary>
    /// <param name="claimedLength">The length of the claimed SAID (its code is Blake3-256, whose full size is 44).</param>
    [TestMethod]
    [DataRow(1_000_000, DisplayName = "A megabyte-long claimed SAID (the unbounded-stack-allocation vector).")]
    [DataRow(45, DisplayName = "One character too long for the 44-character 256-bit SAID.")]
    [DataRow(43, DisplayName = "One character too short for the 44-character 256-bit SAID.")]
    public async Task RejectsOffSizeClaimedSaidRatherThanSizingAStackBufferToIt(int claimedLength)
    {
        //A Blake3-256 ('E') code padded to the requested length; every character is Base64URL, so only the length
        //is wrong. The serialization is irrelevant — the claimed SAID is validated before it is read against it.
        string offSize = "E" + new string('A', claimedLength - 1);
        byte[] serialization = Encoding.UTF8.GetBytes(JsonDummied);

        await Assert.ThrowsExactlyAsync<CesrFormatException>(
            async () => await CesrSaid.VerifyEmbeddedAsync(serialization, offSize, AgileDigest, BaseMemoryPool.Shared, TestContext.CancellationToken),
            "A claimed SAID whose length is not its code's full size must be rejected as malformed.");
    }
}
