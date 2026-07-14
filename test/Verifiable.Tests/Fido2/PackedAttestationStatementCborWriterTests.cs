using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="PackedAttestationStatementCborWriter"/>: the production counterpart to
/// <see cref="PackedAttestationStatementCborReader"/>, spanning a hand-computed byte-exact self-attestation
/// vector and a round trip through the shipped reader confirming the omitted-<c>x5c</c> shape.
/// </summary>
[TestClass]
internal sealed class PackedAttestationStatementCborWriterTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An ES256 (<c>alg=-7</c>) self-attestation statement with a fixed 4-byte signature matches a fully
    /// hand-computed CTAP2 canonical CBOR byte sequence: map header (2 entries), then <c>alg</c>/<c>sig</c>
    /// in ascending canonical key order (equal-length text-string keys sort lexicographically: <c>"alg"</c>
    /// &lt; <c>"sig"</c>), with no <c>x5c</c> member at all.
    /// </summary>
    [TestMethod]
    public void WritesASelfAttestationStatementToHandComputedBytes()
    {
        byte[] signature = [0x01, 0x02, 0x03, 0x04];

        //Map header (0xA2, 2 entries), "alg" (0x63 616C67) -> -7 (0x26), "sig" (0x63 736967) -> byte
        //string of length 4 (0x44) followed by the signature bytes.
        byte[] expected = Convert.FromHexString("A263616C6726637369674401020304");

        TaggedMemory<byte> written = PackedAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Es256, signature);

        Assert.IsTrue(written.Span.SequenceEqual(expected));
        Assert.IsTrue(written.Tag.TryGet(out BufferKind kind));
        Assert.AreEqual(Fido2BufferTags.PackedAttestationStatementKind, kind);
    }


    /// <summary>
    /// An RS256 self-attestation statement round-trips through the shipped
    /// <see cref="PackedAttestationStatementCborReader"/> with <c>x5c</c> decoding to <see langword="null"/>
    /// — the self-attestation shape, never an empty array — and <c>alg</c>/<c>sig</c> preserved exactly.
    /// </summary>
    [TestMethod]
    public void RoundTripsThroughTheShippedReaderWithX5cOmittedEntirely()
    {
        byte[] signature = new byte[64];
        for(int i = 0; i < signature.Length; i++)
        {
            signature[i] = (byte)(i + 1);
        }

        TaggedMemory<byte> written = PackedAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Rs256, signature);

        PackedAttestationStatement statement = PackedAttestationStatementCborReader.Parse(written.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual(WellKnownCoseAlgorithms.Rs256, statement.Alg);
        Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
        Assert.IsNull(statement.X5c, "Self-attestation must decode with x5c null, never an empty array.");
    }


    /// <summary>An empty signature is rejected with <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public void EmptySignatureThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentException>(() => PackedAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Es256, ReadOnlySpan<byte>.Empty));
    }
}
