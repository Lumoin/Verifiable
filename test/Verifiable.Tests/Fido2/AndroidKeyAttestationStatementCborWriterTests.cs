using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="AndroidKeyAttestationStatementCborWriter"/>: the production counterpart to
/// <see cref="AndroidKeyAttestationStatementCborReader"/>, spanning a hand-computed byte-exact vector and
/// a round trip through the shipped reader confirming field equality.
/// </summary>
[TestClass]
internal sealed class AndroidKeyAttestationStatementCborWriterTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// An ES256 (<c>alg=-7</c>) statement with a fixed 4-byte signature and single-element <c>x5c</c>
    /// matches a fully hand-computed CTAP2 canonical CBOR byte sequence: map header (3 entries), then
    /// <c>alg</c>/<c>sig</c>/<c>x5c</c> in ascending canonical key order (equal-length text-string keys
    /// sort bytewise: <c>'a'</c> &lt; <c>'s'</c> &lt; <c>'x'</c>).
    /// </summary>
    [TestMethod]
    public void WritesAStatementToHandComputedBytes()
    {
        byte[] signature = [0x01, 0x02, 0x03, 0x04];
        byte[] certificateDerBytes = [0x0A, 0x0B, 0x0C, 0x0D, 0x0E];
        using PkiCertificateMemory certificate = Fido2AttestationTestVectors.ToPkiCertificateMemory(certificateDerBytes);

        //Map header (0xA3, 3 entries), "alg" (0x63 616C67) -> -7 (0x26), "sig" (0x63 736967) -> byte
        //string of length 4 (0x44) followed by the signature, "x5c" (0x63 783563) -> array of 1 element
        //(0x81) -> byte string of length 5 (0x45) followed by the certificate bytes.
        byte[] expected = Convert.FromHexString("A363616C67266373696744010203046378356381450A0B0C0D0E");

        TaggedMemory<byte> written = AndroidKeyAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Es256, signature, [certificate]);

        Assert.IsTrue(written.Span.SequenceEqual(expected));
        Assert.IsTrue(written.Tag.TryGet(out BufferKind kind));
        Assert.AreEqual(Fido2BufferTags.AndroidKeyAttestationStatementKind, kind);
    }


    /// <summary>
    /// An RS256 statement with a credCert-first two-element <c>x5c</c> round-trips through the shipped
    /// <see cref="AndroidKeyAttestationStatementCborReader"/> with <c>alg</c>, <c>signature</c>, and each
    /// <c>x5c</c> entry's bytes preserved exactly, in order.
    /// </summary>
    [TestMethod]
    public void RoundTripsThroughTheShippedReaderWithFieldEquality()
    {
        byte[] signature = new byte[64];
        for(int i = 0; i < signature.Length; i++)
        {
            signature[i] = (byte)(i + 1);
        }

        byte[] credCertDerBytes = [0x10, 0x20, 0x30];
        byte[] caCertDerBytes = [0x40, 0x50, 0x60, 0x70];
        using PkiCertificateMemory credCert = Fido2AttestationTestVectors.ToPkiCertificateMemory(credCertDerBytes);
        using PkiCertificateMemory caCert = Fido2AttestationTestVectors.ToPkiCertificateMemory(caCertDerBytes);

        TaggedMemory<byte> written = AndroidKeyAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Rs256, signature, [credCert, caCert]);

        AndroidKeyAttestationStatement statement = AndroidKeyAttestationStatementCborReader.Parse(written.Memory, BaseMemoryPool.Shared);
        try
        {
            Assert.AreEqual(WellKnownCoseAlgorithms.Rs256, statement.Alg);
            Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
            Assert.HasCount(2, statement.X5c);
            Assert.IsTrue(statement.X5c[0].AsReadOnlySpan().SequenceEqual(credCertDerBytes));
            Assert.IsTrue(statement.X5c[1].AsReadOnlySpan().SequenceEqual(caCertDerBytes));
        }
        finally
        {
            foreach(PkiCertificateMemory decodedCertificate in statement.X5c)
            {
                decodedCertificate.Dispose();
            }
        }
    }


    /// <summary>An empty signature is rejected with <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public void EmptySignatureThrowsArgumentException()
    {
        using PkiCertificateMemory certificate = Fido2AttestationTestVectors.ToPkiCertificateMemory([0x01]);

        Assert.ThrowsExactly<ArgumentException>(
            () => AndroidKeyAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Es256, ReadOnlySpan<byte>.Empty, [certificate]));
    }


    /// <summary>
    /// A <see langword="null"/> <c>x5c</c> is rejected with <see cref="ArgumentNullException"/> — unlike
    /// <c>packed</c>'s optional <c>x5c</c>, android-key has no self-attestation branch, so <c>x5c</c> is
    /// always required.
    /// </summary>
    [TestMethod]
    public void NullX5cThrowsArgumentNullException()
    {
        byte[] signature = [0x01, 0x02, 0x03];

        Assert.ThrowsExactly<ArgumentNullException>(
            () => AndroidKeyAttestationStatementCborWriter.Write(WellKnownCoseAlgorithms.Es256, signature, null!));
    }
}
