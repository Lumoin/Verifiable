using System.Buffers;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="FidoU2fAttestationStatementCborWriter"/>: the production counterpart to
/// <see cref="FidoU2fAttestationStatementCborReader"/>, spanning a hand-computed byte-exact vector and a
/// round trip through the shipped reader confirming field equality.
/// </summary>
[TestClass]
internal sealed class FidoU2fAttestationStatementCborWriterTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A signature and single-element <c>x5c</c> statement matches a fully hand-computed CTAP2 canonical
    /// CBOR byte sequence: map header (2 entries), then <c>sig</c>/<c>x5c</c> in ascending canonical key
    /// order (equal-length text-string keys sort bytewise: <c>"sig"</c> &lt; <c>"x5c"</c>).
    /// </summary>
    [TestMethod]
    public void WritesAStatementToHandComputedBytes()
    {
        using IMemoryOwner<byte> signatureOwner = BaseMemoryPool.Shared.Rent(4);
        Span<byte> signature = signatureOwner.Memory.Span[..4];
        signature[0] = 0x01;
        signature[1] = 0x02;
        signature[2] = 0x03;
        signature[3] = 0x04;

        byte[] certificateDerBytes = [0x0A, 0x0B, 0x0C];
        using PkiCertificateMemory certificate = Fido2AttestationTestVectors.ToPkiCertificateMemory(certificateDerBytes);

        //Map header (0xA2, 2 entries), "sig" (0x63 736967) -> byte string of length 4 (0x44) followed by
        //the signature, "x5c" (0x63 783563) -> array of 1 element (0x81) -> byte string of length 3
        //(0x43) followed by the certificate bytes.
        byte[] expected = Convert.FromHexString("A26373696744010203046378356381430A0B0C");

        TaggedMemory<byte> written = FidoU2fAttestationStatementCborWriter.Write(signature, [certificate]);

        Assert.IsTrue(written.Span.SequenceEqual(expected));
        Assert.IsTrue(written.Tag.TryGet(out BufferKind kind));
        Assert.AreEqual(Fido2BufferTags.FidoU2fAttestationStatementKind, kind);
    }


    /// <summary>
    /// A statement round-trips through the shipped <see cref="FidoU2fAttestationStatementCborReader"/>
    /// with <c>signature</c> and the single <c>x5c</c> certificate's bytes preserved exactly.
    /// </summary>
    [TestMethod]
    public void RoundTripsThroughTheShippedReaderWithFieldEquality()
    {
        using IMemoryOwner<byte> signatureOwner = BaseMemoryPool.Shared.Rent(64);
        Span<byte> signature = signatureOwner.Memory.Span[..64];
        for(int i = 0; i < signature.Length; i++)
        {
            signature[i] = (byte)(i + 1);
        }

        byte[] certificateDerBytes = [0x10, 0x20, 0x30, 0x40, 0x50];
        using PkiCertificateMemory certificate = Fido2AttestationTestVectors.ToPkiCertificateMemory(certificateDerBytes);

        TaggedMemory<byte> written = FidoU2fAttestationStatementCborWriter.Write(signature, [certificate]);

        FidoU2fAttestationStatement statement = FidoU2fAttestationStatementCborReader.Parse(written.Memory, BaseMemoryPool.Shared);
        try
        {
            Assert.IsTrue(statement.Signature.Span.SequenceEqual(signature));
            Assert.HasCount(1, statement.X5c);
            Assert.IsTrue(statement.X5c[0].AsReadOnlySpan().SequenceEqual(certificateDerBytes));
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
        byte[] certificateDerBytes = [0x01];
        using PkiCertificateMemory certificate = Fido2AttestationTestVectors.ToPkiCertificateMemory(certificateDerBytes);

        Assert.ThrowsExactly<ArgumentException>(() => FidoU2fAttestationStatementCborWriter.Write(ReadOnlySpan<byte>.Empty, [certificate]));
    }


    /// <summary>An <c>x5c</c> carrying zero elements is rejected with <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public void EmptyX5cThrowsArgumentException()
    {
        using IMemoryOwner<byte> signatureOwner = BaseMemoryPool.Shared.Rent(3);
        Memory<byte> signature = signatureOwner.Memory[..3];
        signature.Span[0] = 0x01;
        signature.Span[1] = 0x02;
        signature.Span[2] = 0x03;

        Assert.ThrowsExactly<ArgumentException>(() => FidoU2fAttestationStatementCborWriter.Write(signature.Span, []));
    }


    /// <summary>An <c>x5c</c> carrying two elements is rejected with <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public void TwoElementX5cThrowsArgumentException()
    {
        using IMemoryOwner<byte> signatureOwner = BaseMemoryPool.Shared.Rent(3);
        Memory<byte> signature = signatureOwner.Memory[..3];
        signature.Span[0] = 0x01;
        signature.Span[1] = 0x02;
        signature.Span[2] = 0x03;
        using PkiCertificateMemory first = Fido2AttestationTestVectors.ToPkiCertificateMemory([0x01]);
        using PkiCertificateMemory second = Fido2AttestationTestVectors.ToPkiCertificateMemory([0x02]);

        Assert.ThrowsExactly<ArgumentException>(() => FidoU2fAttestationStatementCborWriter.Write(signature.Span, [first, second]));
    }
}
