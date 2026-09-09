using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The firewalled lifecycle (RP-4, mirroring <c>CAdESCapstoneFirewalledFlowTests</c>'s own
/// "wire bytes alone" discipline, scaled to this file's own scope): create→wire-bytes→validate over the
/// incremental-update fixture, spanning both levels (PAdES-B-B, then a second, layered PAdES-B-T signature)
/// in one document. Every signing call reads only <see cref="PAdESSigningRequest.PriorDocument"/>/<see
/// cref="PAdESSigningRequest.Anchor"/>; every validation call reads only the completed document's own bytes — no
/// state from creation is threaded past <see cref="PAdESSignedDocument.Bytes"/>, and the bytes handed to
/// <see cref="PAdESSignatureValidation.ValidateAsync"/> are an independent copy, so a leak through shared memory
/// rather than the wire itself cannot silently pass this test.
/// </summary>
[TestClass]
internal sealed class PAdESFirewalledFlowTests
{
    private const string TsaUri = "http://tsa.pades-firewalled.example.test/";

    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    private static DateTimeOffset FirstSigningTime { get; } = TestClock.CanonicalEpoch;

    private static DateTimeOffset SecondSigningTime { get; } = TestClock.CanonicalEpoch.AddDays(1);

    private static DateTimeOffset SignatureTimestampTime { get; } = TestClock.CanonicalEpoch.AddDays(1).AddHours(1);


    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Builds a two-revision incremental-update document — a PAdES-B-B first signature, then a PAdES-B-T second
    /// signature layered on top of it through its own <see cref="PdfSignaturePlaceholder.NextAnchor"/> — and
    /// validates the finished document from wire bytes alone. Both legs (RP-6) are exercised
    /// together: the first signature's own <c>ByteRange</c> covers only the shorter first revision, the second's
    /// covers the whole final file, and both must independently verify against the SAME final byte array.
    /// </summary>
    [TestMethod]
    public async Task FirewalledLifecycleValidatesALayeredBBThenBTSignatureFromWireBytesAlone()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        (PkiCertificateMemory firstCertificate, PrivateKeyMemory firstKey) = MintSigner();
        (PkiCertificateMemory secondCertificate, PrivateKeyMemory secondKey) = MintSigner();
        using(firstCertificate)
        using(firstKey)
        using(secondCertificate)
        using(secondKey)
        {
            (byte[] unsignedDocument, PdfIncrementalUpdateAnchor firstAnchor) = BuildUnsignedBasePdf();

            PAdESSignedDocument first = await PAdESSignatureCreation.SignAsync(
                new PAdESSigningRequest
                {
                    PriorDocument = unsignedDocument,
                    Anchor = firstAnchor,
                    ContentsCapacityBytes = 4096,
                    SignerCertificate = firstCertificate,
                    SignerPrivateKey = firstKey,
                    SigningTime = FirstSigningTime,
                    Name = "First Signer"
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AdESBaselineLevel.BB, first.Level);

            //Wire-bytes-only: the second signing call locates its own anchor purely from the first signature's
            //produced bytes, exactly as an independent second-signing tool would over a file handed to it cold.
            PdfIncrementalUpdateAnchor secondAnchor = LocateNextAnchor(first.Bytes);
            var responder = new MintingTimestampResponder(authority, [authority, root], SignatureTimestampTime);

            PAdESSignedDocument second = await PAdESSignatureCreation.SignAsync(
                new PAdESSigningRequest
                {
                    PriorDocument = first.Bytes,
                    Anchor = secondAnchor,
                    ContentsCapacityBytes = 16384,
                    SignerCertificate = secondCertificate,
                    SignerPrivateKey = secondKey,
                    SigningTime = SecondSigningTime,
                    Name = "Second Signer",
                    SignatureTimestamp = new PAdESSignatureTimestampRequest
                    {
                        MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                        TsaUri = TsaUri,
                        FetchResponse = responder.FetchAsync
                    }
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AdESBaselineLevel.BT, second.Level);

            //An independent copy: nothing from the creation calls above -- pools, certificates, anchors -- is
            //reachable from this point on, only the finished document's own bytes.
            byte[] wireBytes = (byte[])second.Bytes.Clone();

            using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
                wireBytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
            Assert.HasCount(2, validation.Signatures!);

            PAdESSignatureValidationResult firstResult = validation.Signatures![0];
            Assert.IsTrue(firstResult.IsValid, $"First (B-B) signature: expected Valid, was {firstResult.Status}.");
            Assert.AreEqual(AdESBaselineLevel.BB, firstResult.Level);
            Assert.AreEqual(FirstSigningTime, firstResult.SigningTime);
            Assert.IsNull(firstResult.TimestampTime);

            PAdESSignatureValidationResult secondResult = validation.Signatures![1];
            Assert.IsTrue(secondResult.IsValid, $"Second (B-T) signature: expected Valid, was {secondResult.Status}.");
            Assert.AreEqual(AdESBaselineLevel.BT, secondResult.Level);
            Assert.AreEqual(SecondSigningTime, secondResult.SigningTime);
            Assert.AreEqual(SignatureTimestampTime, secondResult.TimestampTime);
        }
    }


    private static PdfIncrementalUpdateAnchor LocateNextAnchor(byte[] document)
    {
        using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(document, BaseMemoryPool.Shared);
        int xrefOffset = FindLastXrefOffset(document);

        //The base fixture always starts its own signature object at number 2 (object 1 is the catalog), so the
        //first signature's own object is 2 and the next incremental update's own object count is 3 -- known from
        //this test's own fixture layout, never asked of the located signature.
        return new PdfIncrementalUpdateAnchor
        {
            PriorXrefOffset = xrefOffset,
            PriorObjectCount = 3,
            RootObjectNumber = 1,
            RootGeneration = 0
        };
    }


    private static int FindLastXrefOffset(byte[] document)
    {
        string text = Encoding.ASCII.GetString(document);
        int index = text.LastIndexOf("startxref", StringComparison.Ordinal);
        int numberStart = index + "startxref".Length;
        while(document[numberStart] is (byte)'\n' or (byte)'\r')
        {
            numberStart++;
        }

        int numberEnd = numberStart;
        while(document[numberEnd] is >= (byte)'0' and <= (byte)'9')
        {
            numberEnd++;
        }

        return int.Parse(text[numberStart..numberEnd], System.Globalization.CultureInfo.InvariantCulture);
    }


    /// <summary>Builds a minimal unsigned PDF: a catalog object plus a classic xref/trailer, independently of any reader/writer this library ships.</summary>
    private static (byte[] Bytes, PdfIncrementalUpdateAnchor Anchor) BuildUnsignedBasePdf()
    {
        var writer = new System.Collections.Generic.List<byte>();
        void Ascii(string s) => writer.AddRange(Encoding.ASCII.GetBytes(s));

        Ascii("%PDF-1.7\n");
        int obj1Offset = writer.Count;
        Ascii("1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        int xrefOffset = writer.Count;
        Ascii("xref\n0 2\n");
        Ascii("0000000000 65535 f \n");
        Ascii($"{obj1Offset:D10} 00000 n \n");
        Ascii("trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n");
        Ascii(xrefOffset.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Ascii("\n%%EOF\n");

        byte[] bytes = [.. writer];
        var anchor = new PdfIncrementalUpdateAnchor
        {
            PriorXrefOffset = xrefOffset,
            PriorObjectCount = 2,
            RootObjectNumber = 1,
            RootGeneration = 0
        };

        return (bytes, anchor);
    }


    /// <summary>Mints a P-256 signer: key material through <see cref="BouncyCastleKeyMaterialCreator"/>, and a self-signed certificate over the same public point through a platform <see cref="ECDsa"/> reconstructed from it.</summary>
    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintSigner()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using(keys.PublicKey)
        {
            byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                Q = new ECPoint
                {
                    X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                    Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                }
            };

            using ECDsa platformKey = ECDsa.Create(ecParameters);
            using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);

            return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
        }
    }


    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
