using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="PAdESSignatureFacts"/>: the fourth EN 319 102-1 format-facts binding,
/// composed over the shipped CAdES binding (PA-6.3-h, RP-3).
/// </summary>
[TestClass]
internal sealed class PAdESSignatureFactsTests
{
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);


    public required TestContext TestContext { get; set; }


    /// <summary>PA-6.3-h: the extracted facts are stamped <see cref="SignatureFormatIdentifier.PAdES"/> (never <see cref="SignatureFormatIdentifier.CAdES"/>), while every CMS-level fact reads exactly as the composed CAdES binding would report it.</summary>
    [TestMethod]
    public async Task ExtractsFactsStampedPAdESOverAGenuinelySignedDocumentsOwnContents()
    {
        (PkiCertificateMemory signerCertificate, PrivateKeyMemory signerKey) = MintSigner();
        using(signerCertificate)
        using(signerKey)
        {
            (byte[] unsigned, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
            PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
                new PAdESSigningRequest
                {
                    PriorDocument = unsigned,
                    Anchor = anchor,
                    ContentsCapacityBytes = 4096,
                    SignerCertificate = signerCertificate,
                    SignerPrivateKey = signerKey,
                    SigningTime = TestClock.CanonicalEpoch
                },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(signed.Bytes, BaseMemoryPool.Shared);
            Assert.IsTrue(located.IsSuccess, located.FailureReason);
            PdfSignatureDictionary signature = located.SignatureDictionaries![0];

            SignatureFactsExtractionContext extractionContext = PAdESSignatureFacts.BuildExtractionContext(signature, BaseMemoryPool.Shared);
            try
            {
                using SignatureFacts facts = await PAdESSignatureFacts.Seam.ExtractFacts(
                    extractionContext, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status);
                Assert.AreEqual(SignatureFormatIdentifier.PAdES, facts.Format);
                Assert.IsNotNull(facts.SigningCertificate);
                Assert.IsTrue(facts.SigningCertificate!.AsReadOnlySpan().SequenceEqual(signerCertificate.AsReadOnlySpan()));
                Assert.AreEqual(SignedContentPlacement.Detached, facts.SignedContentPlacement, "PAdES.CAdES.detached — never encapsulated.");

                SignatureCryptographicVerification cryptography = await PAdESSignatureFacts.Seam.VerifyCryptography(
                    new SignatureCryptographicVerificationContext { Signature = facts, SigningCertificate = signerCertificate },
                    BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(SignatureCryptographicOutcome.Verified, cryptography.Outcome);
            }
            finally
            {
                (extractionContext.SignedDataObject as IDisposable)?.Dispose();
                extractionContext.SignerDocuments[0].Content?.Dispose();
            }
        }
    }


    /// <summary>A Signed Data Object that is not well-formed CMS is reported as <see cref="SignatureFactsStatus.FormatFailure"/> — never an exception, and never a cryptographic-failure outcome (the mapping discipline).</summary>
    [TestMethod]
    public async Task MalformedCmsBytesAreReportedAsAFormatFailureNotAnException()
    {
        using CmsSignedData notCms = CmsSignedData.FromBytes([0x01, 0x02, 0x03], BaseMemoryPool.Shared);
        var context = new SignatureFactsExtractionContext { SignedDataObject = notCms };

        using SignatureFacts facts = await PAdESSignatureFacts.ExtractAsync(context, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureFactsStatus.FormatFailure, facts.Status);
        Assert.AreEqual(SignatureFormatIdentifier.PAdES, facts.Format);
        Assert.IsNotNull(facts.FormatFailureReason);
    }


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
        var anchor = new PdfIncrementalUpdateAnchor { PriorXrefOffset = xrefOffset, PriorObjectCount = 2, RootObjectNumber = 1, RootGeneration = 0 };

        return (bytes, anchor);
    }


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

            return (ToCarrier(platformCertificate.RawData, PkiCertificateTags.X509Certificate), keys.PrivateKey);
        }
    }


    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }
}
