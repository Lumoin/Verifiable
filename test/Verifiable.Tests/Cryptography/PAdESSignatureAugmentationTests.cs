using System;
using System.Buffers;
using System.Diagnostics;
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
/// Conformance tests for <see cref="PAdESSignatureAugmentation"/>: the B-LT/B-LTA LTV augmentation ladder verbs,
/// their own structural and pre-billing gates (PA-6.3-T27, PA-6.3-x1), and letter v)'s no-VRI-by-default posture.
/// </summary>
[TestClass]
internal sealed class PAdESSignatureAugmentationTests
{
    private const string TsaUri = "http://tsa.pades-augmentation.example.test/";

    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);


    public required TestContext TestContext { get; set; }


    /// <summary>PA-6.3-T27/T30: a B-T document is raised to B-LT (DSS placed, no VRI by default — letter v) and then to B-LTA (Document Time-stamp placed), each new revision retaining every earlier byte unchanged.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">ETSI EN 319 142-1 V1.2.1</see>
    /// PA-5.4.2.3-14, PA-5.4.2.3-15, PA-6.3-v, PA-6.3-x2.
    /// </remarks>
    [TestMethod]
    public async Task RaisesABTSignatureThroughBLtToBLtaAndEachRevisionRetainsThePriorBytes()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        (PkiCertificateMemory signerCertificate, PrivateKeyMemory signerKey) = MintSigner();
        using(signerCertificate)
        using(signerKey)
        {
            (byte[] unsigned, PdfIncrementalUpdateAnchor signingAnchor) = BuildUnsignedBasePdf();
            var signatureResponder = new MintingTimestampResponder(authority, [authority, root], TestClock.CanonicalEpoch.AddHours(1));
            PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
                new PAdESSigningRequest
                {
                    PriorDocument = unsigned,
                    Anchor = signingAnchor,
                    ContentsCapacityBytes = 16384,
                    SignerCertificate = signerCertificate,
                    SignerPrivateKey = signerKey,
                    SigningTime = TestClock.CanonicalEpoch,
                    SignatureTimestamp = new PAdESSignatureTimestampRequest
                    {
                        MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                        TsaUri = TsaUri,
                        FetchResponse = signatureResponder.FetchAsync
                    }
                },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AdESBaselineLevel.BT, signed.Level);

            using PkiCertificateMemory rootCertificate = ToCarrier(root.Certificate.RawData, PkiCertificateTags.X509Certificate);
            using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
                root, TestClock.CanonicalEpoch, TestClock.CanonicalEpoch.AddYears(1), []);

            PdfIncrementalUpdateAnchor dssAnchor = LocatePlaceholderAnchor(signed.Bytes, expectedSignatureObjectNumber: 2);
            PdfDssPlacementResult raisedToBLt = PAdESSignatureAugmentation.AugmentToBLT(
                new PAdESBLTAugmentationRequest
                {
                    PriorDocument = signed.Bytes,
                    Anchor = dssAnchor,
                    Certificates = [rootCertificate],
                    CertificateRevocationLists = [revocationList]
                },
                BaseMemoryPool.Shared);

            Assert.IsGreaterThan(signed.Bytes.Length, raisedToBLt.Bytes.Length, "The DSS revision must be strictly longer.");
            Assert.IsTrue(raisedToBLt.Bytes.AsSpan(0, signed.Bytes.Length).SequenceEqual(signed.Bytes),
                "Every byte of the B-T revision must survive unchanged at the same offsets.");
            Assert.IsEmpty(
                PdfDssReader.Locate(raisedToBLt.Bytes, BaseMemoryPool.Shared).Dss!.VriEntries,
                "Letter v): AugmentToBLT places no VRI entry by default.");

            var archiveResponder = new MintingTimestampResponder(authority, [authority, root], TestClock.CanonicalEpoch.AddHours(2));
            PAdESDocTimeStampResult raisedToBLta = await PAdESSignatureAugmentation.AugmentToBLTAAsync(
                new PAdESDocTimeStampRequest
                {
                    PriorDocument = raisedToBLt.Bytes,
                    Anchor = raisedToBLt.NextAnchor(rootObjectNumber: 1),
                    ContentsCapacityBytes = 16384,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = archiveResponder.FetchAsync
                },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsGreaterThan(raisedToBLt.Bytes.Length, raisedToBLta.Bytes.Length - 1,
                "The Document Time-stamp revision must be strictly longer than the B-LT revision.");
            Assert.IsTrue(raisedToBLta.Bytes.AsSpan(0, raisedToBLt.Bytes.Length).SequenceEqual(raisedToBLt.Bytes),
                "Every byte of the B-LT revision must survive unchanged at the same offsets.");

            using PAdESDocTimeStampCollectionResult docTimeStamps = await PAdESDocTimeStampValidation.ValidateAsync(
                raisedToBLta.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(docTimeStamps.IsSuccess, docTimeStamps.FailureReason);
            Assert.HasCount(1, docTimeStamps.DocTimeStamps!);
            Assert.IsTrue(docTimeStamps.DocTimeStamps![0].IsValid, $"Expected Valid, was {docTimeStamps.DocTimeStamps![0].Status}.");
        }
    }


    /// <summary>
    /// PA-6.3-T27/PA-6.2.2-22's own "&gt;= 1" cardinality at B-LT/B-LTA counts instances of the SPO: DSS row
    /// itself (DSS dictionaries), never the <c>Certs</c>/<c>CRLs</c>/<c>OCSPs</c> entries one DSS dictionary
    /// carries — each independently "(Optional)" per PA-5.4.2.2's own table. A request supplying none of them is
    /// therefore NOT refused: exactly one (empty) DSS dictionary is still placed, satisfying the row's own
    /// cardinality by construction.
    /// </summary>
    [TestMethod]
    public void AugmentsToBLtWithNoValidationMaterialAtAllBecauseTheCardinalityIsOnTheDssInstanceNotItsItems()
    {
        (byte[] unsigned, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 certificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(key, NotBefore, NotAfter);
        using PkiCertificateMemory signerCertificate = ToCarrier(certificate.RawData, PkiCertificateTags.X509Certificate);

        byte[] signedDocument = BuildSingleSignatureDocument(unsigned, anchor, signerCertificate);
        PdfIncrementalUpdateAnchor dssAnchor = LocatePlaceholderAnchor(signedDocument, expectedSignatureObjectNumber: 2);
        var request = new PAdESBLTAugmentationRequest { PriorDocument = signedDocument, Anchor = dssAnchor };

        PdfDssPlacementResult placed = PAdESSignatureAugmentation.AugmentToBLT(request, BaseMemoryPool.Shared);

        using PdfDssParseResult dss = PdfDssReader.Locate(placed.Bytes, BaseMemoryPool.Shared);
        Assert.IsTrue(dss.IsSuccess, dss.FailureReason);
        Assert.IsTrue(dss.HasDss);
        Assert.IsEmpty(dss.Dss!.Certificates);
        Assert.IsEmpty(dss.Dss.CertificateRevocationLists);
        Assert.IsEmpty(dss.Dss.OcspResponses);
    }


    /// <summary>Byte-assembles a single PAdES-shaped Signature Dictionary directly (via <see cref="PdfIncrementalUpdateWriter.AppendPlaceholderSignature"/>) without a real CMS signature — sufficient for <see cref="PAdESSignatureAugmentation.AugmentToBLT"/>'s own structural gate, which only needs a located Signature Dictionary to exist.</summary>
    private static byte[] BuildSingleSignatureDocument(byte[] unsigned, PdfIncrementalUpdateAnchor anchor, PkiCertificateMemory signerCertificate)
    {
        PdfSignaturePlaceholder placeholder = PdfIncrementalUpdateWriter.AppendPlaceholderSignature(
            unsigned, anchor, new PdfSignatureFieldValues { SigningTime = TestClock.CanonicalEpoch }, contentsCapacityBytes: 256);

        return PdfIncrementalUpdateWriter.CompleteSignature(placeholder, signerCertificate.AsReadOnlySpan()[..32].ToArray());
    }


    /// <summary>The B-LT gate's own structural half: a DSS naming validation material "for a specific signature" over a document that carries no Signature Dictionary at all is refused.</summary>
    [TestMethod]
    public void RefusesToAugmentToBLtOverADocumentCarryingNoSignature()
    {
        (byte[] unsigned, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 certificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(key, NotBefore, NotAfter);
        using PkiCertificateMemory carrier = ToCarrier(certificate.RawData, PkiCertificateTags.X509Certificate);

        var request = new PAdESBLTAugmentationRequest { PriorDocument = unsigned, Anchor = anchor, Certificates = [carrier] };

        Assert.ThrowsExactly<ArgumentException>(() => PAdESSignatureAugmentation.AugmentToBLT(request, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// PA-6.3-x1's own pre-billing gate: a document carrying no DSS dictionary at all is refused before the
    /// Time-Stamping Authority is ever contacted — the responder's own call counter proves it was never reached.
    /// </summary>
    [TestMethod]
    public async Task RefusesToAugmentToBLtaOverADocumentWithNoDssAndNeverContactsTheAuthority()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        (PkiCertificateMemory signerCertificate, PrivateKeyMemory signerKey) = MintSigner();
        using(signerCertificate)
        using(signerKey)
        {
            (byte[] unsigned, PdfIncrementalUpdateAnchor signingAnchor) = BuildUnsignedBasePdf();
            PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
                new PAdESSigningRequest
                {
                    PriorDocument = unsigned,
                    Anchor = signingAnchor,
                    ContentsCapacityBytes = 4096,
                    SignerCertificate = signerCertificate,
                    SignerPrivateKey = signerKey,
                    SigningTime = TestClock.CanonicalEpoch
                },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            //A poison-pill transport: if the gate incorrectly let the call through, this delegate's own distinct
            //exception -- never PA-6.3-x1's own InvalidOperationException -- would surface instead, proving the
            //authority was never actually contacted rather than merely asserting a counter.
            var request = new PAdESDocTimeStampRequest
            {
                PriorDocument = signed.Bytes,
                Anchor = LocatePlaceholderAnchor(signed.Bytes, expectedSignatureObjectNumber: 2),
                ContentsCapacityBytes = 8192,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = static (_, _, _) => throw new UnreachableException("The gate must refuse before the Time-Stamping Authority is ever contacted.")
            };

            InvalidOperationException thrown = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await PAdESSignatureAugmentation.AugmentToBLTAAsync(request, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
            Assert.Contains("PA-6.3-x1", thrown.Message, StringComparison.Ordinal);
        }
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


    private static PdfIncrementalUpdateAnchor LocatePlaceholderAnchor(byte[] document, int expectedSignatureObjectNumber)
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

        int xrefOffset = int.Parse(text[numberStart..numberEnd], System.Globalization.CultureInfo.InvariantCulture);

        return new PdfIncrementalUpdateAnchor
        {
            PriorXrefOffset = xrefOffset,
            PriorObjectCount = expectedSignatureObjectNumber + 1,
            RootObjectNumber = 1,
            RootGeneration = 0
        };
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
