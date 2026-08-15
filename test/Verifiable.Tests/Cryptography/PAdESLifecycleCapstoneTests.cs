using System;
using System.Buffers;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The capstone (RP-6): a firewalled full PAdES lifecycle — B-T minted directly, then raised
/// through B-LT to B-LTA by <see cref="PAdESSignatureAugmentation"/> — validated from document bytes alone at
/// every stage by <see cref="PAdESLifecycleValidation"/>, reaching the pinned <see cref="SignatureValidationIndication"/>/
/// <see cref="SignatureValidationSubIndication"/> Table 5/6 of ETSI EN 319 102-1 V1.4.1 clause 5.1.3 mandate: a
/// <c>TOTAL-PASSED</c> leg at each of B-T/B-LT/B-LTA, a <c>TOTAL-FAILED</c> leg over a tampered signature value,
/// and an <c>INDETERMINATE</c> leg over a signer chaining to no trusted anchor.
/// </summary>
[TestClass]
internal sealed class PAdESLifecycleCapstoneTests
{
    private const string TsaUri = "http://tsa.pades-capstone.example.test/";

    private const string SignerDnsName = "pades-capstone.example.test";


    public required TestContext TestContext { get; set; }


    /// <summary>The full ladder: one document, minted at B-T, raised to B-LT then B-LTA, TOTAL-PASSED and the expected <see cref="PAdESReachedLevel"/> pinned at every stage.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-6.1-DEF-c, PA-6.1-DEF-d, PA-6.3-T23, PA-6.3-T26, PA-6.3-T27, PA-6.3-T29, PA-6.3-T30.
    /// </remarks>
    [TestMethod]
    public async Task TheFullLadderReachesTotalPassedAtBTThenBLtThenBLtaFromWireBytesAlone()
    {
        CapstoneWorld world = await MintWorldAsync().ConfigureAwait(false);
        using(world)
        {
            var completer = new CertificateChainCompleter([world.TrustAnchor]);
            var revocationChecker = new CrlRevocationChecker([world.RevocationList]);
            SignatureValidationConstraints constraints = BuildConstraints(world.TrustAnchor);

            using PAdESLifecycleResult btLeg = await PAdESLifecycleValidation.ValidateAsync(
                world.BtDocument, constraints, completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync,
                revocationChecker.CheckAsync, world.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(SignatureValidationIndication.TotalPassed, btLeg.Indication, $"B-T leg reason: {btLeg.Reason}; subs: {string.Join(",", btLeg.SubIndications.Select(s => s.Value))}");
            Assert.AreEqual(PAdESReachedLevel.BT, btLeg.ReachedLevel);
            AssertMintedBoundSignature(btLeg, world.Signer.Certificate.RawData);

            PdfDssPlacementResult bltPlacement = PAdESSignatureAugmentation.AugmentToBLT(
                new PAdESBLTAugmentationRequest
                {
                    PriorDocument = world.BtDocument,
                    Anchor = LocatePlaceholderAnchor(world.BtDocument, expectedSignatureObjectNumber: 2),
                    Certificates = [world.TrustAnchor],
                    CertificateRevocationLists = [world.RevocationList]
                },
                BaseMemoryPool.Shared);
            byte[] bltDocument = bltPlacement.Bytes;

            using PAdESLifecycleResult bltLeg = await PAdESLifecycleValidation.ValidateAsync(
                bltDocument, constraints, completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync,
                revocationChecker.CheckAsync, world.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(SignatureValidationIndication.TotalPassed, bltLeg.Indication, $"B-LT leg reason: {bltLeg.Reason}");
            Assert.AreEqual(PAdESReachedLevel.BLT, bltLeg.ReachedLevel);
            AssertMintedBoundSignature(bltLeg, world.Signer.Certificate.RawData);

            var archiveResponder = new MintingTimestampResponder(world.Authority, [world.Authority, world.Root], world.ArchiveTimestampTime);
            PdfDssParseResult dssBeforeLta = PdfDssReader.Locate(bltDocument, BaseMemoryPool.Shared);
            using(dssBeforeLta)
            {
                PAdESDocTimeStampResult bltaResult = await PAdESSignatureAugmentation.AugmentToBLTAAsync(
                    new PAdESDocTimeStampRequest
                    {
                        PriorDocument = bltDocument,
                        Anchor = bltPlacement.NextAnchor(rootObjectNumber: 1),
                        ContentsCapacityBytes = 16384,
                        MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                        TsaUri = TsaUri,
                        FetchResponse = archiveResponder.FetchAsync
                    },
                    BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

                using PAdESLifecycleResult bltaLeg = await PAdESLifecycleValidation.ValidateAsync(
                    bltaResult.Bytes, constraints, completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync,
                    revocationChecker.CheckAsync, world.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(SignatureValidationIndication.TotalPassed, bltaLeg.Indication, $"B-LTA leg reason: {bltaLeg.Reason}");
                Assert.AreEqual(PAdESReachedLevel.BLTA, bltaLeg.ReachedLevel, $"B-LTA leg reason: {bltaLeg.Reason}");
                AssertMintedBoundSignature(bltaLeg, world.Signer.Certificate.RawData);
            }
        }
    }


    /// <summary>A <c>TOTAL-FAILED</c> leg, pinned to <see cref="SignatureValidationSubIndication.SignatureCryptographicFailure"/>: one octet flipped inside the CMS <c>Contents</c> is caught by the PDF-side gate before the CMS-level engine ever runs.</summary>
    [TestMethod]
    public async Task ATamperedSignatureValueReachesTotalFailedPinnedToSignatureCryptographicFailure()
    {
        CapstoneWorld world = await MintWorldAsync().ConfigureAwait(false);
        using(world)
        {
            using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(world.BtDocument, BaseMemoryPool.Shared);
            PdfSignatureDictionary signature = located.SignatureDictionaries![0];
            byte[] tampered = (byte[])world.BtDocument.Clone();
            //Well inside the Signature Dictionary's own opening "<< /Type /Sig ..." text — safely within the
            //ByteRange's FIRST signed segment (before ContentsHexStart), never inside the Contents hex digits.
            int flipOffset = signature.ObjectOffset + 20;
            tampered[flipOffset] ^= 0xFF;

            var completer = new CertificateChainCompleter([world.TrustAnchor]);
            var revocationChecker = new CrlRevocationChecker([world.RevocationList]);
            SignatureValidationConstraints constraints = BuildConstraints(world.TrustAnchor);

            using PAdESLifecycleResult result = await PAdESLifecycleValidation.ValidateAsync(
                tampered, constraints, completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync,
                revocationChecker.CheckAsync, world.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(SignatureValidationIndication.TotalFailed, result.Indication);
            Assert.AreEqual(PAdESReachedLevel.None, result.ReachedLevel);
            Assert.Contains(SignatureValidationSubIndication.SignatureCryptographicFailure, result.SubIndications);
            Assert.IsNull(result.VerifiedSignature, "A non-passing outcome must never mint.");
        }
    }


    /// <summary>
    /// (the ladder is cumulative, negative arm): a DSS placed directly over a B-B signature that never reached B-T (no <c>signature-time-stamp</c>
    /// attribute, so PA-6.3-T23's own trusted-time SERVICE was never delivered) must never report <see cref="PAdESReachedLevel.BLT"/> — its Table 1
    /// states the SAME "shall be provided" presence for that service at B-T, B-LT and B-LTA alike (PA-6.3-T23), so B-LT's own "material required
    /// for validating the signature" (PA-6.1-DEF-c) presupposes B-T's trusted time already exists; it is never independently satisfiable by a DSS
    /// alone. The positive arm — a document that DID reach B-T correctly promotes to B-LT once a DSS is placed — is <see
    /// cref="TheFullLadderReachesTotalPassedAtBTThenBLtThenBLtaFromWireBytesAlone"/>.
    /// </summary>
    [TestMethod]
    public async Task ADssPlacedOverASignatureThatNeverReachedBTNeverReportsBLt()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset validationTime = signingTime.AddDays(1);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using PkiCertificateMemory signerCertificate = ToCarrier(signer.Certificate.RawData, PkiCertificateTags.X509Certificate);
        using PrivateKeyMemory signerPrivateKey = ToPrivateKeyCarrier(signer.SigningKey);
        using PkiCertificateMemory trustAnchor = ToCarrier(root.Certificate.RawData, PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, signingTime.AddMinutes(-30), signingTime.AddYears(1), []);

        (byte[] unsigned, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
            new PAdESSigningRequest
            {
                PriorDocument = unsigned,
                Anchor = anchor,
                ContentsCapacityBytes = 4096,
                SignerCertificate = signerCertificate,
                SignerPrivateKey = signerPrivateKey,
                SigningTime = signingTime
                //No SignatureTimestamp: this signature never reaches PAdES-B-T.
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AdESBaselineLevel.BB, signed.Level);

        PdfDssPlacementResult bltPlacement = PAdESSignatureAugmentation.AugmentToBLT(
            new PAdESBLTAugmentationRequest
            {
                PriorDocument = signed.Bytes,
                Anchor = LocatePlaceholderAnchor(signed.Bytes, expectedSignatureObjectNumber: 2),
                Certificates = [trustAnchor],
                CertificateRevocationLists = [revocationList]
            },
            BaseMemoryPool.Shared);

        var completer = new CertificateChainCompleter([trustAnchor]);
        var revocationChecker = new CrlRevocationChecker([revocationList]);
        SignatureValidationConstraints constraints = BuildConstraints(trustAnchor);

        using PAdESLifecycleResult result = await PAdESLifecycleValidation.ValidateAsync(
            bltPlacement.Bytes, constraints, completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync,
            revocationChecker.CheckAsync, validationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(PAdESReachedLevel.BLT, result.ReachedLevel, $"Reason: {result.Reason}");
        Assert.AreNotEqual(PAdESReachedLevel.BLTA, result.ReachedLevel, $"Reason: {result.Reason}");
    }


    /// <summary>
    /// (the shadow attack reopened through the LTV path): an incremental update appended past the signature's own
    /// <c>ByteRange</c> coverage that REDEFINES an already-decided object — the document catalog, object 1 —
    /// outside the one recognised DSS-catalog-extension shape must be rejected by <see
    /// cref="PAdESLifecycleValidation"/> exactly as it already is by the structural entry point (<see
    /// cref="PAdESSignatureValidation"/>), over the SAME bytes: the two surfaces must never disagree.
    /// </summary>
    [TestMethod]
    public async Task AnIncrementalUpdateRedefiningTheDocumentCatalogIsRejectedByBothSurfacesInAgreement()
    {
        CapstoneWorld world = await MintWorldAsync().ConfigureAwait(false);
        using(world)
        {
            int priorXrefOffset = LocatePlaceholderAnchor(world.BtDocument, expectedSignatureObjectNumber: 2).PriorXrefOffset;
            byte[] shadowed = PdfFixtureBuilder.AppendUnsignedIncrementalUpdate(
                world.BtDocument, priorXrefOffset, objectNumber: 1, objectBody: "<< /Type /Catalog /OpenAction 999 0 R >>");

            using PAdESValidationResult entryPointResult = await PAdESSignatureValidation.ValidateAsync(
                shadowed, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(entryPointResult.IsSuccess, entryPointResult.FailureReason);
            Assert.HasCount(1, entryPointResult.Signatures!);
            Assert.AreEqual(PAdESSignatureStatus.IncompleteByteRangeCoverage, entryPointResult.Signatures![0].Status,
                "The structural entry point rejects any content appended past the newest signature's own coverage (PA-6.3-k).");

            var completer = new CertificateChainCompleter([world.TrustAnchor]);
            var revocationChecker = new CrlRevocationChecker([world.RevocationList]);
            SignatureValidationConstraints constraints = BuildConstraints(world.TrustAnchor);

            using PAdESLifecycleResult lifecycleResult = await PAdESLifecycleValidation.ValidateAsync(
                shadowed, constraints, completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync,
                revocationChecker.CheckAsync, world.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(SignatureValidationIndication.TotalPassed, lifecycleResult.Indication,
                $"The lifecycle path must reject a redefined document catalog exactly as the entry point does, never silently ignore it. Reason: {lifecycleResult.Reason}");
            Assert.AreEqual(PAdESReachedLevel.None, lifecycleResult.ReachedLevel);
        }
    }


    /// <summary>An <c>INDETERMINATE</c> leg: a cryptographically valid signature chaining to no trust anchor the verifier configured reaches <see cref="SignatureValidationSubIndication.NoCertificateChainFound"/>, not a passing outcome.</summary>
    [TestMethod]
    public async Task ASignerChainingToNoTrustedAnchorReachesIndeterminate()
    {
        CapstoneWorld world = await MintWorldAsync().ConfigureAwait(false);
        using(world)
        {
            FakeTimeProvider unrelatedTimeProvider = new(TestClock.CanonicalEpoch);
            using X509ChainTestRingNode unrelatedRoot = X509ChainTestRing.CreateRootCa(unrelatedTimeProvider, notBefore: world.NotBefore, notAfter: world.NotAfter);
            using PkiCertificateMemory unrelatedTrustAnchor = ToCarrier(unrelatedRoot.Certificate.RawData, PkiCertificateTags.X509Certificate);

            var completer = new CertificateChainCompleter([unrelatedTrustAnchor]);
            var revocationChecker = new CrlRevocationChecker([world.RevocationList]);
            SignatureValidationConstraints constraints = BuildConstraints(unrelatedTrustAnchor);

            using PAdESLifecycleResult result = await PAdESLifecycleValidation.ValidateAsync(
                world.BtDocument, constraints, completer.CompleteAsync, MicrosoftX509Functions.ValidateChainAsync,
                revocationChecker.CheckAsync, world.ValidationTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(SignatureValidationIndication.Indeterminate, result.Indication);
            Assert.AreEqual(PAdESReachedLevel.None, result.ReachedLevel);
            Assert.IsNotEmpty(result.SubIndications);
            Assert.IsNull(result.VerifiedSignature, "A non-passing outcome must never mint.");
        }
    }


    /// <summary>
    /// A TOTAL-PASSED leg mints an identity-bound <see cref="PAdESVerifiedSignatureFacts"/> — the digest
    /// gate's own <see cref="ResolutionSource.CertificateDigest"/> witness, and the owned certificate copy
    /// byte-equal to the world's own signer certificate.
    /// </summary>
    private static void AssertMintedBoundSignature(PAdESLifecycleResult leg, byte[] expectedSignerCertificate)
    {
        Assert.IsNotNull(leg.VerifiedSignature, $"A TOTAL-PASSED leg must mint. Reason: {leg.Reason}");
        Verified<PAdESVerifiedSignatureFacts> verified = leg.VerifiedSignature!.Value;
        Assert.IsTrue(verified.IsVerified);
        Assert.IsTrue(verified.IsIdentityBound, "The pipeline-gated mint must be identity-bound, never asserted.");
        Assert.IsInstanceOfType<BoundProvenance>(verified.Provenance);
        var bound = (BoundProvenance)verified.Provenance!;
        Assert.AreEqual(ResolutionSource.CertificateDigest, bound.Source);
        Assert.IsTrue(verified.Value.SigningCertificate.AsReadOnlySpan().SequenceEqual(expectedSignerCertificate));
    }


    private static SignatureValidationConstraints BuildConstraints(PkiCertificateMemory trustAnchor)
    {
        var x509Constraints = new X509ValidationConstraints { TrustAnchors = [new TrustAnchorConstraint(trustAnchor, SunsetDate: null)] };
        var cryptographicConstraints = new CryptographicConstraints
        {
            Entries =
            [
                new AlgorithmReliabilityEntry(
                    new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                    MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits, TrustedUntil: null),
                new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)
            ]
        };

        return new SignatureValidationConstraints
        {
            Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
            X509 = x509Constraints,
            Cryptographic = cryptographicConstraints,
            SignatureElements = SignatureElementsConstraints.None
        };
    }


    /// <summary>Mints the root/TSA/leaf, signs a B-T document, and mints the CRL a live verifier obtains independently of anything a DSS bundles.</summary>
    private static async ValueTask<CapstoneWorld> MintWorldAsync()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset archiveTimestampTime = signingTime.AddHours(3);
        DateTimeOffset validationTime = signingTime.AddDays(1);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);

        X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: notBefore, notAfter: notAfter);

        PkiCertificateMemory signerCertificate = ToCarrier(signer.Certificate.RawData, PkiCertificateTags.X509Certificate);
        PrivateKeyMemory signerPrivateKey = ToPrivateKeyCarrier(signer.SigningKey);
        PkiCertificateMemory trustAnchor = ToCarrier(root.Certificate.RawData, PkiCertificateTags.X509Certificate);
        PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, signingTime.AddMinutes(-30), signingTime.AddYears(1), []);

        using(signerCertificate)
        using(signerPrivateKey)
        {
            (byte[] unsigned, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
            var signatureResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
            PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
                new PAdESSigningRequest
                {
                    PriorDocument = unsigned,
                    Anchor = anchor,
                    ContentsCapacityBytes = 16384,
                    SignerCertificate = signerCertificate,
                    SignerPrivateKey = signerPrivateKey,
                    SigningTime = signingTime,
                    SignatureTimestamp = new PAdESSignatureTimestampRequest
                    {
                        MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                        TsaUri = TsaUri,
                        FetchResponse = signatureResponder.FetchAsync
                    }
                },
                BaseMemoryPool.Shared, CancellationToken.None).ConfigureAwait(false);

            return new CapstoneWorld
            {
                Root = root,
                Authority = authority,
                Signer = signer,
                TrustAnchor = trustAnchor,
                RevocationList = revocationList,
                BtDocument = signed.Bytes,
                ValidationTime = validationTime,
                ArchiveTimestampTime = archiveTimestampTime,
                NotBefore = notBefore,
                NotAfter = notAfter
            };
        }
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


    private static PrivateKeyMemory ToPrivateKeyCarrier(ECDsa key)
    {
        byte[] d = key.ExportParameters(includePrivateParameters: true).D!;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(d.Length);
        d.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, CryptoTags.P256PrivateKey);
    }


    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>Everything the capstone's own three tests share: the minted world, disposed together once.</summary>
    private sealed class CapstoneWorld: IDisposable
    {
        public required X509ChainTestRingNode Root { get; init; }

        public required X509ChainTestRingNode Authority { get; init; }

        public required X509ChainTestRingNode Signer { get; init; }

        public required PkiCertificateMemory TrustAnchor { get; init; }

        public required PkiCertificateMemory RevocationList { get; init; }

        public required byte[] BtDocument { get; init; }

        public required DateTimeOffset ValidationTime { get; init; }

        public required DateTimeOffset ArchiveTimestampTime { get; init; }

        public required DateTimeOffset NotBefore { get; init; }

        public required DateTimeOffset NotAfter { get; init; }


        public void Dispose()
        {
            Root.Dispose();
            Authority.Dispose();
            Signer.Dispose();
            TrustAnchor.Dispose();
            RevocationList.Dispose();
        }
    }
}
