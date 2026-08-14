using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
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
/// Conformance tests for <see cref="PdfIncrementalUpdateWriter.AppendValidationData"/> and <see
/// cref="PdfDssReader"/>: DSS/VRI dictionary write→read round trips over
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.4.2, byte-exactness of the retained prior revision, VRI keying
/// (<see cref="PdfVriKey"/>) against an independent SHA-1 oracle, fail-closed negatives, and metered custody.
/// </summary>
[TestClass]
internal sealed class PdfDssRoundTripTests
{
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);


    public required TestContext TestContext { get; set; }


    /// <summary>
    /// PA-5.4.2.2-01/-02/-05/-06/-07/-08: the DSS dictionary is written under the catalog's own <c>DSS</c> key,
    /// and its <c>Certs</c>/<c>CRLs</c>/<c>OCSPs</c> arrays round-trip byte-exactly.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-5.4.2.1-T1, PA-5.4.2.2-03, PA-6.3-T26, PA-6.3-u.
    /// </remarks>
    [TestMethod]
    public async Task WritesAndReadsBackDssCertificatesCrlsAndOcspResponses()
    {
        (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(document, out PdfCatalogLocation? catalog, out string? locateError), locateError);
        Assert.IsFalse(catalog!.HasDssEntry);

        using PkiCertificateMemory cert1 = MintDerCertificate("dss-cert-1.example.test");
        using PkiCertificateMemory cert2 = MintDerCertificate("dss-cert-2.example.test");
        using PkiCertificateMemory crl = ToCarrier([0x30, 0x03, 0x02, 0x01, 0x01], PkiCertificateTags.X509Crl);
        using PkiCertificateMemory ocsp = ToCarrier([0x30, 0x03, 0x02, 0x01, 0x02], PkiCertificateTags.OcspResponse);

        PdfDssPlacementResult placed = PdfIncrementalUpdateWriter.AppendValidationData(new PdfDssPlacementRequest
        {
            PriorDocument = document,
            Anchor = anchor,
            Catalog = catalog!,
            Certificates = [cert1, cert2],
            CertificateRevocationLists = [crl],
            OcspResponses = [ocsp]
        });

        using PdfDssParseResult located = PdfDssReader.Locate(placed.Bytes, BaseMemoryPool.Shared);
        Assert.IsTrue(located.IsSuccess, located.FailureReason);
        Assert.IsTrue(located.HasDss);
        Assert.HasCount(2, located.Dss!.Certificates);
        Assert.IsTrue(located.Dss.Certificates[0].AsReadOnlySpan().SequenceEqual(cert1.AsReadOnlySpan()));
        Assert.IsTrue(located.Dss.Certificates[1].AsReadOnlySpan().SequenceEqual(cert2.AsReadOnlySpan()));
        Assert.HasCount(1, located.Dss.CertificateRevocationLists);
        Assert.IsTrue(located.Dss.CertificateRevocationLists[0].AsReadOnlySpan().SequenceEqual(crl.AsReadOnlySpan()));
        Assert.HasCount(1, located.Dss.OcspResponses);
        Assert.IsTrue(located.Dss.OcspResponses[0].AsReadOnlySpan().SequenceEqual(ocsp.AsReadOnlySpan()));
        Assert.IsEmpty(located.Dss.VriEntries);

        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(placed.Bytes, out PdfCatalogLocation? updatedCatalog, out string? updatedError), updatedError);
        Assert.IsTrue(updatedCatalog!.HasDssEntry, "PA-5.4.2.1-T1: the catalog gains a DSS entry.");
    }


    /// <summary>
    /// Incremental-update discipline (shared with PA-6.3-k/PA-5.4.3-07): appending a DSS revision never rewrites
    /// a single byte of the prior revision — its own bytes survive at the same offsets, unchanged.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-5.4.2.2-12.
    /// </remarks>
    [TestMethod]
    public void RetainedPriorRevisionBytesAreUnchangedAfterAppendingDss()
    {
        (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(document, out PdfCatalogLocation? catalog, out string? locateError), locateError);

        using PkiCertificateMemory cert = MintDerCertificate("retained-bytes.example.test");
        PdfDssPlacementResult placed = PdfIncrementalUpdateWriter.AppendValidationData(new PdfDssPlacementRequest
        {
            PriorDocument = document,
            Anchor = anchor,
            Catalog = catalog!,
            Certificates = [cert]
        });

        Assert.IsGreaterThan(document.Length, placed.Bytes.Length, "The new revision must be strictly longer.");
        ReadOnlySpan<byte> retainedPrefix = placed.Bytes.AsSpan(0, document.Length);
        Assert.IsTrue(retainedPrefix.SequenceEqual(document), "Every byte of the prior revision must survive unchanged at the same offsets.");
    }


    /// <summary>
    /// PA-5.4.2.2-09 (letter a)), verbatim: "For document signatures or document time-stamp signatures the bytes
    /// that are hashed shall be those of the complete hexadecimal string in the entry with the key Contents ...".
    /// Checked against an independent SHA-1 oracle that slices the ASCII bytes DIRECTLY off the produced
    /// document's own <c>Contents</c> string — never through <see cref="PdfVriKey"/>, and never re-derived from
    /// the decoded signature value — over a fixture deliberately sized so <c>Contents</c>' own reserved capacity
    /// carries genuine trailing zero-padding hexadecimal digits past the real signature value's own end (ISO
    /// 32000-1 clause 7.3.4): the scenario that distinguishes hashing the printed string (correct) from hashing a
    /// re-rendering of the decoded value (silently drops the padding, PA-5.4.2.2-09's own defect this regresses).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-5.4.2.2-T2.
    /// </remarks>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms",
        Justification = "SHA-1 here is the independent oracle for a spec-mandated object-identification digest (PA-5.4.2.2-09), never a signature-strength claim; mirrors CryptoTags.Sha1Digest's own scoped rationale.")]
    public async Task VriKeyForSignatureContentsMatchesTheIndependentSha1OracleOverThePaddedContentsString()
    {
        (byte[] unsigned, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        byte[] signatureValue = [0x30, 0x82, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x00, 0xAB];
        PdfSignaturePlaceholder placeholder = PdfIncrementalUpdateWriter.AppendPlaceholderSignature(
            unsigned, anchor, new PdfSignatureFieldValues { SigningTime = TestClock.CanonicalEpoch }, contentsCapacityBytes: signatureValue.Length + 64);
        byte[] document = PdfIncrementalUpdateWriter.CompleteSignature(placeholder, signatureValue);

        byte[] printedHexAscii = document.AsSpan(placeholder.ContentsHexStart, placeholder.ContentsHexEnd - placeholder.ContentsHexStart).ToArray();
        Assert.IsGreaterThan(signatureValue.Length * 2, printedHexAscii.Length,
            "The fixture must exercise genuine trailing padding, or this test cannot distinguish the fix from the re-rendering defect it regresses.");
        byte[] expectedDigest = SHA1.HashData(printedHexAscii);
        string expectedKey = Convert.ToHexString(expectedDigest);

        using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(document, BaseMemoryPool.Shared);
        Assert.IsTrue(located.IsSuccess, located.FailureReason);
        string actualKey = await PdfVriKey.ForSignatureContentsAsync(located.SignatureDictionaries![0], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedKey, actualKey);
        Assert.IsTrue(PdfVriKey.IsWellFormed(actualKey));
    }


    /// <summary>
    /// PA-5.4.2.2-10 (letter b)), verbatim: "For the signatures of CRLs and OCSP responses, the bytes that are
    /// hashed shall be the respective signature objects represented as a BER-encoded OCTET STRING encoded with
    /// primitive encoding." Checked against an independent oracle that hand-assembles the primitive OCTET STRING
    /// TLV (short-form DER length) and hashes it with <see cref="SHA1"/> directly.
    /// </summary>
    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms",
        Justification = "SHA-1 here is the independent oracle for a spec-mandated object-identification digest (PA-5.4.2.2-10), never a signature-strength claim; mirrors CryptoTags.Sha1Digest's own scoped rationale.")]
    public async Task VriKeyForCrlOrOcspResponseMatchesTheIndependentSha1Oracle()
    {
        byte[] responseDer = [0x30, 0x05, 0x02, 0x01, 0x2A, 0x01, 0x00];
        byte[] octetStringTlv = [0x04, (byte)responseDer.Length, .. responseDer];
        byte[] expectedDigest = SHA1.HashData(octetStringTlv);
        string expectedKey = Convert.ToHexString(expectedDigest);

        string actualKey = await PdfVriKey.ForCrlOrOcspResponseAsync(responseDer, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedKey, actualKey);
    }


    /// <summary>
    /// PA-5.4.2.3-17 ("Any values in the Cert, CRL and OCSP arrays of a Signature VRI dictionary shall also be
    /// present in the DSS dictionary") true by construction: the VRI entry's own <c>Cert</c> array references the
    /// SAME stream objects the DSS-level <c>Certs</c> array references, over a real PAdES-signed document's own
    /// <c>Contents</c>. Also exercises PA-5.4.2.3-12 (<c>TS</c>).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-5.4.2.2-13, PA-5.4.2.3-01, PA-5.4.2.3-02, PA-5.4.2.3-03, PA-5.4.2.3-04,
    /// PA-5.4.2.3-06, PA-5.4.2.3-07, PA-5.4.2.3-08, PA-5.4.2.3-09, PA-5.4.2.3-11, PA-5.4.2.3-18, PA-6.3-T28.
    /// </remarks>
    [TestMethod]
    public async Task WritesAndReadsBackAVriEntryReferencingTheSameDssLevelCertificate()
    {
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

            using PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(signed.Bytes, BaseMemoryPool.Shared);
            Assert.IsTrue(located.IsSuccess, located.FailureReason);
            string vriKey = await PdfVriKey.ForSignatureContentsAsync(located.SignatureDictionaries![0], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            PdfIncrementalUpdateAnchor dssAnchor = LocatePlaceholderAnchor(signed.Bytes, expectedSignatureObjectNumber: 2);
            Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(signed.Bytes, out PdfCatalogLocation? catalog, out string? locateError), locateError);

            using PkiCertificateMemory dssCertificate = ToCarrier(signerCertificate.AsReadOnlySpan().ToArray(), PkiCertificateTags.X509Certificate);
            DateTimeOffset vriTime = TestClock.CanonicalEpoch.AddHours(3);

            PdfDssPlacementResult placed = PdfIncrementalUpdateWriter.AppendValidationData(new PdfDssPlacementRequest
            {
                PriorDocument = signed.Bytes,
                Anchor = dssAnchor,
                Catalog = catalog!,
                Certificates = [dssCertificate],
                VriEntries = new Dictionary<string, PdfVriEntryRequest>(StringComparer.Ordinal)
                {
                    [vriKey] = new PdfVriEntryRequest { CertificateIndices = [0], TimeUpdated = vriTime }
                }
            });

            using PdfDssParseResult readBack = PdfDssReader.Locate(placed.Bytes, BaseMemoryPool.Shared);
            Assert.IsTrue(readBack.IsSuccess, readBack.FailureReason);
            Assert.HasCount(1, readBack.Dss!.VriEntries);
            Assert.IsTrue(readBack.Dss.VriEntries.ContainsKey(vriKey));
            PdfVriDictionary vri = readBack.Dss.VriEntries[vriKey];
            Assert.HasCount(1, vri.Certificates);
            Assert.IsTrue(vri.Certificates[0].AsReadOnlySpan().SequenceEqual(dssCertificate.AsReadOnlySpan()),
                "PA-5.4.2.3-17: the VRI entry's own Cert array references the same certificate the DSS-level Certs array carries.");
            Assert.AreEqual(vriTime, vri.TimeUpdated);
            Assert.IsNull(vri.TimeStampToken);
        }
    }


    /// <summary>PA-5.4.2.3-10/-13: TU and TS are mutually exclusive. Fail-closed at the writer, before any byte is emitted.</summary>
    [TestMethod]
    public void RefusesAVriEntryNamingBothTuAndTs()
    {
        (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(document, out PdfCatalogLocation? catalog, out string? locateError), locateError);

        using PkiCertificateMemory token = ToCarrier([0x30, 0x03, 0x02, 0x01, 0x03], PkiCertificateTags.TimestampToken);
        var request = new PdfDssPlacementRequest
        {
            PriorDocument = document,
            Anchor = anchor,
            Catalog = catalog!,
            VriEntries = new Dictionary<string, PdfVriEntryRequest>(StringComparer.Ordinal)
            {
                [new string('A', 40)] = new PdfVriEntryRequest { TimeUpdated = TestClock.CanonicalEpoch, TimeStampToken = token }
            }
        };

        Assert.ThrowsExactly<ArgumentException>(() => PdfIncrementalUpdateWriter.AppendValidationData(request));
    }


    /// <summary>
    /// PA-5.4.2.3-12: a VRI entry naming <c>TS</c> alone (never <c>TU</c>) round-trips its own DER-encoded
    /// time-stamp token byte-exactly, and <see cref="PdfVriDictionary.TimeUpdated"/> reads back <see langword="null"/> —
    /// the positive counterpart s3's own spot-verification found <see cref="RefusesAVriEntryNamingBothTuAndTs"/>
    /// alone does not cover, since that test's own request is refused before any <c>TS</c> object is ever written.
    /// </summary>
    [TestMethod]
    public void WritesAndReadsBackAVriEntryCarryingATimeStampTokenInsteadOfTu()
    {
        (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(document, out PdfCatalogLocation? catalog, out string? locateError), locateError);

        byte[] tokenDer = [0x30, 0x05, 0x02, 0x01, 0x2A, 0x01, 0x00];
        using PkiCertificateMemory token = ToCarrier(tokenDer, PkiCertificateTags.TimestampToken);
        string vriKey = new string('B', 40);
        PdfDssPlacementResult placed = PdfIncrementalUpdateWriter.AppendValidationData(new PdfDssPlacementRequest
        {
            PriorDocument = document,
            Anchor = anchor,
            Catalog = catalog!,
            VriEntries = new Dictionary<string, PdfVriEntryRequest>(StringComparer.Ordinal)
            {
                [vriKey] = new PdfVriEntryRequest { TimeStampToken = token }
            }
        });

        using PdfDssParseResult located = PdfDssReader.Locate(placed.Bytes, BaseMemoryPool.Shared);
        Assert.IsTrue(located.IsSuccess, located.FailureReason);
        Assert.IsTrue(located.Dss!.VriEntries.ContainsKey(vriKey));
        PdfVriDictionary vri = located.Dss.VriEntries[vriKey];
        Assert.IsNull(vri.TimeUpdated, "PA-5.4.2.3-13: TS present means TU must read back absent.");
        Assert.IsNotNull(vri.TimeStampToken);
        Assert.IsTrue(vri.TimeStampToken!.AsReadOnlySpan().SequenceEqual(tokenDer));
    }


    /// <summary>This writer mints a document's first DSS revision only; a second call over a catalog that already carries <c>DSS</c> refuses fail-closed rather than silently dropping PA-5.4.1-01's own retained-values obligation.</summary>
    [TestMethod]
    public void RefusesToAppendASecondDssRevisionOverAnAlreadyDssCarryingCatalog()
    {
        (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(document, out PdfCatalogLocation? catalog, out string? locateError), locateError);

        using PkiCertificateMemory cert = MintDerCertificate("first-dss.example.test");
        PdfDssPlacementResult first = PdfIncrementalUpdateWriter.AppendValidationData(new PdfDssPlacementRequest
        {
            PriorDocument = document,
            Anchor = anchor,
            Catalog = catalog!,
            Certificates = [cert]
        });

        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(first.Bytes, out PdfCatalogLocation? secondCatalog, out string? secondError), secondError);
        var secondRequest = new PdfDssPlacementRequest
        {
            PriorDocument = first.Bytes,
            Anchor = first.NextAnchor(secondCatalog!.ObjectNumber, secondCatalog.Generation),
            Catalog = secondCatalog
        };

        Assert.ThrowsExactly<ArgumentException>(() => PdfIncrementalUpdateWriter.AppendValidationData(secondRequest));
    }


    /// <summary>A DSS object that resolves to a Name rather than a Dictionary is rejected fail-closed (PA-5.4.2.2-01), not silently accepted as an empty DSS.</summary>
    [TestMethod]
    public void FailsClosedWhenTheDssEntryDoesNotResolveToADictionary()
    {
        var writer = new List<byte>();
        void Ascii(string s) => writer.AddRange(Encoding.ASCII.GetBytes(s));

        Ascii("%PDF-1.7\n");
        int obj1Offset = writer.Count;
        Ascii("1 0 obj\n<< /Type /Catalog /DSS 2 0 R >>\nendobj\n");
        int obj2Offset = writer.Count;
        Ascii("2 0 obj\n/NotADictionary\nendobj\n");
        int xrefOffset = writer.Count;
        Ascii("xref\n0 3\n");
        Ascii("0000000000 65535 f \n");
        Ascii($"{obj1Offset:D10} 00000 n \n");
        Ascii($"{obj2Offset:D10} 00000 n \n");
        Ascii("trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n");
        Ascii(xrefOffset.ToString(CultureInfo.InvariantCulture));
        Ascii("\n%%EOF\n");

        byte[] bytes = [.. writer];
        using PdfDssParseResult located = PdfDssReader.Locate(bytes, BaseMemoryPool.Shared);

        Assert.IsFalse(located.IsSuccess);
        Assert.IsFalse(located.HasDss);
        Assert.IsNotNull(located.FailureReason);
    }


    /// <summary>A well-formed document with no <c>DSS</c> catalog entry is a legitimate, successful "no DSS" outcome (clause 5.4.2.2's own entry is optional) — not a failure.</summary>
    [TestMethod]
    public void ADocumentWithNoDssEntryIsALegitimateNoDssSuccess()
    {
        (byte[] document, _) = BuildUnsignedBasePdf();

        using PdfDssParseResult located = PdfDssReader.Locate(document, BaseMemoryPool.Shared);

        Assert.IsTrue(located.IsSuccess, located.FailureReason);
        Assert.IsFalse(located.HasDss);
        Assert.IsNull(located.Dss);
    }


    [TestMethod]
    public void AppendValidationDataAndPdfDssReaderAreMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();
        (byte[] document, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();
        Assert.IsTrue(PdfByteSurfaceReader.TryLocateCatalog(document, out PdfCatalogLocation? catalog, out string? locateError), locateError);

        using PkiCertificateMemory cert = MintDerCertificate("metered.example.test");
        PdfDssPlacementResult placed = PdfIncrementalUpdateWriter.AppendValidationData(new PdfDssPlacementRequest
        {
            PriorDocument = document,
            Anchor = anchor,
            Catalog = catalog!,
            Certificates = [cert]
        });

        using(PdfDssParseResult located = PdfDssReader.Locate(placed.Bytes, metered.Pool))
        {
            Assert.IsTrue(located.IsSuccess, located.FailureReason);
            Assert.IsTrue(located.HasDss);
        }

        Assert.AreEqual(metered.RentedCount, metered.ReturnedCount, "Every carrier PdfDssReader.Locate rents must be returned once the owning result is disposed.");
        Assert.AreEqual(0, metered.OutstandingCount);
    }


    private static (byte[] Bytes, PdfIncrementalUpdateAnchor Anchor) BuildUnsignedBasePdf()
    {
        var writer = new List<byte>();
        void Ascii(string s) => writer.AddRange(Encoding.ASCII.GetBytes(s));

        Ascii("%PDF-1.7\n");
        int obj1Offset = writer.Count;
        Ascii("1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        int xrefOffset = writer.Count;
        Ascii("xref\n0 2\n");
        Ascii("0000000000 65535 f \n");
        Ascii($"{obj1Offset:D10} 00000 n \n");
        Ascii("trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n");
        Ascii(xrefOffset.ToString(CultureInfo.InvariantCulture));
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

        int xrefOffset = int.Parse(text[numberStart..numberEnd], CultureInfo.InvariantCulture);

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


    private static PkiCertificateMemory MintDerCertificate(string subjectCommonName)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 certificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(key, NotBefore, NotAfter, $"CN={subjectCommonName}");

        return ToCarrier(certificate.RawData, PkiCertificateTags.X509Certificate);
    }


    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }
}
