using System;
using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Validates the targeted PDF byte-surface reader: locating PDF Signature Dictionaries across
/// incremental-update cross-reference sections, byte-exact <c>ByteRange</c> extraction, and fail-closed
/// rejection of the byte-surface defects
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 6.3 requirement k) (PA-6.3-k) rules out. Every fixture is byte-assembled
/// by <see cref="PdfFixtureBuilder"/>, independently of <see cref="PdfByteSurfaceReader"/> itself (the
/// independent-oracle discipline).
/// </summary>
[TestClass]
internal sealed class PdfByteSurfaceReaderTests
{
    private static readonly byte[] FirstContentsPayload = [0x30, 0x82, 0x01, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    private static readonly byte[] SecondContentsPayload = [0x30, 0x82, 0x02, 0x20, 0xFE, 0xED, 0xFA, 0xCE, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90];


    public required TestContext TestContext { get; set; }


    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-4.1-01, PA-5.3-01, PA-6.3-T14, PA-6.3-T15, PA-6.3-T17, PA-6.3-T18,
    /// PA-6.3-T20, PA-6.3-T21, PA-6.3-l.
    /// </remarks>
    [TestMethod]
    public void LocatesASingleUpdatePdfsSignatureDictionary()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(FirstContentsPayload);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(fixture.Bytes, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        IReadOnlyList<PdfSignatureDictionary> signatures = result.SignatureDictionaries!;
        Assert.HasCount(1, signatures);

        PdfSignatureDictionary signature = signatures[0];
        Assert.AreEqual("Adobe.PPKLite", signature.Filter);
        Assert.AreEqual(PdfSubFilter.EtsiCAdESDetached, signature.SubFilter);
        Assert.IsTrue(signature.Contents.AsReadOnlySpan().SequenceEqual(FirstContentsPayload), "The decoded Contents must equal the hex-encoded payload byte-for-byte.");
        Assert.AreEqual(new DateTimeOffset(2025, 3, 14, 12, 0, 0, TimeSpan.FromHours(2)), signature.SigningTime);
        Assert.AreEqual("Helsinki", signature.Location);
        Assert.AreEqual("Testing", signature.Reason);
        Assert.AreEqual("test@example.com", signature.ContactInfo);
        Assert.AreEqual("Test Signer", signature.Name);
        Assert.IsTrue(signature.ByteRange.CoversEntireDocument(fixture.Bytes.Length), "A single-revision document's own signature covers the whole file (PA-6.3-k).");
    }


    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-6.3-T16.
    /// </remarks>
    [TestMethod]
    public void ExtractsTheByteRangeByteExactly()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(FirstContentsPayload);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(fixture.Bytes, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        IReadOnlyList<PdfSignatureDictionary> signatures = result.SignatureDictionaries!;
        PdfByteRange byteRange = signatures[0].ByteRange;

        //Independently known from the builder's own bookkeeping, never derived by asking the reader anything.
        //ISO 32000-1 clause 12.8.1: the gap excludes the entire Contents string value, '<'/'>' delimiters included.
        Assert.AreEqual(fixture.Signature.ContentsHexStart - 1, byteRange.GapStart, "The first segment must end exactly before the opening '<' delimiter.");
        Assert.AreEqual(fixture.Signature.ContentsHexEnd + 1, byteRange.SecondOffset, "The second segment must begin exactly after the closing '>' delimiter.");
        Assert.AreEqual(fixture.Bytes.Length, byteRange.DocumentLength, "The two segments together must span the whole document.");

        ReadOnlyMemory<byte> firstSegment = signatures[0].FirstSignedSegment;
        ReadOnlyMemory<byte> secondSegment = signatures[0].SecondSignedSegment;
        Assert.IsTrue(firstSegment.Span.SequenceEqual(fixture.Bytes.AsSpan(0, byteRange.FirstLength)), "The first signed segment must be an exact view over the document's own leading bytes.");
        Assert.IsTrue(secondSegment.Span.SequenceEqual(fixture.Bytes.AsSpan(byteRange.SecondOffset, byteRange.SecondLength)), "The second signed segment must be an exact view over the document's own trailing bytes.");
        Assert.AreEqual((byte)'<', fixture.Bytes[byteRange.GapStart], "The opening '<' delimiter must be the gap's own first byte, excluded from both signed segments.");
        Assert.AreEqual((byte)'>', fixture.Bytes[byteRange.SecondOffset - 1], "The closing '>' delimiter must be the gap's own last byte, excluded from both signed segments.");
    }


    [TestMethod]
    public void LocatesBothSignaturesAcrossAnIncrementalUpdate()
    {
        PdfFixtureBuilder.IncrementalUpdateFixture fixture = PdfFixtureBuilder.BuildIncrementalUpdateSignedPdf(FirstContentsPayload, SecondContentsPayload);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(fixture.Bytes, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        IReadOnlyList<PdfSignatureDictionary> signatures = result.SignatureDictionaries!;
        Assert.HasCount(2, signatures);

        PdfSignatureDictionary first = signatures[0];
        PdfSignatureDictionary second = signatures[1];
        Assert.IsTrue(first.Contents.AsReadOnlySpan().SequenceEqual(FirstContentsPayload), "The base revision's own signature must decode.");
        Assert.IsTrue(second.Contents.AsReadOnlySpan().SequenceEqual(SecondContentsPayload), "The incremental update's own signature must decode.");
        Assert.AreEqual("First Signer", first.Name);
        Assert.AreEqual("Second Signer", second.Name);

        Assert.IsFalse(first.ByteRange.CoversEntireDocument(fixture.Bytes.Length), "The earlier signature's ByteRange must stop at its own, shorter revision's length, not the final document's.");
        Assert.IsTrue(second.ByteRange.CoversEntireDocument(fixture.Bytes.Length), "The most recent signature's ByteRange must cover the whole final document (PA-6.3-k).");
        Assert.IsLessThan(second.ByteRange.DocumentLength, first.ByteRange.DocumentLength, "The base revision's own ByteRange total must be strictly shorter than the incremental update's.");
    }


    [TestMethod]
    public void FailsClosedOnAMalformedCrossReferenceSection()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(FirstContentsPayload);
        byte[] corrupted = (byte[])fixture.Bytes.Clone();
        PdfFixtureBuilder.CorruptXrefKeyword(corrupted, fixture.XrefOffset);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(corrupted, BaseMemoryPool.Shared);

        Assert.IsFalse(result.IsSuccess, "A document whose 'xref' keyword is overwritten must be reported as malformed, not silently skipped.");
        Assert.IsNotNull(result.FailureReason);
        Assert.IsNull(result.SignatureDictionaries);
    }


    /// <summary>(fail-closed per candidate, not per document): the sole candidate in a single-signature fixture fails the overlap invariant and is skipped, not a document-level failure.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-6.3-k.
    /// </remarks>
    [TestMethod]
    public void FailsClosedOnOverlappingByteRangeSegments()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(FirstContentsPayload);
        byte[] corrupted = (byte[])fixture.Bytes.Clone();
        PdfFixtureBuilder.CorruptByteRangeToOverlap(corrupted, fixture.Signature);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(corrupted, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        Assert.IsEmpty(result.SignatureDictionaries!, "A ByteRange whose two segments overlap must never be accepted as a located signature.");
        Assert.HasCount(1, result.SkippedCandidateReasons, "The overlap must be recorded as a skipped candidate, not silently dropped.");
    }


    /// <summary>(fail-closed per candidate, not per document): the sole candidate in a single-signature fixture fails the gap-alignment invariant and is skipped, not a document-level failure.</summary>
    [TestMethod]
    public void FailsClosedWhenContentsDoesNotSitInsideTheByteRangeGap()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(FirstContentsPayload);
        byte[] corrupted = (byte[])fixture.Bytes.Clone();
        PdfFixtureBuilder.CorruptByteRangeToMissTheContentsGap(corrupted, fixture.Signature, corrupted.Length);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(corrupted, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        Assert.IsEmpty(result.SignatureDictionaries!, "A ByteRange whose gap does not exactly bracket the Contents string must never be accepted as a located signature (PA-6.3-k).");
        Assert.HasCount(1, result.SkippedCandidateReasons, "The misalignment must be recorded as a skipped candidate, not silently dropped.");
    }


    /// <summary>Pinned in the rejecting direction: a ByteRange built with the OLD (delimiters-included) gap convention must be rejected now that ISO 32000-1 clause 12.8.1 requires the '&lt;'/'&gt;' delimiters excluded too.</summary>
    [TestMethod]
    public void RejectsAByteRangeBuiltWithTheOldHexDigitsOnlyGapConvention()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(FirstContentsPayload);
        byte[] corrupted = (byte[])fixture.Bytes.Clone();
        PdfFixtureBuilder.CorruptByteRangeToTheOldHexDigitsOnlyGapConvention(corrupted, fixture.Signature, corrupted.Length);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(corrupted, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        Assert.IsEmpty(result.SignatureDictionaries!, "The old, delimiters-included gap convention must be rejected.");
        Assert.HasCount(1, result.SkippedCandidateReasons);
    }


    /// <summary>the regression: a decoy object shaped like a Signature Dictionary but structurally malformed must not sink the document's own genuinely valid signature.</summary>
    [TestMethod]
    public void AValidSignaturePlusAnAppendedDecoyObjectStillYieldsTheValidSignature()
    {
        PdfFixtureBuilder.SingleUpdateFixture fixture = PdfFixtureBuilder.BuildSingleUpdateSignedPdf(FirstContentsPayload);
        byte[] withDecoy = PdfFixtureBuilder.AppendMalformedDecoySignatureObject(fixture.Bytes, fixture.XrefOffset);

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(withDecoy, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        Assert.HasCount(1, result.SignatureDictionaries!, "The genuinely valid signature must still be located despite the decoy.");
        Assert.IsTrue(result.SignatureDictionaries![0].Contents.AsReadOnlySpan().SequenceEqual(FirstContentsPayload));
        Assert.HasCount(1, result.SkippedCandidateReasons, "The decoy's own malformation must be recorded, not silently absorbed.");
    }


    [TestMethod]
    public void ReportsSuccessWithNoSignaturesForAnUnsignedDocument()
    {
        byte[] unsigned = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n45\n%%EOF\n"u8.ToArray();

        using PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(unsigned, BaseMemoryPool.Shared);

        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        Assert.IsEmpty(result.SignatureDictionaries!);
    }


    [TestMethod]
    public void LocatingAndDisposingIsMeteredPoolBalanced()
    {
        using var metered = new MeteredHousePool();
        PdfFixtureBuilder.IncrementalUpdateFixture fixture = PdfFixtureBuilder.BuildIncrementalUpdateSignedPdf(FirstContentsPayload, SecondContentsPayload);

        using(PdfByteSurfaceParseResult result = PdfByteSurfaceReader.Locate(fixture.Bytes, metered.Pool))
        {
            Assert.IsTrue(result.IsSuccess, result.FailureReason);
            Assert.HasCount(2, result.SignatureDictionaries!);
        }

        Assert.AreEqual(metered.RentedCount, metered.ReturnedCount, "Every carrier the reader rented for a decoded Contents must be returned once the parse result is disposed.");
        Assert.AreEqual(0, metered.OutstandingCount);
    }
}
