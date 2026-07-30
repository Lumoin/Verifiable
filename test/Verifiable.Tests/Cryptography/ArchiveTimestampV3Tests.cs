using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="ArchiveTimestampV3"/> and <see cref="AtsHashIndexV3"/>: the hash index of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.2</see> and the archive time-stamp message imprint input of clause
/// 5.5.3, in both the direction that creates them and the direction that checks them.
/// </summary>
/// <remarks>
/// <para>
/// Every expected value comes from <see cref="AtsHashIndexV3Oracle"/>, an independent reimplementation written
/// from the clause text: it walks the structure with the hand-written walker of the augmentation tests, encodes
/// the index with its own writer, and hashes through a different digest implementation than the one the test
/// host registers. The strongest leg is the round trip: an archive time-stamp token minted by the independent
/// time-stamp protocol oracle over the imprint input this library built, whose own message imprint the library
/// then verifies against the input it recomputes from the wire bytes alone.
/// </para>
/// <para>
/// Signatures are minted by the framework's own CMS signer and augmented through the shipped byte-preserving
/// splice, so the inputs are structures a real signer produced rather than fixtures shaped to suit the
/// computation. Instants are derived from <see cref="TestClock.CanonicalEpoch"/>; nothing here reads a clock.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ArchiveTimestampV3Tests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time the minted signatures carry.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The generation time the minted signature time-stamps carry.</summary>
    private static DateTimeOffset SignatureTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The generation time the minted archive time-stamps carry.</summary>
    private static DateTimeOffset ArchiveTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the archive time-stamped content"u8.ToArray());

    /// <summary>An attribute type the tests append material under, chosen from the CAdES unsigned attributes.</summary>
    private static string FirstAppendedAttributeType { get; } = CAdESSignatureFacts.CertificateValuesAttributeOid;

    /// <summary>A second attribute type the tests append material under.</summary>
    private static string SecondAppendedAttributeType { get; } = CAdESSignatureFacts.RevocationValuesAttributeOid;


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The index the library computes over a signature's current material is the one the independent oracle
    /// recomputes, octet for octet — the same algorithm identifier, the same three lists, the same entries in
    /// the same order.
    /// </summary>
    [TestMethod]
    public async Task ComputesTheHashIndexTheIndependentOracleRecomputes()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCAdEST(
            Content.Span, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);

        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = signature.AsReadOnlySpan().ToArray();
        using PooledMemory expected = AtsHashIndexV3Oracle.EncodeHashIndex(octets, signerIndex: 0, PkiDigestAlgorithm.Sha256);

        Assert.AreSequenceEqual(expected.AsReadOnlySpan().ToArray(), hashIndex.AsReadOnlySpan().ToArray(),
            "Clause 5.5.2: the encoded ats-hash-index-v3 is the one an independent computation from the clause text produces.");
        Assert.AreEqual(PkiDigestAlgorithm.Sha256.Identifier.Oid, hashIndex.HashIndexAlgorithm.Oid, "The index states the algorithm its hash values were computed under.");
        Assert.HasCount(1, hashIndex.CertificatesHashIndex, "A signature embedding its signer's certificate indexes exactly that one instance of CertificateChoices.");
        Assert.IsEmpty(hashIndex.CrlsHashIndex, "Clause 5.5.2 NOTE 3: an absent crls field leaves the list empty.");
        Assert.HasCount(1, hashIndex.UnsignedAttributeValuesHashIndex, "A CAdES-B-T signature carries one unsigned attribute with one value, the signature time-stamp.");

        using DigestValue expectedCertificateHash = AtsHashIndexV3Oracle.Hash(AtsHashIndexV3Oracle.CertificateEncodings(octets)[0], PkiDigestAlgorithm.Sha256);
        Assert.AreSequenceEqual(expectedCertificateHash.AsReadOnlySpan().ToArray(), hashIndex.CertificatesHashIndex[0].ToArray(),
            "Clause 5.5.2: a certificate's hash value covers its entire encoded component, tag and length octets included.");

        using DigestValue expectedAttributeHash = AtsHashIndexV3Oracle.Hash(
            AtsHashIndexV3Oracle.UnsignedAttributeTypeAndValueConcatenations(octets, signerIndex: 0)[0], PkiDigestAlgorithm.Sha256);
        Assert.AreSequenceEqual(expectedAttributeHash.AsReadOnlySpan().ToArray(), hashIndex.UnsignedAttributeValuesHashIndex[0].ToArray(),
            "Clause 5.5.2: an unsigned attribute's hash value covers the concatenation of its attrType field and the one AttributeValue.");
    }


    /// <summary>
    /// The message imprint input the library assembles is the one the independent oracle assembles, and its
    /// four parts appear in the order clause 5.5.3 lists them: the eContentType field, the hash of the signed
    /// data, the SignerInfo fields other than unsignedAttrs, and the index.
    /// </summary>
    [TestMethod]
    public async Task BuildsTheMessageImprintInputTheIndependentOracleAssembles()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCAdEST(
            Content.Span, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);

        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SignedContentMemory imprintInput = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
            new ArchiveTimestampImprintContext
            {
                SignedData = signature,
                HashIndex = hashIndex,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = signature.AsReadOnlySpan().ToArray();
        using SignedContentMemory expected = AtsHashIndexV3Oracle.BuildMessageImprintInput(
            octets, signerIndex: 0, hashIndex.AsReadOnlySpan(), PkiDigestAlgorithm.Sha256);

        Assert.AreSequenceEqual(expected.AsReadOnlySpan().ToArray(), imprintInput.AsReadOnlySpan().ToArray(),
            "Clause 5.5.3: the imprint input is the one an independent computation from the clause text assembles.");

        byte[] built = imprintInput.AsReadOnlySpan().ToArray();
        byte[] contentType = AtsHashIndexV3Oracle.EncapsulatedContentTypeEncoding(octets);
        Assert.AreSequenceEqual(contentType, built[..contentType.Length], "Part 1) is the whole encoding of SignedData.encapContentInfo.eContentType.");

        using DigestValue contentHash = AtsHashIndexV3Oracle.Hash(AtsHashIndexV3Oracle.EncapsulatedContent(octets), PkiDigestAlgorithm.Sha256);
        Assert.AreSequenceEqual(contentHash.AsReadOnlySpan().ToArray(), built[contentType.Length..(contentType.Length + contentHash.AsReadOnlySpan().Length)],
            "Part 2) is the hash of the signed data, recomputed under the archive time-stamp's own algorithm.");
        Assert.AreSequenceEqual(hashIndex.AsReadOnlySpan().ToArray(), built[^hashIndex.Length..],
            "Part 4) is a single instance of ATSHashIndexV3, and it ends the input.");

        List<byte[]> signerFields = AtsHashIndexV3Oracle.ImprintSignerFields(octets, signerIndex: 0);
        Assert.HasCount(6, signerFields, "Part 3) is version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm and signature.");

        int fieldsLength = 0;
        foreach(byte[] field in signerFields)
        {
            fieldsLength += field.Length;
        }

        Assert.HasCount(contentType.Length + contentHash.AsReadOnlySpan().Length + fieldsLength + hashIndex.Length, built,
            "The input is exactly the four parts and nothing else — the unsignedAttrs field is not among them.");
    }


    /// <summary>
    /// The two directions agree where it counts: an archive time-stamp token minted over the imprint input this
    /// library built verifies against the input the library recomputes from the signature's wire bytes after
    /// the token has been attached, and the coverage report names what the index protects.
    /// </summary>
    [TestMethod]
    public async Task StatesTheCoverageOfAnArchiveTimestampAndTheTokenVerifiesAgainstIt()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdEST(
            Content.Span, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);

        using TsaScenario tsa = BuildTimeStampingAuthority();
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            baseline, baseline, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = world.Signature, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "A signature carrying the archive time-stamp it was built for has its coverage stated.");
        Assert.IsNotNull(coverage.MessageImprintInput, "A stated coverage carries the octets the imprint was computed over.");
        Assert.IsNotNull(coverage.ProtectedObjects, "A stated coverage reports which objects the index protects.");

        using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(
            world.Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(tokenInfo.IsRead, "Grafting the ats-hash-index-v3 attribute into the token leaves the token's own signature verifiable.");
        Assert.IsTrue(
            await tokenInfo.VerifyMessageImprintAsync(coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "Clause 5.5.3: the imprint recomputed at validation is the one the token was created over.");

        AtsHashIndexCoverage objects = coverage.ProtectedObjects!;
        Assert.IsTrue(objects.EveryIndexEntryMatched, "Every entry of the index matches material the signature still carries.");
        Assert.HasCount(1, objects.Certificates, "The signature carries the signer's certificate.");
        Assert.IsTrue(objects.Certificates[0].IsCovered, "The certificate present when the index was built is covered by it.");
        Assert.HasCount(2, objects.UnsignedAttributeValues, "The signature now carries the signature time-stamp and the archive time-stamp attributes.");

        CoveredAttributeValue archiveAttribute = FindAttributeValue(objects, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        CoveredAttributeValue signatureTimestamp = FindAttributeValue(objects, CAdESSignatureFacts.SignatureTimestampAttributeOid);

        Assert.IsTrue(signatureTimestamp.IsCovered, "The signature time-stamp was present when the index was built, so the index covers it.");
        Assert.IsFalse(archiveAttribute.IsCovered, "The archive time-stamp attribute was added after the index was built, so it is not covered by its own index.");
    }


    /// <summary>
    /// Material added after an archive time-stamp was applied is reported as uncovered and is not an error —
    /// clause 5.5.2's NOTE 5 is the point of the design, and the earlier token still verifies against the
    /// imprint recomputed over the augmented signature.
    /// </summary>
    [TestMethod]
    public async Task MaterialAddedAfterTheArchiveTimestampIsUncoveredAndNotAnError()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdEST(
            Content.Span, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);

        using TsaScenario tsa = BuildTimeStampingAuthority();
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            baseline, baseline, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);

        using CmsAttribute added = CmsAttribute.Create(FirstAppendedAttributeType, WriteOctetString([0x51, 0x52, 0x53]), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(world.Signature, signerIndex: 0, [added], BaseMemoryPool.Shared);

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = augmented, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status,
            "Clause 5.5.2 NOTE 5: adding material after an archive time-stamp does not invalidate it.");

        using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(
            world.Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            await tokenInfo.VerifyMessageImprintAsync(coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The earlier archive time-stamp still verifies against the imprint recomputed over the augmented signature.");

        CoveredAttributeValue appended = FindAttributeValue(coverage.ProtectedObjects!, FirstAppendedAttributeType);
        Assert.IsFalse(appended.IsCovered, "An attribute value added after the index was built has no entry, and that is reported rather than treated as a failure.");
        Assert.IsTrue(FindAttributeValue(coverage.ProtectedObjects!, CAdESSignatureFacts.SignatureTimestampAttributeOid).IsCovered,
            "What the index did name is still covered.");
    }


    /// <summary>
    /// The check runs from the index towards the material, and only that way: an index entry naming an
    /// attribute value the signature does not carry makes the index invalid, and no imprint input is stated.
    /// </summary>
    [TestMethod]
    public async Task AnIndexEntryWithNoMatchingMaterialMakesTheIndexInvalid()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdEST(
            Content.Span, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);

        using CmsAttribute removedLater = CmsAttribute.Create(FirstAppendedAttributeType, WriteOctetString([0x61, 0x62]), BaseMemoryPool.Shared);
        using CmsSignedData richer = CmsSignedDataAugmentation.AppendUnsignedAttributes(baseline, signerIndex: 0, [removedLater], BaseMemoryPool.Shared);

        using TsaScenario tsa = BuildTimeStampingAuthority();

        //The index and the token are built over the richer signature, and the token is then attached to the one
        //that never carried the extra attribute — the shape of material having gone missing since the archive
        //time-stamp was applied.
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            baseline, richer, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = world.Signature, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexInvalid, coverage.Status,
            "Clause 5.5.2: an index holding a reference for which the original value is not found is invalid.");
        Assert.IsNull(coverage.MessageImprintInput, "An invalid index states no imprint input, so no proof of existence can be derived from the token.");
        Assert.IsFalse(coverage.ProtectedObjects!.EveryIndexEntryMatched, "The report names the reason: an entry matched nothing.");
    }


    /// <summary>
    /// An element that is re-encoded rather than modified loses its coverage: clause 5.5.2's NOTE 7 states that
    /// an encoding change to a protected element makes validation fail, because the recomputed hash is no
    /// longer among the ones the index holds. The two signatures here differ only in how one attribute value
    /// encodes the same boolean — the canonical form X.690 clause 11.1 requires of DER, and the other form the
    /// basic rules admit.
    /// </summary>
    [TestMethod]
    public async Task AReEncodedCoveredElementLosesItsCoverage()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdEST(
            Content.Span, signerCertificate, SigningTime, timestampCertificate, SignatureTimestampTime);

        using CmsAttribute distinguished = EncodeAttributeWithShortLengths(FirstAppendedAttributeType, [0x01, 0x01, 0xFF]);
        using CmsAttribute basic = EncodeAttributeWithShortLengths(FirstAppendedAttributeType, [0x01, 0x01, 0x01]);
        using CmsSignedData asDistinguished = CmsSignedDataAugmentation.AppendUnsignedAttributes(baseline, signerIndex: 0, [distinguished], BaseMemoryPool.Shared);
        using CmsSignedData asBasic = CmsSignedDataAugmentation.AppendUnsignedAttributes(baseline, signerIndex: 0, [basic], BaseMemoryPool.Shared);

        using TsaScenario tsa = BuildTimeStampingAuthority();
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            asDistinguished, asDistinguished, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);

        using ArchiveTimestampCoverage stated = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = world.Signature, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, stated.Status, "The signature whose octets the index was built over has its coverage stated.");

        //The archive time-stamp attribute is moved onto the signature carrying the other encoding of the same
        //value; nothing else about the two structures differs.
        using CmsAttribute archiveAttribute = CmsAttribute.Create(
            CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, world.Token.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using CmsSignedData reEncoded = CmsSignedDataAugmentation.AppendUnsignedAttributes(asBasic, signerIndex: 0, [archiveAttribute], BaseMemoryPool.Shared);

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = reEncoded, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexInvalid, coverage.Status,
            "Clause 5.5.2 NOTE 7: re-encoding an element the index protects makes the archive time-stamp fail to validate.");
        Assert.IsNull(coverage.MessageImprintInput, "Nothing is stated about what a token whose index no longer matches protects.");
    }


    /// <summary>
    /// The unit of the unsigned-attribute index is the attribute value, not the attribute: an attribute
    /// carrying two values contributes two entries, and each names one value.
    /// </summary>
    [TestMethod]
    public async Task IndexesEveryValueOfAMultiValuedUnsignedAttributeSeparately()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdES(Content.Span, signerCertificate, SigningTime);

        ReadOnlyMemory<byte>[] values = [WriteOctetString([0x01, 0x02]), WriteOctetString([0x03, 0x04])];
        using CmsAttribute multiValued = CmsAttribute.Create(FirstAppendedAttributeType, values, BaseMemoryPool.Shared);
        using CmsSignedData signature = CmsSignedDataAugmentation.AppendUnsignedAttributes(baseline, signerIndex: 0, [multiValued], BaseMemoryPool.Shared);

        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, hashIndex.UnsignedAttributeValuesHashIndex,
            "Clause 5.5.2: the sequence holds one octet string for every component within the attrValues field of every Attribute.");

        byte[] octets = signature.AsReadOnlySpan().ToArray();
        List<byte[]> concatenations = AtsHashIndexV3Oracle.UnsignedAttributeTypeAndValueConcatenations(octets, signerIndex: 0);
        Assert.HasCount(2, concatenations, "The independent walk finds the same two values.");

        for(int i = 0; i < concatenations.Count; ++i)
        {
            using DigestValue expected = AtsHashIndexV3Oracle.Hash(concatenations[i], PkiDigestAlgorithm.Sha256);
            Assert.AreSequenceEqual(expected.AsReadOnlySpan().ToArray(), hashIndex.UnsignedAttributeValuesHashIndex[i].ToArray(),
                "Each entry is the hash of one attrType field concatenated with one AttributeValue.");
        }

        using TsaScenario tsa = BuildTimeStampingAuthority();
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            signature, signature, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);
        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = world.Signature, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "The multi-valued attribute's values are all found again.");
        Assert.HasCount(3, coverage.ProtectedObjects!.UnsignedAttributeValues, "Coverage is reported per value: the two indexed ones and the archive time-stamp attribute.");
        Assert.IsTrue(coverage.ProtectedObjects!.UnsignedAttributeValues[0].IsCovered, "The first value of the multi-valued attribute is covered.");
        Assert.IsTrue(coverage.ProtectedObjects!.UnsignedAttributeValues[1].IsCovered, "The second value of the multi-valued attribute is covered.");
        Assert.AreEqual(0, coverage.ProtectedObjects!.UnsignedAttributeValues[1].AttributeIndex, "Both values belong to the same attribute.");
        Assert.AreEqual(1, coverage.ProtectedObjects!.UnsignedAttributeValues[1].ValueIndex, "The second value is reported at its own position within that attribute.");
    }


    /// <summary>
    /// Clause 5.5.2 NOTE 3: a <c>SignedData</c> carrying no <c>certificates</c> and no <c>crls</c> field yields
    /// two zero-length hash-index lists rather than an unstated index, and that index reads back as it was
    /// written.
    /// </summary>
    [TestMethod]
    public async Task LeavesTheCertificateAndRevocationListsEmptyWhenTheFieldsAreAbsent()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCmsWithoutCertificates(Content.Span, signerCertificate);

        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(hashIndex.CertificatesHashIndex, "An absent certificates field leaves the certificatesHashIndex empty.");
        Assert.IsEmpty(hashIndex.CrlsHashIndex, "An absent crls field leaves the crlsHashIndex empty.");
        Assert.IsEmpty(hashIndex.UnsignedAttributeValuesHashIndex, "A signer with no unsigned attributes leaves the unsignedAttrValuesHashIndex empty.");

        using PooledMemory expected = AtsHashIndexV3Oracle.EncodeHashIndex(signature.AsReadOnlySpan().ToArray(), signerIndex: 0, PkiDigestAlgorithm.Sha256);
        Assert.AreSequenceEqual(expected.AsReadOnlySpan().ToArray(), hashIndex.AsReadOnlySpan().ToArray(),
            "An index over nothing is still a well-formed ATSHashIndexV3 with three empty SEQUENCEs.");

        using AtsHashIndexV3 readBack = AtsHashIndexV3.Read(hashIndex.AsReadOnlySpan(), BaseMemoryPool.Shared);
        Assert.AreEqual(hashIndex, readBack, "The encoded index reads back as the value it was written from.");
    }


    /// <summary>
    /// Clause 5.5.2: the index's <c>hashIndAlgorithm</c> shall be the algorithm of the token's own message
    /// imprint. An index under another algorithm is refused rather than evaluated, because its hash values name
    /// nothing the token's imprint binds.
    /// </summary>
    [TestMethod]
    public async Task RefusesAnIndexWhoseAlgorithmIsNotTheTokensMessageImprintAlgorithm()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdES(Content.Span, signerCertificate, SigningTime);

        using TsaScenario tsa = BuildTimeStampingAuthority();

        //The index is built under SHA-384 while the time-stamping authority oracle mints SHA-256 imprints, which
        //is exactly the disagreement clause 5.5.2 forbids.
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            baseline, baseline, tsa.Authority, PkiDigestAlgorithm.Sha384, TestContext.CancellationToken).ConfigureAwait(false);

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = world.Signature, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexAlgorithmMismatch, coverage.Status,
            "An index whose algorithm is not the token's message-imprint algorithm states no coverage.");
        Assert.IsNull(coverage.MessageImprintInput, "Nothing is stated, so there are no octets to hand a validation process.");
    }


    /// <summary>
    /// The attribute is read out of the token's own unsigned attributes, which is where clause 5.5.3 places it,
    /// and a token that carries none — the shape of the deprecated v2 archive time-stamp of Annex A.2.4 — is
    /// reported as carrying none rather than guessed at.
    /// </summary>
    [TestMethod]
    public async Task ReadsTheHashIndexOutOfATokenAndReportsAbsenceWhenThereIsNone()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdES(Content.Span, signerCertificate, SigningTime);

        using TsaScenario tsa = BuildTimeStampingAuthority();
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            baseline, baseline, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);

        using AtsHashIndexV3? read = ArchiveTimestampV3.ReadHashIndexFromToken(world.Token, BaseMemoryPool.Shared);
        Assert.IsNotNull(read, "Clause 5.5.3: an archive-time-stamp-v3 token includes a single ats-hash-index-v3 unsigned attribute.");
        Assert.AreEqual(world.HashIndex, read, "The attribute carries the very index the imprint was computed over.");

        using PkiCertificateMemory withoutIndex = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], world.ImprintInput.AsReadOnlyMemory(), ArchiveTimestampTime, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using AtsHashIndexV3? absent = ArchiveTimestampV3.ReadHashIndexFromToken(withoutIndex, BaseMemoryPool.Shared);
        Assert.IsNull(absent, "A token carrying no ats-hash-index-v3 attribute yields none.");

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = world.Signature, ArchiveTimestampToken = withoutIndex },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexAbsent, coverage.Status, "Without an index nothing is stated about what the token protects.");
    }


    /// <summary>
    /// A detached signature has no encapsulated content, so step 2) of clause 5.5.3 needs the hash of the signed
    /// data from elsewhere (NOTE 1). The caller supplies the content or its digest; supplying neither fails
    /// closed, and a digest of the wrong length is refused rather than adapted.
    /// </summary>
    [TestMethod]
    public async Task TakesTheSignedDataHashOfADetachedSignatureFromTheCaller()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData attached = CmsSignedDataTestFactory.SignAsCAdES(Content.Span, signerCertificate, SigningTime);
        using CmsSignedData detached = StripEncapsulatedContent(attached);

        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            detached, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () => await ArchiveTimestampV3.BuildMessageImprintInputAsync(
                new ArchiveTimestampImprintContext { SignedData = detached, HashIndex = hashIndex, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256 },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "Clause 5.5.3 NOTE 1: without the signed data or its hash the imprint input has no step 2), and nothing is invented for it.").ConfigureAwait(false);

        using SignedContentMemory content = SignedContentMemory.FromBytes(Content.Span, BaseMemoryPool.Shared);
        using SignedContentMemory fromContent = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
            new ArchiveTimestampImprintContext
            {
                SignedData = detached,
                HashIndex = hashIndex,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                DetachedSignedContent = content
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using DigestValue contentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using SignedContentMemory fromDigest = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
            new ArchiveTimestampImprintContext
            {
                SignedData = detached,
                HashIndex = hashIndex,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                DetachedSignedContentDigest = contentDigest
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreSequenceEqual(fromContent.AsReadOnlySpan().ToArray(), fromDigest.AsReadOnlySpan().ToArray(),
            "The two forms clause 5.5.3 NOTE 1 admits produce the same imprint input.");

        using DigestValue wrongLength = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha384.OutputByteLength, PkiDigestAlgorithm.Sha384.DigestTag, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () => await ArchiveTimestampV3.BuildMessageImprintInputAsync(
                new ArchiveTimestampImprintContext
                {
                    SignedData = detached,
                    HashIndex = hashIndex,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    DetachedSignedContentDigest = wrongLength
                },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A digest under another algorithm than the archive time-stamp's own is refused, because clause 5.5.3 fixes which algorithm step 2) uses.").ConfigureAwait(false);
    }


    /// <summary>
    /// The encoded index reads back through its own reader, and octets that are not a single well-formed DER
    /// <c>ATSHashIndexV3</c> are refused rather than partly accepted.
    /// </summary>
    [TestMethod]
    public async Task RoundTripsAnEncodedIndexAndRefusesOctetsThatAreNotOne()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCAdES(Content.Span, signerCertificate, SigningTime);

        using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using AtsHashIndexV3 readBack = AtsHashIndexV3.Read(hashIndex.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(hashIndex.HashIndexAlgorithm, readBack.HashIndexAlgorithm, "The algorithm survives the round trip.");
        Assert.HasCount(hashIndex.CertificatesHashIndex.Count, readBack.CertificatesHashIndex, "The certificates list survives the round trip.");
        Assert.AreSequenceEqual(hashIndex.CertificatesHashIndex[0].ToArray(), readBack.CertificatesHashIndex[0].ToArray(), "Each entry survives the round trip.");
        Assert.AreEqual(hashIndex, readBack, "An index equals one read back from its own octets.");

        byte[] encoded = hashIndex.AsReadOnlySpan().ToArray();

        Assert.ThrowsExactly<AsnContentException>(
            () => AtsHashIndexV3.Read([.. encoded, 0x00], BaseMemoryPool.Shared),
            "Octets after the structure are rejected rather than ignored.");
        Assert.ThrowsExactly<AsnContentException>(
            () => AtsHashIndexV3.Read(encoded.AsSpan()[..^2], BaseMemoryPool.Shared),
            "A truncated structure is refused.");
        Assert.ThrowsExactly<ArgumentException>(
            () => AtsHashIndexV3.Read(ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared),
            "An empty attribute value is not an ATSHashIndexV3.");
        Assert.ThrowsExactly<AsnContentException>(
            () => AtsHashIndexV3.Read(signerCertificate.RawData, BaseMemoryPool.Shared),
            "A structure that is not an ATSHashIndexV3 at all is refused.");
    }


    /// <summary>
    /// Input the computation cannot walk states no coverage rather than throwing into the validation process
    /// that called it, and the generator-facing entry points refuse the same input with a typed exception.
    /// </summary>
    [TestMethod]
    public async Task MapsUnwalkableInputToNoCoverageAndRefusesItOnTheGeneratorSide()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdES(Content.Span, signerCertificate, SigningTime);

        using TsaScenario tsa = BuildTimeStampingAuthority();
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            baseline, baseline, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = world.Signature.AsReadOnlySpan().ToArray();
        using CmsSignedData truncated = CmsSignedData.FromBytes(octets.AsSpan()[..^5], BaseMemoryPool.Shared);
        using CmsSignedData notSignedData = CmsSignedData.FromBytes(signerCertificate.RawData, BaseMemoryPool.Shared);

        using ArchiveTimestampCoverage fromTruncated = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = truncated, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using ArchiveTimestampCoverage fromForeign = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = notSignedData, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.SignedDataMalformed, fromTruncated.Status, "A truncated Signed Data Object states no coverage.");
        Assert.AreEqual(ArchiveTimestampCoverageStatus.SignedDataMalformed, fromForeign.Status, "A structure that is not a CMS SignedData states no coverage.");
        Assert.IsNull(fromTruncated.MessageImprintInput, "Nothing is stated, so nothing is handed onward.");

        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () => await ArchiveTimestampV3.ComputeHashIndexAsync(
                notSignedData, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A generator handed something that is not a CMS SignedData has made a composition error, which is reported as one.").ConfigureAwait(false);
        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () => await ArchiveTimestampV3.ComputeHashIndexAsync(
                world.Signature, signerIndex: 1, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A single-signer signature has no second SignerInfo to archive time-stamp.").ConfigureAwait(false);
    }


    /// <summary>
    /// Clause 4.7.2 permits BER generally, and <see cref="CmsSignedDataAugmentation"/> itself preserves an
    /// indefinite-length BER wrapper rather than rejecting it (a third-party verifier may still need the
    /// original octets). This computation is knowingly narrower: an indefinite-length Signed Data Object states
    /// no coverage — the documented gap <see cref="ArchiveTimestampV3"/>'s remarks on its private
    /// <c>ReadMaterial</c> record — and the generator-facing entry points refuse the same structure with a
    /// typed parse exception rather than a silent DER re-encoding, which is exactly the change NOTE 7 forbids.
    /// A signature left in legal indefinite-length BER form is therefore not self-validatable by this library's
    /// own ATSv3 coverage computation, even though a differently-scoped verifier could still check it.
    /// </summary>
    [TestMethod]
    public async Task MapsAnIndefiniteLengthBerSignedDataObjectToNoCoverageAndRefusesItOnTheGeneratorSide()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData baseline = CmsSignedDataTestFactory.SignAsCAdES(Content.Span, signerCertificate, SigningTime);

        using TsaScenario tsa = BuildTimeStampingAuthority();
        using ArchiveTimestampedSignature world = await ApplyArchiveTimestampAsync(
            baseline, baseline, tsa.Authority, PkiDigestAlgorithm.Sha256, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] indefiniteLengthOctets = CmsStructureOracle.ToIndefiniteOuterWrappers(world.Signature.AsReadOnlySpan().ToArray());
        using CmsSignedData indefiniteLength = CmsSignedData.FromBytes(indefiniteLengthOctets, BaseMemoryPool.Shared);

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = indefiniteLength, ArchiveTimestampToken = world.Token },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.SignedDataMalformed, coverage.Status,
            "The DER-only scope documented at ReadMaterial states no coverage for an indefinite-length Signed Data Object rather than accepting and mishandling it.");
        Assert.IsNull(coverage.MessageImprintInput, "Nothing is stated, so nothing is handed onward.");

        await Assert.ThrowsExactlyAsync<AsnContentException>(
            async () => await ArchiveTimestampV3.ComputeHashIndexAsync(
                indefiniteLength, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The generator-facing hash-index computation refuses the same indefinite-length structure with a typed parse exception.").ConfigureAwait(false);
        await Assert.ThrowsExactlyAsync<AsnContentException>(
            async () => await ArchiveTimestampV3.BuildMessageImprintInputAsync(
                new ArchiveTimestampImprintContext { SignedData = indefiniteLength, HashIndex = world.HashIndex, MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256 },
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The generator-facing message-imprint-input assembly refuses it identically.").ConfigureAwait(false);
    }


    /// <summary>
    /// Finds one attribute value of a coverage report by its attribute type.
    /// </summary>
    /// <param name="coverage">The coverage report.</param>
    /// <param name="attributeType">The attribute type object identifier to find.</param>
    /// <returns>The reported coverage of that attribute's first value.</returns>
    private static CoveredAttributeValue FindAttributeValue(AtsHashIndexCoverage coverage, string attributeType)
    {
        for(int i = 0; i < coverage.UnsignedAttributeValues.Count; ++i)
        {
            if(string.Equals(coverage.UnsignedAttributeValues[i].AttributeType, attributeType, StringComparison.Ordinal))
            {
                return coverage.UnsignedAttributeValues[i];
            }
        }

        Assert.Fail($"The coverage report names no unsigned attribute of type '{attributeType}'.");

        return default;
    }


    /// <summary>
    /// Applies an archive time-stamp the way clause 5.5.3 describes: the index is computed over one signature,
    /// the imprint input is assembled from it, an independent time-stamping authority mints a token over that
    /// input, the index is grafted into the token's own unsigned attributes, and the token is attached to the
    /// signature as the archive-time-stamp-v3 attribute.
    /// </summary>
    /// <param name="attachTo">The signature the attribute is attached to.</param>
    /// <param name="indexed">The signature the index and the imprint are computed over, usually the same one.</param>
    /// <param name="authority">The time-stamping authority node that mints the token.</param>
    /// <param name="algorithm">The algorithm the index states.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The archive-time-stamped signature and the material it was built from; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of every carrier transfers to the returned record, which the caller disposes.")]
    private static async ValueTask<ArchiveTimestampedSignature> ApplyArchiveTimestampAsync(
        CmsSignedData attachTo,
        CmsSignedData indexed,
        X509ChainTestRingNode authority,
        PkiDigestAlgorithm algorithm,
        CancellationToken cancellationToken)
    {
        AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
            indexed, signerIndex: 0, algorithm, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        SignedContentMemory imprintInput = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
            new ArchiveTimestampImprintContext { SignedData = indexed, HashIndex = hashIndex, MessageImprintAlgorithm = algorithm },
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory minted = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], imprintInput.AsReadOnlyMemory(), ArchiveTimestampTime, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        //Clause 5.5.3: the archive-time-stamp-v3 shall include, as an unsigned attribute of the token itself, a
        //single ats-hash-index-v3 attribute. A time-stamp token is a CMS SignedData, so the graft is the same
        //byte-preserving splice every other augmentation uses.
        using CmsSignedData tokenAsSignedData = CmsSignedData.FromBytes(minted.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using CmsAttribute indexAttribute = CmsAttribute.Create(
            CAdESSignatureFacts.AtsHashIndexV3AttributeOid, hashIndex.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using CmsSignedData grafted = CmsSignedDataAugmentation.AppendUnsignedAttributes(
            tokenAsSignedData, signerIndex: 0, [indexAttribute], BaseMemoryPool.Shared);

        PkiCertificateMemory token = ToTokenCarrier(grafted.AsReadOnlySpan());
        using CmsAttribute archiveAttribute = CmsAttribute.Create(
            CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, grafted.AsReadOnlySpan(), BaseMemoryPool.Shared);
        CmsSignedData signature = CmsSignedDataAugmentation.AppendUnsignedAttributes(
            attachTo, signerIndex: 0, [archiveAttribute], BaseMemoryPool.Shared);

        return new ArchiveTimestampedSignature(signature, token, hashIndex, imprintInput);
    }


    /// <summary>
    /// Copies token octets into the carrier kind an embedded time-stamp arrives in.
    /// </summary>
    /// <param name="der">The DER-encoded token.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToTokenCarrier(ReadOnlySpan<byte> der)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(der.Length);
        try
        {
            der.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Removes the <c>eContent</c> field of a signature's <c>encapContentInfo</c>, producing the detached shape
    /// whose signed data has to be supplied from outside. The structure is rebuilt with an independent writer
    /// rather than spliced, because a detached signature is a different structure rather than an augmented one.
    /// </summary>
    /// <param name="attached">The signature encapsulating its content.</param>
    /// <returns>The same signature without the encapsulated content; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the carrier transfers to the caller, which disposes it.")]
    private static CmsSignedData StripEncapsulatedContent(CmsSignedData attached)
    {
        byte[] octets = attached.AsReadOnlySpan().ToArray();
        CmsTlvBounds contentInfo = CmsStructureOracle.ReadElement(octets, 0);
        List<CmsTlvBounds> contentInfoChildren = CmsStructureOracle.Children(octets, contentInfo);
        CmsTlvBounds content = contentInfoChildren[^1];
        CmsTlvBounds signedData = CmsStructureOracle.Children(octets, content)[0];
        List<CmsTlvBounds> signedDataChildren = CmsStructureOracle.Children(octets, signedData);
        CmsTlvBounds encapContentInfo = signedDataChildren[2];
        List<CmsTlvBounds> encapChildren = CmsStructureOracle.Children(octets, encapContentInfo);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteEncodedValue(Element(octets, contentInfoChildren[0]));
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteEncodedValue(Element(octets, signedDataChildren[0]));
                    writer.WriteEncodedValue(Element(octets, signedDataChildren[1]));
                    using(writer.PushSequence())
                    {
                        writer.WriteEncodedValue(Element(octets, encapChildren[0]));
                    }

                    for(int i = 3; i < signedDataChildren.Count; ++i)
                    {
                        writer.WriteEncodedValue(Element(octets, signedDataChildren[i]));
                    }
                }
            }
        }

        return CmsSignedData.FromBytes(writer.Encode(), BaseMemoryPool.Shared);

        //One element's whole encoding as a span over the structure, so nothing is copied to be written back out.
        static ReadOnlySpan<byte> Element(byte[] octets, CmsTlvBounds bounds) => octets.AsSpan(bounds.Start, bounds.End - bounds.Start);
    }


    /// <summary>
    /// Encodes a CMS <c>Attribute</c> from octets chosen exactly, rather than through the library's own encoder,
    /// so that a value the distinguished encoding rules would not produce can be placed in a signature. Only
    /// short-form lengths are written, which the values these tests use stay within.
    /// </summary>
    /// <param name="attributeType">The <c>attrType</c> object identifier.</param>
    /// <param name="attributeValue">The one <c>AttributeValue</c>, tag and length octets included.</param>
    /// <returns>The attribute carrier; the caller disposes it.</returns>
    private static CmsAttribute EncodeAttributeWithShortLengths(string attributeType, byte[] attributeValue)
    {
        var oidWriter = new AsnWriter(AsnEncodingRules.DER);
        oidWriter.WriteObjectIdentifier(attributeType);
        byte[] attributeTypeEncoding = oidWriter.Encode();
        byte[] values = [0x31, (byte)attributeValue.Length, .. attributeValue];
        byte[] attribute = [0x30, (byte)(attributeTypeEncoding.Length + values.Length), .. attributeTypeEncoding, .. values];

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(attribute.Length);
        try
        {
            attribute.CopyTo(owner.Memory.Span);

            return new CmsAttribute(attributeType, owner, attribute.Length);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Writes a DER OCTET STRING value, the compact stand-in for a real attribute value in tests that are about
    /// the index rather than about any particular attribute's syntax.
    /// </summary>
    /// <param name="content">The octets the string carries.</param>
    /// <returns>The encoded value.</returns>
    private static byte[] WriteOctetString(ReadOnlySpan<byte> content)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(content);

        return writer.Encode();
    }


    /// <summary>Builds a Root CA and a Time-Stamping Authority certificate anchored to <see cref="TestClock.CanonicalEpoch"/>.</summary>
    /// <returns>The minted nodes; the caller disposes them.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of both nodes transfers to the returned scenario, which the caller disposes; the catch disposes the root on a partial failure.")]
    private static TsaScenario BuildTimeStampingAuthority()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        try
        {
            return new TsaScenario(root, X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider));
        }
        catch
        {
            root.Dispose();

            throw;
        }
    }


    /// <summary>The minted Root CA and Time-Stamping Authority nodes for a scenario, disposed together.</summary>
    /// <param name="Root">The root certification authority.</param>
    /// <param name="Authority">The time-stamping authority whose key signs the tokens.</param>
    private sealed record TsaScenario(X509ChainTestRingNode Root, X509ChainTestRingNode Authority): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            Authority.Dispose();
            Root.Dispose();
        }
    }


    /// <summary>
    /// An archive-time-stamped signature and the material it was built from, so a test can assert against the
    /// creation side and the validation side of the same act.
    /// </summary>
    /// <param name="Signature">The signature carrying the archive-time-stamp-v3 attribute.</param>
    /// <param name="Token">The time-stamp token that attribute envelopes, with the index grafted into it.</param>
    /// <param name="HashIndex">The index the token was minted over.</param>
    /// <param name="ImprintInput">The imprint input the token's message imprint was computed over.</param>
    private sealed record ArchiveTimestampedSignature(
        CmsSignedData Signature,
        PkiCertificateMemory Token,
        AtsHashIndexV3 HashIndex,
        SignedContentMemory ImprintInput): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            Signature.Dispose();
            Token.Dispose();
            HashIndex.Dispose();
            ImprintInput.Dispose();
        }
    }
}
