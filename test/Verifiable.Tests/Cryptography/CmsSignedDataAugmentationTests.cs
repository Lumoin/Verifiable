using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="CmsSignedDataAugmentation"/>: appending unsigned attributes to an existing
/// CMS SignedData (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see>) under
/// the preservation rule of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.3</see>: "The augmentation shall preserve the binary encoding of already
/// present unsigned attributes and any component contributing to the archive time-stamp's message imprint
/// computation input."
/// </summary>
/// <remarks>
/// <para>
/// Two independent readers judge every augmented structure: the platform's own CMS reader, which decodes it and
/// checks the signature still verifies, and <see cref="CmsStructureOracle"/>, a walker written for these tests
/// from the encoding rules alone, which decides which octets the augmentation was allowed to rewrite. Neither
/// shares code with the operation under test.
/// </para>
/// <para>
/// Signatures are minted by the framework's own CMS signer through <see cref="CmsSignedDataTestFactory"/>, so
/// the inputs are structures a real signer produced rather than fixtures shaped to suit the splice.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CmsSignedDataAugmentationTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The signing time the minted signatures carry.</summary>
    private static DateTimeOffset SigningTime { get; } = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The time-stamp time the minted CAdES-B-T signatures carry.</summary>
    private static DateTimeOffset TimestampTime { get; } = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A signer that carries no <c>unsignedAttrs</c> field gains one: the new set is a DER
    /// <c>[1] IMPLICIT SET OF</c>, the platform's reader finds the attribute in it, the signature still
    /// verifies, and the library's own CAdES verification still accepts the signature.
    /// </summary>
    [TestMethod]
    public async Task AppendsAnUnsignedAttributeToASignerThatCarriesNone()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);

        byte[] originalOctets = original.AsReadOnlySpan().ToArray();
        Assert.IsEmpty(CmsStructureOracle.UnsignedAttributes(originalOctets, signerIndex: 0), "A CAdES-B-B signature carries no unsigned attributes to begin with.");

        byte[] attributeValue = WriteOctetString([0xAA, 0xBB, 0xCC]);
        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, attributeValue, BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);

        byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();

        AssertParsesAsOneValueWithNoTrailingData(augmentedOctets);
        AssertTheSignatureStillVerifies(augmentedOctets, expectedUnsignedAttributeCount: 1);
        AssertCarriesTheAttributeValue(augmentedOctets, CAdESSignatureFacts.CertificateValuesAttributeOid, attributeValue);
        Assert.IsTrue(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(originalOctets, augmentedOctets, signerIndex: 0),
            "Clause 5.5.3: every octet outside the length octets of the enclosing containers is preserved.");

        using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(augmented, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CAdESVerificationStatus.Valid, result.Status, "An unsigned attribute is not covered by the signature, so appending one leaves the signature valid.");
    }


    /// <summary>
    /// A signer that already carries unsigned attributes keeps their octets exactly: the signature time-stamp
    /// of a CAdES-B-T signature is found unchanged in the augmented structure, and the new attribute follows it.
    /// </summary>
    [TestMethod]
    public void PreservesTheOctetsOfUnsignedAttributesAlreadyPresent()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdEST("the augmented content"u8, signerCertificate, SigningTime, timestampCertificate, TimestampTime);

        byte[] originalOctets = original.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> existing = CmsStructureOracle.UnsignedAttributes(originalOctets, signerIndex: 0);
        Assert.HasCount(1, existing, "A CAdES-B-T signature carries exactly the signature time-stamp as an unsigned attribute.");
        byte[] existingOctets = originalOctets[existing[0].Start..existing[0].End];

        byte[] attributeValue = WriteOctetString([0x01, 0x02, 0x03, 0x04]);
        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, attributeValue, BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);

        byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> augmentedAttributes = CmsStructureOracle.UnsignedAttributes(augmentedOctets, signerIndex: 0);

        Assert.HasCount(2, augmentedAttributes, "The set holds the attribute that was there and the one appended.");
        Assert.AreSequenceEqual(existingOctets, augmentedOctets[augmentedAttributes[0].Start..augmentedAttributes[0].End],
            "Clause 5.5.3: the binary encoding of an already present unsigned attribute is preserved, and it keeps its position.");
        Assert.AreSequenceEqual(attribute.AsReadOnlySpan().ToArray(), augmentedOctets[augmentedAttributes[1].Start..augmentedAttributes[1].End],
            "The appended attribute reaches the wire as the octets it was encoded with.");

        AssertParsesAsOneValueWithNoTrailingData(augmentedOctets);
        AssertTheSignatureStillVerifies(augmentedOctets, expectedUnsignedAttributeCount: 2);
        Assert.IsTrue(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(originalOctets, augmentedOctets, signerIndex: 0),
            "Clause 5.5.3: every octet outside the length octets of the enclosing containers is preserved.");
    }


    /// <summary>
    /// BER indefinite-length outer wrappers are carried through unchanged: an indefinite-length container
    /// states no length to grow, so its header stays as it was and the growth flows outward to the next
    /// definite-length container. Re-encoding such a wrapper into definite-length DER is exactly the change
    /// clause 5.5.3's NOTE 7 says would break an archive time-stamp.
    /// </summary>
    [TestMethod]
    public void PreservesIndefiniteLengthOuterWrappers()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData definiteLength = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);

        byte[] originalOctets = CmsStructureOracle.ToIndefiniteOuterWrappers(definiteLength.AsReadOnlySpan().ToArray());
        using CmsSignedData original = CmsSignedData.FromBytes(originalOctets, BaseMemoryPool.Shared);

        List<CmsTlvBounds> originalChain = CmsStructureOracle.LocateLengthChain(originalOctets, signerIndex: 0);
        Assert.IsTrue(originalChain[0].IsIndefinite, "The rewritten ContentInfo carries an indefinite length.");
        Assert.IsTrue(originalChain[1].IsIndefinite, "The rewritten content field carries an indefinite length.");

        byte[] attributeValue = WriteOctetString([0x11, 0x22]);
        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, attributeValue, BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);

        byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> augmentedChain = CmsStructureOracle.LocateLengthChain(augmentedOctets, signerIndex: 0);

        Assert.IsTrue(augmentedChain[0].IsIndefinite, "An indefinite-length ContentInfo is preserved rather than rewritten into definite-length DER.");
        Assert.IsTrue(augmentedChain[1].IsIndefinite, "An indefinite-length content field is preserved rather than rewritten into definite-length DER.");
        Assert.AreEqual(originalChain[0].HeaderLength, augmentedChain[0].HeaderLength, "An indefinite-length container's header does not change size.");
        Assert.AreEqual(originalOctets.Length - originalChain[2].ContentEnd, augmentedOctets.Length - augmentedChain[2].ContentEnd,
            "The end-of-contents octets of the indefinite-length wrappers are carried through untouched.");

        AssertTheSignatureStillVerifies(augmentedOctets, expectedUnsignedAttributeCount: 1);
        AssertCarriesTheAttributeValue(augmentedOctets, CAdESSignatureFacts.CertificateValuesAttributeOid, attributeValue);
        Assert.IsTrue(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(originalOctets, augmentedOctets, signerIndex: 0),
            "Clause 5.5.3: every octet outside the length octets of the enclosing containers is preserved.");
    }


    /// <summary>
    /// A container whose content grows past what its length octets can state gains the octets it needs: the
    /// unsigned-attribute set starts in the short form and moves to the long form when a larger attribute is
    /// appended, while the attribute already in it keeps its octets.
    /// </summary>
    [TestMethod]
    public void GrowsTheLengthOctetsOfAContainerThatOutgrowsTheShortForm()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);

        using CmsAttribute small = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString(new byte[8]), BaseMemoryPool.Shared);
        using CmsSignedData firstAugmentation = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [small], BaseMemoryPool.Shared);

        byte[] firstOctets = firstAugmentation.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> firstChain = CmsStructureOracle.LocateLengthChain(firstOctets, signerIndex: 0);
        Assert.HasCount(6, firstChain, "The signer now carries an unsignedAttrs set.");
        Assert.AreEqual(2, firstChain[^1].HeaderLength, "X.690 clause 8.1.3.4: a content length below 128 is stated in the short form, one tag octet and one length octet.");

        using CmsAttribute large = CmsAttribute.Create(CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, WriteOctetString(new byte[200]), BaseMemoryPool.Shared);
        using CmsSignedData secondAugmentation = CmsSignedDataAugmentation.AppendUnsignedAttributes(firstAugmentation, signerIndex: 0, [large], BaseMemoryPool.Shared);

        byte[] secondOctets = secondAugmentation.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> secondChain = CmsStructureOracle.LocateLengthChain(secondOctets, signerIndex: 0);
        Assert.AreEqual(3, secondChain[^1].HeaderLength, "X.690 clause 8.1.3.5: a content length of 128 or more moves to the long form, which costs one more octet.");

        AssertParsesAsOneValueWithNoTrailingData(secondOctets);
        AssertTheSignatureStillVerifies(secondOctets, expectedUnsignedAttributeCount: 2);
        Assert.IsTrue(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(firstOctets, secondOctets, signerIndex: 0),
            "Clause 5.5.3: the attribute already present keeps its octets when the set's own header grows.");
    }


    /// <summary>
    /// Several attributes appended in one call all reach the wire, each with the octets it was encoded with.
    /// </summary>
    [TestMethod]
    public void AppendsSeveralAttributesInOneCall()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);

        using CmsAttribute first = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString([0x01]), BaseMemoryPool.Shared);
        using CmsAttribute second = CmsAttribute.Create(CAdESSignatureFacts.RevocationValuesAttributeOid, WriteOctetString([0x02]), BaseMemoryPool.Shared);
        using CmsAttribute third = CmsAttribute.Create(CAdESSignatureFacts.ArchiveTimestampV3AttributeOid, WriteOctetString([0x03]), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [first, second, third], BaseMemoryPool.Shared);

        byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();

        AssertParsesAsOneValueWithNoTrailingData(augmentedOctets);
        AssertTheSignatureStillVerifies(augmentedOctets, expectedUnsignedAttributeCount: 3);
        Assert.HasCount(3, CmsStructureOracle.UnsignedAttributes(augmentedOctets, signerIndex: 0), "Every attribute supplied reaches the set.");
        Assert.IsTrue(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(original.AsReadOnlySpan().ToArray(), augmentedOctets, signerIndex: 0),
            "Clause 5.5.3: every octet outside the length octets of the enclosing containers is preserved.");
    }


    /// <summary>
    /// With several signers, only the chosen one is augmented; the other SignerInfo keeps its octets exactly.
    /// </summary>
    [TestMethod]
    public void AppendsOnlyToTheChosenSignerOfASignatureWithSeveralSigners()
    {
        using ECDsa firstKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var firstCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(firstKey, NotBefore, NotAfter);
        using ECDsa secondKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var secondCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(secondKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCmsWithTwoSigners("the augmented content"u8, firstCertificate, secondCertificate);

        byte[] originalOctets = original.AsReadOnlySpan().ToArray();
        CmsTlvBounds untouchedSigner = CmsStructureOracle.LocateLengthChain(originalOctets, signerIndex: 0)[4];
        byte[] untouchedOctets = originalOctets[untouchedSigner.Start..untouchedSigner.End];

        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString([0x77]), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 1, [attribute], BaseMemoryPool.Shared);

        byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();
        CmsTlvBounds augmentedFirstSigner = CmsStructureOracle.LocateLengthChain(augmentedOctets, signerIndex: 0)[4];

        Assert.AreSequenceEqual(untouchedOctets, augmentedOctets[augmentedFirstSigner.Start..augmentedFirstSigner.End], "A SignerInfo that was not addressed keeps every octet it had.");
        Assert.IsEmpty(CmsStructureOracle.UnsignedAttributes(augmentedOctets, signerIndex: 0), "The signer that was not addressed gains no unsignedAttrs field.");
        Assert.HasCount(1, CmsStructureOracle.UnsignedAttributes(augmentedOctets, signerIndex: 1), "The addressed signer carries the appended attribute.");
        Assert.IsTrue(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(originalOctets, augmentedOctets, signerIndex: 1),
            "Clause 5.5.3: every octet outside the length octets of the enclosing containers is preserved.");

        AssertParsesAsOneValueWithNoTrailingData(augmentedOctets);
        var decoded = new SignedCms();
        decoded.Decode(augmentedOctets);
        Assert.HasCount(2, decoded.SignerInfos, "Both SignerInfo structures survive the augmentation.");
        decoded.SignerInfos[0].CheckSignature(verifySignatureOnly: true);
        decoded.SignerInfos[1].CheckSignature(verifySignatureOnly: true);
    }


    /// <summary>
    /// The octet-level invariant the other tests assert has teeth: a single flipped octet inside a region the
    /// preservation rule protects — here the signature value itself — is reported as a violation, so a passing
    /// preservation assertion elsewhere is evidence rather than a tautology.
    /// </summary>
    [TestMethod]
    public void TheOctetLevelInvariantDetectsAChangeOutsideTheLengthChain()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);

        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString([0x01]), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);

        byte[] originalOctets = original.AsReadOnlySpan().ToArray();
        byte[] tampered = augmented.AsReadOnlySpan().ToArray();

        Assert.IsTrue(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(originalOctets, tampered, signerIndex: 0), "The augmentation itself upholds the invariant.");

        foreach(CmsTlvBounds field in CmsStructureOracle.SignerFields(tampered, signerIndex: 0))
        {
            if(tampered[field.Start] == 0x04)
            {
                tampered[field.ContentStart] ^= 0x01;

                break;
            }
        }

        Assert.IsFalse(CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(originalOctets, tampered, signerIndex: 0),
            "A flipped octet in the signature value is a change the preservation rule forbids, and the invariant reports it.");
    }


    /// <summary>
    /// Input that cannot be preserved is refused outright rather than partly spliced: a truncated structure,
    /// one carrying octets after its ContentInfo, and one that is not a CMS SignedData at all.
    /// </summary>
    [TestMethod]
    public void RefusesInputItCannotPreserve()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);
        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString([0x01]), BaseMemoryPool.Shared);

        byte[] octets = original.AsReadOnlySpan().ToArray();
        using CmsSignedData truncated = CmsSignedData.FromBytes(octets.AsSpan()[..^5], BaseMemoryPool.Shared);
        using CmsSignedData withTrailingOctet = CmsSignedData.FromBytes([.. octets, 0x00], BaseMemoryPool.Shared);
        using CmsSignedData notSignedData = CmsSignedData.FromBytes(signerCertificate.RawData, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<AsnContentException>(
            () => CmsSignedDataAugmentation.AppendUnsignedAttributes(truncated, signerIndex: 0, [attribute], BaseMemoryPool.Shared),
            "A truncated structure has no preserved encoding to append to.");
        Assert.ThrowsExactly<AsnContentException>(
            () => CmsSignedDataAugmentation.AppendUnsignedAttributes(withTrailingOctet, signerIndex: 0, [attribute], BaseMemoryPool.Shared),
            "Octets after the ContentInfo are rejected rather than carried along.");
        Assert.ThrowsExactly<CryptographicException>(
            () => CmsSignedDataAugmentation.AppendUnsignedAttributes(notSignedData, signerIndex: 0, [attribute], BaseMemoryPool.Shared),
            "RFC 5652 §5.1: only an id-signedData ContentInfo carries SignerInfo structures to augment.");
    }


    /// <summary>
    /// The signer index and the attribute list are checked before anything is written: a negative index, an
    /// index no SignerInfo occupies, an empty list, and a list beyond the supported count are all refused.
    /// </summary>
    [TestMethod]
    public void RefusesAnUnusableSignerIndexOrAttributeList()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);
        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString([0x01]), BaseMemoryPool.Shared);

        var beyondTheSupportedCount = new List<CmsAttribute>(65);
        for(int i = 0; i < 65; ++i)
        {
            beyondTheSupportedCount.Add(attribute);
        }

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: -1, [attribute], BaseMemoryPool.Shared),
            "A signer index is a position in the signerInfos set, never negative.");
        Assert.ThrowsExactly<CryptographicException>(
            () => CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 1, [attribute], BaseMemoryPool.Shared),
            "A single-signer signature has no second SignerInfo to augment.");
        Assert.ThrowsExactly<ArgumentException>(
            () => CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [], BaseMemoryPool.Shared),
            "An augmentation that appends nothing would rewrite length octets for no reason.");
        Assert.ThrowsExactly<ArgumentException>(
            () => CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, beyondTheSupportedCount, BaseMemoryPool.Shared),
            "The number of attributes appended in one call is bounded.");
    }


    /// <summary>
    /// <see cref="CmsSignedDataAugmentation.ReadSignedAttributeValue"/> returns the exact octets of a present
    /// signed attribute, and <see langword="null"/> — never a present-but-empty value — for one that is absent.
    /// A conditional expression resolving the non-nullable true branch's type and converting the <see
    /// langword="null"/> false branch to THAT type's default (an empty <see cref="ReadOnlyMemory{T}"/>, not an
    /// absent one) was caught making the absent case indistinguishable from a genuinely empty attribute value —
    /// the exact trap <see cref="TimestampAcquisition"/>'s own <c>ReadTimeStampResp</c> documents.
    /// </summary>
    [TestMethod]
    public void ReadSignedAttributeValueDistinguishesAbsentFromEmpty()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the augmented content"u8, signerCertificate, SigningTime);

        ReadOnlyMemory<byte>? contentType = CmsSignedDataAugmentation.ReadSignedAttributeValue(original, signerIndex: 0, CAdESSignatureFacts.ContentTypeAttributeOid);
        Assert.IsTrue(contentType.HasValue, "content-type is a mandatory signed attribute of a CAdES-B-B signature.");
        Assert.IsGreaterThan(0, contentType!.Value.Length, "A present attribute's value is never reported as zero-length.");

        ReadOnlyMemory<byte>? absent = CmsSignedDataAugmentation.ReadSignedAttributeValue(original, signerIndex: 0, CAdESSignatureFacts.SignaturePolicyIdentifierAttributeOid);
        Assert.IsFalse(absent.HasValue, "signature-policy-identifier was never added, so it must be reported absent, not a zero-length value.");
    }


    /// <summary>
    /// Writes a DER OCTET STRING value, a compact stand-in for a real attribute value in tests that are about
    /// the splice rather than about any particular attribute's syntax.
    /// </summary>
    /// <param name="content">The octets the string carries.</param>
    /// <returns>The encoded value.</returns>
    private static byte[] WriteOctetString(ReadOnlySpan<byte> content)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(content);

        return writer.Encode();
    }


    /// <summary>
    /// Asserts the structure is one encoded value with nothing after it, read by the framework's own reader.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    private static void AssertParsesAsOneValueWithNoTrailingData(byte[] signedData)
    {
        var reader = new AsnReader(signedData, AsnEncodingRules.BER);
        _ = reader.ReadEncodedValue();

        Assert.IsFalse(reader.HasData, "The augmented structure is exactly one encoded value, with no octets after it.");
    }


    /// <summary>
    /// Asserts the platform's own CMS reader decodes the structure, finds the expected number of unsigned
    /// attributes on the first signer, and still accepts the signature.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="expectedUnsignedAttributeCount">The number of unsigned attributes the first signer is expected to carry.</param>
    private static void AssertTheSignatureStillVerifies(byte[] signedData, int expectedUnsignedAttributeCount)
    {
        var decoded = new SignedCms();
        decoded.Decode(signedData);

        Assert.HasCount(expectedUnsignedAttributeCount, decoded.SignerInfos[0].UnsignedAttributes, "The independent reader finds exactly the unsigned attributes the structure carries.");

        decoded.SignerInfos[0].CheckSignature(verifySignatureOnly: true);
    }


    /// <summary>
    /// Asserts the platform's own CMS reader finds an unsigned attribute of the given type carrying the given
    /// value octets.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="attributeType">The expected attribute type object identifier.</param>
    /// <param name="attributeValue">The expected DER-encoded attribute value.</param>
    private static void AssertCarriesTheAttributeValue(byte[] signedData, string attributeType, byte[] attributeValue)
    {
        var decoded = new SignedCms();
        decoded.Decode(signedData);

        foreach(CryptographicAttributeObject candidate in decoded.SignerInfos[0].UnsignedAttributes)
        {
            if(string.Equals(candidate.Oid.Value, attributeType, StringComparison.Ordinal))
            {
                Assert.AreSequenceEqual(attributeValue, candidate.Values[0].RawData, "The appended attribute's value reaches the wire unchanged.");

                return;
            }
        }

        Assert.Fail($"The augmented structure carries no unsigned attribute of type '{attributeType}'.");
    }
}
