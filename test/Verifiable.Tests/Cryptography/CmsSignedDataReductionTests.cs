using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="CmsSignedDataReduction"/>: removing unsigned attribute values from a CMS
/// SignedData (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see>) under the
/// reconstruction rule of <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">IETF RFC 4998
/// Appendix A</see>: "the attribute has to be removed before verification. The length of fields containing tags
/// has to be adapted. Apart from that, the existing coding must not be modified."
/// </summary>
/// <remarks>
/// <para>
/// The strongest statement of that rule is that the removal is the exact inverse of the append: a structure that
/// gained attributes and then lost them again is the structure it was, octet for octet. Most tests here assert
/// exactly that, over attribute sizes chosen so the enclosing containers' length octets grow across every
/// short-form and long-form boundary on the way out and have to shrink back on the way in.
/// </para>
/// <para>
/// Every result is judged additionally by two readers that share no code with the operation:
/// <see cref="CmsStructureOracle.RemoveUnsignedAttributeValues"/>, which rebuilds the structure from the
/// surviving elements rather than splicing it, and the platform's own <see cref="SignedCms"/> reader, which
/// decodes the result and rechecks the signature.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CmsSignedDataReductionTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The signing time the minted signatures carry.</summary>
    private static DateTimeOffset SigningTime { get; } = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The time-stamp time the minted CAdES-B-T signature carries.</summary>
    private static DateTimeOffset TimestampTime { get; } = new(2025, 6, 1, 12, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// A signer that had no <c>unsignedAttrs</c> field, gained one holding a single attribute, and then lost that
    /// attribute again is the structure it started as — every octet of it, the field itself gone rather than
    /// written as an empty set. The value sizes cross the short-form, one-octet and two-octet length boundaries,
    /// so the enclosing containers' length octets grow on the way out and have to shrink back on the way in.
    /// </summary>
    /// <param name="valueLength">The size of the removed attribute's value content.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(60)]
    [DataRow(200)]
    [DataRow(70000)]
    public void RemovingTheOnlyAttributeRestoresTheStructureExactly(int valueLength)
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the reduced content"u8, signerCertificate, SigningTime);

        byte[] originalOctets = original.AsReadOnlySpan().ToArray();
        Assert.IsEmpty(CmsStructureOracle.UnsignedAttributes(originalOctets, signerIndex: 0), "A CAdES-B-B signature carries no unsigned attributes to begin with.");

        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString(valueLength), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);
        using CmsSignedData reduced = CmsSignedDataReduction.RemoveUnsignedAttributeValues(
            augmented, signerIndex: 0, [new CmsUnsignedAttributeValueLocation(0, 0, CAdESSignatureFacts.CertificateValuesAttributeOid)], BaseMemoryPool.Shared);

        byte[] reducedOctets = reduced.AsReadOnlySpan().ToArray();
        Assert.AreSequenceEqual(originalOctets, reducedOctets, "Removing what was appended restores the coding that stood before it.");
        Assert.IsEmpty(CmsStructureOracle.UnsignedAttributes(reducedOctets, signerIndex: 0), "The optional unsignedAttrs field is gone, not written as an empty set.");
        Assert.AreSequenceEqual(
            CmsStructureOracle.RemoveUnsignedAttributeValues(augmented.AsReadOnlySpan().ToArray(), signerIndex: 0, [0]),
            reducedOctets,
            "The independent rebuild reaches the same octets as the splice.");

        AssertTheSignatureStillVerifies(reducedOctets, expectedUnsignedAttributeCount: 0);
    }


    /// <summary>
    /// Removing one attribute of several leaves the surviving attributes' octets exactly where they were, in the
    /// order they were in, and shrinks only the containers that enclose the removed one.
    /// </summary>
    [TestMethod]
    public void RemovingOneOfSeveralAttributesLeavesTheOthersVerbatim()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using ECDsa timestampKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var timestampCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(timestampKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdEST("the reduced content"u8, signerCertificate, SigningTime, timestampCertificate, TimestampTime);

        using CmsAttribute first = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString(150), BaseMemoryPool.Shared);
        using CmsAttribute second = CmsAttribute.Create(CAdESSignatureFacts.RevocationValuesAttributeOid, WriteOctetString(250), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [first, second], BaseMemoryPool.Shared);

        byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> augmentedAttributes = CmsStructureOracle.UnsignedAttributes(augmentedOctets, signerIndex: 0);
        Assert.HasCount(3, augmentedAttributes, "The signature time-stamp that was there plus the two appended.");
        byte[] survivingTimestamp = augmentedOctets[augmentedAttributes[0].Start..augmentedAttributes[0].End];

        //The middle attribute goes, which is the case that shrinks the set without emptying it.
        using CmsSignedData reduced = CmsSignedDataReduction.RemoveUnsignedAttributeValues(
            augmented, signerIndex: 0, [new CmsUnsignedAttributeValueLocation(1, 0, CAdESSignatureFacts.CertificateValuesAttributeOid)], BaseMemoryPool.Shared);

        byte[] reducedOctets = reduced.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> reducedAttributes = CmsStructureOracle.UnsignedAttributes(reducedOctets, signerIndex: 0);

        Assert.HasCount(2, reducedAttributes);
        Assert.AreSequenceEqual(survivingTimestamp, reducedOctets[reducedAttributes[0].Start..reducedAttributes[0].End], "The attribute before the removed one keeps its octets and its position.");
        Assert.AreSequenceEqual(second.AsReadOnlySpan().ToArray(), reducedOctets[reducedAttributes[1].Start..reducedAttributes[1].End], "The attribute after the removed one keeps its octets.");
        Assert.AreSequenceEqual(
            CmsStructureOracle.RemoveUnsignedAttributeValues(augmentedOctets, signerIndex: 0, [1]),
            reducedOctets,
            "The independent rebuild reaches the same octets as the splice.");

        AssertTheSignatureStillVerifies(reducedOctets, expectedUnsignedAttributeCount: 2);
    }


    /// <summary>
    /// Removing one value of an attribute that carries several leaves the attribute in place with its remaining
    /// values: the <c>Attribute</c> SEQUENCE and its <c>attrValues</c> SET both shrink, and the shrink of their
    /// own headers reaches the containers above them.
    /// </summary>
    [TestMethod]
    public void RemovingOneValueOfAMultiValuedAttributeKeepsTheAttribute()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the reduced content"u8, signerCertificate, SigningTime);

        byte[] keptValue = WriteOctetString(40);
        byte[] removedValue = WriteOctetString(200);
        using CmsAttribute attribute = CmsAttribute.Create(
            CAdESSignatureFacts.SignatureTimestampAttributeOid,
            [new ReadOnlyMemory<byte>(keptValue), new ReadOnlyMemory<byte>(removedValue)],
            BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);

        byte[] augmentedOctets = augmented.AsReadOnlySpan().ToArray();
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(augmented, signerIndex: 0);
        Assert.HasCount(2, locations, "One attribute carrying two values is two addressable sites.");

        //The values of a DER SET OF are sorted by their encodings, so which of the two carries the removed
        //content is read from the structure rather than assumed.
        int removedIndex = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(augmented, 0, locations[0].AttributeIndex, locations[0].ValueIndex).Span.SequenceEqual(removedValue) ? 0 : 1;
        using CmsSignedData reduced = CmsSignedDataReduction.RemoveUnsignedAttributeValues(
            augmented, signerIndex: 0, [locations[removedIndex]], BaseMemoryPool.Shared);

        byte[] reducedOctets = reduced.AsReadOnlySpan().ToArray();
        IReadOnlyList<CmsUnsignedAttributeValueLocation> remaining = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(reduced, signerIndex: 0);

        Assert.HasCount(1, remaining, "The attribute survives with the value that was not removed.");
        Assert.AreSequenceEqual(
            keptValue,
            CmsSignedDataAugmentation.ReadUnsignedAttributeValue(reduced, 0, remaining[0].AttributeIndex, remaining[0].ValueIndex).ToArray(),
            "The surviving value keeps the octets it was encoded with.");
        Assert.AreSequenceEqual(
            CmsStructureOracle.RemoveUnsignedAttributeValues(augmentedOctets, signerIndex: 0, [removedIndex]),
            reducedOctets,
            "The independent rebuild reaches the same octets as the splice.");

        AssertTheSignatureStillVerifies(reducedOctets, expectedUnsignedAttributeCount: 1);
    }


    /// <summary>
    /// BER indefinite-length outer wrappers survive a removal exactly as they survive an append: such a
    /// container states no length to re-derive, so its <c>0x80</c> length octet and its end-of-contents pair are
    /// carried through and the shrink flows to the next definite-length container. Third-party CMS objects
    /// carrying Evidence Records are encoded this way, and their records only verify when this holds.
    /// </summary>
    [TestMethod]
    public void PreservesIndefiniteLengthOuterWrappers()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData definiteLength = CmsSignedDataTestFactory.SignAsCAdES("the reduced content"u8, signerCertificate, SigningTime);

        byte[] originalOctets = CmsStructureOracle.ToIndefiniteOuterWrappers(definiteLength.AsReadOnlySpan().ToArray());
        using CmsSignedData original = CmsSignedData.FromBytes(originalOctets, BaseMemoryPool.Shared);

        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString(400), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);
        using CmsSignedData reduced = CmsSignedDataReduction.RemoveUnsignedAttributeValues(
            augmented, signerIndex: 0, [new CmsUnsignedAttributeValueLocation(0, 0, CAdESSignatureFacts.CertificateValuesAttributeOid)], BaseMemoryPool.Shared);

        byte[] reducedOctets = reduced.AsReadOnlySpan().ToArray();
        Assert.AreSequenceEqual(originalOctets, reducedOctets, "The indefinite-length wrappers come back exactly as they went in.");
        Assert.IsTrue(CmsStructureOracle.LocateLengthChain(reducedOctets, signerIndex: 0)[0].IsIndefinite, "The ContentInfo still carries an indefinite length.");
        Assert.AreSequenceEqual(
            CmsStructureOracle.RemoveUnsignedAttributeValues(augmented.AsReadOnlySpan().ToArray(), signerIndex: 0, [0]),
            reducedOctets,
            "The independent rebuild reaches the same octets as the splice.");
    }


    /// <summary>
    /// A container whose definite length is written in more octets than it needs is refused: nothing states
    /// whether the coding before the removed octets were added used the same non-minimal count or the minimal
    /// one, and Appendix A permits adapting the length and modifying nothing else, so a reconstruction that had
    /// to guess would not be one. This is also the shape a re-encoded ancestor arrives in.
    /// </summary>
    [TestMethod]
    public void RefusesAContainerWhoseDefiniteLengthIsNotMinimallyEncoded()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the reduced content"u8, signerCertificate, SigningTime);

        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString(64), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);

        byte[] widened = WidenTheOuterLength(augmented.AsReadOnlySpan().ToArray());
        using CmsSignedData reEncoded = CmsSignedData.FromBytes(widened, BaseMemoryPool.Shared);

        _ = Assert.Throws<CryptographicException>(() => CmsSignedDataReduction.RemoveUnsignedAttributeValues(
            reEncoded, signerIndex: 0, [new CmsUnsignedAttributeValueLocation(0, 0, CAdESSignatureFacts.CertificateValuesAttributeOid)], BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A location the signer does not carry is refused rather than ignored, so a caller never receives a
    /// structure it believes something was removed from.
    /// </summary>
    [TestMethod]
    public void RefusesAValueTheSignerDoesNotCarry()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the reduced content"u8, signerCertificate, SigningTime);

        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, WriteOctetString(16), BaseMemoryPool.Shared);
        using CmsSignedData augmented = CmsSignedDataAugmentation.AppendUnsignedAttributes(original, signerIndex: 0, [attribute], BaseMemoryPool.Shared);

        _ = Assert.Throws<CryptographicException>(() => CmsSignedDataReduction.RemoveUnsignedAttributeValues(
            augmented, signerIndex: 0, [new CmsUnsignedAttributeValueLocation(1, 0, CAdESSignatureFacts.CertificateValuesAttributeOid)], BaseMemoryPool.Shared));

        _ = Assert.Throws<CryptographicException>(() => CmsSignedDataReduction.RemoveUnsignedAttributeValues(
            original, signerIndex: 0, [new CmsUnsignedAttributeValueLocation(0, 0, CAdESSignatureFacts.CertificateValuesAttributeOid)], BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Removing nothing produces the input's own octets, which keeps the caller's ownership contract the same
    /// whether or not anything had to be taken out.
    /// </summary>
    [TestMethod]
    public void RemovingNothingCopiesTheInput()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData original = CmsSignedDataTestFactory.SignAsCAdES("the reduced content"u8, signerCertificate, SigningTime);

        using CmsSignedData reduced = CmsSignedDataReduction.RemoveUnsignedAttributeValues(original, signerIndex: 0, [], BaseMemoryPool.Shared);

        Assert.AreSequenceEqual(original.AsReadOnlySpan().ToArray(), reduced.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// Widens the outer <c>ContentInfo</c>'s definite length by one octet without changing what it states,
    /// which is a legal BER encoding of the same value and a non-minimal one under DER.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The same structure with a non-minimally encoded outer length.</returns>
    private static byte[] WidenTheOuterLength(byte[] signedData)
    {
        CmsTlvBounds contentInfo = CmsStructureOracle.ReadElement(signedData, 0);
        int lengthOctetCount = contentInfo.HeaderLength - contentInfo.TagLength - 1;
        var widened = new List<byte>(signedData.Length + 1)
        {
            signedData[0],
            (byte)(0x80 | (lengthOctetCount + 1)),
            0x00
        };

        for(int i = 0; i < lengthOctetCount; ++i)
        {
            widened.Add(signedData[contentInfo.Start + contentInfo.TagLength + 1 + i]);
        }

        widened.AddRange(signedData[contentInfo.ContentStart..contentInfo.ContentEnd]);

        return [.. widened];
    }


    /// <summary>
    /// Decodes a Signed Data Object with the platform's own CMS reader, rechecks the signature over the content
    /// it carries, and states how many unsigned attributes the first signer holds.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="expectedUnsignedAttributeCount">The number of unsigned attributes the signer is expected to carry.</param>
    private static void AssertTheSignatureStillVerifies(byte[] signedData, int expectedUnsignedAttributeCount)
    {
        var reader = new SignedCms();
        reader.Decode(signedData);
        reader.CheckSignature(verifySignatureOnly: true);

        Assert.HasCount(expectedUnsignedAttributeCount, reader.SignerInfos[0].UnsignedAttributes);
    }


    /// <summary>
    /// Writes a DER OCTET STRING of the requested content length, the shape an attribute value takes here.
    /// </summary>
    /// <param name="contentLength">The number of content octets.</param>
    /// <returns>The encoded value.</returns>
    private static byte[] WriteOctetString(int contentLength)
    {
        var content = new byte[contentLength];
        for(int i = 0; i < content.Length; ++i)
        {
            content[i] = (byte)(contentLength + i);
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(content);

        return writer.Encode();
    }
}
