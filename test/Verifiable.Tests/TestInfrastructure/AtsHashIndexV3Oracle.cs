using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An independent recomputation of the <c>ats-hash-index-v3</c> of ETSI EN 319 122-1 V1.3.1 clause 5.5.2 and of
/// the <c>archive-time-stamp-v3</c> message imprint input of clause 5.5.3, written for these tests from the
/// clause text alone.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here calls the surface it checks. The structure is navigated by position through
/// <see cref="CmsStructureOracle"/> — the hand-written tag and length walker of the augmentation tests — rather
/// than through the production walker, the hash-index encoding is written by an <see cref="AsnWriter"/> in this
/// file, and every hash value is taken through the BouncyCastle digest implementation
/// (<see cref="BouncyCastleCryptographicFunctions.ComputeDigest"/>), which is a different implementation from
/// the one the test host registers for the SHA family and therefore an independent answer to the same question.
/// Digests are library carriers, never hand-rolled hashing.
/// </para>
/// <para>
/// The clause text this reimplements, so a reader can check it against the specification rather than against
/// the production code: each certificate hash covers "one instance of <c>CertificateChoices</c> within the
/// <c>certificates</c> field of the root <c>SignedData</c>"; each revocation hash covers one instance of
/// <c>RevocationInfoChoice</c> within <c>crls</c>; each unsigned-attribute hash covers "the octets resulting
/// from concatenating the corresponding <c>Attribute.attrType</c> field and one of the instances of
/// <c>AttributeValue</c>", one per value; and every hash is taken over "the entire encoded components including
/// their tag, length and value octets". The imprint input is "the concatenation (in the order shown by the
/// list below)" of the <c>eContentType</c> field, the hash of the signed data, the <c>version</c>, <c>sid</c>,
/// <c>digestAlgorithm</c>, <c>signedAttrs</c>, <c>signatureAlgorithm</c> and <c>signature</c> fields of the
/// <c>SignerInfo</c>, and a single instance of <c>ATSHashIndexV3</c>.
/// </para>
/// </remarks>
internal static class AtsHashIndexV3Oracle
{
    /// <summary>The <c>[0]</c> constructed context tag octet: <c>SignedData.certificates</c> and <c>SignerInfo.signedAttrs</c>.</summary>
    private const byte ContextConstructed0Octet = 0xA0;

    /// <summary>The <c>[1]</c> constructed context tag octet: <c>SignedData.crls</c> and <c>SignerInfo.unsignedAttrs</c>.</summary>
    private const byte ContextConstructed1Octet = 0xA1;


    /// <summary>
    /// Encodes the <c>ATSHashIndexV3</c> this oracle says a signature's current material produces, with its own
    /// writer and its own digests.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer the archive time-stamp corresponds to.</param>
    /// <param name="algorithm">The algorithm every hash value is computed under.</param>
    /// <returns>The DER-encoded index; the caller disposes it.</returns>
    internal static PooledMemory EncodeHashIndex(byte[] signedData, int signerIndex, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                writer.WriteObjectIdentifier(algorithm.Identifier.Oid);
            }

            WriteHashes(writer, CertificateEncodings(signedData), algorithm);
            WriteHashes(writer, RevocationEncodings(signedData), algorithm);
            WriteHashes(writer, UnsignedAttributeTypeAndValueConcatenations(signedData, signerIndex), algorithm);
        }

        return PooledMemory.FromBytes(writer.Encode(), BaseMemoryPool.Shared, AtsHashIndexV3.ValueTag);
    }


    /// <summary>
    /// Assembles the four-part message imprint input this oracle says clause 5.5.3 defines for one signature and
    /// one already-encoded hash index.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer the archive time-stamp corresponds to.</param>
    /// <param name="hashIndex">The DER-encoded <c>ATSHashIndexV3</c> that goes in as part 4.</param>
    /// <param name="algorithm">The archive time-stamp's own algorithm, which part 2's hash is taken under.</param>
    /// <returns>The imprint input; the caller disposes it.</returns>
    internal static SignedContentMemory BuildMessageImprintInput(
        byte[] signedData,
        int signerIndex,
        ReadOnlySpan<byte> hashIndex,
        PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        var assembled = new List<byte>(signedData.Length);
        assembled.AddRange(EncapsulatedContentTypeEncoding(signedData));

        using(DigestValue contentHash = Hash(EncapsulatedContent(signedData), algorithm))
        {
            assembled.AddRange(contentHash.AsReadOnlySpan());
        }

        foreach(byte[] field in ImprintSignerFields(signedData, signerIndex))
        {
            assembled.AddRange(field);
        }

        assembled.AddRange(hashIndex);

        return SignedContentMemory.FromBytes([.. assembled], BaseMemoryPool.Shared);
    }


    /// <summary>
    /// The whole encoding of every instance of <c>CertificateChoices</c> in <c>SignedData.certificates</c>, in
    /// the order they appear — every alternative, not only the X.509 certificate one, since clause 5.5.2 indexes
    /// every instance and no other.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The encodings.</returns>
    internal static List<byte[]> CertificateEncodings(byte[] signedData) =>
        SetMembers(signedData, ContextConstructed0Octet);


    /// <summary>
    /// The whole encoding of every instance of <c>RevocationInfoChoice</c> in <c>SignedData.crls</c>, in the
    /// order they appear, which per NOTE 1 of clause 5.5.2 covers certificate revocation lists and OCSP
    /// responses alike.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The encodings.</returns>
    internal static List<byte[]> RevocationEncodings(byte[] signedData) =>
        SetMembers(signedData, ContextConstructed1Octet);


    /// <summary>
    /// The concatenation of the <c>attrType</c> field and one <c>AttributeValue</c>, one entry per value of
    /// every unsigned attribute of one signer — the octets clause 5.5.2 hashes for the
    /// <c>unsignedAttrValuesHashIndex</c>.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <returns>The concatenations, in the order the values appear.</returns>
    internal static List<byte[]> UnsignedAttributeTypeAndValueConcatenations(byte[] signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        var concatenations = new List<byte[]>();
        foreach(CmsTlvBounds attribute in CmsStructureOracle.UnsignedAttributes(signedData, signerIndex))
        {
            List<CmsTlvBounds> attributeChildren = CmsStructureOracle.Children(signedData, attribute);
            byte[] attributeType = signedData[attributeChildren[0].Start..attributeChildren[0].End];
            foreach(CmsTlvBounds value in CmsStructureOracle.Children(signedData, attributeChildren[1]))
            {
                concatenations.Add([.. attributeType, .. signedData[value.Start..value.End]]);
            }
        }

        return concatenations;
    }


    /// <summary>
    /// The whole encoding of <c>SignedData.encapContentInfo.eContentType</c> — part 1 of the imprint input.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The encoding.</returns>
    internal static byte[] EncapsulatedContentTypeEncoding(byte[] signedData)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        CmsTlvBounds contentType = CmsStructureOracle.Children(signedData, EncapsulatedContentInfo(signedData))[0];

        return signedData[contentType.Start..contentType.End];
    }


    /// <summary>
    /// The content octets of <c>SignedData.encapContentInfo.eContent</c> — the signed data whose hash is part 2
    /// of the imprint input.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The content octets.</returns>
    internal static byte[] EncapsulatedContent(byte[] signedData)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        List<CmsTlvBounds> children = CmsStructureOracle.Children(signedData, EncapsulatedContentInfo(signedData));
        CmsTlvBounds octetString = CmsStructureOracle.Children(signedData, children[1])[0];

        return signedData[octetString.ContentStart..octetString.ContentEnd];
    }


    /// <summary>
    /// The whole encodings of the <c>SignerInfo</c> fields part 3 of the imprint input concatenates: every field
    /// in its order of appearance except a trailing <c>unsignedAttrs</c>, which the clause leaves out.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <returns>The field encodings, in order.</returns>
    internal static List<byte[]> ImprintSignerFields(byte[] signedData, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        var fields = new List<byte[]>();
        foreach(CmsTlvBounds field in CmsStructureOracle.SignerFields(signedData, signerIndex))
        {
            if(signedData[field.Start] == ContextConstructed1Octet)
            {
                continue;
            }

            fields.Add(signedData[field.Start..field.End]);
        }

        return fields;
    }


    /// <summary>
    /// Computes one hash value through the independent BouncyCastle digest implementation.
    /// </summary>
    /// <param name="input">The octets to hash.</param>
    /// <param name="algorithm">The algorithm to hash under.</param>
    /// <returns>The digest carrier; the caller disposes it.</returns>
    internal static DigestValue Hash(ReadOnlySpan<byte> input, PkiDigestAlgorithm algorithm) =>
        BouncyCastleCryptographicFunctions.ComputeDigest(input, algorithm.OutputByteLength, algorithm.DigestTag, BaseMemoryPool.Shared).Result;


    /// <summary>
    /// Writes one <c>SEQUENCE OF OCTET STRING</c> hash-index list from the octets each entry covers.
    /// </summary>
    /// <param name="writer">The writer positioned inside the <c>ATSHashIndexV3</c> SEQUENCE.</param>
    /// <param name="covered">The octets each entry is the hash of.</param>
    /// <param name="algorithm">The algorithm each hash value is computed under.</param>
    private static void WriteHashes(AsnWriter writer, List<byte[]> covered, PkiDigestAlgorithm algorithm)
    {
        using(writer.PushSequence())
        {
            foreach(byte[] octets in covered)
            {
                using DigestValue hash = Hash(octets, algorithm);
                writer.WriteOctetString(hash.AsReadOnlySpan());
            }
        }
    }


    /// <summary>
    /// The whole encoding of every member of one optional implicitly tagged <c>SET OF</c> of the
    /// <c>SignedData</c>, or an empty list when the field is absent.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="setTagOctet">The tag octet the field carries.</param>
    /// <returns>The members' encodings.</returns>
    private static List<byte[]> SetMembers(byte[] signedData, byte setTagOctet)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        var members = new List<byte[]>();
        foreach(CmsTlvBounds child in SignedDataChildren(signedData))
        {
            if(signedData[child.Start] != setTagOctet)
            {
                continue;
            }

            foreach(CmsTlvBounds member in CmsStructureOracle.Children(signedData, child))
            {
                members.Add(signedData[member.Start..member.End]);
            }
        }

        return members;
    }


    /// <summary>
    /// The <c>encapContentInfo</c> field of the <c>SignedData</c>, which is its third field (RFC 5652 §5.1).
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The field's bounds.</returns>
    private static CmsTlvBounds EncapsulatedContentInfo(byte[] signedData) => SignedDataChildren(signedData)[2];


    /// <summary>
    /// The fields of the <c>SignedData</c>, reached by position: the content is the last field of the
    /// ContentInfo and the <c>SignedData</c> is the only field of that content.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The <c>SignedData</c>'s child elements.</returns>
    private static List<CmsTlvBounds> SignedDataChildren(byte[] signedData)
    {
        CmsTlvBounds contentInfo = CmsStructureOracle.ReadElement(signedData, 0);
        CmsTlvBounds content = CmsStructureOracle.Children(signedData, contentInfo)[^1];
        CmsTlvBounds signedDataSequence = CmsStructureOracle.Children(signedData, content)[0];

        return CmsStructureOracle.Children(signedData, signedDataSequence);
    }
}
