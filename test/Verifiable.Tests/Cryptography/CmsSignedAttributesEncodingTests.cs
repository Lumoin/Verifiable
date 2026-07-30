using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="CmsSignedAttributesEncoding"/>: the creation direction of the one rule of
/// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.4">RFC 5652 §5.4</see> — the signature is
/// computed over the <c>SET OF</c> encoding of the signed attributes, while the <c>[0] IMPLICIT</c> encoding
/// of the same length and content octets is what the <c>SignerInfo</c> carries.
/// </summary>
/// <remarks>
/// The evidential test is <see cref="ProducesTheExactOctetsAnExistingSignatureWasComputedOver"/>: a signature
/// minted by the framework's own CMS signer is verified, by the platform's own ECDSA verifier, over the octets
/// this encoder produces from that signature's embedded signed attributes. Nothing in the library under test
/// participates in that check, so it fails if the retagging is off by a single octet.
/// </remarks>
[TestClass]
internal sealed class CmsSignedAttributesEncodingTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = new(2034, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The signing time the minted signatures carry.</summary>
    private static DateTimeOffset SigningTime { get; } = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The <c>[0] IMPLICIT</c> constructed tag octet of <c>SignerInfo.signedAttrs</c>.</summary>
    private const byte SignedAttributesTagOctet = 0xA0;

    /// <summary>The universal <c>SET OF</c> tag octet of the RFC 5652 §5.4 signature input.</summary>
    private const byte SetOfTagOctet = 0x31;


    /// <summary>
    /// The two encodings share every length and content octet and differ only in the first, which is exactly
    /// what RFC 5652 §5.4 asks the signature input to be.
    /// </summary>
    [TestMethod]
    public void EncodesTheTwoFormsDifferingOnlyInTheTagOctet()
    {
        using CmsAttribute contentType = CmsAttribute.Create(CAdESSignatureFacts.ContentTypeAttributeOid, WriteObjectIdentifier(WellKnownContentTypeOid), BaseMemoryPool.Shared);
        using CmsAttribute messageDigest = CmsAttribute.Create(CAdESSignatureFacts.MessageDigestAttributeOid, WriteOctetString([1, 2, 3, 4]), BaseMemoryPool.Shared);

        using CmsSignedAttributesEncoding encoding = CmsSignedAttributesEncoding.Create([contentType, messageDigest], BaseMemoryPool.Shared);

        byte[] embedded = encoding.EmbeddedForm.AsReadOnlySpan().ToArray();
        byte[] signingInput = encoding.SigningInput.AsReadOnlySpan().ToArray();

        Assert.HasCount(embedded.Length, signingInput, "RFC 5652 §5.4: the two encodings differ in the tag alone, so their lengths match.");
        Assert.AreEqual(SignedAttributesTagOctet, embedded[0], "RFC 5652 §5.3: the embedded form carries the [0] IMPLICIT constructed tag.");
        Assert.AreEqual(SetOfTagOctet, signingInput[0], "RFC 5652 §5.4: the signature input carries the universal SET OF tag.");
        Assert.AreSequenceEqual(embedded[1..], signingInput[1..], "Every length and content octet is shared between the two encodings.");
    }


    /// <summary>
    /// The octets this encoder produces from a real signature's signed attributes are the octets that
    /// signature was computed over: the platform's own ECDSA verifier accepts the signature value over them.
    /// </summary>
    [TestMethod]
    public void ProducesTheExactOctetsAnExistingSignatureWasComputedOver()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCAdES("the signed attributes content"u8, signerCertificate, SigningTime);

        byte[] octets = signature.AsReadOnlySpan().ToArray();
        byte[] embeddedSignedAttributes = ReadSignerField(octets, SignedAttributesTagOctet, wholeElement: true);
        byte[] signatureValue = ReadSignerField(octets, tagOctet: 0x04, wholeElement: false);

        using PooledMemory signingInput = CmsSignedAttributesEncoding.ToSigningInput(embeddedSignedAttributes, BaseMemoryPool.Shared);

        using ECDsa publicKey = signerCertificate.GetECDsaPublicKey()!;
        bool verified = publicKey.VerifyData(signingInput.AsReadOnlySpan(), signatureValue, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        Assert.IsTrue(verified, "RFC 5652 §5.4: the retagged signed attributes are the exact octets the signature covers.");
    }


    /// <summary>
    /// Rebuilding a real signature's signed-attribute set from its own attributes reproduces its octets
    /// exactly, even when the attributes are supplied in reverse order: X.690 clause 11.6 fixes the encoded
    /// order of a <c>SET OF</c>, and this encoder emits that order rather than the caller's.
    /// </summary>
    [TestMethod]
    public void RebuildsAnExistingSignedAttributeSetOctetForOctetWhateverOrderTheAttributesArriveIn()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData signature = CmsSignedDataTestFactory.SignAsCAdES("the signed attributes content"u8, signerCertificate, SigningTime);

        byte[] octets = signature.AsReadOnlySpan().ToArray();
        byte[] embeddedSignedAttributes = ReadSignerField(octets, SignedAttributesTagOctet, wholeElement: true);

        List<CmsAttribute> rebuilt = [];
        try
        {
            foreach((string attributeType, ReadOnlyMemory<byte> attributeValue) in DecodeAttributes(embeddedSignedAttributes))
            {
                rebuilt.Add(CmsAttribute.Create(attributeType, attributeValue.Span, BaseMemoryPool.Shared));
            }

            Assert.IsGreaterThan(1, rebuilt.Count, "A CAdES-B-B signature carries several signed attributes, so the ordering assertion has something to order.");

            rebuilt.Reverse();
            using CmsSignedAttributesEncoding encoding = CmsSignedAttributesEncoding.Create(rebuilt, BaseMemoryPool.Shared);

            Assert.AreSequenceEqual(embeddedSignedAttributes, encoding.EmbeddedForm.AsReadOnlySpan().ToArray(), "The rebuilt set reproduces the original octets, DER ordering included.");
        }
        finally
        {
            foreach(CmsAttribute attribute in rebuilt)
            {
                attribute.Dispose();
            }
        }
    }


    /// <summary>
    /// A multi-valued attribute round-trips: the values are emitted in DER's own order, and the attribute is a
    /// single <c>SEQUENCE</c> carrying one <c>SET OF</c> with both values.
    /// </summary>
    [TestMethod]
    public void EncodesAMultiValuedAttributeAsOneAttributeWithBothValues()
    {
        byte[] firstValue = WriteOctetString([0x01]);
        byte[] secondValue = WriteOctetString([0x02]);

        using CmsAttribute attribute = CmsAttribute.Create(CAdESSignatureFacts.CertificateValuesAttributeOid, [secondValue, firstValue], BaseMemoryPool.Shared);

        List<(string AttributeType, ReadOnlyMemory<byte> Value)> decoded = DecodeAttributeValues(attribute.AsReadOnlySpan().ToArray());

        Assert.HasCount(2, decoded, "A multi-valued attribute carries every value supplied.");
        Assert.AreEqual(CAdESSignatureFacts.CertificateValuesAttributeOid, decoded[0].AttributeType, "The attribute type is the one supplied.");
        Assert.AreSequenceEqual(firstValue, decoded[0].Value.ToArray(), "X.690 clause 11.6: the DER SET OF order is the encoder's, not the caller's.");
        Assert.AreSequenceEqual(secondValue, decoded[1].Value.ToArray(), "X.690 clause 11.6: the DER SET OF order is the encoder's, not the caller's.");
    }


    /// <summary>
    /// RFC 5652 §5.3 admits at most one instance of each attribute type in a signed-attribute set, and an
    /// empty set is outside the syntax; both are refused rather than encoded.
    /// </summary>
    [TestMethod]
    public void RefusesAnEmptySetAndARepeatedAttributeType()
    {
        using CmsAttribute contentType = CmsAttribute.Create(CAdESSignatureFacts.ContentTypeAttributeOid, WriteObjectIdentifier(WellKnownContentTypeOid), BaseMemoryPool.Shared);
        using CmsAttribute repeated = CmsAttribute.Create(CAdESSignatureFacts.ContentTypeAttributeOid, WriteObjectIdentifier(WellKnownContentTypeOid), BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(
            () => CmsSignedAttributesEncoding.Create([], BaseMemoryPool.Shared),
            "RFC 5652 §5.3: SignedAttributes is SET SIZE (1..MAX) OF Attribute.");
        Assert.ThrowsExactly<ArgumentException>(
            () => CmsSignedAttributesEncoding.Create([contentType, repeated], BaseMemoryPool.Shared),
            "RFC 5652 §5.3: signed attributes include at most one instance of each attribute type.");
    }


    /// <summary>
    /// The retagging step accepts only what a <c>SignerInfo.signedAttrs</c> field actually is: one
    /// <c>[0] IMPLICIT</c> constructed value with nothing after it.
    /// </summary>
    [TestMethod]
    public void RefusesInputThatIsNotASingleImplicitlyTaggedSet()
    {
        using CmsAttribute contentType = CmsAttribute.Create(CAdESSignatureFacts.ContentTypeAttributeOid, WriteObjectIdentifier(WellKnownContentTypeOid), BaseMemoryPool.Shared);
        using CmsSignedAttributesEncoding encoding = CmsSignedAttributesEncoding.Create([contentType], BaseMemoryPool.Shared);

        byte[] embedded = encoding.EmbeddedForm.AsReadOnlySpan().ToArray();
        byte[] alreadyRetagged = [.. embedded];
        alreadyRetagged[0] = SetOfTagOctet;
        byte[] withTrailingOctet = [.. embedded, 0x00];

        Assert.ThrowsExactly<CryptographicException>(
            () => CmsSignedAttributesEncoding.ToSigningInput([], BaseMemoryPool.Shared),
            "An empty input carries no signed attributes at all.");
        Assert.ThrowsExactly<CryptographicException>(
            () => CmsSignedAttributesEncoding.ToSigningInput(alreadyRetagged, BaseMemoryPool.Shared),
            "A universal SET OF is the signature input, not the embedded form; retagging it again would be a silent no-op.");
        Assert.ThrowsExactly<AsnContentException>(
            () => CmsSignedAttributesEncoding.ToSigningInput(withTrailingOctet, BaseMemoryPool.Shared),
            "Trailing octets after the set are rejected rather than ignored.");
    }


    /// <summary>
    /// An attribute value is exactly one DER-encoded value; an empty value, a truncated one, and one with
    /// trailing octets are all refused at the point the attribute is built.
    /// </summary>
    [TestMethod]
    public void RefusesAnAttributeValueThatIsNotExactlyOneEncodedValue()
    {
        byte[] value = WriteOctetString([0x01, 0x02]);
        byte[] truncated = value[..^1];
        byte[] withTrailingOctet = [.. value, 0x00];

        Assert.ThrowsExactly<ArgumentException>(
            () => CmsAttribute.Create(CAdESSignatureFacts.ContentTypeAttributeOid, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared),
            "RFC 5652 §5.3: an attribute value is a DER-encoded value.");
        Assert.ThrowsExactly<AsnContentException>(
            () => CmsAttribute.Create(CAdESSignatureFacts.ContentTypeAttributeOid, truncated, BaseMemoryPool.Shared),
            "A truncated value is malformed DER.");
        Assert.ThrowsExactly<AsnContentException>(
            () => CmsAttribute.Create(CAdESSignatureFacts.ContentTypeAttributeOid, withTrailingOctet, BaseMemoryPool.Shared),
            "Octets after the value are rejected rather than ignored.");
    }


    /// <summary>The id-data content type object identifier (RFC 5652 §4), the value of a content-type attribute over plain data.</summary>
    private static string WellKnownContentTypeOid { get; } = "1.2.840.113549.1.7.1";


    /// <summary>
    /// Writes a DER OBJECT IDENTIFIER value, the shape a content-type attribute's value has.
    /// </summary>
    /// <param name="oid">The object identifier in dotted form.</param>
    /// <returns>The encoded value.</returns>
    private static byte[] WriteObjectIdentifier(string oid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);

        return writer.Encode();
    }


    /// <summary>
    /// Writes a DER OCTET STRING value, the shape a message-digest attribute's value has.
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
    /// Reads one field of the first SignerInfo of a minted signature, located by its tag octet through the
    /// independent structure oracle.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="tagOctet">The field's first tag octet.</param>
    /// <param name="wholeElement">Whether to return the whole element or only its content octets.</param>
    /// <returns>The field's octets.</returns>
    private static byte[] ReadSignerField(byte[] signedData, byte tagOctet, bool wholeElement)
    {
        foreach(CmsTlvBounds field in CmsStructureOracle.SignerFields(signedData, signerIndex: 0))
        {
            if(signedData[field.Start] == tagOctet)
            {
                return wholeElement
                    ? signedData[field.Start..field.End]
                    : signedData[field.ContentStart..field.ContentEnd];
            }
        }

        throw new InvalidOperationException($"The minted signature carries no SignerInfo field tagged 0x{tagOctet:X2}.");
    }


    /// <summary>
    /// Decodes a <c>[0] IMPLICIT</c> signed-attribute set into its attribute types and single values.
    /// </summary>
    /// <param name="embeddedSignedAttributes">The <c>[0] IMPLICIT</c> encoding.</param>
    /// <returns>Each attribute's type and its first value.</returns>
    private static List<(string AttributeType, ReadOnlyMemory<byte> Value)> DecodeAttributes(byte[] embeddedSignedAttributes)
    {
        var decoded = new List<(string, ReadOnlyMemory<byte>)>();
        var reader = new AsnReader(embeddedSignedAttributes, AsnEncodingRules.DER);
        AsnReader set = reader.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0));
        while(set.HasData)
        {
            decoded.AddRange(DecodeAttributeValues(set.ReadEncodedValue().ToArray()));
        }

        return decoded;
    }


    /// <summary>
    /// Decodes one complete DER <c>Attribute</c> into its type and every value it carries.
    /// </summary>
    /// <param name="encodedAttribute">The DER-encoded attribute.</param>
    /// <returns>The attribute type paired with each of its values.</returns>
    private static List<(string AttributeType, ReadOnlyMemory<byte> Value)> DecodeAttributeValues(byte[] encodedAttribute)
    {
        var decoded = new List<(string, ReadOnlyMemory<byte>)>();
        var reader = new AsnReader(encodedAttribute, AsnEncodingRules.DER);
        AsnReader attribute = reader.ReadSequence();
        string attributeType = attribute.ReadObjectIdentifier();
        AsnReader values = attribute.ReadSetOf();
        while(values.HasData)
        {
            decoded.Add((attributeType, values.ReadEncodedValue()));
        }

        return decoded;
    }
}
