using System;
using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the delta-stage D2 surfaces: the opt-in Table 1 signed-attribute set
/// (<see cref="CAdESOptionalSignedAttributes"/>) <see cref="CAdESSignatureCreation.PrepareAsync"/> now accepts
/// (commitment-type-indication §5.2.3, content-hints §5.2.4.1, mime-type §5.2.4.2, signer-location §5.2.5,
/// content-reference §5.2.11, content-identifier §5.2.12, signature-policy-identifier §5.2.9.1,
/// content-time-stamp §5.2.8), <see cref="CAdESSignatureAugmentation.AddSignaturePolicyStore"/> gated exactly
/// per Table 1 requirement k), and Table 1 requirement m) enforcement at B-T/B-LTA attachment. Delta stage D3
/// added one more member to the same record, <c>signer-attributes-v2</c> (§5.2.6.1, <c>claimedAttributes</c> arm
/// only), whose tests sit here with the others rather than in the countersignature class.
/// </summary>
/// <remarks>
/// Every signature under test is minted by the shipped creation surface over
/// <see cref="BouncyCastleKeyMaterialCreator"/> key material; every produced attribute is read back by the
/// independently-registered BouncyCastle <see cref="VerifyCmsSignedDataDelegate"/> backend (a CMS parser
/// sharing no code with <see cref="CAdESSignatureCreation"/>) and re-checked against the shipped
/// <see cref="CAdESVerification"/> path.
/// </remarks>
[TestClass]
internal sealed class CAdESOptionalAttributesTests
{
    /// <summary>The BouncyCastle-backed <see cref="VerifyCmsSignedDataDelegate"/> registration qualifier.</summary>
    private const string BouncyCastleQualifier = "BouncyCastle";

    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.optional-attributes.example.test/";

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time every minted signature carries.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the D2 optional-attribute content"u8.ToArray());


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The <c>commitment-type-indication</c> attribute (§5.2.3) round-trips through the independent BouncyCastle
    /// reader byte for byte, decodes to the requested <c>commitmentTypeId</c>, and the signature still verifies
    /// under the shipped engine.
    /// </summary>
    [TestMethod]
    public async Task CommitmentTypeIndicationRoundTripsAndTheEngineAcceptsTheSignature()
    {
        const string CommitmentTypeId = "1.2.840.113549.1.9.16.6.1"; // id-cti-ets-proofOfOrigin (informative, any OID suffices here).
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes { CommitmentType = new CAdESCommitmentType { CommitmentTypeId = CommitmentTypeId } })
                .ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.CommitmentTypeIndicationAttributeOid).ConfigureAwait(false);

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader indication = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            Assert.AreEqual(CommitmentTypeId, indication.ReadObjectIdentifier(), "commitmentTypeId round-trips exactly.");
            Assert.IsFalse(indication.HasData, "No qualifier was requested, so none is present.");

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The <c>content-hints</c> attribute (§5.2.4.1) round-trips its optional <c>contentDescription</c> and its
    /// <c>contentType</c>, satisfying one alternative of the Table 1 requirement t) service.
    /// </summary>
    [TestMethod]
    public async Task ContentHintsRoundTripsAndTheEngineAcceptsTheSignature()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes
                {
                    ContentHints = new CAdESContentHints { ContentDescription = "an inner MIME part", ContentType = "1.2.840.113549.1.7.1" }
                }).ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.ContentHintsAttributeOid).ConfigureAwait(false);

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader hints = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            Assert.AreEqual("an inner MIME part", hints.ReadCharacterString(UniversalTagNumber.UTF8String), "contentDescription round-trips exactly.");
            Assert.AreEqual("1.2.840.113549.1.7.1", hints.ReadObjectIdentifier(), "contentType round-trips exactly.");

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The <c>mime-type</c> attribute (§5.2.4.2) is a bare <c>UTF8String</c> and round-trips exactly — the other
    /// alternative of the Table 1 requirement t) service.
    /// </summary>
    [TestMethod]
    public async Task MimeTypeRoundTripsAndTheEngineAcceptsTheSignature()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey, new CAdESOptionalSignedAttributes { MimeType = "application/octet-stream" }).ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.MimeTypeAttributeOid).ConfigureAwait(false);

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            Assert.AreEqual("application/octet-stream", reader.ReadCharacterString(UniversalTagNumber.UTF8String), "MimeType round-trips exactly (NOTE 7's detached fallback value here).");
            reader.ThrowIfNotEmpty();

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The <c>signer-location</c> attribute (§5.2.5) round-trips every field. The Annex D module opens
    /// <c>DEFINITIONS EXPLICIT TAGS</c>, so each <c>[n]</c> field is written CONSTRUCTED and encloses the tagged
    /// type's own tag: <c>countryName</c>/<c>localityName</c> enclose the chosen <c>DirectoryString</c>
    /// alternative, and <c>postalAddress</c> encloses its <c>PostalAddress</c> SEQUENCE OF —
    /// <c>[2] { SEQUENCE { DirectoryString, ... } }</c>. The exact DER is pinned so a drift in the writer cannot
    /// pass unnoticed by an independent reader moving with it.
    /// </summary>
    [TestMethod]
    public async Task SignerLocationRoundTripsEveryFieldAndTheEngineAcceptsTheSignature()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes
                {
                    SignerLocation = new CAdESSignerLocation
                    {
                        CountryName = "FI",
                        LocalityName = "Helsinki",
                        PostalAddress = ["Line one", "Line two"]
                    }
                }).ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.SignerLocationAttributeOid).ConfigureAwait(false);

            //Pin the exact DER (not merely re-read it), so a writer drift cannot pass unnoticed by moving the
            //reader with it: SignerLocation SEQUENCE { [0] { UTF8 "FI" }, [1] { UTF8 "Helsinki" },
            //[2] { SEQUENCE { UTF8 "Line one", UTF8 "Line two" } } } — postalAddress [2] EXPLICIT per the module.
            Assert.AreEqual(
                "302AA0040C024649A10A0C0848656C73696E6B69A21630140C084C696E65206F6E650C084C696E652074776F",
                Convert.ToHexString(attribute.AsReadOnlyMemory().Span),
                "The signer-location attribute value is the Annex D module's EXPLICIT-TAGS encoding to the octet.");

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader location = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            AsnReader country = location.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            Assert.AreEqual("FI", country.ReadCharacterString(UniversalTagNumber.UTF8String), "countryName round-trips under its explicit [0] wrapper.");

            AsnReader locality = location.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
            Assert.AreEqual("Helsinki", locality.ReadCharacterString(UniversalTagNumber.UTF8String), "localityName round-trips under its explicit [1] wrapper.");

            //postalAddress [2] is EXPLICIT (the Annex D module is DEFINITIONS EXPLICIT TAGS): the [2] tag encloses
            //PostalAddress's own SEQUENCE OF, so the inner SEQUENCE is read before the DirectoryString lines.
            AsnReader postalAddressField = location.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true));
            AsnReader postalAddress = postalAddressField.ReadSequence();
            postalAddressField.ThrowIfNotEmpty();
            Assert.AreEqual("Line one", postalAddress.ReadCharacterString(UniversalTagNumber.UTF8String), "The first postal address line round-trips.");
            Assert.AreEqual("Line two", postalAddress.ReadCharacterString(UniversalTagNumber.UTF8String), "The second postal address line round-trips.");
            Assert.IsFalse(postalAddress.HasData, "Exactly the two supplied lines are present.");
            location.ThrowIfNotEmpty();

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// <see cref="CAdESSignerLocation"/> requires at least one field (clause 5.2.5's own precondition) and at
    /// most six postal-address lines (<c>PostalAddress SIZE(1..6)</c>).
    /// </summary>
    [TestMethod]
    public async Task SignerLocationRequiresAtLeastOneFieldAndAtMostSixPostalAddressLines()
    {
        using PkiCertificateMemory certificate = MintP256Certificate();

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, null, PkiDigestAlgorithm.Sha256, SigningTime, null, null, BaseMemoryPool.Shared,
                TestContext.CancellationToken, new CAdESOptionalSignedAttributes { SignerLocation = new CAdESSignerLocation() }).ConfigureAwait(false);
        }).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, null, PkiDigestAlgorithm.Sha256, SigningTime, null, null, BaseMemoryPool.Shared,
                TestContext.CancellationToken,
                new CAdESOptionalSignedAttributes { SignerLocation = new CAdESSignerLocation { PostalAddress = ["1", "2", "3", "4", "5", "6", "7"] } }).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// The <c>content-reference</c> attribute (§5.2.11) round-trips its three fields exactly.
    /// </summary>
    [TestMethod]
    public async Task ContentReferenceRoundTripsAndTheEngineAcceptsTheSignature()
    {
        byte[] signedContentIdentifier = [1, 2, 3, 4];
        byte[] originatorSignatureValue = [9, 8, 7, 6, 5];
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes
                {
                    ContentReference = new CAdESContentReference
                    {
                        ContentType = "1.2.840.113549.1.7.1",
                        SignedContentIdentifier = signedContentIdentifier,
                        OriginatorSignatureValue = originatorSignatureValue
                    }
                }).ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.ContentReferenceAttributeOid).ConfigureAwait(false);

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader reference = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            Assert.AreEqual("1.2.840.113549.1.7.1", reference.ReadObjectIdentifier(), "contentType round-trips exactly.");
            Assert.AreSequenceEqual(signedContentIdentifier, reference.ReadOctetString(), "signedContentIdentifier round-trips exactly.");
            Assert.AreSequenceEqual(originatorSignatureValue, reference.ReadOctetString(), "originatorSignatureValue round-trips exactly.");

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The <c>signer-attributes-v2</c> attribute (§5.2.6.1) carries its <c>claimedAttributes</c> arm and nothing
    /// else: the <c>[0]</c> tag is EXPLICIT — the module of Annex D opens <c>DEFINITIONS EXPLICIT TAGS</c> and
    /// <c>ClaimedAttributes</c> is a <c>SEQUENCE OF</c>, not an untagged CHOICE — so the encoding is
    /// <c>[0] { SEQUENCE { Attribute, ... } }</c>, and every claimed <c>Attribute</c> arrives byte for byte as the
    /// caller built it.
    /// </summary>
    [TestMethod]
    public async Task SignerAttributesV2CarriesTheClaimedAttributesArmAndTheEngineAcceptsTheSignature()
    {
        //Clause 5.2.6.1 NOTE 1 suggests X.509's RoleAttribute for a claimed role; neither it nor the
        //claimed-SAML-assertion of clause 5.2.6.2 is modelled, the surface placing whatever Attribute it is given.
        const string RoleAttributeType = "2.5.4.72";                     //id-at-role (Recommendation ITU-T X.509).
        const string OrganizationalUnitType = "2.5.4.11";                //id-at-organizationalUnitName.
        using CmsAttribute role = CmsAttribute.Create(RoleAttributeType, Utf8String("Head of Procurement"), BaseMemoryPool.Shared);
        using CmsAttribute organizationalUnit = CmsAttribute.Create(OrganizationalUnitType, Utf8String("Procurement"), BaseMemoryPool.Shared);

        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes
                {
                    SignerAttributes = new CAdESSignerAttributesV2 { ClaimedAttributes = [role, organizationalUnit] }
                }).ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.SignerAttributesV2AttributeOid).ConfigureAwait(false);

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader signerAttribute = reader.ReadSequence();            //SignerAttributeV2
            reader.ThrowIfNotEmpty();

            AsnReader claimedArm = signerAttribute.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            Assert.IsFalse(signerAttribute.HasData,
                "certifiedAttributesV2 [1] and signedAssertions [2] are a recorded deliberate pass, so neither arm is present.");

            AsnReader claimedAttributes = claimedArm.ReadSequence();      //ClaimedAttributes ::= SEQUENCE OF Attribute
            claimedArm.ThrowIfNotEmpty();
            Assert.AreSequenceEqual(role.AsReadOnlySpan().ToArray(), claimedAttributes.ReadEncodedValue().ToArray(),
                "The first claimed Attribute is the caller's own octets, unchanged.");
            Assert.AreSequenceEqual(organizationalUnit.AsReadOnlySpan().ToArray(), claimedAttributes.ReadEncodedValue().ToArray(),
                "The second claimed Attribute likewise, in the order it was supplied — ClaimedAttributes is a SEQUENCE OF, so order is the caller's.");
            Assert.IsFalse(claimedAttributes.HasData, "Exactly the two supplied attributes are present.");

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Clause 5.2.6.1: "Empty <c>signer-attributes-v2</c> shall not be created" — and with the
    /// <c>certifiedAttributesV2</c>/<c>signedAssertions</c> arms deliberately not offered, an empty
    /// <c>claimedAttributes</c> set is the only way to ask for an empty attribute, so it is refused.
    /// </summary>
    [TestMethod]
    public async Task SignerAttributesV2RefusesAnEmptyClaimedAttributeSet()
    {
        using PkiCertificateMemory certificate = MintP256Certificate();

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, null, PkiDigestAlgorithm.Sha256, SigningTime, null, null, BaseMemoryPool.Shared,
                TestContext.CancellationToken,
                new CAdESOptionalSignedAttributes { SignerAttributes = new CAdESSignerAttributesV2 { ClaimedAttributes = [] } }).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>Encodes a DER <c>UTF8String</c>, for the claimed-attribute values of the §5.2.6.1 test.</summary>
    /// <param name="value">The text to encode.</param>
    /// <returns>The DER encoding.</returns>
    private static byte[] Utf8String(string value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);

        return writer.Encode();
    }


    /// <summary>
    /// The <c>content-identifier</c> attribute (§5.2.12) is a bare <c>OCTET STRING</c> and round-trips exactly.
    /// </summary>
    [TestMethod]
    public async Task ContentIdentifierRoundTripsAndTheEngineAcceptsTheSignature()
    {
        byte[] identifier = "signer@example.test|2026-07-30T00:00:00Z|random"u8.ToArray();
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey, new CAdESOptionalSignedAttributes { ContentIdentifier = identifier }).ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.ContentIdentifierAttributeOid).ConfigureAwait(false);

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            Assert.AreSequenceEqual(identifier, reader.ReadOctetString(), "ContentIdentifier round-trips exactly.");
            reader.ThrowIfNotEmpty();

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The <c>signature-policy-identifier</c> attribute (§5.2.9.1) round-trips its <c>sigPolicyId</c> and
    /// <c>sigPolicyHash</c>, always the <c>signaturePolicyId</c> CHOICE alternative.
    /// </summary>
    [TestMethod]
    public async Task SignaturePolicyIdentifierRoundTripsAndTheEngineAcceptsTheSignature()
    {
        const string SigPolicyId = "1.2.3.4.5.6.7.8.9";
        using DigestValue hashValue = AtsHashIndexV3Oracle.Hash("a real signature policy document"u8.ToArray(), PkiDigestAlgorithm.Sha256);
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes
                {
                    SignaturePolicyIdentifier = new CAdESSignaturePolicyIdentifier
                    {
                        SigPolicyId = SigPolicyId,
                        HashAlgorithm = PkiDigestAlgorithm.Sha256,
                        SigPolicyHash = hashValue.AsReadOnlyMemory()
                    }
                }).ConfigureAwait(false);

            using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
                signedData, CAdESSignatureFacts.SignaturePolicyIdentifierAttributeOid).ConfigureAwait(false);

            var reader = new AsnReader(attribute.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader signaturePolicyId = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            Assert.AreEqual(SigPolicyId, signaturePolicyId.ReadObjectIdentifier(), "sigPolicyId round-trips exactly.");
            AsnReader sigPolicyHash = signaturePolicyId.ReadSequence();
            AsnReader hashAlgorithm = sigPolicyHash.ReadSequence();
            Assert.AreEqual(WellKnownOids.Sha256, hashAlgorithm.ReadObjectIdentifier(), "hashAlgorithm round-trips exactly.");
            Assert.AreSequenceEqual(hashValue.AsReadOnlySpan().ToArray(), sigPolicyHash.ReadOctetString(), "sigPolicyHash round-trips exactly.");

            await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The <c>content-time-stamp</c> token's message imprint (§5.2.8) is the RAW hash of the encapsulated
    /// content — no ASN.1 tag or length — and is NOT the hash of the content re-encoded as a TLV, the
    /// convention clause 5.5.3's <c>archive-time-stamp-v3</c> uses instead and which this attribute must not
    /// borrow.
    /// </summary>
    [TestMethod]
    public async Task ContentTimeStampUsesTheRawValueImprintConventionNotTheAtsv3TlvConvention()
    {
        using Scenario scenario = Scenario.Create();
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], SigningTime.AddMinutes(1));

        using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
            scenario.Certificate, scenario.PrivateKey, Content, null, SigningTime, additionalCertificates: null,
            algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
            TestContext.CancellationToken,
            new CAdESOptionalSignedAttributes
            {
                ContentTimestampRequests =
                [
                    new CAdESContentTimestampRequest { TsaUri = TsaUri, FetchResponse = responder.FetchAsync }
                ]
            }).ConfigureAwait(false);

        using CmsSignedAttribute attribute = await ReadBackSignedAttributeAsync(
            signedData, CAdESSignatureFacts.ContentTimestampAttributeOid).ConfigureAwait(false);

        //ContentTimestamp ::= TimeStampToken — the whole attribute value IS one token (cardinality >= 0 is one
        //Attribute with one AttributeValue per token, RFC 5652 §5.3 forbidding a repeated attribute type).
        IMemoryOwner<byte> tokenOwner = BaseMemoryPool.Shared.Rent(attribute.Length);
        attribute.AsReadOnlySpan().CopyTo(tokenOwner.Memory.Span);
        using var token = new PkiCertificateMemory(tokenOwner, PkiCertificateTags.TimestampToken);
        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using DigestValue rawImprint = AtsHashIndexV3Oracle.Hash(Content.Span, PkiDigestAlgorithm.Sha256);
        var tlvWriter = new AsnWriter(AsnEncodingRules.DER);
        tlvWriter.WriteOctetString(Content.Span);
        using DigestValue tlvImprint = AtsHashIndexV3Oracle.Hash(tlvWriter.Encode(), PkiDigestAlgorithm.Sha256);

        Assert.IsNotNull(info.MessageImprint, "A content-time-stamp token this surface acquired states a message imprint.");
        Assert.AreSequenceEqual(rawImprint.AsReadOnlySpan().ToArray(), info.MessageImprint!.AsReadOnlySpan().ToArray(),
            "Clause 5.2.8: the imprint is the raw hash of the content, without ASN.1 tag and length.");
        Assert.IsFalse(tlvImprint.AsReadOnlySpan().SequenceEqual(info.MessageImprint!.AsReadOnlySpan()),
            "The imprint is not the hash of the content wrapped as a TLV — that convention belongs to clause 5.5.3, not 5.2.8.");

        await AssertEngineAcceptsAsync(signedData).ConfigureAwait(false);
    }


    /// <summary>
    /// Requirement k): <c>signature-policy-store</c> is refused when no <c>signature-policy-identifier</c>
    /// attribute is present at all.
    /// </summary>
    [TestMethod]
    public async Task SignaturePolicyStoreIsRefusedWithoutASignaturePolicyIdentifier()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            CAdESAugmentationException failure = Assert.ThrowsExactly<CAdESAugmentationException>(() =>
            {
                using CmsSignedData _ = CAdESSignatureAugmentation.AddSignaturePolicyStore(
                    signedData, signerIndex: 0,
                    new CAdESSignaturePolicyStore { DocumentSpecificationOid = "1.2.3", EncodedDocument = new byte[] { 1 } },
                    BaseMemoryPool.Shared);
            });

            Assert.AreEqual(CAdESAugmentationFailureKind.SignaturePolicyStoreRequirementNotMet, failure.FailureKind,
                "Requirement k): no signature-policy-identifier at all means the store shall not be incorporated.");
        }
    }


    /// <summary>
    /// Requirement k): <c>signature-policy-store</c> is refused when <c>signature-policy-identifier</c> is
    /// present but its <c>sigPolicyHash</c> is a zero-hash value (the "policy hash not known" convention).
    /// </summary>
    [TestMethod]
    public async Task SignaturePolicyStoreIsRefusedWhenTheHashIsZero()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes
                {
                    SignaturePolicyIdentifier = new CAdESSignaturePolicyIdentifier
                    {
                        SigPolicyId = "1.2.3.4",
                        HashAlgorithm = PkiDigestAlgorithm.Sha256,
                        SigPolicyHash = new byte[32] // every octet zero — the zero-hash convention.
                    }
                }).ConfigureAwait(false);

            CAdESAugmentationException failure = Assert.ThrowsExactly<CAdESAugmentationException>(() =>
            {
                using CmsSignedData _ = CAdESSignatureAugmentation.AddSignaturePolicyStore(
                    signedData, signerIndex: 0,
                    new CAdESSignaturePolicyStore { DocumentSpecificationOid = "1.2.3", EncodedDocument = new byte[] { 1 } },
                    BaseMemoryPool.Shared);
            });

            Assert.AreEqual(CAdESAugmentationFailureKind.SignaturePolicyStoreRequirementNotMet, failure.FailureKind,
                "Requirement k): a zero-hash sigPolicyHash states the hash is not known, so the store shall not be incorporated.");
        }
    }


    /// <summary>
    /// Requirement k): <c>signature-policy-store</c> is incorporated when <c>signature-policy-identifier</c>
    /// carries a real, non-zero <c>sigPolicyHash</c> — and the added attribute round-trips through the
    /// independent BouncyCastle reader.
    /// </summary>
    [TestMethod]
    public async Task SignaturePolicyStoreIsAddedWhenTheHashIsNonZeroAndRoundTrips()
    {
        using DigestValue hashValue = AtsHashIndexV3Oracle.Hash("a real signature policy document"u8.ToArray(), PkiDigestAlgorithm.Sha256);
        byte[] document = "the encoded signature policy document"u8.ToArray();
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await SignWithOptionalAttributesAsync(
                certificate, privateKey,
                new CAdESOptionalSignedAttributes
                {
                    SignaturePolicyIdentifier = new CAdESSignaturePolicyIdentifier
                    {
                        SigPolicyId = "1.2.3.4",
                        HashAlgorithm = PkiDigestAlgorithm.Sha256,
                        SigPolicyHash = hashValue.AsReadOnlyMemory()
                    }
                }).ConfigureAwait(false);

            using CmsSignedData withStore = CAdESSignatureAugmentation.AddSignaturePolicyStore(
                signedData, signerIndex: 0,
                new CAdESSignaturePolicyStore { DocumentSpecificationOid = "1.2.3", EncodedDocument = document },
                BaseMemoryPool.Shared);

            VerifyCmsSignedDataDelegate verify = ResolveBouncyCastleVerifier();
            using CmsVerifiedContent verified = await verify(withStore, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(verified.TryGetSignedAttribute(CAdESSignatureFacts.SignaturePolicyIdentifierAttributeOid, out _),
                "The signature-policy-identifier signed attribute is unaffected and still verifies.");

            byte[] octets = withStore.AsReadOnlySpan().ToArray();
            var storeReader = new AsnReader(
                UnsignedAttributeValue(octets, CAdESSignatureFacts.SignaturePolicyStoreAttributeOid), AsnEncodingRules.DER);
            AsnReader store = storeReader.ReadSequence();
            storeReader.ThrowIfNotEmpty();
            Assert.AreEqual("1.2.3", store.ReadObjectIdentifier(), "spDocSpec round-trips exactly.");
            Assert.AreSequenceEqual(document, store.ReadOctetString(), "spDocument.sigPolicyEncoded round-trips exactly.");

            await AssertEngineAcceptsAsync(withStore).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Requirement m): a signature-time-stamp token generated BEFORE the signing certificate's validity window
    /// began is refused rather than attached.
    /// </summary>
    [TestMethod]
    public async Task RequirementMRefusesASignatureTimestampTokenGeneratedBeforeTheCertificateWasValid()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await SignBaselineAsync(scenario).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], NotBefore.AddDays(-1));

        CAdESAugmentationException failure = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(
            () => CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = responder.FetchAsync,
                    SigningCertificate = scenario.Certificate
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(CAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp, failure.FailureKind,
            "Table 1 requirement m): the token's generation time falls before notBefore.");
    }


    /// <summary>
    /// Requirement m): a signature-time-stamp token generated AFTER the signing certificate expired is refused.
    /// </summary>
    [TestMethod]
    public async Task RequirementMRefusesASignatureTimestampTokenGeneratedAfterTheCertificateExpired()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await SignBaselineAsync(scenario).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], NotAfter.AddDays(1));

        CAdESAugmentationException failure = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(
            () => CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = responder.FetchAsync,
                    SigningCertificate = scenario.Certificate
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(CAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp, failure.FailureKind,
            "Table 1 requirement m): the token's generation time falls after notAfter.");
    }


    /// <summary>
    /// Requirement m): a token generated at or after a caller-supplied revocation instant is refused even
    /// though it falls within the certificate's raw validity window.
    /// </summary>
    [TestMethod]
    public async Task RequirementMRefusesATokenGeneratedAtOrAfterTheStatedRevocationInstant()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await SignBaselineAsync(scenario).ConfigureAwait(false);
        DateTimeOffset revokedAt = SigningTime.AddDays(1);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], revokedAt.AddHours(1));

        CAdESAugmentationException failure = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(
            () => CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = responder.FetchAsync,
                    SigningCertificate = scenario.Certificate,
                    SigningCertificateRevokedAt = revokedAt
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

        Assert.AreEqual(CAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp, failure.FailureKind,
            "Table 1 requirement m): the token's generation time is at or after the stated revocation instant.");
    }


    /// <summary>
    /// Requirement m)'s check is opt-out-able: a caller explicitly setting
    /// <see cref="CAdESSignatureTimestampContext.EnforceSigningCertificateValidity"/> to <see langword="false"/>
    /// gets a token attached even though its generation time falls outside the certificate's validity window.
    /// </summary>
    [TestMethod]
    public async Task RequirementMCanBeExplicitlyOptedOut()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await SignBaselineAsync(scenario).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], NotAfter.AddDays(1));

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                EnforceSigningCertificateValidity = false
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        VerifyCmsSignedDataDelegate verify = ResolveBouncyCastleVerifier();
        using CmsVerifiedContent verified = await verify(timestamped, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(Content.Span.SequenceEqual(verified.Content.Span), "Opting out still attaches the token; the signature otherwise verifies normally.");
    }


    /// <summary>
    /// Requirement m) enforcement (the secure default) needs a certificate to check the token's generation time
    /// against; omitting one while enforcement is on is a configuration error, not a silent bypass.
    /// </summary>
    [TestMethod]
    public async Task RequirementMRequiresACertificateWhenEnforcementIsOn()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await SignBaselineAsync(scenario).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], SigningTime.AddMinutes(1));

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CmsSignedData _ = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = responder.FetchAsync
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Requirement m)'s secure default applies equally at B-LTA attachment (defense in depth, see
    /// <see cref="CAdESArchiveTimestampContext.EnforceSigningCertificateValidity"/>): a token generated after
    /// the certificate expired is refused by default, and accepted when the caller opts out — the shape a
    /// caller raising an already-expired signature to B-LTA (the normal long-term-preservation case) needs.
    /// </summary>
    [TestMethod]
    public async Task RequirementMAppliesToTheArchiveTimestampAndCanBeOptedOut()
    {
        using Scenario scenario = Scenario.Create();
        using CmsSignedData baseline = await SignBaselineAsync(scenario).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], NotAfter.AddDays(1));

        CAdESAugmentationException failure = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(
            () => CAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CAdESArchiveTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = responder.FetchAsync,
                    ValidationMaterial = CAdESValidationMaterial.None,
                    SigningCertificate = scenario.Certificate
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).AsTask()).ConfigureAwait(false);
        Assert.AreEqual(CAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp, failure.FailureKind,
            "Defense in depth: the same secure default gates the archive time-stamp token by default.");

        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                EnforceSigningCertificateValidity = false
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        VerifyCmsSignedDataDelegate verify = ResolveBouncyCastleVerifier();
        using CmsVerifiedContent verified = await verify(archived, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(Content.Span.SequenceEqual(verified.Content.Span),
            "Opting out is exactly the CAdES-B-LTA-over-an-expired-signature case this knob exists for.");
    }


    /// <summary>Signs <see cref="Content"/> with <paramref name="optionalAttributes"/> through the shipped convenience surface.</summary>
    private async ValueTask<CmsSignedData> SignWithOptionalAttributesAsync(
        PkiCertificateMemory certificate, PrivateKeyMemory privateKey, CAdESOptionalSignedAttributes optionalAttributes) =>
        await CAdESSignatureCreation.SignAsync(
            certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
            algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
            TestContext.CancellationToken, optionalAttributes).ConfigureAwait(false);


    /// <summary>Signs <see cref="Content"/> as a CAdES-B-B baseline over <paramref name="scenario"/>'s key material, with no optional attributes.</summary>
    private async ValueTask<CmsSignedData> SignBaselineAsync(Scenario scenario) =>
        await CAdESSignatureCreation.SignAsync(
            scenario.Certificate, scenario.PrivateKey, Content, null, SigningTime, additionalCertificates: null,
            algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Reads one signed attribute back through the independently-registered BouncyCastle CMS backend — the
    /// "BC-oracle read-back" this stage's tests are required to exercise per attribute.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <param name="attributeType">The attribute's object identifier.</param>
    /// <returns>The attribute the independent reader recovered. The caller disposes it.</returns>
    private async ValueTask<CmsSignedAttribute> ReadBackSignedAttributeAsync(CmsSignedData signedData, string attributeType)
    {
        VerifyCmsSignedDataDelegate verify = ResolveBouncyCastleVerifier();
        using CmsVerifiedContent verified = await verify(signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified.TryGetSignedAttribute(attributeType, out CmsSignedAttribute? attribute),
            $"The independent BouncyCastle reader must recover the '{attributeType}' signed attribute.");

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(attribute!.Length);
        attribute.AsReadOnlySpan().CopyTo(owner.Memory.Span);

        return new CmsSignedAttribute(attributeType, owner);
    }


    /// <summary>Asserts the shipped <see cref="CAdESVerification"/> path (engine SAV acceptance) still accepts <paramref name="signedData"/>.</summary>
    private async ValueTask AssertEngineAcceptsAsync(CmsSignedData signedData)
    {
        using CAdESVerificationResult verification = await CAdESVerification.VerifyAsync(
            signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verification.IsValid, "An extra optional signed attribute must not break baseline CAdES-B-B verification.");
    }


    /// <summary>Resolves the registered BouncyCastle <see cref="VerifyCmsSignedDataDelegate"/> — an independent backend sharing no code with the creation/augmentation surfaces.</summary>
    private static VerifyCmsSignedDataDelegate ResolveBouncyCastleVerifier() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), BouncyCastleQualifier)
            ?? throw new InvalidOperationException("No BouncyCastle VerifyCmsSignedDataDelegate has been registered.");


    /// <summary>
    /// Walks <paramref name="signedData"/>'s first signer's <c>unsignedAttrs</c> independently of the library's
    /// own reader, returning the single <c>AttributeValue</c> of the named attribute.
    /// </summary>
    private static ReadOnlyMemory<byte> UnsignedAttributeValue(byte[] signedData, string attributeType)
    {
        var outer = new AsnReader(signedData, AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        AsnReader cmsSignedData = explicitContent.ReadSequence();
        _ = cmsSignedData.ReadInteger();
        _ = cmsSignedData.ReadSetOf();
        _ = cmsSignedData.ReadSequence();
        if(cmsSignedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = cmsSignedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        }

        AsnReader signerInfos = cmsSignedData.ReadSetOf();
        AsnReader signerInfo = signerInfos.ReadSequence();
        _ = signerInfo.ReadInteger();
        _ = signerInfo.ReadSequence();
        _ = signerInfo.ReadSequence();
        _ = signerInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        _ = signerInfo.ReadSequence();
        _ = signerInfo.ReadOctetString();
        AsnReader unsignedAttrs = signerInfo.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
        while(unsignedAttrs.HasData)
        {
            AsnReader attribute = unsignedAttrs.ReadSequence();
            string oid = attribute.ReadObjectIdentifier();
            AsnReader values = attribute.ReadSetOf();
            if(string.Equals(oid, attributeType, StringComparison.Ordinal))
            {
                return values.ReadEncodedValue();
            }
        }

        throw new InvalidOperationException($"The signature carries no unsigned attribute '{attributeType}'.");
    }


    /// <summary>Mints a P-256 signer certificate for a test that needs no signing key of its own.</summary>
    private static PkiCertificateMemory MintP256Certificate()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        privateKey.Dispose();

        return certificate;
    }


    /// <summary>
    /// Mints a P-256 signer: key material via <see cref="BouncyCastleKeyMaterialCreator"/> (the repo's test-key
    /// convention), and a self-signed certificate over the exact same public point through a platform
    /// <see cref="ECDsa"/> reconstructed from it.
    /// </summary>
    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintP256Signer()
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
            PkiCertificateMemory certificate = ToCertificateCarrier(platformCertificate.RawData);

            return (certificate, keys.PrivateKey);
        }
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as an X.509 certificate.</summary>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// The material the requirement m)/content-time-stamp tests start from: a Root CA and a Time-Stamping
    /// Authority under it, and a signer whose key material comes from the repository's test-key creator.
    /// </summary>
    private sealed class Scenario: IDisposable
    {
        /// <summary>Gets the Root CA the authority is issued by.</summary>
        internal required X509ChainTestRingNode Root { get; init; }

        /// <summary>Gets the Time-Stamping Authority every token in these tests is signed by.</summary>
        internal required X509ChainTestRingNode Authority { get; init; }

        /// <summary>Gets the signer's certificate.</summary>
        internal required PkiCertificateMemory Certificate { get; init; }

        /// <summary>Gets the signer's private key material.</summary>
        internal required PrivateKeyMemory PrivateKey { get; init; }


        /// <summary>Builds the scenario: mints the ring and the signer.</summary>
        /// <returns>The scenario. The caller disposes it.</returns>
        internal static Scenario Create()
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();

            return new Scenario { Root = root, Authority = authority, Certificate = certificate, PrivateKey = privateKey };
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            PrivateKey.Dispose();
            Certificate.Dispose();
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
