using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
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
/// Conformance tests for <see cref="CAdESSignatureAugmentation"/>: raising a CAdES signature to the B-T, B-LT
/// and B-LTA levels of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see> — the <c>signature-time-stamp</c> of clause 5.3, the validation-data
/// placement of clause 5.5.3 with both of its strategies, and the <c>archive-time-stamp-v3</c> with its
/// <c>ats-hash-index-v3</c> of clauses 5.5.2 and 5.5.3.
/// </summary>
/// <remarks>
/// <para>
/// Every signature under augmentation is minted by the shipped creation surface
/// (<see cref="CAdESSignatureCreation.SignAsync"/>) over key material from
/// <see cref="BouncyCastleKeyMaterialCreator"/>, so the whole B-B to B-LTA succession runs through shipped code.
/// Every augmented result is then checked by readers that share no code with the augmentation: the platform
/// <see cref="SignedCms"/> reader, the independent time-stamp protocol oracle
/// (<see cref="X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate"/>), the independent hash-index
/// reimplementation (<see cref="AtsHashIndexV3Oracle"/>), the independent structural walker
/// (<see cref="CmsStructureOracle"/>), and the shipped <see cref="CAdESVerification"/> path.
/// </para>
/// <para>
/// Time-stamp tokens come from a <see cref="MintingTimestampResponder"/>, which answers the request octets that
/// crossed the transport seam by minting a genuine token over the imprint they state — the acquisition path is
/// therefore exercised end to end, request and response included, without a network.
/// </para>
/// <para>
/// The certificates, revocation lists and OCSP responses placed as validation material are minted for the
/// placement they are being tested against; whether they would validate this signature's own certificate is a
/// question for the validation processes, not for where clause 5.5.3 says the octets go.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESSignatureAugmentationTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.augmentation.example.test/";

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time every minted signature carries.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The generation time the signature time-stamps state.</summary>
    private static DateTimeOffset SignatureTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The generation time the archive time-stamps state.</summary>
    private static DateTimeOffset ArchiveTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The <c>thisUpdate</c> instant the minted revocation material states.</summary>
    private static DateTimeOffset ThisUpdate { get; } = TestClock.CanonicalEpoch.AddMinutes(-30);

    /// <summary>The <c>nextUpdate</c> instant the minted revocation material states.</summary>
    private static DateTimeOffset NextUpdate { get; } = TestClock.CanonicalEpoch.AddDays(7);

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the augmented CAdES content"u8.ToArray());


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A signature raised to CAdES-B-T carries a <c>signature-time-stamp</c> whose token the independent
    /// time-stamp protocol oracle accepts, whose enclosing signature the platform reader still verifies, and
    /// which the shipped CAdES verification reports as reaching the time-stamp level.
    /// </summary>
    [TestMethod]
    public async Task AddsASignatureTimestampTheIndependentOraclesAccept()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], SignatureTimestampTime);

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        var platformReader = new SignedCms();
        platformReader.Decode(timestamped.AsReadOnlySpan().ToArray());
        platformReader.CheckSignature(verifySignatureOnly: true);

        List<byte[]> tokens = UnsignedAttributeValues(timestamped.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.SignatureTimestampAttributeOid);
        Assert.HasCount(1, tokens, "Table 1 requires at least one signature-time-stamp at B-T; this augmentation added exactly one.");

        using PkiCertificateMemory token = ToTokenCarrier(tokens[0]);
        Assert.IsTrue(X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate(token, scenario.Authority),
            "The attached token is the one the authority signed, and the independent validator accepts it under the authority's certificate.");

        using CAdESVerificationResult verification = await CAdESVerification.VerifyAsync(
            timestamped, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verification.IsValid, "The augmented signature still verifies against the baseline rules.");
        Assert.AreEqual(CAdESLevel.Timestamp, verification.Level, "A signature carrying a verified signature-time-stamp has reached the time-stamp level.");
        Assert.AreEqual(SignatureTimestampTime, verification.TimestampTime, "The level's time is the one the authority stated.");
    }


    /// <summary>
    /// The message imprint of the attached token is the digest of the <c>SignerInfo.signature</c> value octets
    /// alone — clause 5.3's "without the ASN.1 tag and length" — and not of the whole encoded field, which is
    /// the convention clause 5.5.3 uses instead and which this level must not borrow.
    /// </summary>
    [TestMethod]
    public async Task TheSignatureTimestampImprintIsTheSignatureValueWithoutItsTagAndLength()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], SignatureTimestampTime);

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = scenario.Baseline.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> signerFields = CmsStructureOracle.SignerFields(octets, signerIndex: 0);
        CmsTlvBounds signature = signerFields[^1];
        byte[] valueOctets = octets[signature.ContentStart..signature.ContentEnd];
        byte[] wholeField = octets[signature.Start..signature.End];

        List<byte[]> tokens = UnsignedAttributeValues(timestamped.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.SignatureTimestampAttributeOid);
        using PkiCertificateMemory token = ToTokenCarrier(tokens[0]);
        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using DigestValue expected = AtsHashIndexV3Oracle.Hash(valueOctets, PkiDigestAlgorithm.Sha256);
        using DigestValue wholeFieldDigest = AtsHashIndexV3Oracle.Hash(wholeField, PkiDigestAlgorithm.Sha256);

        Assert.IsNotNull(info.MessageImprint, "A token this augmentation attached states a message imprint.");
        Assert.AreSequenceEqual(expected.AsReadOnlySpan().ToArray(), info.MessageImprint!.AsReadOnlySpan().ToArray(),
            "Clause 5.3: the imprint is the hash of the signature field's value octets.");
        Assert.IsFalse(wholeFieldDigest.AsReadOnlySpan().SequenceEqual(info.MessageImprint!.AsReadOnlySpan()),
            "The imprint is not the hash of the whole encoded field: that is clause 5.5.3's convention, not clause 5.3's.");
    }


    /// <summary>
    /// Raising a signature to B-T rewrites nothing but the length octets of the containers enclosing the new
    /// attribute — the preservation clause 5.5.3 states, asserted at the octet level by the independent walker.
    /// </summary>
    [TestMethod]
    public async Task TheSignatureTimestampAugmentationPreservesEveryOctetOutsideTheLengthChain()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], SignatureTimestampTime);

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(
                scenario.Baseline.AsReadOnlySpan().ToArray(), timestamped.AsReadOnlySpan().ToArray(), signerIndex: 0),
            "Clause 5.5.3: the augmentation preserves the binary encoding of everything already present.");
    }


    /// <summary>
    /// Validation material goes exactly where Table 1 requirements d), q) and r) put it: certificates into
    /// <c>SignedData.certificates</c>, a CRL into <c>SignedData.crls</c> as the <c>crl</c> alternative, and an
    /// OCSP response into <c>SignedData.crls</c> as the <c>other</c> alternative typed by the RFC 5940 object
    /// identifier.
    /// </summary>
    [TestMethod]
    public async Task PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory authorityCertificate = ToCertificateCarrier(scenario.Authority.Certificate.RawData);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(scenario.Root, ThisUpdate, NextUpdate, []);
        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            scenario.Baseline,
            signerIndex: 0,
            new CAdESValidationMaterial
            {
                Certificates = [authorityCertificate],
                CertificateRevocationLists = [revocationList],
                OcspResponses = [ocspResponse]
            },
            BaseMemoryPool.Shared);

        var platformReader = new SignedCms();
        platformReader.Decode(longTerm.AsReadOnlySpan().ToArray());
        platformReader.CheckSignature(verifySignatureOnly: true);
        Assert.HasCount(2, platformReader.Certificates, "The signer's own certificate plus the one placed as validation material.");

        List<byte[]> revocationEntries = RevocationInformation(longTerm.AsReadOnlySpan().ToArray());
        Assert.HasCount(2, revocationEntries, "Both the certificate revocation list and the OCSP response are members of the one crls field.");
        Assert.AreEqual(0x30, revocationEntries[0][0], "Requirement q: a CRL is placed as the crl alternative, a CertificateList SEQUENCE.");
        Assert.AreEqual(0xA1, revocationEntries[1][0], "Requirement r: an OCSP response is placed as the other alternative, the [1] context-tagged OtherRevocationInfoFormat.");

        var otherReader = new AsnReader(revocationEntries[1], AsnEncodingRules.DER)
            .ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
        Assert.AreEqual("1.3.6.1.5.5.7.16.2", otherReader.ReadObjectIdentifier(),
            "RFC 5940 §2: the format identifier types the octets that follow as an OCSPResponse.");
        Assert.AreSequenceEqual(ocspResponse.AsReadOnlySpan().ToArray(), otherReader.ReadEncodedValue().ToArray(),
            "The response is carried verbatim, not re-encoded.");
    }


    /// <summary>
    /// The creation-to-extraction round trip closes for an embedded OCSP response under the first placement: a
    /// whole <c>OCSPResponse</c> placed into the root <c>SignedData.crls</c> by the shipped
    /// <see cref="CAdESSignatureAugmentation.AddValidationData"/> — under RFC 5940 §2's
    /// <c>id-ri-ocsp-response</c> (clause 5.4.2.2) — is surfaced again by the shipped
    /// <see cref="CAdESSignatureFacts.ExtractAsync"/> as exactly one <c>EmbeddedOcspResponses</c> entry
    /// byte-identical to what was placed. Regression for the reader that recognised only
    /// <c>id-pkix-ocsp-basic</c> and silently dropped every self-produced embedded response.
    /// </summary>
    [TestMethod]
    public async Task ARoundTripThroughTheRootPlacementSurfacesTheEmbeddedOcspResponseByteForByte()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { OcspResponses = [ocspResponse] }, BaseMemoryPool.Shared);

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = longTerm }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, facts.EmbeddedOcspResponses,
            "Clause 5.4.2.2: the one OCSP response placed in the root SignedData.crls is surfaced exactly once.");
        Assert.AreSequenceEqual(ocspResponse.AsReadOnlySpan().ToArray(), facts.EmbeddedOcspResponses[0].AsReadOnlySpan().ToArray(),
            "The whole OCSPResponse RFC 5940 §2's id-ri-ocsp-response types is surfaced verbatim — not re-encoded, and not dropped as the id-pkix-ocsp-basic-only reader dropped it.");
    }


    /// <summary>
    /// The same round trip through the second placement of clause 5.5.3: a whole <c>OCSPResponse</c> written
    /// into the latest archive time-stamp token's own <c>revocation-values</c> attribute — its
    /// <c>otherRevVals</c> field under <c>id-ri-ocsp-response</c> (clause A.1.2.2) — is surfaced again,
    /// byte-identical, when that token is read as a Signed Data Object of its own.
    /// </summary>
    [TestMethod]
    public async Task ARoundTripThroughTheNestedPlacementSurfacesTheEmbeddedOcspResponseByteForByte()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData legacy = await AttachLegacyArchiveTimestampAsync(scenario, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid).ConfigureAwait(false);
        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            legacy, signerIndex: 0, new CAdESValidationMaterial { OcspResponses = [ocspResponse] }, BaseMemoryPool.Shared);

        List<byte[]> tokens = UnsignedAttributeValues(longTerm.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid);
        Assert.HasCount(1, tokens, "The material went into the one archive time-stamp token's own revocation-values, not the root.");

        using CmsSignedData token = CmsSignedData.FromBytes(tokens[0], BaseMemoryPool.Shared);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = token }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, facts.EmbeddedOcspResponses,
            "Clause A.1.2.2: the OCSP response in the token's revocation-values.otherRevVals is surfaced exactly once.");
        Assert.AreSequenceEqual(ocspResponse.AsReadOnlySpan().ToArray(), facts.EmbeddedOcspResponses[0].AsReadOnlySpan().ToArray(),
            "The whole OCSPResponse carried under id-ri-ocsp-response is surfaced verbatim from the nested placement.");
    }


    /// <summary>
    /// The <c>revocation-values</c> attribute the augmentation writes tags every field per the Annex D module's
    /// <c>DEFINITIONS EXPLICIT TAGS</c>: <c>crlVals [0] { SEQUENCE OF CertificateList }</c>,
    /// <c>ocspVals [1] { SEQUENCE OF BasicOCSPResponse }</c>, and
    /// <c>otherRevVals [2] { OtherRevVals SEQUENCE { id-ri-ocsp-response, SEQUENCE OF OCSPResponse } }</c>
    /// (clause A.1.2.2). Decoded field by field against the offered DER — a <c>BasicOCSPResponse</c> lands in
    /// <c>ocspVals</c> and a whole <c>OCSPResponse</c> under <c>otherRevVals</c>'s <c>id-ri-ocsp-response</c>,
    /// each carried verbatim — so the type routing is proven by inspection, not by a presence count.
    /// </summary>
    [TestMethod]
    public async Task RevocationValuesTagsEveryFieldWithTheModulesExplicitTagsAndRoutesBothOcspFormsByType()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData legacy = await AttachLegacyArchiveTimestampAsync(scenario, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid).ConfigureAwait(false);

        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(scenario.Root, ThisUpdate, NextUpdate, []);
        using PkiCertificateMemory wholeResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);
        byte[] basicResponseDer = ExtractBasicResponse(wholeResponse.AsReadOnlySpan().ToArray());
        using PkiCertificateMemory basicResponse = ToOcspResponseCarrier(basicResponseDer);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            legacy,
            signerIndex: 0,
            new CAdESValidationMaterial { CertificateRevocationLists = [revocationList], OcspResponses = [wholeResponse, basicResponse] },
            BaseMemoryPool.Shared);

        List<byte[]> tokens = UnsignedAttributeValues(longTerm.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid);
        List<byte[]> revocationValues = UnsignedAttributeValues(tokens[0], signerIndex: 0, CAdESSignatureFacts.RevocationValuesAttributeOid);
        Assert.HasCount(1, revocationValues, "Clause A.1.2.2: the material is written as one revocation-values attribute.");

        AsnReader values = new AsnReader(revocationValues[0], AsnEncodingRules.DER).ReadSequence();

        //crlVals [0] EXPLICIT: the [0] tag encloses the crlVals SEQUENCE OF, so the inner SEQUENCE is read before
        //the CertificateList — not the CertificateList directly (reading it directly is the pre-fix bug).
        AsnReader crlField = values.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        AsnReader crlSequenceOf = crlField.ReadSequence();
        Assert.IsFalse(crlField.HasData, "crlVals [0] encloses exactly the SEQUENCE OF (EXPLICIT TAGS), nothing else.");
        Assert.AreSequenceEqual(revocationList.AsReadOnlySpan().ToArray(), crlSequenceOf.ReadEncodedValue().ToArray(), "crlVals's SEQUENCE OF carries the CertificateList verbatim.");
        Assert.IsFalse(crlSequenceOf.HasData, "Exactly one CRL is stated.");

        //ocspVals [1] EXPLICIT: a BasicOCSPResponse is routed here, wrapped in the explicit SEQUENCE OF.
        AsnReader ocspField = values.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
        AsnReader ocspSequenceOf = ocspField.ReadSequence();
        Assert.IsFalse(ocspField.HasData, "ocspVals [1] encloses exactly the SEQUENCE OF.");
        Assert.AreSequenceEqual(basicResponseDer, ocspSequenceOf.ReadEncodedValue().ToArray(), "ocspVals carries the BasicOCSPResponse verbatim — the type routing, by field inspection.");
        Assert.IsFalse(ocspSequenceOf.HasData, "Exactly one BasicOCSPResponse is stated.");

        //otherRevVals [2] EXPLICIT: a whole OCSPResponse is routed here under id-ri-ocsp-response.
        AsnReader otherField = values.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true));
        AsnReader otherRevVals = otherField.ReadSequence();
        Assert.IsFalse(otherField.HasData, "otherRevVals [2] encloses exactly the OtherRevVals SEQUENCE.");
        Assert.AreEqual("1.3.6.1.5.5.7.16.2", otherRevVals.ReadObjectIdentifier(), "A whole OCSPResponse is typed id-ri-ocsp-response (clause A.1.2.2 / RFC 5940 §2) — routed by field inspection, not a presence count.");
        AsnReader wholeSequenceOf = otherRevVals.ReadSequence();
        Assert.AreSequenceEqual(wholeResponse.AsReadOnlySpan().ToArray(), wholeSequenceOf.ReadEncodedValue().ToArray(), "otherRevVals carries the whole OCSPResponse verbatim.");
        Assert.IsFalse(wholeSequenceOf.HasData, "Exactly one whole OCSPResponse is stated.");
        Assert.IsFalse(values.HasData, "RevocationValues holds exactly crlVals, ocspVals and otherRevVals.");
    }


    /// <summary>
    /// A foreign signature that wrote <c>revocation-values</c> in the tag-replacing legacy shape (the context tag
    /// standing in for the inner <c>SEQUENCE OF</c>'s own tag, rather than the module's EXPLICIT
    /// <c>[n] { SEQUENCE OF }</c>) is still read: a lenient read of foreign material is defensible while the
    /// writer always emits the explicit shape (lenient read, strict write).
    /// </summary>
    [TestMethod]
    public async Task ReadsALegacyTagReplacingRevocationValuesShapeFromAForeignSignature()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(scenario.Root, ThisUpdate, NextUpdate, []);
        using PkiCertificateMemory wholeResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);
        byte[] basicResponseDer = ExtractBasicResponse(wholeResponse.AsReadOnlySpan().ToArray());

        //A tag-replacing encoder: each context tag stands in for the inner SEQUENCE OF's own tag, and otherRevVals
        //[2] is written AS the OtherRevVals content (its first child the OID). This is what the pre-fix writer of
        //this very library produced, and what the fixed reader must still tolerate when reading foreign input.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                                                    //RevocationValues
        {
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))    //crlVals [0] tag-replacing
            {
                writer.WriteEncodedValue(revocationList.AsReadOnlySpan());
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true)))    //ocspVals [1] tag-replacing
            {
                writer.WriteEncodedValue(basicResponseDer);
            }

            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true)))    //otherRevVals [2] tag-replacing OtherRevVals SEQUENCE
            {
                writer.WriteObjectIdentifier("1.3.6.1.5.5.7.16.2");
                using(writer.PushSequence())                                                            //SEQUENCE OF OCSPResponse
                {
                    writer.WriteEncodedValue(wholeResponse.AsReadOnlySpan());
                }
            }
        }

        using CmsAttribute legacyRevocationValues = CmsAttribute.Create(CAdESSignatureFacts.RevocationValuesAttributeOid, writer.Encode(), BaseMemoryPool.Shared);
        using CmsSignedData withLegacyShape = CmsSignedDataAugmentation.AppendUnsignedAttributes(
            scenario.Baseline, signerIndex: 0, [legacyRevocationValues], BaseMemoryPool.Shared);

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = withLegacyShape }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, facts.EmbeddedCertificateRevocationLists, "crlVals's tag-replacing CertificateList is still read.");
        Assert.AreSequenceEqual(revocationList.AsReadOnlySpan().ToArray(), facts.EmbeddedCertificateRevocationLists[0].AsReadOnlySpan().ToArray(), "The CRL surfaces verbatim from the legacy shape.");
        Assert.HasCount(2, facts.EmbeddedOcspResponses, "The BasicOCSPResponse (ocspVals) and the whole OCSPResponse (otherRevVals) both surface from the legacy shape.");
    }


    /// <summary>
    /// Placing validation material leaves every field the archive time-stamp's message imprint is computed over
    /// byte-identical, which is what makes B-LT reachable after an archive time-stamp already exists.
    /// </summary>
    [TestMethod]
    public async Task PlacingValidationMaterialPreservesTheSignerInfoFieldsAnImprintIsTakenOver()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory authorityCertificate = ToCertificateCarrier(scenario.Authority.Certificate.RawData);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { Certificates = [authorityCertificate] }, BaseMemoryPool.Shared);

        List<byte[]> before = AtsHashIndexV3Oracle.ImprintSignerFields(scenario.Baseline.AsReadOnlySpan().ToArray(), signerIndex: 0);
        List<byte[]> after = AtsHashIndexV3Oracle.ImprintSignerFields(longTerm.AsReadOnlySpan().ToArray(), signerIndex: 0);

        Assert.HasCount(before.Count, after, "The same SignerInfo fields are there afterwards.");
        for(int i = 0; i < before.Count; ++i)
        {
            Assert.AreSequenceEqual(before[i], after[i], $"Clause 5.5.3: the encoding of SignerInfo field {i} is preserved by the augmentation.");
        }
    }


    /// <summary>
    /// A certificate the signature already carries is not placed a second time — requirement e)'s "duplication
    /// of certificate values should be avoided", applied by construction.
    /// </summary>
    [TestMethod]
    public async Task AvoidsDuplicatingMaterialTheSignatureAlreadyCarries()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { Certificates = [scenario.SignerCertificate] }, BaseMemoryPool.Shared);

        var platformReader = new SignedCms();
        platformReader.Decode(longTerm.AsReadOnlySpan().ToArray());
        Assert.HasCount(1, platformReader.Certificates, "The signer's certificate was already there, so nothing was added.");
        Assert.AreSequenceEqual(scenario.Baseline.AsReadOnlySpan().ToArray(), longTerm.AsReadOnlySpan().ToArray(),
            "With nothing to add, the signature stands octet for octet as it was.");
    }


    /// <summary>
    /// A Delta CRL is refused unless the complete set accompanies it — clause 5.5.3's "in the case that the
    /// validation data contains a Delta CRL, then the whole set of CRLs shall be included" — and accepted when
    /// a complete list is placed alongside it.
    /// </summary>
    [TestMethod]
    public async Task RefusesADeltaCrlWithoutTheCompleteSetAndAcceptsItWithOne()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory deltaList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            scenario.Root, ThisUpdate, NextUpdate, [], deltaCrlIndicatorBaseNumber: 1);
        using PkiCertificateMemory completeList = X509ChainTestRingRevocation.MintCertificateRevocationList(scenario.Root, ThisUpdate, NextUpdate, []);

        CAdESAugmentationException failure = Assert.ThrowsExactly<CAdESAugmentationException>(() =>
        {
            using CmsSignedData _ = CAdESSignatureAugmentation.AddValidationData(
                scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { CertificateRevocationLists = [deltaList] }, BaseMemoryPool.Shared);
        });
        Assert.AreEqual(CAdESAugmentationFailureKind.DeltaCrlWithoutCompleteSet, failure.FailureKind,
            "A Delta CRL alone leaves the revocation list incomplete, which clause 5.5.3 refuses.");

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { CertificateRevocationLists = [deltaList, completeList] }, BaseMemoryPool.Shared);
        Assert.HasCount(2, RevocationInformation(longTerm.AsReadOnlySpan().ToArray()),
            "With the complete list alongside it, both lists are placed.");
    }


    /// <summary>
    /// A bare <c>BasicOCSPResponse</c> has no place in <c>SignedData.crls</c>, whose RFC 5940 encoding names the
    /// whole <c>OCSPResponse</c> type (clause 5.4.2.2); it is refused rather than written under a format
    /// identifier that would misdescribe it.
    /// </summary>
    [TestMethod]
    public async Task RefusesABareBasicResponseAtTheRootPlacement()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);
        using PkiCertificateMemory basicResponse = ToOcspResponseCarrier(ExtractBasicResponse(ocspResponse.AsReadOnlySpan().ToArray()));

        CAdESAugmentationException failure = Assert.ThrowsExactly<CAdESAugmentationException>(() =>
        {
            using CmsSignedData _ = CAdESSignatureAugmentation.AddValidationData(
                scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { OcspResponses = [basicResponse] }, BaseMemoryPool.Shared);
        });

        Assert.AreEqual(CAdESAugmentationFailureKind.UnsupportedValidationObject, failure.FailureKind,
            "Clause 5.4.2.2: an OCSP response inside SignedData.crls is the OCSPResponse type RFC 5940 names.");
    }


    /// <summary>
    /// A signature carrying neither optional set gets both created in their syntax positions —
    /// <c>certificates</c> after <c>encapContentInfo</c> and <c>crls</c> after it, both before
    /// <c>signerInfos</c> (RFC 5652 §5.1) — and the platform reader accepts the result.
    /// </summary>
    [TestMethod]
    public void CreatesTheOptionalSetsWhenTheSignatureCarriesNeither()
    {
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData bare = CmsSignedDataTestFactory.SignAsCmsWithoutCertificates(Content.Span, signerCertificate);
        using PkiCertificateMemory certificate = ToCertificateCarrier(signerCertificate.RawData);
        using X509ChainTestRingNode listIssuer = X509ChainTestRing.CreateRootCa(
            new FakeTimeProvider(TestClock.CanonicalEpoch), notBefore: NotBefore, notAfter: NotAfter);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(listIssuer, ThisUpdate, NextUpdate, []);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            bare,
            signerIndex: 0,
            new CAdESValidationMaterial { Certificates = [certificate], CertificateRevocationLists = [revocationList] },
            BaseMemoryPool.Shared);

        byte[] octets = longTerm.AsReadOnlySpan().ToArray();
        Assert.HasCount(1, Certificates(octets), "The absent certificates field was created to hold the one certificate placed.");
        Assert.HasCount(1, RevocationInformation(octets), "The absent crls field was created to hold the one list placed.");

        var platformReader = new SignedCms();
        platformReader.Decode(octets);
        platformReader.CheckSignature(verifySignatureOnly: true);
        Assert.HasCount(1, platformReader.SignerInfos, "The structure the platform reader walks is still the one signer's.");
    }


    /// <summary>
    /// A signature carrying no legacy long-term-availability attribute takes the first placement, and one
    /// carrying a deprecated version-two archive time-stamp takes the second — the branch clause 5.5.3 makes on
    /// the presence of such an attribute in any signer of the root Signed Data.
    /// </summary>
    [TestMethod]
    public async Task DetectsThePlacementFromTheLegacyAttributesTheSignatureCarries()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(CAdESValidationDataPlacement.RootSignedData, CAdESSignatureAugmentation.DetectValidationDataPlacement(scenario.Baseline),
            "With no legacy attribute anywhere, the new material belongs in the root SignedData.");

        using CmsSignedData legacy = await AttachLegacyArchiveTimestampAsync(scenario, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid).ConfigureAwait(false);
        Assert.AreEqual(CAdESValidationDataPlacement.LatestArchiveTimestampToken, CAdESSignatureAugmentation.DetectValidationDataPlacement(legacy),
            "A deprecated version-two archive time-stamp makes the root SignedData off limits.");
    }


    /// <summary>
    /// Under the second placement the root <c>SignedData</c> is left byte-identical and the material is written
    /// into the latest archive time-stamp's own token as <c>certificate-values</c> and <c>revocation-values</c>,
    /// leaving that token's own signature intact — the independent time-stamp validator still accepts it.
    /// </summary>
    [TestMethod]
    public async Task PlacesMaterialInsideTheLatestArchiveTimestampTokenAndLeavesTheRootUntouched()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData legacy = await AttachLegacyArchiveTimestampAsync(scenario, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid).ConfigureAwait(false);

        //The token already embeds the authority's own certificate, and clause A.1.1.2's closed set excludes what
        //the Signed Data it belongs to already stores, so the certificate placed here is one the token lacks.
        using PkiCertificateMemory rootCertificate = ToCertificateCarrier(scenario.Root.Certificate.RawData);
        using PkiCertificateMemory authorityCertificate = ToCertificateCarrier(scenario.Authority.Certificate.RawData);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(scenario.Root, ThisUpdate, NextUpdate, []);
        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            legacy,
            signerIndex: 0,
            new CAdESValidationMaterial
            {
                Certificates = [rootCertificate, authorityCertificate],
                CertificateRevocationLists = [revocationList],
                OcspResponses = [ocspResponse]
            },
            BaseMemoryPool.Shared);

        byte[] before = legacy.AsReadOnlySpan().ToArray();
        byte[] after = longTerm.AsReadOnlySpan().ToArray();
        Assert.HasCount(1, Certificates(after), "Clause 5.5.3: the root SignedData.certificates contents shall not be modified under this placement.");
        Assert.IsEmpty(RevocationInformation(after), "Clause 5.5.3: the root SignedData.crls contents shall not be modified under this placement.");

        List<byte[]> tokensBefore = UnsignedAttributeValues(before, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid);
        List<byte[]> tokensAfter = UnsignedAttributeValues(after, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid);
        Assert.HasCount(1, tokensAfter, "The archive time-stamp attribute still carries exactly one token.");
        Assert.IsGreaterThan(tokensBefore[0].Length, tokensAfter[0].Length, "The token grew by the attributes written into it.");

        List<byte[]> certificateValues = UnsignedAttributeValues(tokensAfter[0], signerIndex: 0, CAdESSignatureFacts.CertificateValuesAttributeOid);
        Assert.HasCount(1, certificateValues, "Clause A.1.1.2: the certificates are written into the token as a certificate-values attribute.");
        Assert.HasCount(1, UnsignedAttributeValues(tokensAfter[0], signerIndex: 0, CAdESSignatureFacts.RevocationValuesAttributeOid),
            "Clause A.1.2.2: the revocation information is written into the token as a revocation-values attribute.");

        AsnReader certificateSequence = new AsnReader(certificateValues[0], AsnEncodingRules.DER).ReadSequence();
        List<byte[]> stated = [];
        while(certificateSequence.HasData)
        {
            stated.Add(certificateSequence.ReadEncodedValue().ToArray());
        }

        Assert.HasCount(1, stated,
            "Clause A.1.1.2: certificate values already within the SignedData the attribute belongs to are not included, so only the one the token lacked is stated.");
        Assert.AreSequenceEqual(scenario.Root.Certificate.RawData, stated[0], "The certificate stated is the one the token did not already carry.");

        using PkiCertificateMemory tokenCarrier = ToTokenCarrier(tokensAfter[0]);
        Assert.IsTrue(X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate(tokenCarrier, scenario.Authority),
            "The unsigned attributes of a token are outside the authority's signature, so writing them leaves the token valid.");
    }


    /// <summary>
    /// When the latest legacy attribute is a <c>long-term-validation</c> attribute, whose value is not a
    /// time-stamp token, the augmentation refuses rather than falling back to the root placement clause 5.5.3
    /// has just forbidden.
    /// </summary>
    [TestMethod]
    public async Task RefusesToPlaceMaterialWhenTheLatestLegacyAttributeIsALongTermValidationAttribute()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData legacy = await AttachLegacyArchiveTimestampAsync(scenario, CAdESSignatureFacts.LongTermValidationAttributeOid).ConfigureAwait(false);
        using PkiCertificateMemory authorityCertificate = ToCertificateCarrier(scenario.Authority.Certificate.RawData);

        //Captured ahead of the throwing call, not after: sampling both sides of the comparison once the call has
        //already run (and thrown) would compare the one surviving object with itself, which holds trivially
        //whether or not the refusal actually leaves the input untouched — no bug in the augmentation could ever
        //make that assertion fail. Only a value fixed BEFORE the call is independent evidence of what "after"
        //still is.
        byte[] before = legacy.AsReadOnlySpan().ToArray();

        CAdESAugmentationException failure = Assert.ThrowsExactly<CAdESAugmentationException>(() =>
        {
            using CmsSignedData _ = CAdESSignatureAugmentation.AddValidationData(
                legacy, signerIndex: 0, new CAdESValidationMaterial { Certificates = [authorityCertificate] }, BaseMemoryPool.Shared);
        });

        Assert.AreEqual(CAdESAugmentationFailureKind.LegacyAttributePlacementUnsupported, failure.FailureKind,
            "Refusing is the fail-closed outcome; writing into the root would break the clause's own prohibition.");
        Assert.AreSequenceEqual(before, legacy.AsReadOnlySpan().ToArray(), "The refused augmentation produced nothing: the input is exactly what it was before the call.");
    }


    /// <summary>
    /// Clause 5.5.3's attribute-addition lockdown covers <see cref="CAdESSignatureAugmentation.AddSignatureTimestampAsync"/>
    /// too: once a legacy long-term-availability attribute is present, "no other attributes than ATSv3 or
    /// attributes specified as per annex B shall be added to the <c>unsignedAttrs</c>", and a
    /// <c>signature-time-stamp</c> is neither. The gate runs before the digest and the Time-Stamping Authority
    /// round trip, so a refused call must not fetch — let alone bill — a token; the zero call count on the
    /// transport double is what discriminates this from an incidental refusal that happens only after a token
    /// was already obtained (e.g. a requirement-m) validity-window failure).
    /// </summary>
    [TestMethod]
    public async Task ALegacyLongTermAvailabilityAttributeForbidsAddingASignatureTimestampBeforeAnyAuthorityContact()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData legacy = await AttachLegacyArchiveTimestampAsync(scenario, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid).ConfigureAwait(false);
        var responder = new CallCountingTimestampResponder();

        CAdESAugmentationException refusal = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(async () =>
            await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = legacy,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = responder.FetchAsync,
                    SigningCertificate = scenario.SignerCertificate
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(CAdESAugmentationFailureKind.LegacyAttributeForbidsFurtherAttributes, refusal.FailureKind,
            "signature-time-stamp is equally not an ATSv3 nor an Annex B attribute, so the same lockdown that already covers countersignature and signature-policy-store covers it.");
        Assert.AreEqual(0, responder.CallCount,
            "The gate is checked before the digest is computed and before the Time-Stamping Authority is contacted; a genuine fix never lets the transport delegate run for a refused call.");
    }


    /// <summary>
    /// A signature raised to CAdES-B-LTA carries an <c>archive-time-stamp-v3</c> whose token holds the single
    /// <c>ats-hash-index-v3</c> clause 5.5.3 requires, whose index is the one the independent reimplementation
    /// recomputes, and whose message imprint verifies against the octets the shipped coverage computation
    /// restates from the wire bytes alone.
    /// </summary>
    [TestMethod]
    public async Task AddsAnArchiveTimestampTheIndependentOracleAndTheCoverageComputationBothAgreeWith()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority, scenario.Root], ArchiveTimestampTime);

        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        List<byte[]> tokens = UnsignedAttributeValues(archived.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        Assert.HasCount(1, tokens, "Table 1 requirement s: the archive-time-stamp-v3 service is provided by exactly one attribute here.");

        using PkiCertificateMemory token = ToTokenCarrier(tokens[0]);
        Assert.IsTrue(X509ChainTestRingTimestamping.VerifiesUnderAuthorityCertificate(token, scenario.Authority),
            "The attached token is the one the authority signed, index graft included.");

        using AtsHashIndexV3? attachedIndex = ArchiveTimestampV3.ReadHashIndexFromToken(token, BaseMemoryPool.Shared);
        Assert.IsNotNull(attachedIndex, "Clause 5.5.3: the token includes a single ats-hash-index-v3 among its own unsigned attributes.");

        using PooledMemory expectedIndex = AtsHashIndexV3Oracle.EncodeHashIndex(
            scenario.Baseline.AsReadOnlySpan().ToArray(), signerIndex: 0, PkiDigestAlgorithm.Sha256);
        Assert.AreSequenceEqual(expectedIndex.AsReadOnlySpan().ToArray(), attachedIndex!.AsReadOnlySpan().ToArray(),
            "Clause 5.5.2: the index covers the material present when the archive time-stamp was requested, and equals the independent recomputation.");

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = archived, ArchiveTimestampToken = token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "The coverage of the attached token is stated from the wire bytes alone.");

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(await info.VerifyMessageImprintAsync(coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The imprint the authority signed is the digest of exactly the octets the coverage computation restates.");
    }


    /// <summary>
    /// Requirement s) has the validation material go in before the archive time-stamp is generated, so the
    /// index covers it: the certificate placed in the same call is a member of the root certificates set and is
    /// reported as covered by the token's own index.
    /// </summary>
    [TestMethod]
    public async Task IncludesTheValidationMaterialBeforeGeneratingTheArchiveTimestamp()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], ArchiveTimestampTime);
        using PkiCertificateMemory authorityCertificate = ToCertificateCarrier(scenario.Authority.Certificate.RawData);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(scenario.Root, ThisUpdate, NextUpdate, []);

        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                ValidationMaterial = new CAdESValidationMaterial
                {
                    Certificates = [authorityCertificate],
                    CertificateRevocationLists = [revocationList]
                },
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = archived.AsReadOnlySpan().ToArray();
        Assert.HasCount(2, Certificates(octets), "The material went in first, so the archived signature carries it.");
        Assert.HasCount(1, RevocationInformation(octets), "The revocation list went in with it.");

        List<byte[]> tokens = UnsignedAttributeValues(octets, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        using PkiCertificateMemory token = ToTokenCarrier(tokens[0]);
        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = archived, ArchiveTimestampToken = token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "The archive time-stamp states what it covers.");
        Assert.HasCount(2, coverage.ProtectedObjects!.Certificates, "Both certificates are named by the coverage.");
        for(int i = 0; i < coverage.ProtectedObjects!.Certificates.Count; ++i)
        {
            Assert.IsTrue(coverage.ProtectedObjects!.Certificates[i].IsCovered, $"Requirement s: certificate {i} was included before the time-stamp and is protected by it.");
        }

        Assert.IsTrue(coverage.ProtectedObjects!.RevocationInformation[0].IsCovered, "Requirement s: the revocation list is protected by the archive time-stamp too.");
    }


    /// <summary>
    /// Material added after an archive time-stamp leaves that time-stamp valid — clause 5.5.2 NOTE 5's whole
    /// purpose, and the reason the membership check runs from the index toward the material and not back.
    /// </summary>
    [TestMethod]
    public async Task MaterialAddedAfterTheArchiveTimestampLeavesItValid()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], ArchiveTimestampTime);

        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory authorityCertificate = ToCertificateCarrier(scenario.Authority.Certificate.RawData);
        using CmsSignedData later = CAdESSignatureAugmentation.AddValidationData(
            archived, signerIndex: 0, new CAdESValidationMaterial { Certificates = [authorityCertificate] }, BaseMemoryPool.Shared);

        List<byte[]> tokens = UnsignedAttributeValues(later.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        using PkiCertificateMemory token = ToTokenCarrier(tokens[0]);
        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = later, ArchiveTimestampToken = token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "NOTE 5: adding material later does not invalidate the archive time-stamp.");
        Assert.HasCount(2, coverage.ProtectedObjects!.Certificates, "The later certificate is present.");
        Assert.IsFalse(coverage.ProtectedObjects!.Certificates[1].IsCovered, "The later certificate is uncovered by the earlier time-stamp, which is not an error.");

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(await info.VerifyMessageImprintAsync(coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The earlier archive time-stamp still verifies against the imprint input recomputed after the addition.");
    }


    /// <summary>
    /// Placing an OCSP response embeds a <c>[1] OtherRevocationInfoFormat</c> member in <c>SignedData.crls</c>
    /// (RFC 5940 §2 / clause 5.4.2.2), which
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see> requires the
    /// <c>SignedData.version</c> to state as 5. The shipped
    /// <see cref="CAdESSignatureAugmentation.AddValidationData"/> writes the member and raises the version from
    /// the 1 the baseline CAdES-B-B signature carried.
    /// </summary>
    [TestMethod]
    public async Task AnOcspPlacementRaisesTheSignedDataVersionToFive()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);

        Assert.AreEqual(1, ReadSignedDataVersion(scenario.Baseline.AsReadOnlyMemory()), "The baseline CAdES-B-B signature carries version 1.");

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { OcspResponses = [ocspResponse] }, BaseMemoryPool.Shared);

        Assert.AreEqual(0xA1, RevocationInformation(longTerm.AsReadOnlySpan().ToArray())[0][0],
            "The OCSP response is placed as the [1] other alternative of RevocationInfoChoice, an OtherRevocationInfoFormat.");
        Assert.AreEqual(5, ReadSignedDataVersion(longTerm.AsReadOnlyMemory()),
            "RFC 5652 §5.1: SignedData.version is 5 once the crls set holds an OtherRevocationInfoFormat member.");

        var platformReader = new SignedCms();
        platformReader.Decode(longTerm.AsReadOnlySpan().ToArray());
        platformReader.CheckSignature(verifySignatureOnly: true);
    }


    /// <summary>
    /// A CRL is placed as the <c>crl</c> alternative — a <c>CertificateList</c> SEQUENCE, not an other-format
    /// member — so <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see> keeps
    /// <c>SignedData.version</c> at 1. The version INTEGER is read directly with an <see cref="AsnReader"/>, the
    /// way <see cref="CAdESSignatureCreationTests.TheCmsAndSignerInfoVersionsAreBothOne"/> reads it.
    /// </summary>
    [TestMethod]
    public async Task ACrlOnlyPlacementLeavesTheSignedDataVersionAtOne()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(scenario.Root, ThisUpdate, NextUpdate, []);

        using CmsSignedData longTerm = CAdESSignatureAugmentation.AddValidationData(
            scenario.Baseline, signerIndex: 0, new CAdESValidationMaterial { CertificateRevocationLists = [revocationList] }, BaseMemoryPool.Shared);

        Assert.AreEqual(0x30, RevocationInformation(longTerm.AsReadOnlySpan().ToArray())[0][0],
            "The CRL is placed as the crl alternative, a CertificateList SEQUENCE, not an other-format member.");
        Assert.AreEqual(1, ReadSignedDataVersion(longTerm.AsReadOnlyMemory()),
            "RFC 5652 §5.1: a crls set holding only crl-alternative members leaves the version at 1.");
    }


    /// <summary>
    /// Embedding an OCSP response after an <c>archive-time-stamp-v3</c> already exists raises the root
    /// <c>SignedData.version</c> to 5 (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652
    /// §5.1</see>) — a one-octet, length-preserving change — yet the earlier archive time-stamp still validates:
    /// its coverage is still stated and its message imprint still verifies against the octets the shipped
    /// coverage computation restates from the augmented wire bytes, because the version field is outside both
    /// clause 5.5.3's imprint concatenation and clause 5.5.2's hash indexes.
    /// </summary>
    [TestMethod]
    public async Task AddingDataToASignatureThatAlreadyHasAnArchiveTimestampRaisesTheVersionYetTheArchiveTimestampStillValidates()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var responder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], ArchiveTimestampTime);

        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = responder.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, ReadSignedDataVersion(archived.AsReadOnlyMemory()),
            "The archived signature carries no other-format member yet, so its version is still 1.");

        using PkiCertificateMemory ocspResponse = X509ChainTestRingRevocation.MintOcspResponse(
            scenario.Authority, scenario.Root, OcspCertificateStatus.Good, ThisUpdate, NextUpdate);
        using CmsSignedData later = CAdESSignatureAugmentation.AddValidationData(
            archived, signerIndex: 0, new CAdESValidationMaterial { OcspResponses = [ocspResponse] }, BaseMemoryPool.Shared);

        Assert.AreEqual(5, ReadSignedDataVersion(later.AsReadOnlyMemory()),
            "RFC 5652 §5.1: embedding the OCSP response as an other-format crls member raises the version to 5.");

        List<byte[]> tokens = UnsignedAttributeValues(later.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        using PkiCertificateMemory token = ToTokenCarrier(tokens[0]);
        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = later, ArchiveTimestampToken = token },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status,
            "The version raise is length-preserving, so the archive time-stamp still states what it covers.");

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(await info.VerifyMessageImprintAsync(coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "The archive time-stamp the authority signed still verifies against the imprint restated after the version was raised — the version field is outside clause 5.5.3's imprint and clause 5.5.2's hash indexes.");
    }


    /// <summary>
    /// Nothing an augmentation writes is one of the attributes clause A.2 deprecates: the whole B-T to B-LTA
    /// succession is walked and every attribute type it produced is checked against that list.
    /// </summary>
    [TestMethod]
    public async Task TheAugmentationsEmitNoDeprecatedAttribute()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var signatureResponder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], SignatureTimestampTime);
        var archiveResponder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], ArchiveTimestampTime);
        using PkiCertificateMemory authorityCertificate = ToCertificateCarrier(scenario.Authority.Certificate.RawData);

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = signatureResponder.FetchAsync,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = timestamped,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = archiveResponder.FetchAsync,
                ValidationMaterial = new CAdESValidationMaterial { Certificates = [authorityCertificate] },
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        string[] deprecated =
        [
            CAdESSignatureFacts.ArchiveTimestampV2AttributeOid,
            CAdESSignatureFacts.LongTermValidationAttributeOid,
            CAdESSignatureFacts.AtsHashIndexAttributeOid,
            CAdESSignatureFacts.AtsHashIndexV2AttributeOid
        ];
        byte[] octets = archived.AsReadOnlySpan().ToArray();
        for(int i = 0; i < deprecated.Length; ++i)
        {
            Assert.IsEmpty(UnsignedAttributeValues(octets, signerIndex: 0, deprecated[i]),
                $"Clause A.2: '{deprecated[i]}' is recognised but never created by an augmentation.");
        }

        Assert.HasCount(1, UnsignedAttributeValues(octets, signerIndex: 0, CAdESSignatureFacts.SignatureTimestampAttributeOid), "The B-T attribute is there.");
        Assert.HasCount(1, UnsignedAttributeValues(octets, signerIndex: 0, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid), "The B-LTA attribute is there.");
    }


    /// <summary>
    /// Raising a signature to B-LTA rewrites nothing but the length octets of the containers enclosing the new
    /// attribute, so the signature time-stamp already there keeps its octets exactly.
    /// </summary>
    [TestMethod]
    public async Task TheArchiveTimestampAugmentationPreservesEveryOctetOutsideTheLengthChain()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        var signatureResponder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], SignatureTimestampTime);
        var archiveResponder = new MintingTimestampResponder(scenario.Authority, [scenario.Authority], ArchiveTimestampTime);

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = scenario.Baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = signatureResponder.FetchAsync,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
            new CAdESArchiveTimestampContext
            {
                SignedData = timestamped,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = TsaUri,
                FetchResponse = archiveResponder.FetchAsync,
                ValidationMaterial = CAdESValidationMaterial.None,
                SigningCertificate = scenario.SignerCertificate
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(
                timestamped.AsReadOnlySpan().ToArray(), archived.AsReadOnlySpan().ToArray(), signerIndex: 0),
            "Clause 5.5.3: the archive time-stamp's own augmentation preserves every component already present.");

        List<byte[]> signatureTimestamps = UnsignedAttributeValues(archived.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.SignatureTimestampAttributeOid);
        List<byte[]> before = UnsignedAttributeValues(timestamped.AsReadOnlySpan().ToArray(), signerIndex: 0, CAdESSignatureFacts.SignatureTimestampAttributeOid);
        Assert.AreSequenceEqual(before[0], signatureTimestamps[0], "The signature time-stamp already present keeps its octets.");
    }


    /// <summary>
    /// A Signed Data Object <see cref="ArchiveTimestampV3.ComputeHashIndexAsync"/>/<see cref="ArchiveTimestampV3.BuildMessageImprintInputAsync"/>
    /// cannot read — truncated, or (clause 4.7.2's DER-only narrowing at that computation, documented at
    /// <see cref="CmsSignedDataAugmentation"/>'s and <see cref="ArchiveTimestampV3.ReadHashIndexFromToken"/>'s
    /// remarks) indefinite-length BER — is reported by <see cref="CAdESSignatureAugmentation.AddArchiveTimestampAsync"/>
    /// as <see cref="CAdESAugmentationFailureKind.SignedDataMalformed"/>, never as the raw <see cref="AsnContentException"/>
    /// those two reads would otherwise let escape. The truncated case is reported identically by
    /// <see cref="CAdESSignatureAugmentation.AddSignatureTimestampAsync"/> (B-T), which already read its input
    /// through the class's typed-catch pattern before this fix — the parity is the proof that B-LTA now meets
    /// the same typed-failure discipline B-T always had, not a new rule invented for this one path. Both
    /// failures happen before any Time-Stamping Authority is contacted, which the zero call count proves.
    /// </summary>
    [TestMethod]
    public async Task RejectsAnUnreadableSignedDataObjectAsSignedDataMalformedInsteadOfLeakingARawParserException()
    {
        using AugmentationScenario scenario = await AugmentationScenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        byte[] baselineOctets = scenario.Baseline.AsReadOnlySpan().ToArray();
        using CmsSignedData truncated = CmsSignedData.FromBytes(baselineOctets.AsSpan()[..^5], BaseMemoryPool.Shared);
        using CmsSignedData indefiniteLength = CmsSignedData.FromBytes(CmsStructureOracle.ToIndefiniteOuterWrappers(baselineOctets), BaseMemoryPool.Shared);

        var archiveResponderForTruncated = new CallCountingTimestampResponder();
        CAdESAugmentationException archiveFromTruncated = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(async () =>
            await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CAdESArchiveTimestampContext
                {
                    SignedData = truncated,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = archiveResponderForTruncated.FetchAsync,
                    ValidationMaterial = CAdESValidationMaterial.None,
                    SigningCertificate = scenario.SignerCertificate
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(CAdESAugmentationFailureKind.SignedDataMalformed, archiveFromTruncated.FailureKind,
            "A truncated Signed Data Object is reported as SignedDataMalformed, not left to leak the AsnContentException the hash-index/imprint reads would otherwise throw.");
        Assert.AreEqual(0, archiveResponderForTruncated.CallCount, "The parse failure happens before any Time-Stamping Authority is contacted.");

        var archiveResponderForIndefinite = new CallCountingTimestampResponder();
        CAdESAugmentationException archiveFromIndefinite = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(async () =>
            await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CAdESArchiveTimestampContext
                {
                    SignedData = indefiniteLength,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = archiveResponderForIndefinite.FetchAsync,
                    ValidationMaterial = CAdESValidationMaterial.None,
                    SigningCertificate = scenario.SignerCertificate
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(CAdESAugmentationFailureKind.SignedDataMalformed, archiveFromIndefinite.FailureKind,
            "Clause 4.7.2 permits BER, but this computation's own DER-only scope reports an indefinite-length Signed Data Object the same way a truncated one is reported, not by mishandling it.");
        Assert.AreEqual(0, archiveResponderForIndefinite.CallCount, "The parse failure happens before any Time-Stamping Authority is contacted.");

        var signatureResponderForTruncated = new CallCountingTimestampResponder();
        CAdESAugmentationException signatureFromTruncated = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(async () =>
            await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = truncated,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = signatureResponderForTruncated.FetchAsync,
                    SigningCertificate = scenario.SignerCertificate
                },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(CAdESAugmentationFailureKind.SignedDataMalformed, signatureFromTruncated.FailureKind,
            "B-T reports the same truncated input as SignedDataMalformed: B-T and B-LTA fail identically on the shared truncated-input case.");
        Assert.AreEqual(0, signatureResponderForTruncated.CallCount, "The parse failure happens before any Time-Stamping Authority is contacted.");
    }


    /// <summary>
    /// Attaches a token under a deprecated attribute type, which only a hostile or legacy fixture ever does:
    /// clause A.2 forbids creating these, so no shipped surface writes one and the test assembles it itself.
    /// </summary>
    /// <param name="scenario">The scenario whose baseline signature is augmented.</param>
    /// <param name="attributeType">The deprecated attribute's object identifier.</param>
    /// <returns>The signature carrying the legacy attribute. The caller disposes it.</returns>
    private static async ValueTask<CmsSignedData> AttachLegacyArchiveTimestampAsync(AugmentationScenario scenario, string attributeType)
    {
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            scenario.Authority, [scenario.Authority], scenario.Baseline.AsReadOnlyMemory(), ArchiveTimestampTime, BaseMemoryPool.Shared).ConfigureAwait(false);
        using CmsAttribute attribute = CmsAttribute.Create(attributeType, token.AsReadOnlySpan(), BaseMemoryPool.Shared);

        return CmsSignedDataAugmentation.AppendUnsignedAttributes(scenario.Baseline, signerIndex: 0, [attribute], BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Returns every value of every unsigned attribute of one attribute type, walked independently of the
    /// library's own locator.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <param name="attributeType">The attribute's object identifier.</param>
    /// <returns>The whole encodings of the matching values.</returns>
    private static List<byte[]> UnsignedAttributeValues(byte[] signedData, int signerIndex, string attributeType)
    {
        List<byte[]> values = [];
        List<CmsTlvBounds> attributes = CmsStructureOracle.UnsignedAttributes(signedData, signerIndex);
        for(int i = 0; i < attributes.Count; ++i)
        {
            List<CmsTlvBounds> parts = CmsStructureOracle.Children(signedData, attributes[i]);
            string oid = AsnDecoder.ReadObjectIdentifier(signedData.AsSpan()[parts[0].Start..parts[0].End], AsnEncodingRules.BER, out _);
            if(!string.Equals(oid, attributeType, StringComparison.Ordinal))
            {
                continue;
            }

            List<CmsTlvBounds> members = CmsStructureOracle.Children(signedData, parts[1]);
            for(int j = 0; j < members.Count; ++j)
            {
                values.Add(signedData[members[j].Start..members[j].End]);
            }
        }

        return values;
    }


    /// <summary>
    /// Returns the whole encoding of every member of <c>SignedData.certificates</c>, walked independently of
    /// the library's own reader.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The members' encodings.</returns>
    private static List<byte[]> Certificates(byte[] signedData) => AtsHashIndexV3Oracle.CertificateEncodings(signedData);


    /// <summary>
    /// Returns the whole encoding of every member of <c>SignedData.crls</c>, walked independently of the
    /// library's own reader.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The members' encodings.</returns>
    private static List<byte[]> RevocationInformation(byte[] signedData) => AtsHashIndexV3Oracle.RevocationEncodings(signedData);


    /// <summary>
    /// Reads the <c>SignedData.version</c> INTEGER directly, walking ContentInfo → <c>[0]</c> → SignedData with
    /// an independent <see cref="AsnReader"/> (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">
    /// RFC 5652 §5.1</see>), the way <see cref="CAdESSignatureCreationTests.TheCmsAndSignerInfoVersionsAreBothOne"/>
    /// reads it — no shared code with the augmentation under test.
    /// </summary>
    /// <param name="signedData">The Signed Data Object.</param>
    /// <returns>The value of the <c>SignedData.version</c> field.</returns>
    private static int ReadSignedDataVersion(ReadOnlyMemory<byte> signedData)
    {
        AsnReader contentInfo = new AsnReader(signedData, AsnEncodingRules.DER).ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader cmsSignedData = explicitContent.ReadSequence();
        if(!cmsSignedData.TryReadInt32(out int version))
        {
            throw new InvalidOperationException("The SignedData.version is not a 32-bit integer (RFC 5652 §5.1).");
        }

        return version;
    }


    /// <summary>
    /// Extracts the <c>BasicOCSPResponse</c> out of a whole <c>OCSPResponse</c>, for the fixture that offers
    /// the wrong one of the two types (RFC 6960 §4.2.1).
    /// </summary>
    /// <param name="response">The DER-encoded <c>OCSPResponse</c>.</param>
    /// <returns>The DER-encoded <c>BasicOCSPResponse</c>.</returns>
    private static byte[] ExtractBasicResponse(byte[] response)
    {
        AsnReader outer = new AsnReader(response, AsnEncodingRules.DER).ReadSequence();
        _ = outer.ReadEnumeratedBytes();
        AsnReader responseBytes = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)).ReadSequence();
        _ = responseBytes.ReadObjectIdentifier();

        return responseBytes.ReadOctetString();
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as a time-stamp token.</summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToTokenCarrier(byte[] token)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(token.Length);
        token.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as an X.509 certificate.</summary>
    /// <param name="certificate">The DER-encoded certificate.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as an OCSP response.</summary>
    /// <param name="response">The DER-encoded response.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToOcspResponseCarrier(byte[] response)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(response.Length);
        response.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.OcspResponse);
    }


    /// <summary>
    /// A <see cref="FetchTimestampResponseAsyncDelegate"/> test double that records how many times it was
    /// invoked and always reports the authority as unreachable — a configured object exposing its own state
    /// rather than a lambda capturing a local counter, per the codebase's no-closure-capture convention for
    /// callback seams (mirroring <see cref="MintingTimestampResponder"/>). Used to prove a fail-closed refusal
    /// happens before any Time-Stamping Authority contact: a test asserting <see cref="CallCount"/> stays zero
    /// cannot be satisfied by a refusal that only happens after the delegate already ran once.
    /// </summary>
    private sealed class CallCountingTimestampResponder
    {
        /// <summary>Gets the number of times <see cref="FetchAsync"/> was invoked.</summary>
        internal int CallCount { get; private set; }


        /// <summary>
        /// Implements <see cref="FetchTimestampResponseAsyncDelegate"/>: records the call and reports the
        /// authority as unreachable.
        /// </summary>
        /// <param name="context">The fetch context; unused, as this test double never answers a request.</param>
        /// <param name="pool">The memory pool; unused, as nothing is ever returned.</param>
        /// <param name="cancellationToken">A cancellation token; unused, as this double performs no input or output.</param>
        /// <returns>Always <see langword="null"/>, simulating an unreachable authority.</returns>
        internal ValueTask<PkiCertificateMemory?> FetchAsync(TimestampFetchContext context, BaseMemoryPool pool, CancellationToken cancellationToken)
        {
            ++CallCount;

            return ValueTask.FromResult<PkiCertificateMemory?>(null);
        }
    }


    /// <summary>
    /// The material every test in this class starts from: a Root CA and a Time-Stamping Authority under it, a
    /// signer whose key material comes from the repository's test-key creator, and the CAdES-B-B signature the
    /// shipped creation surface produced with it.
    /// </summary>
    private sealed class AugmentationScenario: IDisposable
    {
        /// <summary>Gets the Root CA the authority is issued by.</summary>
        internal required X509ChainTestRingNode Root { get; init; }

        /// <summary>Gets the Time-Stamping Authority every token in these tests is signed by.</summary>
        internal required X509ChainTestRingNode Authority { get; init; }

        /// <summary>Gets the signer's certificate.</summary>
        internal required PkiCertificateMemory SignerCertificate { get; init; }

        /// <summary>Gets the signer's private key material.</summary>
        internal required PrivateKeyMemory SignerPrivateKey { get; init; }

        /// <summary>Gets the CAdES-B-B signature the augmentations start from.</summary>
        internal required CmsSignedData Baseline { get; init; }


        /// <summary>
        /// Builds the scenario: mints the ring, the signer, and the baseline signature.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The scenario. The caller disposes it.</returns>
        internal static async ValueTask<AugmentationScenario> CreateAsync(CancellationToken cancellationToken)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintSigner();
            CmsSignedData baseline = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            return new AugmentationScenario
            {
                Root = root,
                Authority = authority,
                SignerCertificate = certificate,
                SignerPrivateKey = privateKey,
                Baseline = baseline
            };
        }


        /// <summary>
        /// Mints a P-256 signer: key material through <see cref="BouncyCastleKeyMaterialCreator"/>, and a
        /// self-signed certificate over the same public point through a platform <see cref="ECDsa"/>
        /// reconstructed from it — the certificate vehicle is platform code, the key material is not.
        /// </summary>
        /// <returns>The certificate and the private key material, both owned by the caller.</returns>
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

                return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
            }
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            Baseline.Dispose();
            SignerPrivateKey.Dispose();
            SignerCertificate.Dispose();
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
