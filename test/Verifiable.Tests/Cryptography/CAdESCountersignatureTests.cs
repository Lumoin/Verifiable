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
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcSignerInformation = Org.BouncyCastle.Cms.SignerInformation;
using BcX509CertificateParser = Org.BouncyCastle.X509.X509CertificateParser;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the <c>countersignature</c> attribute of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.2.7</see>, which states the attribute "shall be as defined in CMS" —
/// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-11.4">RFC 5652 §11.4</see>, whose value is a whole
/// <c>SignerInfo</c> signed over the countersigned <c>SignerInfo.signature</c> value octets and carrying no
/// <c>content-type</c> attribute.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every countersignature here is produced by the shipped surfaces</strong> —
/// <see cref="CAdESSignatureCreation.PrepareCountersignatureAsync"/> /
/// <see cref="CAdESSignatureCreation.CompleteCountersignature"/> /
/// <see cref="CAdESSignatureCreation.CountersignAsync(CmsSignedData, int, PkiCertificateMemory, PrivateKeyMemory, DateTimeOffset, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken)"/>
/// and <see cref="CAdESSignatureAugmentation.AddCountersignatureAsync"/> — over key material from
/// <see cref="BouncyCastleKeyMaterialCreator"/>, the repository's test-key convention.
/// </para>
/// <para>
/// <strong>What verifies what.</strong> The countersignature's own cryptography is checked by two readers that
/// share no code with the creation surface and implement RFC 5652 §11.4's digest rule independently of each other:
/// the platform CMS reader (<see cref="SignerInfo.CounterSignerInfos"/> plus
/// <see cref="SignerInfo.CheckSignature(bool)"/>) and the BouncyCastle CMS reader
/// (<c>SignerInformation.GetCounterSignatures</c> plus <c>SignerInformation.Verify</c>). Two independent readers
/// accepting the countersignature is what proves the <c>message-digest</c> attribute really covers the outer
/// signature value: a wrong digest input would be rejected by both. The shipped
/// <see cref="CAdESVerification.VerifyAsync"/> path is asserted on the <em>outer</em> signature, which is the
/// signature it verifies — the library has no in-house verifier for a bare countersignature <c>SignerInfo</c>,
/// the verification side being unchanged this wave.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESCountersignatureTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time the countersigned signature carries.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The signing time the counter signer states.</summary>
    private static DateTimeOffset CountersigningTime { get; } = TestClock.CanonicalEpoch.AddMinutes(30);

    /// <summary>The generation time the archive time-stamps and the legacy fixture's token state.</summary>
    private static DateTimeOffset ArchiveTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The address the transport delegate is handed; no socket is opened for it.</summary>
    private static string AuthorityAddress { get; } = "https://countersignature-authority.example.test/tsa";

    /// <summary>The content the countersigned signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the countersigned CAdES content"u8.ToArray());


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A countersigned CAdES-B-B signature still verifies through the shipped path, and the countersignature
    /// itself is accepted by both independent CMS readers — which is the evidence that RFC 5652 §11.4's
    /// digesting rule was applied, since each of them computes that digest for itself.
    /// </summary>
    [TestMethod]
    public async Task ACountersignedBaselineSignatureVerifiesUnderTheShippedPathAndBothIndependentReaders()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData countersigned = await scenario.CountersignAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);

        using CAdESVerificationResult verification = await CAdESVerification.VerifyAsync(
            countersigned, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verification.IsValid, "Appending a countersignature is an unsigned-attribute addition, so the countersigned signature verifies exactly as it did before.");
        Assert.AreEqual(CAdESLevel.Baseline, verification.Level, "A countersignature is not a level: Table 1 gives it cardinality >= 0 at every level and clause 6.1 defines the levels by their time-stamps.");

        byte[] octets = countersigned.AsReadOnlySpan().ToArray();

        //The platform reader: it resolves the counter signer's certificate out of SignedData.certificates by the
        //IssuerAndSerialNumber the countersignature states, and computes the countersignature's digest input from
        //the parent SignerInfo's signature itself.
        var platformReader = new SignedCms();
        platformReader.Decode(octets);
        platformReader.CheckSignature(verifySignatureOnly: true);
        SignerInfoCollection counterSigners = platformReader.SignerInfos[0].CounterSignerInfos;
        Assert.HasCount(1, counterSigners, "Exactly the one countersignature this augmentation added is present.");
        counterSigners[0].CheckSignature(verifySignatureOnly: true);
        Assert.AreEqual(
            CountersignatureScenario.CountersignerSubject,
            counterSigners[0].Certificate?.Subject,
            "The platform reader resolves the counter signer's own certificate, which the augmentation placed in SignedData.certificates.");

        Assert.AreEqual(1, CountBouncyCastleCountersignaturesThatVerify(octets),
            "The independent BouncyCastle CMS reader accepts the countersignature under the certificate the signature carries for it.");
    }


    /// <summary>
    /// RFC 5652 §11.4 items 1 and 3, read off the produced octets: the countersignature's <c>signedAttrs</c>
    /// carries no <c>content-type</c> attribute, and its <c>message-digest</c> is the digest of the countersigned
    /// <c>SignerInfo.signature</c> <em>value</em> octets — not of the whole encoded field, which is clause 5.5.3's
    /// convention and must not be borrowed here.
    /// </summary>
    [TestMethod]
    public async Task TheCountersignatureCarriesNoContentTypeAndItsMessageDigestIsTheCountersignedSignatureValue()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData countersigned = await scenario.CountersignAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] baselineOctets = baseline.AsReadOnlySpan().ToArray();
        List<CmsTlvBounds> signerFields = CmsStructureOracle.SignerFields(baselineOctets, signerIndex: 0);
        CmsTlvBounds signature = signerFields[^1];
        byte[] signatureValueOctets = baselineOctets[signature.ContentStart..signature.ContentEnd];
        byte[] wholeSignatureField = baselineOctets[signature.Start..signature.End];

        CountersignatureFields fields = ReadCountersignature(SoleCountersignatureValue(countersigned));

        Assert.DoesNotContain(CAdESSignatureFacts.ContentTypeAttributeOid, fields.SignedAttributeTypes,
            "RFC 5652 §11.4 item 1: the signedAttributes field MUST NOT contain a content-type attribute; there is no content type for countersignatures.");
        Assert.Contains(CAdESSignatureFacts.MessageDigestAttributeOid, fields.SignedAttributeTypes,
            "RFC 5652 §11.4 item 2: a message-digest attribute is present, the signedAttributes holding other attributes besides.");

        using DigestValue expected = AtsHashIndexV3Oracle.Hash(signatureValueOctets, PkiDigestAlgorithm.Sha256);
        using DigestValue wholeFieldDigest = AtsHashIndexV3Oracle.Hash(wholeSignatureField, PkiDigestAlgorithm.Sha256);

        Assert.AreSequenceEqual(expected.AsReadOnlySpan().ToArray(), fields.MessageDigest,
            "RFC 5652 §11.4 item 3: the digest input is the contents octets of the countersigned SignerInfo's signature field.");
        Assert.IsFalse(wholeFieldDigest.AsReadOnlySpan().SequenceEqual(fields.MessageDigest),
            "The digest is not over the whole encoded signature field: that is clause 5.5.3's TLV-inclusive convention, not RFC 5652 §11.4's.");
    }


    /// <summary>
    /// The countersignature binds its own signer the way clause 5.2.7 makes it a CAdES signature in its own right:
    /// its <c>signedAttrs</c> carries an ESS <c>signing-certificate-v2</c> whose hash is the counter signer's own
    /// certificate — never the countersigned signer's — so a substituted counter signer certificate cannot be
    /// passed off as the counter signer. <c>signing-time</c> is present and states what was asked for.
    /// </summary>
    [TestMethod]
    public async Task TheCountersignatureBindsItsOwnSignerThroughSigningCertificateV2AndStatesItsSigningTime()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData countersigned = await scenario.CountersignAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);

        CountersignatureFields fields = ReadCountersignature(SoleCountersignatureValue(countersigned));

        using DigestValue countersignerHash = AtsHashIndexV3Oracle.Hash(
            scenario.CountersignerCertificate.AsReadOnlySpan(), PkiDigestAlgorithm.Sha256);
        using DigestValue signerHash = AtsHashIndexV3Oracle.Hash(
            scenario.SignerCertificate.AsReadOnlySpan(), PkiDigestAlgorithm.Sha256);

        Assert.IsNotNull(fields.SigningCertificateHash, "Requirement i): a signing-certificate-v2 attribute is present.");
        Assert.AreSequenceEqual(countersignerHash.AsReadOnlySpan().ToArray(), fields.SigningCertificateHash!,
            "The ESSCertIDv2 hash is the counter signer's own certificate.");
        Assert.IsFalse(signerHash.AsReadOnlySpan().SequenceEqual(fields.SigningCertificateHash!),
            "It is emphatically not the countersigned signer's certificate.");
        Assert.AreEqual(CountersigningTime, fields.SigningTime, "The countersignature states the signing time the counter signer asked for.");
    }


    /// <summary>
    /// Table 1 gives <c>countersignature</c> cardinality <c>&gt;= 0</c> and clause 5.5.3 NOTE 6 names both shapes
    /// a further countersignature may take: "in the same attribute or as a new <c>countersignature</c> attribute".
    /// Both are produced here and both are accepted by the two independent readers.
    /// </summary>
    [TestMethod]
    public async Task SeveralCountersignaturesArriveAsSiblingAttributesOrAsSeveralValuesOfOneAttribute()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //Shape one: two attributes, each added by its own augmentation call.
        using CmsSignedData once = await scenario.CountersignAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData twice = await scenario.CountersignAsync(once, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] siblingOctets = twice.AsReadOnlySpan().ToArray();
        Assert.HasCount(2, CountersignatureValues(twice),
            "Two countersignature attributes, each carrying one value — the sibling-attribute shape of NOTE 6.");
        Assert.AreEqual(2, CountBouncyCastleCountersignaturesThatVerify(siblingOctets),
            "The independent reader accepts both sibling countersignatures.");

        //Shape two: one attribute carrying two values, assembled from two Countersignature structures.
        using PooledMemory first = await scenario.BuildCountersignatureAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory second = await scenario.BuildCountersignatureAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsAttribute multiValued = CmsAttribute.Create(
            CAdESSignatureFacts.CountersignatureAttributeOid,
            [first.AsReadOnlyMemory(), second.AsReadOnlyMemory()],
            BaseMemoryPool.Shared);
        using CmsSignedData multiValuedSignature = CmsSignedDataAugmentation.AppendUnsignedAttributes(
            baseline, signerIndex: 0, [multiValued], BaseMemoryPool.Shared);
        using CmsSignedData withCertificate = CmsSignedDataAugmentation.AddCertificates(
            multiValuedSignature, [scenario.CountersignerCertificate.AsReadOnlyMemory()], BaseMemoryPool.Shared);

        byte[] multiValuedOctets = withCertificate.AsReadOnlySpan().ToArray();
        Assert.HasCount(2, CountersignatureValues(withCertificate),
            "One countersignature attribute carrying two values — the same-attribute shape of NOTE 6.");
        Assert.AreEqual(2, CountBouncyCastleCountersignaturesThatVerify(multiValuedOctets),
            "The independent reader accepts both values of the one attribute.");

        var platformReader = new SignedCms();
        platformReader.Decode(multiValuedOctets);
        Assert.HasCount(2, platformReader.SignerInfos[0].CounterSignerInfos, "The platform reader sees both values of the one attribute as two counter signers.");
    }


    /// <summary>
    /// The counter signer's certificate is placed into <c>SignedData.certificates</c> by default, because a
    /// verifier reaching the countersignature has to find it and RFC 5652 §5.1 is where a signature's signers'
    /// certificates live; a caller distributing it out of band opts out and the set is left exactly as it was.
    /// </summary>
    [TestMethod]
    public async Task TheCountersignerCertificateIsPlacedInTheCertificateSetUnlessTheCallerOptsOut()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);

        List<byte[]> before = AtsHashIndexV3Oracle.CertificateEncodings(baseline.AsReadOnlySpan().ToArray());
        Assert.HasCount(1, before, "The baseline carries the signer's certificate alone (requirement a).");

        using CmsSignedData withCertificate = await scenario.CountersignAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);
        List<byte[]> included = AtsHashIndexV3Oracle.CertificateEncodings(withCertificate.AsReadOnlySpan().ToArray());
        Assert.HasCount(2, included, "The counter signer's certificate joins the signer's own (requirements d and e).");
        Assert.AreSequenceEqual(scenario.CountersignerCertificate.AsReadOnlySpan().ToArray(), included[1],
            "The added member is the counter signer's certificate, appended rather than the set being re-sorted.");

        using CmsSignedData withoutCertificate = await scenario.CountersignAsync(
            baseline, TestContext.CancellationToken, includeCountersignerCertificate: false).ConfigureAwait(false);
        List<byte[]> omitted = AtsHashIndexV3Oracle.CertificateEncodings(withoutCertificate.AsReadOnlySpan().ToArray());
        Assert.HasCount(1, omitted, "Opting out leaves SignedData.certificates exactly as the baseline had it.");
        Assert.HasCount(1, CountersignatureValues(withoutCertificate), "The countersignature itself is still attached.");
    }


    /// <summary>
    /// Adding a countersignature rewrites nothing but the length octets of the containers enclosing the new
    /// attribute — the preservation rule of clause 5.5.3, asserted at the octet level by the independent walker.
    /// The certificate-set placement is opted out of here so exactly one splice region is under test.
    /// </summary>
    [TestMethod]
    public async Task TheCountersignatureAugmentationPreservesEveryOctetOutsideTheLengthChain()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData countersigned = await scenario.CountersignAsync(
            baseline, TestContext.CancellationToken, includeCountersignerCertificate: false).ConfigureAwait(false);

        Assert.IsTrue(
            CmsStructureOracle.PreservesEveryOctetOutsideTheLengthChain(
                baseline.AsReadOnlySpan().ToArray(), countersigned.AsReadOnlySpan().ToArray(), signerIndex: 0),
            "Clause 5.5.3: the augmentation preserves the binary encoding of everything already present.");
    }


    /// <summary>
    /// Clause 5.5.3's attribute-addition lockdown: once a legacy long-term-availability attribute is present,
    /// "no other attributes than ATSv3 or attributes specified as per annex B shall be added to the
    /// <c>unsignedAttrs</c>" — so a countersignature is refused, fail-closed, rather than written into a
    /// signature the clause forbids it in.
    /// </summary>
    [TestMethod]
    public async Task ALegacyLongTermAvailabilityAttributeForbidsAddingACountersignature()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData legacy = await scenario.AttachLegacyArchiveTimestampAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CAdESValidationDataPlacement.LatestArchiveTimestampToken,
            CAdESSignatureAugmentation.DetectValidationDataPlacement(legacy),
            "The deprecated archive-time-stamp form of clause A.2.4 selects the second placement strategy, which is the lockdown's own precondition.");

        CAdESAugmentationException refusal = await Assert.ThrowsExactlyAsync<CAdESAugmentationException>(
            async () => await scenario.CountersignAsync(legacy, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        Assert.AreEqual(CAdESAugmentationFailureKind.LegacyAttributeForbidsFurtherAttributes, refusal.FailureKind,
            "The refusal names the clause 5.5.3 lockdown, not a malformed input.");

        //The same lockdown covers the other non-level attribute this surface can add.
        CAdESAugmentationException storeRefusal = Assert.ThrowsExactly<CAdESAugmentationException>(
            () => CAdESSignatureAugmentation.AddSignaturePolicyStore(
                legacy,
                signerIndex: 0,
                new CAdESSignaturePolicyStore { DocumentSpecificationOid = "1.2.3.4", EncodedDocument = new byte[] { 0x00 } },
                BaseMemoryPool.Shared));
        Assert.AreEqual(CAdESAugmentationFailureKind.LegacyAttributeForbidsFurtherAttributes, storeRefusal.FailureKind,
            "signature-policy-store is equally not an ATSv3 nor an Annex B attribute.");
    }


    /// <summary>
    /// Clause 5.5.3 NOTE 6, first direction: "the adding of a new countersignature in the same attribute or as a
    /// new <c>countersignature</c> attribute is possible" for a signature already protected by an
    /// <c>archive-time-stamp-v3</c>. The sibling attribute is new material with no entry in the earlier index, so
    /// clause 5.5.2's asymmetric membership check leaves the archive time-stamp valid and its message imprint still
    /// verifies against the recomputed clause 5.5.3 input — while the new attribute value is reported uncovered,
    /// which is NOTE 5's point rather than an error.
    /// </summary>
    [TestMethod]
    public async Task ASiblingCountersignatureAddedAfterAnArchiveTimestampLeavesItValid()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData countersigned = await scenario.CountersignAsync(baseline, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await scenario.AddArchiveTimestampAsync(
            countersigned, scenario.SignerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

        using ArchiveTimestampCoverage before = await StateArchiveCoverageAsync(archived, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, before.Status, "The archive time-stamp over the countersigned signature states its coverage.");
        Assert.IsTrue(CountersignatureValuesAreCovered(before), "The countersignature present when the index was computed is covered by it — clause 5.5.3 NOTE 4's \"protected by the archive time-stamp as an unsigned attribute\".");

        using CmsSignedData siblingAdded = await scenario.CountersignAsync(archived, TestContext.CancellationToken).ConfigureAwait(false);
        using ArchiveTimestampCoverage after = await StateArchiveCoverageAsync(siblingAdded, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, after.Status, "NOTE 6: adding a sibling countersignature attribute leaves the archive time-stamp usable.");
        Assert.IsTrue(after.ProtectedObjects!.EveryIndexEntryMatched, "Clause 5.5.2's validity condition still holds: every index entry still matches material the signature carries.");
        Assert.IsTrue(await ArchiveTimestampImprintStillVerifiesAsync(siblingAdded, after, TestContext.CancellationToken).ConfigureAwait(false),
            "The authority's own token still verifies against the recomputed clause 5.5.3 imprint input.");
        Assert.HasCount(2, CountersignatureValues(siblingAdded), "Both countersignatures are present.");
        Assert.AreEqual(2, CountBouncyCastleCountersignaturesThatVerify(siblingAdded.AsReadOnlySpan().ToArray()),
            "Both countersignatures verify under the independent reader; the later one simply gains nothing from the earlier archive time-stamp.");
    }


    /// <summary>
    /// Clause 5.5.3 NOTE 6, second direction: "the adding of a countersignature as an unsigned attribute to an
    /// existing countersignature that is protected by an ATSv3 will break the ATSv3 protection, because it changes
    /// the hash of the original <c>countersignature</c> attribute covered by the <c>ats-hash-index-v3</c>
    /// attribute". The countersignature is rebuilt from the very same signed attributes and the very same signature
    /// value, differing only by one unsigned attribute inside its own <c>SignerInfo</c> — so the countersignature
    /// itself still verifies, and it is precisely the archive time-stamp that breaks.
    /// </summary>
    [TestMethod]
    public async Task MutatingACountersignatureTheArchiveTimestampProtectsBreaksTheArchiveTimestamp()
    {
        using CountersignatureScenario scenario = CountersignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareCountersignatureAsync(
            baseline, countersignedSignerIndex: 0, scenario.CountersignerCertificate, PkiDigestAlgorithm.Sha256,
            CountersigningTime, algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        (IMemoryOwner<byte> signatureBuffer, int signatureLength) = await scenario.SignPreparationAsync(
            preparation, TestContext.CancellationToken).ConfigureAwait(false);

        using(signatureBuffer)
        {
            ReadOnlyMemory<byte> signatureValue = signatureBuffer.Memory[..signatureLength];
            using PooledMemory original = CAdESSignatureCreation.CompleteCountersignature(
                preparation, scenario.CountersignerCertificate, CryptoAlgorithm.P256, signatureValue, unsignedAttributes: null, BaseMemoryPool.Shared);
            using CmsAttribute originalAttribute = CmsAttribute.Create(
                CAdESSignatureFacts.CountersignatureAttributeOid, original.AsReadOnlySpan(), BaseMemoryPool.Shared);
            using CmsSignedData countersigned = CmsSignedDataAugmentation.AppendUnsignedAttributes(
                baseline, signerIndex: 0, [originalAttribute], BaseMemoryPool.Shared);
            using CmsSignedData withCountersignerCertificate = CmsSignedDataAugmentation.AddCertificates(
                countersigned, [scenario.CountersignerCertificate.AsReadOnlyMemory()], BaseMemoryPool.Shared);
            using CmsSignedData archived = await scenario.AddArchiveTimestampAsync(
                withCountersignerCertificate, scenario.SignerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

            using ArchiveTimestampCoverage before = await StateArchiveCoverageAsync(archived, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, before.Status, "The archive time-stamp protects the countersignature that was present when its index was computed.");
            Assert.IsTrue(CountersignatureValuesAreCovered(before), "The countersignature attribute value has an index entry of its own.");

            //The same countersignature, byte for byte, except for one unsigned attribute inside its own SignerInfo:
            //a signature-time-stamp over the countersignature's own signature value (clause 5.3's raw-value
            //imprint), which is the realistic act NOTE 6 warns about — raising a countersignature to B-T after the
            //signature carrying it was archive-time-stamped. RFC 5652 §11.3 rules out an attribute like
            //signing-time here, since that one MUST be signed; the independent reader enforces exactly that.
            using PkiCertificateMemory countersignatureTimestamp = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
                scenario.Authority, [scenario.Authority], CountersignatureSignatureValue(original.AsReadOnlySpan().ToArray()),
                CountersigningTime.AddHours(1), BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            using CmsAttribute innerAttribute = CmsAttribute.Create(
                CAdESSignatureFacts.SignatureTimestampAttributeOid, countersignatureTimestamp.AsReadOnlySpan(), BaseMemoryPool.Shared);
            using PooledMemory mutated = CAdESSignatureCreation.CompleteCountersignature(
                preparation, scenario.CountersignerCertificate, CryptoAlgorithm.P256, signatureValue, [innerAttribute], BaseMemoryPool.Shared);
            using CmsSignedData tampered = ReplaceCountersignatureValue(archived, mutated.AsReadOnlySpan());

            using ArchiveTimestampCoverage after = await StateArchiveCoverageAsync(tampered, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(ArchiveTimestampCoverageStatus.HashIndexInvalid, after.Status,
                "NOTE 6: the countersignature attribute value's octets changed, so the index entry naming the original matches nothing and clause 5.5.2 makes the index invalid.");
            Assert.IsFalse(after.ProtectedObjects!.EveryIndexEntryMatched, "The asymmetric check fails in the one direction that is an error: an entry with no matching material.");
            Assert.IsNull(after.MessageImprintInput, "An invalid index states no imprint input, so no proof of existence can be derived.");

            //The break is the archive time-stamp's alone: the countersignature's own signature covers its
            //signedAttrs, which did not change, so both independent readers still accept it.
            Assert.AreEqual(1, CountBouncyCastleCountersignaturesThatVerify(tampered.AsReadOnlySpan().ToArray()),
                "The countersignature itself still verifies — which is exactly why NOTE 6 has to warn about this at all.");
        }
    }


    /// <summary>
    /// States what the sole <c>archive-time-stamp-v3</c> of a signature protects, through the shipped component
    /// both directions of the wave compute the index and the imprint input with.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The stated coverage; the caller disposes it.</returns>
    internal static async ValueTask<ArchiveTimestampCoverage> StateArchiveCoverageAsync(CmsSignedData signedData, CancellationToken cancellationToken)
    {
        using PkiCertificateMemory token = SoleArchiveTimestampToken(signedData);

        return await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = signedData, ArchiveTimestampToken = token },
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Hands the stated imprint input to the archive time-stamp token's own message-imprint verification, so the
    /// claim is checked against a signature an independent time-stamping authority made rather than against the
    /// computation that produced it.
    /// </summary>
    /// <param name="signedData">The signature the coverage was stated for.</param>
    /// <param name="coverage">The stated coverage.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the token's imprint is the digest of the stated octets.</returns>
    internal static async ValueTask<bool> ArchiveTimestampImprintStillVerifiesAsync(
        CmsSignedData signedData, ArchiveTimestampCoverage coverage, CancellationToken cancellationToken)
    {
        using PkiCertificateMemory token = SoleArchiveTimestampToken(signedData);
        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            token, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return await info.VerifyMessageImprintAsync(
            coverage.MessageImprintInput!.AsReadOnlyMemory(), BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>States whether every <c>countersignature</c> attribute value of a stated coverage is covered by the index.</summary>
    /// <param name="coverage">The stated coverage.</param>
    /// <returns><see langword="true"/> when at least one countersignature value is present and all of them are covered.</returns>
    internal static bool CountersignatureValuesAreCovered(ArchiveTimestampCoverage coverage)
    {
        bool sawOne = false;
        foreach(CoveredAttributeValue value in coverage.ProtectedObjects!.UnsignedAttributeValues)
        {
            if(!string.Equals(value.AttributeType, CAdESSignatureFacts.CountersignatureAttributeOid, StringComparison.Ordinal))
            {
                continue;
            }

            sawOne = true;
            if(!value.IsCovered)
            {
                return false;
            }
        }

        return sawOne;
    }


    /// <summary>
    /// Replaces the octets of the sole <c>countersignature</c> attribute value through the shipped byte-preserving
    /// primitive — the one operation that is deliberately not preservation-neutral, and the one clause 5.5.3
    /// NOTE 6 warns about when the replaced value is protected by an archive time-stamp.
    /// </summary>
    /// <param name="signedData">The signature carrying the countersignature.</param>
    /// <param name="replacement">The whole encoding of the <c>Countersignature</c> the attribute is to carry instead.</param>
    /// <returns>The signature carrying the replacement; the caller disposes it.</returns>
    internal static CmsSignedData ReplaceCountersignatureValue(CmsSignedData signedData, ReadOnlySpan<byte> replacement)
    {
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signedData, signerIndex: 0);
        for(int i = 0; i < locations.Count; ++i)
        {
            if(!string.Equals(locations[i].AttributeType, CAdESSignatureFacts.CountersignatureAttributeOid, StringComparison.Ordinal))
            {
                continue;
            }

            return CmsSignedDataAugmentation.ReplaceUnsignedAttributeValue(
                signedData, signerIndex: 0, locations[i].AttributeIndex, locations[i].ValueIndex, replacement, BaseMemoryPool.Shared);
        }

        throw new InvalidOperationException("The signature carries no countersignature attribute to replace.");
    }


    /// <summary>Returns the sole <c>archive-time-stamp-v3</c> token of a signature, walked independently of the library's own locator.</summary>
    /// <param name="signedData">The signature.</param>
    /// <returns>The token carrier; the caller disposes it.</returns>
    internal static PkiCertificateMemory SoleArchiveTimestampToken(CmsSignedData signedData)
    {
        List<byte[]> tokens = UnsignedAttributeValues(signedData, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        Assert.HasCount(1, tokens, "These assertions are about a signature carrying exactly one archive-time-stamp-v3.");

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(tokens[0].Length);
        tokens[0].CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }


    /// <summary>
    /// Returns the <c>signature</c> value octets of a bare <c>Countersignature</c> — the octets clause 5.3's
    /// message imprint covers when a countersignature is itself raised to CAdES-B-T — read with this class's own
    /// walker, since every shipped walk starts at a <c>ContentInfo</c> a bare <c>SignerInfo</c> does not have.
    /// </summary>
    /// <param name="countersignature">The DER-encoded <c>SignerInfo</c>.</param>
    /// <returns>The signature value octets, without the tag and length.</returns>
    internal static byte[] CountersignatureSignatureValue(byte[] countersignature)
    {
        AsnReader signerInfo = new AsnReader(countersignature, AsnEncodingRules.DER).ReadSequence();
        _ = signerInfo.ReadInteger();                                    //version
        _ = signerInfo.ReadSequence();                                   //sid: IssuerAndSerialNumber
        _ = signerInfo.ReadSequence();                                   //digestAlgorithm
        _ = signerInfo.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        _ = signerInfo.ReadSequence();                                   //signatureAlgorithm

        return signerInfo.ReadOctetString();                             //signature
    }


    /// <summary>
    /// Counts how many of a signature's countersignatures the independent BouncyCastle CMS reader accepts, each
    /// under a certificate the signature itself carries — the oracle never sees the minting party's key material,
    /// only wire octets.
    /// </summary>
    /// <param name="signedDataOctets">The DER-encoded Signed Data Object.</param>
    /// <returns>The number of countersignatures that verified.</returns>
    internal static int CountBouncyCastleCountersignaturesThatVerify(byte[] signedDataOctets)
    {
        var bouncyCastle = new BcCmsSignedData(signedDataOctets);
        int verified = 0;
        foreach(BcSignerInformation signer in bouncyCastle.GetSignerInfos().GetSigners())
        {
            foreach(BcSignerInformation counterSigner in signer.GetCounterSignatures().GetSigners())
            {
                foreach(Org.BouncyCastle.X509.X509Certificate candidate in bouncyCastle.GetCertificates().EnumerateMatches(counterSigner.SignerID))
                {
                    if(counterSigner.Verify(candidate))
                    {
                        ++verified;
                    }
                }
            }
        }

        return verified;
    }


    /// <summary>
    /// Returns the whole encoding of every value of every unsigned attribute of one type a signature's first signer
    /// carries, walked independently of the library's own locator.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <param name="attributeType">The attribute's object identifier.</param>
    /// <returns>The values, in encoding order.</returns>
    internal static List<byte[]> UnsignedAttributeValues(CmsSignedData signedData, string attributeType)
    {
        byte[] octets = signedData.AsReadOnlySpan().ToArray();
        List<byte[]> values = [];
        List<CmsTlvBounds> attributes = CmsStructureOracle.UnsignedAttributes(octets, signerIndex: 0);
        for(int i = 0; i < attributes.Count; ++i)
        {
            List<CmsTlvBounds> parts = CmsStructureOracle.Children(octets, attributes[i]);
            string oid = AsnDecoder.ReadObjectIdentifier(octets.AsSpan()[parts[0].Start..parts[0].End], AsnEncodingRules.BER, out _);
            if(!string.Equals(oid, attributeType, StringComparison.Ordinal))
            {
                continue;
            }

            List<CmsTlvBounds> members = CmsStructureOracle.Children(octets, parts[1]);
            for(int j = 0; j < members.Count; ++j)
            {
                values.Add(octets[members[j].Start..members[j].End]);
            }
        }

        return values;
    }


    /// <summary>
    /// Returns the whole encoding of every <c>countersignature</c> attribute value a signature's first signer
    /// carries, walked independently of the library's own locator.
    /// </summary>
    /// <param name="signedData">The signature.</param>
    /// <returns>The values, in encoding order.</returns>
    internal static List<byte[]> CountersignatureValues(CmsSignedData signedData) =>
        UnsignedAttributeValues(signedData, CAdESSignatureFacts.CountersignatureAttributeOid);


    /// <summary>Returns the one <c>countersignature</c> attribute value a signature carries, failing when it carries a different number.</summary>
    /// <param name="signedData">The signature.</param>
    /// <returns>The whole encoding of the value.</returns>
    private static byte[] SoleCountersignatureValue(CmsSignedData signedData)
    {
        List<byte[]> values = CountersignatureValues(signedData);
        Assert.HasCount(1, values, "This assertion is about a signature carrying exactly one countersignature.");

        return values[0];
    }


    /// <summary>
    /// Decodes a <c>Countersignature ::= SignerInfo</c> (RFC 5652 §11.4) with its own reader, written from the
    /// <c>SignerInfo</c> syntax of RFC 5652 §5.3 rather than through any library walker — which could not address
    /// a bare <c>SignerInfo</c> in any case, since every shipped walk starts at a <c>ContentInfo</c>.
    /// </summary>
    /// <param name="countersignature">The DER-encoded <c>SignerInfo</c>.</param>
    /// <returns>The signed-attribute facts the assertions are made about.</returns>
    private static CountersignatureFields ReadCountersignature(byte[] countersignature)
    {
        var reader = new AsnReader(countersignature, AsnEncodingRules.DER);
        AsnReader signerInfo = reader.ReadSequence();
        reader.ThrowIfNotEmpty();

        _ = signerInfo.ReadInteger();                                    //version
        _ = signerInfo.ReadSequence();                                   //sid: IssuerAndSerialNumber
        _ = signerInfo.ReadSequence();                                   //digestAlgorithm
        AsnReader signedAttributes = signerInfo.ReadSetOf(
            skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));

        List<string> types = [];
        byte[]? messageDigest = null;
        byte[]? signingCertificateHash = null;
        DateTimeOffset? signingTime = null;
        while(signedAttributes.HasData)
        {
            AsnReader attribute = signedAttributes.ReadSequence();
            string oid = attribute.ReadObjectIdentifier();
            AsnReader values = attribute.ReadSetOf();
            ReadOnlyMemory<byte> value = values.ReadEncodedValue();
            types.Add(oid);

            if(string.Equals(oid, CAdESSignatureFacts.MessageDigestAttributeOid, StringComparison.Ordinal))
            {
                messageDigest = new AsnReader(value, AsnEncodingRules.DER).ReadOctetString();
            }
            else if(string.Equals(oid, CAdESSignatureFacts.SigningTimeAttributeOid, StringComparison.Ordinal))
            {
                signingTime = new AsnReader(value, AsnEncodingRules.DER).ReadUtcTime();
            }
            else if(string.Equals(oid, CAdESSignatureFacts.SigningCertificateV2AttributeOid, StringComparison.Ordinal))
            {
                //SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }; ESSCertIDv2 ::=
                //SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha256, certHash OCTET STRING, ... }.
                AsnReader essCertId = new AsnReader(value, AsnEncodingRules.DER).ReadSequence().ReadSequence().ReadSequence();
                if(essCertId.PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
                {
                    _ = essCertId.ReadSequence();
                }

                signingCertificateHash = essCertId.ReadOctetString();
            }
        }

        return new CountersignatureFields(types, messageDigest, signingCertificateHash, signingTime);
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


    /// <summary>
    /// Mints a P-256 signer: key material through <see cref="BouncyCastleKeyMaterialCreator"/> (the repository's
    /// test-key convention), and a self-signed certificate over the same public point through a platform
    /// <see cref="ECDsa"/> reconstructed from it — the certificate vehicle is platform code, the key material is
    /// not.
    /// </summary>
    /// <param name="subjectName">The subject distinguished name, distinct per party so the two certificates never share an issuer name.</param>
    /// <returns>The certificate and the private key material, both owned by the caller.</returns>
    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintP256Party(string subjectName)
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
            using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(
                platformKey, NotBefore, NotAfter, subjectName);

            return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
        }
    }


    /// <summary>
    /// The signed-attribute facts of one decoded <c>Countersignature</c> the assertions here are made about.
    /// </summary>
    /// <param name="SignedAttributeTypes">Every <c>attrType</c> present, in encoding order.</param>
    /// <param name="MessageDigest">The <c>message-digest</c> attribute's octets, or <see langword="null"/> when absent.</param>
    /// <param name="SigningCertificateHash">The first <c>ESSCertIDv2</c>'s <c>certHash</c>, or <see langword="null"/> when the attribute is absent.</param>
    /// <param name="SigningTime">The <c>signing-time</c> attribute's instant, or <see langword="null"/> when absent.</param>
    private sealed record CountersignatureFields(
        IReadOnlyList<string> SignedAttributeTypes,
        byte[]? MessageDigest,
        byte[]? SigningCertificateHash,
        DateTimeOffset? SigningTime);


    /// <summary>
    /// The material every test here starts from: a signer and a counter signer, each with its own key material and
    /// its own distinctly named self-signed certificate, plus a Root CA and Time-Stamping Authority for the legacy
    /// archive-time-stamp fixture the lockdown test needs.
    /// </summary>
    internal sealed class CountersignatureScenario: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Gets the Root CA the authority is issued by.</summary>
        internal required X509ChainTestRingNode Root { get; init; }

        /// <summary>Gets the Time-Stamping Authority the legacy fixture's token is signed by.</summary>
        internal required X509ChainTestRingNode Authority { get; init; }

        /// <summary>Gets the signer's certificate.</summary>
        internal required PkiCertificateMemory SignerCertificate { get; init; }

        /// <summary>Gets the signer's private key material.</summary>
        internal required PrivateKeyMemory SignerPrivateKey { get; init; }

        /// <summary>Gets the counter signer's certificate.</summary>
        internal required PkiCertificateMemory CountersignerCertificate { get; init; }

        /// <summary>Gets the counter signer's private key material.</summary>
        internal required PrivateKeyMemory CountersignerPrivateKey { get; init; }

        /// <summary>Gets the counter signer certificate's subject distinguished name, for the reader-resolution assertion.</summary>
        internal static string CountersignerSubject => "CN=Verifiable CAdES Counter Signer";


        /// <summary>Builds the scenario: mints the ring and the two parties.</summary>
        /// <returns>The scenario. The caller disposes it.</returns>
        internal static CountersignatureScenario Create()
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            (PkiCertificateMemory signerCertificate, PrivateKeyMemory signerKey) = MintP256Party("CN=Verifiable CAdES Signer");
            (PkiCertificateMemory countersignerCertificate, PrivateKeyMemory countersignerKey) = MintP256Party(CountersignerSubject);

            return new CountersignatureScenario
            {
                Root = root,
                Authority = authority,
                SignerCertificate = signerCertificate,
                SignerPrivateKey = signerKey,
                CountersignerCertificate = countersignerCertificate,
                CountersignerPrivateKey = countersignerKey
            };
        }


        /// <summary>Signs <see cref="Content"/> as a CAdES-B-B baseline through the shipped creation surface.</summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The baseline signature. The caller disposes it.</returns>
        internal async ValueTask<CmsSignedData> SignBaselineAsync(CancellationToken cancellationToken) =>
            await CAdESSignatureCreation.SignAsync(
                SignerCertificate, SignerPrivateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);


        /// <summary>Countersigns a signature through the shipped augmentation surface.</summary>
        /// <param name="signature">The signature to countersign.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <param name="includeCountersignerCertificate">Whether the counter signer's certificate joins <c>SignedData.certificates</c>.</param>
        /// <returns>The countersigned signature. The caller disposes it.</returns>
        internal async ValueTask<CmsSignedData> CountersignAsync(
            CmsSignedData signature, CancellationToken cancellationToken, bool includeCountersignerCertificate = true) =>
            await CAdESSignatureAugmentation.AddCountersignatureAsync(
                new CAdESCountersignatureContext
                {
                    SignedData = signature,
                    CountersignerCertificate = CountersignerCertificate,
                    CountersignerPrivateKey = CountersignerPrivateKey,
                    SigningTime = CountersigningTime,
                    IncludeCountersignerCertificate = includeCountersignerCertificate
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);


        /// <summary>
        /// Produces one bare <c>Countersignature</c> through the shipped creation phases, for the same-attribute
        /// multi-value shape that needs the <c>SignerInfo</c> octets rather than a finished attribute.
        /// </summary>
        /// <param name="signature">The signature being countersigned.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The DER-encoded <c>Countersignature</c>. The caller disposes it.</returns>
        internal async ValueTask<PooledMemory> BuildCountersignatureAsync(CmsSignedData signature, CancellationToken cancellationToken)
        {
            using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareCountersignatureAsync(
                signature, countersignedSignerIndex: 0, CountersignerCertificate, PkiDigestAlgorithm.Sha256,
                CountersigningTime, algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            (IMemoryOwner<byte> buffer, int length) = await SignPreparationAsync(preparation, cancellationToken).ConfigureAwait(false);

            using(buffer)
            {
                return CAdESSignatureCreation.CompleteCountersignature(
                    preparation, CountersignerCertificate, CryptoAlgorithm.P256, buffer.Memory[..length],
                    unsignedAttributes: null, BaseMemoryPool.Shared);
            }
        }


        /// <summary>
        /// Signs a preparation's <c>SigningInput</c> with the counter signer's key through the registered signing
        /// seam and converts the fixed-width IEEE P1363 result to the DER <c>Ecdsa-Sig-Value</c> the wire encoding
        /// takes, through the shipped converter.
        /// </summary>
        /// <param name="preparation">The preparation whose signing input is signed.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The rented buffer holding the DER signature and the number of valid octets in it; the caller disposes the buffer.</returns>
        internal async ValueTask<(IMemoryOwner<byte> Buffer, int Length)> SignPreparationAsync(
            CAdESSignaturePreparation preparation, CancellationToken cancellationToken)
        {
            CryptoAlgorithm algorithm = CountersignerPrivateKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = CountersignerPrivateKey.Tag.Get<Purpose>();
            SigningDelegate signing = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);
            (Signature signature, CryptoEvent? evt) = await signing(
                CountersignerPrivateKey.AsReadOnlyMemory(), preparation.SigningInput.AsReadOnlyMemory(), BaseMemoryPool.Shared,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            using(signature)
            {
                if(evt is not null)
                {
                    CryptographicKeyEvents.DefaultSink(evt);
                }

                IMemoryOwner<byte> buffer = EcdsaSignatureEncoding.ConvertP1363ToDer(
                    signature.AsReadOnlySpan(), BaseMemoryPool.Shared, out int length);

                return (buffer, length);
            }
        }


        /// <summary>
        /// Raises a signature to CAdES-B-LTA through the shipped augmentation surface, so the
        /// <c>archive-time-stamp-v3</c> and its <c>ats-hash-index-v3</c> are the ones clauses 5.5.2 and 5.5.3
        /// define rather than a fixture shaped to suit the coverage computation.
        /// </summary>
        /// <param name="signature">The signature to raise.</param>
        /// <param name="signingCertificate">The signing certificate requirement m) is enforced against.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The archive-time-stamped signature. The caller disposes it.</returns>
        internal async ValueTask<CmsSignedData> AddArchiveTimestampAsync(
            CmsSignedData signature, PkiCertificateMemory signingCertificate, CancellationToken cancellationToken)
        {
            var responder = new MintingTimestampResponder(Authority, [Authority, Root], ArchiveTimestampTime);

            return await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CAdESArchiveTimestampContext
                {
                    SignedData = signature,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = AuthorityAddress,
                    FetchResponse = responder.FetchAsync,
                    ValidationMaterial = CAdESValidationMaterial.None,
                    SigningCertificate = signingCertificate
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);
        }


        /// <summary>
        /// Attaches a token under the deprecated archive-time-stamp attribute of clause A.2.4, which only a hostile
        /// or legacy fixture ever carries: clause A.2 forbids creating it, so nothing shipped writes one and the
        /// test assembles it through the byte-preserving splice itself.
        /// </summary>
        /// <param name="signature">The signature to attach it to.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The signature carrying the legacy attribute. The caller disposes it.</returns>
        internal async ValueTask<CmsSignedData> AttachLegacyArchiveTimestampAsync(CmsSignedData signature, CancellationToken cancellationToken)
        {
            using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
                Authority, [Authority], signature.AsReadOnlyMemory(), ArchiveTimestampTime, BaseMemoryPool.Shared,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            using CmsAttribute attribute = CmsAttribute.Create(
                CAdESSignatureFacts.ArchiveTimestampV2AttributeOid, token.AsReadOnlySpan(), BaseMemoryPool.Shared);

            return CmsSignedDataAugmentation.AppendUnsignedAttributes(signature, signerIndex: 0, [attribute], BaseMemoryPool.Shared);
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            CountersignerPrivateKey.Dispose();
            CountersignerCertificate.Dispose();
            SignerPrivateKey.Dispose();
            SignerCertificate.Dispose();
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
