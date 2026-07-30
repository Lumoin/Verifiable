using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using AlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The coverage seam of the shipped CAdES binding — <see cref="CAdESSignatureFacts.StateTimestampCoverageAsync"/>,
/// the <c>StateTimestampCoverageAsyncDelegate</c> step 1) of clause 5.6.2.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> asks "which objects does this time-stamp protect" through — for the two
/// classes it did not state before: the <c>archive-time-stamp-v3</c> of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clauses 5.5.2 and 5.5.3</see> and the time-stamps on references to validation data
/// of that document's clause A.1.5.
/// </summary>
/// <remarks>
/// <para>
/// Every assertion is made against octets that crossed the seam and were then handed to the same message-imprint
/// verification the proof-of-existence extraction building block performs
/// (<see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/>): the claim is checked against a token an
/// independent time-stamping authority signed, never against the computation that produced it.
/// </para>
/// <para>
/// The signatures are produced by the shipped creation and augmentation surfaces; the legacy attributes of
/// clause A.1.5 and the deprecated archive-time-stamp form of clause A.2.4 are hand-attached in test code
/// through the byte-preserving splice, because nothing in the library creates them.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESTimestampCoverageTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time the minted signatures carry.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The generation time the minted signature time-stamps carry.</summary>
    private static DateTimeOffset SignatureTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The generation time the minted archive and validation-data time-stamps carry.</summary>
    private static DateTimeOffset ArchiveTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The <c>thisUpdate</c> of the certificate revocation list appended after an archive time-stamp — years after it, so a proof of existence at the archive instant would be provably false.</summary>
    private static DateTimeOffset AppendedRevocationListTime { get; } = TestClock.CanonicalEpoch.AddYears(5);

    /// <summary>The content every minted signature encapsulates and covers.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the coverage-stating content"u8.ToArray());

    /// <summary>The address the transport delegate is handed; nothing dials it.</summary>
    private static string AuthorityAddress { get; } = "https://coverage-authority.example.test/tsa";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The seam states, for an <c>archive-time-stamp-v3</c> the shipped augmentation surface produced, exactly
    /// the octets the token's own <c>messageImprint</c> is the digest of — the four-part concatenation of clause
    /// 5.5.3 recomputed from the wire bytes alone.
    /// </summary>
    [TestMethod]
    public async Task StatesWhatAnArchiveTimestampProtectsAndTheTokenVerifiesAgainstIt()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await world.AddArchiveTimestampAsync(world.TimestampedSignature, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = archived }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp archiveTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[0];

        using SignedContentMemory? covered = await CAdESSignatureFacts.StateTimestampCoverageAsync(
            new TimestampCoverageContext { Signature = facts, Timestamp = archiveTimestamp }, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(covered, "The binding states the covered octets of an archive-time-stamp-v3, which is what closes step 1) of clause 5.6.2.3.4 for that class.");

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            archiveTimestamp.Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        bool imprintHolds = await info.VerifyMessageImprintAsync(covered!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //The same octets the component states directly, so the seam is shown to hand on the clause 5.5.3 input
        //rather than something of its own.
        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = archived, ArchiveTimestampToken = archiveTimestamp.Token },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(imprintHolds,
            "Clause 5.5.3: the archive time-stamp's message imprint is the digest of the concatenation the binding restates, so the authority's own token verifies against it.");
        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "The index is valid and the imprint input was assembled.");
        Assert.AreSequenceEqual(coverage.MessageImprintInput!.AsReadOnlySpan().ToArray(), covered!.AsReadOnlySpan().ToArray(),
            "The seam states the clause 5.5.3 input the shared computation produces, with no second implementation between them.");
    }


    /// <summary>
    /// An archive time-stamp of the deprecated v2 form (clause A.2.4) carries no <c>ats-hash-index-v3</c>, so
    /// nothing names which objects it covers and the binding states nothing — the fail-closed outcome step 1) of
    /// clause 5.6.2.3.4 puts on a time-stamp whose coverage is unknown.
    /// </summary>
    [TestMethod]
    public async Task StatesNothingForAnArchiveTimestampCarryingNoHashIndex()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            world.Authority, [world.Authority], world.TimestampedSignature.AsReadOnlyMemory(), ArchiveTimestampTime,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData legacy = AttachUnsignedAttribute(
            world.TimestampedSignature, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid, token.AsReadOnlySpan());

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = legacy }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp archiveTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[0];

        using SignedContentMemory? covered = await CAdESSignatureFacts.StateTimestampCoverageAsync(
            new TimestampCoverageContext { Signature = facts, Timestamp = archiveTimestamp }, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureTimestampClass.ArchiveTimestamp, archiveTimestamp.Class,
            "The deprecated attribute is still recognised as an archive time-stamp; what changes is that nothing states what it covers.");
        Assert.IsNull(covered, "Clause A.2.4's form predates the hash index, so the binding has nothing to recompute the clause 5.5.3 input from.");
    }


    /// <summary>
    /// Clause 5.5.2 NOTE 5 through the seam: certificates added to a signature after an archive time-stamp was
    /// applied leave that time-stamp's stated coverage intact, because the index is only checked from its own
    /// entries towards the material and the imprint input excludes <c>certificates</c> altogether.
    /// </summary>
    [TestMethod]
    public async Task StillStatesCoverageAfterMaterialIsAddedAfterTheArchiveTimestamp()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await world.AddArchiveTimestampAsync(world.TimestampedSignature, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData extended = CmsSignedDataAugmentation.AddCertificates(
            archived, [world.Authority.Certificate.RawData], BaseMemoryPool.Shared);

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = extended }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp archiveTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[0];

        using SignedContentMemory? covered = await CAdESSignatureFacts.StateTimestampCoverageAsync(
            new TimestampCoverageContext { Signature = facts, Timestamp = archiveTimestamp }, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(covered, "Clause 5.5.2 NOTE 5: further certificates can be added without invalidating an earlier archive time-stamp.");

        using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
            archiveTimestamp.Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        bool imprintHolds = await info.VerifyMessageImprintAsync(covered!.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(imprintHolds, "The imprint input of clause 5.5.3 names no field the addition touched, so the token still verifies against the restated octets.");
    }


    /// <summary>
    /// Clause A.1.5.1: the <c>time-stamped-certs-crls-references</c> attribute's token time-stamps the
    /// <c>complete-certificate-references</c> and <c>complete-revocation-references</c> attributes, each
    /// contributing its <c>attrType</c> and <c>attrValues</c> fields with their own tag and length octets and
    /// without the tag and length of the enclosing SEQUENCE.
    /// </summary>
    [TestMethod]
    public async Task StatesWhatATimeStampOnCertificateAndRevocationReferencesProtects()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData withReferences = AttachReferenceAttributes(world.TimestampedSignature);

        byte[] expected = [.. AttributeContribution(withReferences, CAdESSignatureFacts.CompleteCertificateReferencesAttributeOid),
            .. AttributeContribution(withReferences, CAdESSignatureFacts.CompleteRevocationReferencesAttributeOid)];
        using SignedContentMemory? covered = await StateCoverageOfAttachedTokenAsync(
            world, withReferences, CAdESSignatureFacts.CertificateAndCrlTimestampAttributeOid, expected, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(covered, "The binding states the clause A.1.5.1 concatenation for a token carried in the certCRLTimestamp attribute.");
        Assert.AreSequenceEqual(expected, covered!.AsReadOnlySpan().ToArray(),
            "Clause A.1.5.1: the concatenation is the two reference attributes, each as attrType and attrValues including type and length, in the order the clause lists them.");
    }


    /// <summary>
    /// Clause A.1.5.2: the <c>CAdES-C-timestamp</c> attribute's token time-stamps the <c>signature</c> field's
    /// value octets — without their own tag and length — followed by the <c>signature-time-stamp</c> attribute
    /// and the two reference attributes.
    /// </summary>
    [TestMethod]
    public async Task StatesWhatACadesCTimestampProtects()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData withReferences = AttachReferenceAttributes(world.TimestampedSignature);

        byte[] expected = [.. CmsSignedDataAugmentation.ReadSignatureValue(withReferences, signerIndex: 0).ToArray(),
            .. AttributeContribution(withReferences, CAdESSignatureFacts.SignatureTimestampAttributeOid),
            .. AttributeContribution(withReferences, CAdESSignatureFacts.CompleteCertificateReferencesAttributeOid),
            .. AttributeContribution(withReferences, CAdESSignatureFacts.CompleteRevocationReferencesAttributeOid)];
        using SignedContentMemory? covered = await StateCoverageOfAttachedTokenAsync(
            world, withReferences, CAdESSignatureFacts.EscTimestampAttributeOid, expected, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(covered, "The binding states the clause A.1.5.2 concatenation for a token carried in the escTimeStamp attribute.");
        Assert.AreSequenceEqual(expected, covered!.AsReadOnlySpan().ToArray(),
            "Clause A.1.5.2: the signature value's octets come first, without the ASN.1 type or length encoding for that value, and the three attributes follow in the order the clause lists them.");
    }


    /// <summary>
    /// A signature carrying neither reference attribute is not one either clause A.1.5 token class is defined
    /// over, so a token appended in one of those attributes states nothing rather than a concatenation of
    /// whatever happened to be there.
    /// </summary>
    [TestMethod]
    public async Task StatesNothingForAValidationDataTimestampWhenTheSignatureCarriesNoReferenceAttributes()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            world.Authority, [world.Authority], world.TimestampedSignature.AsReadOnlyMemory(), ArchiveTimestampTime,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData appended = AttachUnsignedAttribute(
            world.TimestampedSignature, CAdESSignatureFacts.EscTimestampAttributeOid, token.AsReadOnlySpan());

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = appended }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp validationDataTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ValidationDataTimestamp)[0];

        using SignedContentMemory? covered = await CAdESSignatureFacts.StateTimestampCoverageAsync(
            new TimestampCoverageContext { Signature = facts, Timestamp = validationDataTimestamp }, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureTimestampClass.ValidationDataTimestamp, validationDataTimestamp.Class, "The attribute is recognised as a time-stamp on references to validation data.");
        Assert.IsNull(covered, "Neither the complete-certificate-references nor the complete-revocation-references attribute is present, so the clause A.1.5 concatenation has no objects to name.");
    }


    /// <summary>
    /// The regression test of the over-admission the coverage seam's closure made reachable: a certificate
    /// revocation list appended to a signature <em>after</em> an <c>archive-time-stamp-v3</c> was applied gains no
    /// proof of existence from that time-stamp. The <c>ats-hash-index-v3</c> of clause 5.5.2 does not name it, and
    /// the binding's <c>StateTimestampProtectsObject</c> filter now answers step 1) of clause 5.6.2.3 of ETSI
    /// EN 319 102-1 from that index rather than from the per-class rule of clause 5.6.3.1 alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>The exploit shape this closes.</strong> A revocation object minted today and appended to
    /// <c>SignedData.crls</c> of a long-term signature leaves the archive time-stamp verifiable: <c>crls</c> is not
    /// among the fields the imprint input of clause 5.5.3 concatenates, and the membership check of clause 5.5.2 is
    /// asymmetric, so every archived index entry still matches. The coarse class rule — "the whole signature except
    /// the last archive time-stamp" — would then hand that object a proof of existence at the archive time-stamp's
    /// instant, and step 2)a) of the validation time sliding process of clause 5.6.2.2 accepts such a proof as
    /// revocation data shown to have existed at or before control-time. Nothing in the signature establishes it.
    /// </para>
    /// <para>
    /// The second half of the assertion is the guard against over-filtering: the material that <em>was</em> present
    /// when the archive time-stamp was requested keeps its proof, which is what makes the filter a narrowing of the
    /// class rule rather than a refusal of it.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task MaterialAppendedAfterTheArchiveTimestampGainsNoProofOfExistenceFromIt()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await world.AddArchiveTimestampAsync(world.TimestampedSignature, TestContext.CancellationToken).ConfigureAwait(false);

        //Minted years after the archive time-stamp's own generation time, so a proof of existence at that instant
        //would be a claim about a document that provably did not exist then.
        using PkiCertificateMemory appendedList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            world.Root, AppendedRevocationListTime, AppendedRevocationListTime.AddDays(1), []);
        using CmsSignedData extended = CAdESSignatureAugmentation.AddValidationData(
            archived, signerIndex: 0, new CAdESValidationMaterial { CertificateRevocationLists = [appendedList] }, BaseMemoryPool.Shared);

        using var resources = new SignatureValidationResources();
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = extended }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp archiveTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[0];

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = extended, ArchiveTimestampToken = archiveTimestamp.Token },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ProofOfExistenceSet derived = await ExtractProofsAsync(facts, archiveTimestamp, resources, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationObjectIdentity appendedIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            facts.EmbeddedCertificateRevocationLists[^1].AsReadOnlyMemory(), ValidationObjectKind.RevocationData, reference: null, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ValidationObjectIdentity signingCertificateIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            facts.SigningCertificate!.AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status,
            "Clause 5.5.2 NOTE 5: appending material leaves every archived index entry matched, so the archive time-stamp is still usable — which is exactly why the over-admission was reachable.");
        Assert.IsFalse(coverage.ProtectedObjects!.RevocationInformation[^1].IsCovered,
            "Clause 5.5.2: the list appended after the archive time-stamp has no entry in that time-stamp's index.");
        Assert.IsFalse(derived.ExistsAtOrBefore(appendedIdentity, ArchiveTimestampTime),
            "Step 1) of clause 5.6.2.3 admits only the objects the time-stamp is shown to protect, and the hash index shows this one is not among them, so no proof of existence is derived for it.");
        Assert.IsTrue(derived.ExistsAtOrBefore(signingCertificateIdentity, ArchiveTimestampTime),
            "The filter narrows the class rule, it does not refuse it: the signing certificate the index does name keeps its proof at the archive time-stamp's generation time.");
    }


    /// <summary>
    /// The other half of the same filter, on the placement clause 5.4.2.2 gives an OCSP response: a response present
    /// <em>before</em> the archive time-stamp keeps its proof of existence. The <c>ats-hash-index-v3</c> holds the
    /// hash of the whole <c>RevocationInfoChoice</c> member — an <c>OtherRevocationInfoFormat</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5940#section-2">RFC 5940 §2</see> — while the extracted facts
    /// surface only the response inside it, so a filter that hashed the surfaced octets alone would report every
    /// embedded OCSP response unprotected and strip a proof the token does establish.
    /// </summary>
    /// <remarks>
    /// The response is placed through the shipped <see cref="CAdESSignatureAugmentation.AddValidationData"/>,
    /// which writes a whole <c>OCSPResponse</c> into <c>SignedData.crls.other</c> under <c>id-ri-ocsp-response</c>
    /// (the RFC 5940 §2 format — the only form defined there), and the shipped
    /// <see cref="CAdESSignatureFacts.ExtractAsync"/> surfaces it back: the whole round trip runs through shipped
    /// code, no hand-built member and no <c>id-pkix-ocsp-basic</c> stand-in.
    /// </remarks>
    [TestMethod]
    public async Task AnOcspResponsePresentBeforeTheArchiveTimestampKeepsItsProofOfExistence()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory response = X509ChainTestRingRevocation.MintOcspResponse(
            world.Authority, world.Root, OcspCertificateStatus.Good, SigningTime, NotAfter);
        using CmsSignedData withRevocationData = CAdESSignatureAugmentation.AddValidationData(
            world.TimestampedSignature, signerIndex: 0, new CAdESValidationMaterial { OcspResponses = [response] }, BaseMemoryPool.Shared);
        using CmsSignedData archived = await world.AddArchiveTimestampAsync(withRevocationData, TestContext.CancellationToken).ConfigureAwait(false);

        using var resources = new SignatureValidationResources();
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = archived }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.HasCount(1, facts.EmbeddedOcspResponses, "The response was placed once, as a member of the root SignedData.crls field.");
        Assert.AreSequenceEqual(response.AsReadOnlySpan().ToArray(), facts.EmbeddedOcspResponses[0].AsReadOnlySpan().ToArray(),
            "The whole OCSPResponse placed under id-ri-ocsp-response is surfaced verbatim by the shipped reader.");

        EmbeddedTimestamp archiveTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[0];
        ProofOfExistenceSet derived = await ExtractProofsAsync(facts, archiveTimestamp, resources, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationObjectIdentity responseIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            facts.EmbeddedOcspResponses[0].AsReadOnlyMemory(), ValidationObjectKind.RevocationData, reference: null, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(derived.ExistsAtOrBefore(responseIdentity, ArchiveTimestampTime),
            "Clause 5.5.2 indexes the whole crls member, so the response that member carries is protected and keeps its proof of existence at the archive time-stamp's generation time.");
    }


    /// <summary>
    /// The regression test of defect D-F (the AMENDMENT-2 filter's over-strictness): a <c>content-time-stamp</c>
    /// (clause 5.2.8, a SIGNED attribute) gains a proof of existence from an <c>archive-time-stamp-v3</c>, because
    /// step 3) of clause 5.5.3 concatenates the whole <c>signedAttrs</c> TLV verbatim into that time-stamp's
    /// message imprint. The <c>ats-hash-index-v3</c> of clause 5.5.2 indexes certificates, revocation objects and
    /// <em>unsigned</em> attribute values alone, so the binding's <c>StateTimestampProtectsObject</c> filter
    /// answers this candidate from the signed attribute values, not from the hash index.
    /// </summary>
    /// <remarks>
    /// The negative guard makes the fix load-bearing: the token is one of the signer's signed attribute values,
    /// and the <c>ats-hash-index-v3</c> never names it, so a hash-index-only lookup — the filter's state before
    /// this fix — would deny the token and strip the proof asserted in the first half. The report-level
    /// projection of this proof (TS 119 102-2 clause 4.4.7 <c>ProvidesProofOfExistenceFor</c>) is asserted
    /// end-to-end over the full validation pipeline by
    /// <c>CAdESCapstoneFirewalledFlowTests.FirewalledCapstoneAttributesAContentTimestampsProofToTheArchiveTimestamp</c>.
    /// </remarks>
    [TestMethod]
    public async Task AContentTimestampGainsItsProofOfExistenceFromTheArchiveTimestamp()
    {
        using var world = await CoverageWorld.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //B-B carrying a content-time-stamp (clause 5.2.8), then B-T, then B-LTA — every step through the shipped
        //surfaces, the content-time-stamp token acquired and verified by CAdESSignatureCreation itself.
        var contentResponder = new MintingTimestampResponder(world.Authority, [world.Authority], SigningTime.AddMinutes(1));
        using CmsSignedData baseline = await CAdESSignatureCreation.SignAsync(
            world.SignerCertificate, world.SignerPrivateKey, Content, null, SigningTime, additionalCertificates: null,
            algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
            TestContext.CancellationToken,
            new CAdESOptionalSignedAttributes
            {
                ContentTimestampRequests =
                [
                    new CAdESContentTimestampRequest { TsaUri = AuthorityAddress, FetchResponse = contentResponder.FetchAsync }
                ]
            }).ConfigureAwait(false);

        var signatureResponder = new MintingTimestampResponder(world.Authority, [world.Authority], SignatureTimestampTime);
        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = baseline,
                MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                TsaUri = AuthorityAddress,
                FetchResponse = signatureResponder.FetchAsync,
                SigningCertificate = world.SignerCertificate
            },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData archived = await world.AddArchiveTimestampAsync(timestamped, TestContext.CancellationToken).ConfigureAwait(false);

        using var resources = new SignatureValidationResources();
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = archived }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp archiveTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp)[0];
        EmbeddedTimestamp contentTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ContentTimestamp)[0];

        ProofOfExistenceSet derived = await ExtractProofsAsync(facts, archiveTimestamp, resources, TestContext.CancellationToken).ConfigureAwait(false);
        ValidationObjectIdentity contentTimestampIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            contentTimestamp.Token.AsReadOnlyMemory(), ValidationObjectKind.TimestampToken, contentTimestamp.Identifier, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //(i) The archive time-stamp's extracted proof-of-existence set names the content-time-stamp token at the
        //archive instant.
        Assert.IsTrue(derived.ExistsAtOrBefore(contentTimestampIdentity, ArchiveTimestampTime),
            "Clause 5.5.3 step 3): the whole signedAttrs is concatenated verbatim into the archive time-stamp's message imprint, so the content-time-stamp signed attribute it carries gains a proof of existence at the archive time-stamp's generation time.");

        //(iii) The negative guard that makes the proof load-bearing on the fix. The token IS one of the signer's
        //signed attribute values, and the ats-hash-index-v3 never names it, so a hash-index-only filter — the
        //filter's state before this fix — would have denied it and lost the proof asserted in (i).
        IReadOnlyList<ReadOnlyMemory<byte>> signedAttributeValues = CmsSignedDataAugmentation.ReadSignedAttributeValues(archived, signerIndex: 0);
        bool amongSignedAttributes = false;
        for(int i = 0; i < signedAttributeValues.Count; ++i)
        {
            amongSignedAttributes |= signedAttributeValues[i].Span.SequenceEqual(contentTimestamp.Token.AsReadOnlySpan());
        }

        Assert.IsTrue(amongSignedAttributes, "Clause 5.2.8: the content-time-stamp token is one of the signer's signed attribute values, which is why step 3) of clause 5.5.3 binds it.");

        using ArchiveTimestampCoverage coverage = await ArchiveTimestampV3.StateCoverageAsync(
            new ArchiveTimestampCoverageContext { SignedData = archived, ArchiveTimestampToken = archiveTimestamp.Token },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ArchiveTimestampCoverageStatus.Stated, coverage.Status, "The archive time-stamp's coverage is stated from the wire bytes.");
        bool namedByHashIndex = false;
        for(int i = 0; i < coverage.ProtectedObjects!.UnsignedAttributeValues.Count; ++i)
        {
            namedByHashIndex |= string.Equals(
                coverage.ProtectedObjects.UnsignedAttributeValues[i].AttributeType, CAdESSignatureFacts.ContentTimestampAttributeOid, StringComparison.Ordinal);
        }

        Assert.IsFalse(namedByHashIndex,
            "Clause 5.5.2: the ats-hash-index-v3 indexes unsignedAttrs values only and never names the content-time-stamp signed attribute, so the proof in (i) rests on the signedAttrs coverage of clause 5.5.3 step 3), not on the index — a hash-index-only filter would deny the token.");
    }


    /// <summary>
    /// Runs the POE extraction building block of clause 5.6.2.3 over one time-stamp of a signature, through the
    /// shipped CAdES seam bundle and under the default signature elements constraints — the composition every
    /// admission assertion here is made against.
    /// </summary>
    /// <param name="facts">The extracted facts of the signature.</param>
    /// <param name="timestamp">The time-stamp the proofs are derived from.</param>
    /// <param name="resources">The caller's ledger, which owns the digests the returned identities reference and therefore outlives the returned set's use.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The derived set.</returns>
    private static async ValueTask<ProofOfExistenceSet> ExtractProofsAsync(
        SignatureFacts facts,
        EmbeddedTimestamp timestamp,
        SignatureValidationResources resources,
        CancellationToken cancellationToken)
    {
        var completer = new CertificateChainCompleter([]);
        var seams = new SignatureValidationSeams
        {
            Format = CAdESSignatureFacts.Seam,
            CompleteCertificateChain = completer.CompleteAsync,
            ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync
        };

        return await ProofOfExistenceExtraction.ExtractAsync(
            facts, timestamp, ArchiveTimestampTime, ProofOfExistenceSet.Empty, ReliableSha256(),
            SignatureElementsConstraints.None, seams, resources, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// States the coverage of a token attached in one of the clause A.1.5 attributes, after minting that token
    /// over the concatenation the test itself assembled.
    /// </summary>
    /// <param name="world">The world whose authority mints the token.</param>
    /// <param name="signature">The signature the attribute is attached to.</param>
    /// <param name="attributeOid">The attribute the token is carried in.</param>
    /// <param name="timestampedOctets">The octets the authority time-stamps.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The stated coverage, which the caller disposes, or <see langword="null"/> when nothing was stated.</returns>
    private static async ValueTask<SignedContentMemory?> StateCoverageOfAttachedTokenAsync(
        CoverageWorld world,
        CmsSignedData signature,
        string attributeOid,
        ReadOnlyMemory<byte> timestampedOctets,
        CancellationToken cancellationToken)
    {
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            world.Authority, [world.Authority], timestampedOctets, ArchiveTimestampTime, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        using CmsSignedData appended = AttachUnsignedAttribute(signature, attributeOid, token.AsReadOnlySpan());

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = appended }, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp validationDataTimestamp = facts.TimestampsOfClass(SignatureTimestampClass.ValidationDataTimestamp)[0];

        SignedContentMemory? covered = await CAdESSignatureFacts.StateTimestampCoverageAsync(
            new TimestampCoverageContext { Signature = facts, Timestamp = validationDataTimestamp }, BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);
        if(covered is not null)
        {
            using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
                validationDataTimestamp.Token, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            bool imprintHolds = await info.VerifyMessageImprintAsync(covered.AsReadOnlyMemory(), BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(imprintHolds, "The token an independent authority minted over the clause A.1.5 concatenation verifies against the octets the binding restates.");
        }

        return covered;
    }


    /// <summary>
    /// Attaches the two reference attributes of clauses A.1.1.1 and A.1.2.1 that clause A.1.5's tokens are
    /// computed over. Their internal syntax is irrelevant to the imprint, which takes the whole encoding, so
    /// each carries an empty <c>SEQUENCE OF</c> — the legal degenerate value of both types.
    /// </summary>
    /// <param name="signature">The signature to attach them to.</param>
    /// <returns>The signature carrying both attributes; the caller disposes it.</returns>
    private static CmsSignedData AttachReferenceAttributes(CmsSignedData signature)
    {
        using CmsAttribute certificateReferences = CmsAttribute.Create(
            CAdESSignatureFacts.CompleteCertificateReferencesAttributeOid, EmptySequence(), BaseMemoryPool.Shared);
        using CmsAttribute revocationReferences = CmsAttribute.Create(
            CAdESSignatureFacts.CompleteRevocationReferencesAttributeOid, EmptySequence(), BaseMemoryPool.Shared);

        return CmsSignedDataAugmentation.AppendUnsignedAttributes(
            signature, signerIndex: 0, [certificateReferences, revocationReferences], BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Assembles, with its own writer, what clause A.1.5 says one attribute contributes to the hash: the
    /// <c>attrType</c> field and the <c>attrValues</c> field, each with its own tag and length octets, and
    /// without the tag and length of the enclosing <c>Attribute</c> SEQUENCE.
    /// </summary>
    /// <param name="signature">The signature carrying the attribute.</param>
    /// <param name="attributeOid">The attribute type.</param>
    /// <returns>The contribution.</returns>
    /// <remarks>
    /// The concatenation rule is written here from the clause text; only the attribute's value is read out of
    /// the structure, so what is compared is the rule the computation under test applies and not a value the
    /// test and the computation happen to share.
    /// </remarks>
    private static byte[] AttributeContribution(CmsSignedData signature, string attributeOid)
    {
        IReadOnlyList<CmsUnsignedAttributeValueLocation> locations = CmsSignedDataAugmentation.LocateUnsignedAttributeValues(signature, signerIndex: 0);
        for(int i = 0; i < locations.Count; ++i)
        {
            if(!string.Equals(locations[i].AttributeType, attributeOid, StringComparison.Ordinal))
            {
                continue;
            }

            ReadOnlyMemory<byte> value = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
                signature, signerIndex: 0, locations[i].AttributeIndex, locations[i].ValueIndex);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteObjectIdentifier(attributeOid);
            using(writer.PushSetOf())
            {
                writer.WriteEncodedValue(value.Span);
            }

            return writer.Encode();
        }

        Assert.Fail($"The signature carries no unsigned attribute of type '{attributeOid}'.");

        return [];
    }


    /// <summary>An empty <c>SEQUENCE OF</c>, the degenerate value the reference attributes carry here.</summary>
    /// <returns>The DER encoding.</returns>
    private static byte[] EmptySequence()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
        }

        return writer.Encode();
    }


    /// <summary>
    /// Attaches one unsigned attribute carrying one value through the shipped byte-preserving splice.
    /// </summary>
    /// <param name="signature">The signature to attach it to.</param>
    /// <param name="attributeOid">The attribute type.</param>
    /// <param name="attributeValue">The single DER-encoded value.</param>
    /// <returns>The signature carrying the attribute; the caller disposes it.</returns>
    private static CmsSignedData AttachUnsignedAttribute(CmsSignedData signature, string attributeOid, ReadOnlySpan<byte> attributeValue)
    {
        using CmsAttribute attribute = CmsAttribute.Create(attributeOid, attributeValue, BaseMemoryPool.Shared);

        return CmsSignedDataAugmentation.AppendUnsignedAttributes(signature, signerIndex: 0, [attribute], BaseMemoryPool.Shared);
    }


    /// <summary>A cryptographic constraints table asserting SHA-256 reliable without expiry.</summary>
    /// <returns>The table.</returns>
    private static CryptographicConstraints ReliableSha256() => new()
    {
        Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null)]
    };


    /// <summary>
    /// The material every test here starts from: a Root CA and a Time-Stamping Authority under it, a signer
    /// whose key material comes from the repository's test-key creator, and the CAdES-B-T signature the shipped
    /// creation and augmentation surfaces produced with them.
    /// </summary>
    private sealed class CoverageWorld: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


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

        /// <summary>Gets the CAdES-B-T signature every coverage test augments or appends to.</summary>
        internal required CmsSignedData TimestampedSignature { get; init; }


        /// <summary>
        /// Builds the world: mints the ring and the signer, signs, and adds the signature time-stamp.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The world. The caller disposes it.</returns>
        internal static async ValueTask<CoverageWorld> CreateAsync(CancellationToken cancellationToken)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintSigner();
            CmsSignedData baseline = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            var responder = new MintingTimestampResponder(authority, [authority], SignatureTimestampTime);
            CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = AuthorityAddress,
                    FetchResponse = responder.FetchAsync,
                    SigningCertificate = certificate
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            return new CoverageWorld
            {
                Root = root,
                Authority = authority,
                SignerCertificate = certificate,
                SignerPrivateKey = privateKey,
                Baseline = baseline,
                TimestampedSignature = timestamped
            };
        }


        /// <summary>
        /// Adds an <c>archive-time-stamp-v3</c> through the shipped augmentation surface, so the attribute is
        /// the one clauses 5.5.2 and 5.5.3 define rather than a fixture shaped to suit the coverage computation.
        /// </summary>
        /// <param name="signature">The signature to raise.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The archive-time-stamped signature. The caller disposes it.</returns>
        internal async ValueTask<CmsSignedData> AddArchiveTimestampAsync(CmsSignedData signature, CancellationToken cancellationToken)
        {
            var responder = new MintingTimestampResponder(Authority, [Authority], ArchiveTimestampTime);

            return await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CAdESArchiveTimestampContext
                {
                    SignedData = signature,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = AuthorityAddress,
                    FetchResponse = responder.FetchAsync,
                    ValidationMaterial = CAdESValidationMaterial.None,
                    SigningCertificate = SignerCertificate
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);
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


        /// <summary>
        /// Copies a certificate's octets into the carrier kind the creation surface takes.
        /// </summary>
        /// <param name="der">The DER-encoded certificate.</param>
        /// <returns>The carrier; the caller disposes it.</returns>
        private static PkiCertificateMemory ToCertificateCarrier(ReadOnlySpan<byte> der)
        {
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(der.Length);
            try
            {
                der.CopyTo(owner.Memory.Span);

                return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
            }
            catch
            {
                owner.Dispose();

                throw;
            }
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            TimestampedSignature.Dispose();
            Baseline.Dispose();
            SignerPrivateKey.Dispose();
            SignerCertificate.Dispose();
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
