using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="EvidenceRecordCmsIntegration"/>: carrying an Evidence Record inside a CMS
/// object as the unsigned attribute of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#appendix-A">IETF RFC 4998 Appendix A</see>, and verifying
/// it against the reconstructed view of the object the record was actually computed over.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything here runs the shipped path.</strong> The signature is a CAdES-B-B minted by the W4 test
/// factory over an <see cref="X509ChainTestRing"/> leaf, the Evidence Record is minted by
/// <see cref="EvidenceRecords.CreateInitialAsync"/> against a Time-Stamping Authority that answers the request
/// octets that crossed the transport seam, the attachment is
/// <see cref="EvidenceRecordCmsIntegration.Attach"/> over the byte-preserving splice, and the verification is
/// <see cref="EvidenceRecordCmsIntegration.VerifyEmbeddedAsync"/>.
/// </para>
/// <para>
/// <strong>What judges the results is independent of them.</strong> The reconstructed views are re-derived by
/// <see cref="CmsStructureOracle.RemoveUnsignedAttributeValues"/>, which rebuilds the structure from its
/// surviving elements rather than splicing it, and every Evidence Record is decoded and its tree recomputed by
/// <see cref="EvidenceRecordOracle"/>, an independent from-spec-text implementation hashing through a different
/// digest implementation.
/// </para>
/// <para>
/// <strong>The chronology is a discovered fact, not an encoding one.</strong> The appendix says several Evidence
/// Records "have to be stored within the first signature in chronological order", which a conformant DER
/// producer cannot honour: <c>unsignedAttrs</c> is a <c>SET OF</c> and its canonical order is its members'
/// encodings. <see cref="TheChronologyIsDiscoveredEvenWhenTheSetHoldsTheRecordsInReverseOrder"/> states that
/// directly by re-ordering the attributes of a finished object, which is a re-ordering a canonicalising producer
/// is entitled to perform.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EvidenceRecordCmsIntegrationTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.evidencerecord.example.test/";

    /// <summary>The DNS name the signing leaf of the ring carries.</summary>
    private const string SignerDnsName = "signer.evidencerecord.example.test";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The claimed signing time every minted signature carries.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The <c>genTime</c> the first archive time-stamp of a test states.</summary>
    private static DateTimeOffset FirstArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The <c>genTime</c> a second, later archive time-stamp of a test states.</summary>
    private static DateTimeOffset SecondArchiveTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The algorithm every record in this class is built under.</summary>
    private static PkiDigestAlgorithm Algorithm { get; } = PkiDigestAlgorithm.Sha256;


    /// <summary>
    /// The mapping Appendix A leaves to structure: the identifier that carries each selection method, and back
    /// again. An identifier that is neither is not read as one.
    /// </summary>
    [TestMethod]
    public void EachSelectionMethodIsCarriedByItsOwnAttributeIdentifier()
    {
        Assert.AreEqual(
            EvidenceRecordWellKnown.InternalEvidenceRecordAttributeOid,
            EvidenceRecordCmsIntegration.SelectionMethodAttributeOid(EvidenceRecordCmsSelectionMethod.CmsObject));
        Assert.AreEqual(
            EvidenceRecordWellKnown.ExternalEvidenceRecordAttributeOid,
            EvidenceRecordCmsIntegration.SelectionMethodAttributeOid(EvidenceRecordCmsSelectionMethod.CmsObjectAndContent));

        Assert.AreEqual(
            EvidenceRecordCmsSelectionMethod.CmsObject,
            EvidenceRecordCmsIntegration.SelectionMethodOfAttribute(EvidenceRecordWellKnown.InternalEvidenceRecordAttributeOid));
        Assert.AreEqual(
            EvidenceRecordCmsSelectionMethod.CmsObjectAndContent,
            EvidenceRecordCmsIntegration.SelectionMethodOfAttribute(EvidenceRecordWellKnown.ExternalEvidenceRecordAttributeOid));
        Assert.AreEqual(
            EvidenceRecordCmsSelectionMethod.NotStated,
            EvidenceRecordCmsIntegration.SelectionMethodOfAttribute(CAdESSignatureFacts.CertificateValuesAttributeOid));

        _ = Assert.Throws<ArgumentOutOfRangeException>(() => EvidenceRecordCmsIntegration.SelectionMethodAttributeOid(EvidenceRecordCmsSelectionMethod.NotStated));
    }


    /// <summary>
    /// The first selection method end to end: an Evidence Record computed over a CAdES signature, carried inside
    /// that signature, verifies against the view of it with the attribute removed — and that view is the octets
    /// the signature had before the attachment, exactly.
    /// </summary>
    [TestMethod]
    public async Task ARecordCarriedByASignatureProvesTheViewWithoutIt()
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());
        byte[] signatureOctets = signature.AsReadOnlySpan().ToArray();

        using EvidenceRecordCreation creation = await CreateRecordAsync([signatureOctets], FirstArchiveTime).ConfigureAwait(false);
        using CmsSignedData carrying = EvidenceRecordCmsIntegration.Attach(
            signature, creation.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);

        IReadOnlyList<EvidenceRecordCmsPlacement> placements = EvidenceRecordCmsIntegration.LocateEvidenceRecords(carrying, signerIndex: 0);
        Assert.HasCount(1, placements);
        Assert.AreEqual(EvidenceRecordCmsSelectionMethod.CmsObject, placements[0].SelectionMethod);

        using(CmsSignedData view = EvidenceRecordCmsIntegration.BuildArchivedDataObject(carrying, signerIndex: 0, [], BaseMemoryPool.Shared))
        {
            Assert.AreSequenceEqual(signatureOctets, view.AsReadOnlySpan().ToArray(), "The view with the attribute removed is the signature as it stood before the attachment.");
            Assert.AreSequenceEqual(
                CmsStructureOracle.RemoveUnsignedAttributeValues(carrying.AsReadOnlySpan().ToArray(), signerIndex: 0, [0]),
                view.AsReadOnlySpan().ToArray(),
                "The independent rebuild reaches the same view.");
        }

        using(CmsSignedData whole = EvidenceRecordCmsIntegration.BuildArchivedDataObject(carrying, signerIndex: 0, placements, BaseMemoryPool.Shared))
        {
            Assert.AreSequenceEqual(
                carrying.AsReadOnlySpan().ToArray(),
                whole.AsReadOnlySpan().ToArray(),
                "Retaining every record returns the object's own octets — what a record supplied beside the object is verified against.");
        }

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(carrying, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, verification.Status);
        Assert.HasCount(1, verification.EvidenceRecords);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, verification.EvidenceRecords[0].Status);
        Assert.AreEqual(0, verification.EvidenceRecords[0].ChronologicalPosition);
        Assert.AreEqual(0, verification.EvidenceRecords[0].ProvedViewEvidenceRecordCount, "The record proves the view holding no Evidence Record.");
        Assert.AreEqual(FirstArchiveTime, verification.EvidenceRecords[0].Verification?.InitialArchiveTime);

        AssertTheIndependentWalkReachesTheTokensImprint(carrying, placements[0], signatureOctets);
    }


    /// <summary>
    /// The second selection method end to end: a detached signature and the content it signs are archived as one
    /// group, the record is carried under the identifier that names that selection, and the group check holds
    /// for the content the object actually signs and fails for any other.
    /// </summary>
    [TestMethod]
    public async Task ARecordUnderTheExternalIdentifierGroupsTheObjectWithItsDetachedContent()
    {
        byte[] content = [.. "the detached content the signature covers"u8];
        using CmsSignedData signature = SignBaselineDetached(content);
        byte[] signatureOctets = signature.AsReadOnlySpan().ToArray();

        using EvidenceRecordCreation creation = await CreateRecordAsync([signatureOctets, content], FirstArchiveTime).ConfigureAwait(false);
        using CmsSignedData carrying = EvidenceRecordCmsIntegration.Attach(
            signature, creation.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObjectAndContent, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);

        IReadOnlyList<EvidenceRecordCmsPlacement> placements = EvidenceRecordCmsIntegration.LocateEvidenceRecords(carrying, signerIndex: 0);
        Assert.HasCount(1, placements);
        Assert.AreEqual(EvidenceRecordCmsSelectionMethod.CmsObjectAndContent, placements[0].SelectionMethod);

        using(EvidenceRecordCmsVerification grouped = await VerifyEmbeddedAsync(carrying, new ReadOnlyMemory<byte>(content)).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, grouped.Status, "The first list holds the reconstructed object and the content, and nothing else.");
            Assert.AreEqual(0, grouped.EvidenceRecords[0].ProvedViewEvidenceRecordCount);
        }

        using(EvidenceRecordCmsVerification coverageOnly = await VerifyEmbeddedAsync(carrying, detachedContent: null).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, coverageOnly.Status, "Leaving the content out verifies coverage of the object alone.");
        }

        byte[] otherContent = [.. "content the signature does not cover"u8];
        using(EvidenceRecordCmsVerification wrongContent = await VerifyEmbeddedAsync(carrying, new ReadOnlyMemory<byte>(otherContent)).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordCmsVerificationStatus.EvidenceRecordNotVerified, wrongContent.Status);
            Assert.AreEqual(
                EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively,
                wrongContent.EvidenceRecords[0].Verification?.Status,
                "A group the record does not bind exactly is refused rather than reduced to coverage.");
        }

        //An empty stated content is a stated content: the group then holds an object the record never bound, and
        //the check fails closed rather than degrading to the coverage-only reading.
        using(EvidenceRecordCmsVerification emptyContent = await VerifyEmbeddedAsync(carrying, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false))
        {
            Assert.AreEqual(EvidenceRecordCmsVerificationStatus.EvidenceRecordNotVerified, emptyContent.Status);
            Assert.AreEqual(
                EvidenceRecordVerificationStatus.DataObjectGroupNotCoveredExclusively,
                emptyContent.EvidenceRecords[0].Verification?.Status);
        }
    }


    /// <summary>
    /// A record computed over some other object proves nothing where it is carried: the walk of clause 4.3 step
    /// 2 terminates because the reconstructed view's hash is not in the first list.
    /// </summary>
    [TestMethod]
    public async Task ARecordComputedOverAnotherObjectProvesNothingWhereItIsCarried()
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());
        using CmsSignedData otherSignature = SignBaseline("a different signature's content"u8.ToArray());

        using EvidenceRecordCreation creation = await CreateRecordAsync([otherSignature.AsReadOnlySpan().ToArray()], FirstArchiveTime).ConfigureAwait(false);
        using CmsSignedData carrying = EvidenceRecordCmsIntegration.Attach(
            signature, creation.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(carrying, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.EvidenceRecordNotVerified, verification.Status);
        Assert.AreEqual(-1, verification.EvidenceRecords[0].ChronologicalPosition, "A record that proves no view has no position in the chronology.");
        Assert.AreEqual(-1, verification.EvidenceRecords[0].ProvedViewEvidenceRecordCount);
        Assert.AreEqual(
            EvidenceRecordVerificationStatus.DataObjectNotCovered,
            verification.EvidenceRecords[0].Verification?.Status,
            "The reason reported is the one from the view Appendix A names first.");
    }


    /// <summary>
    /// Changing one octet of the signed data after the record was attached leaves the record proving nothing:
    /// the reconstructed view is no longer the object the record was computed over.
    /// </summary>
    [TestMethod]
    public async Task TamperingTheSignedDataAfterAttachmentLeavesTheRecordProvingNothing()
    {
        byte[] marker = [.. "the archived signature's content"u8];
        using CmsSignedData signature = SignBaseline(marker);

        using EvidenceRecordCreation creation = await CreateRecordAsync([signature.AsReadOnlySpan().ToArray()], FirstArchiveTime).ConfigureAwait(false);
        using CmsSignedData carrying = EvidenceRecordCmsIntegration.Attach(
            signature, creation.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);

        //The flip lands inside the encapsulated content, which keeps every length octet of the structure the
        //same and so leaves the walk that finds the attribute intact.
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(carrying, marker);
        int carryingOctetCount = carrying.AsReadOnlySpan().Length;
        int tamperedOctetCount = tampered.AsReadOnlySpan().Length;
        Assert.AreEqual(carryingOctetCount, tamperedOctetCount, "The tamper changes an octet without changing any length.");

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(tampered, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.EvidenceRecordNotVerified, verification.Status);
        Assert.AreEqual(EvidenceRecordVerificationStatus.DataObjectNotCovered, verification.EvidenceRecords[0].Verification?.Status);
    }


    /// <summary>
    /// An object whose enclosing container was re-encoded with a length written in more octets than it needs is
    /// refused rather than verified against a guessed reconstruction: Appendix A permits adapting the length of
    /// fields containing tags and nothing else, so the coding that stood before the attachment is not
    /// recoverable and the verifier says so instead of choosing one.
    /// </summary>
    [TestMethod]
    public async Task ARecordCarriedByAReEncodedObjectIsRefusedRatherThanGuessedAt()
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());

        using EvidenceRecordCreation creation = await CreateRecordAsync([signature.AsReadOnlySpan().ToArray()], FirstArchiveTime).ConfigureAwait(false);
        using CmsSignedData carrying = EvidenceRecordCmsIntegration.Attach(
            signature, creation.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);

        using CmsSignedData reEncoded = CmsSignedData.FromBytes(WidenTheOuterLength(carrying.AsReadOnlySpan().ToArray()), BaseMemoryPool.Shared);

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(reEncoded, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.SignedDataMalformed, verification.Status);
        Assert.IsEmpty(verification.EvidenceRecords);
    }


    /// <summary>
    /// The <c>SHOULD</c> of Appendix A — "The attributes SHOULD only occur once" — is the conformant default and
    /// the departure is a choice the caller states, which is the SHOULD/deviation-knob convention the wave
    /// applies to every such statement.
    /// </summary>
    [TestMethod]
    public async Task ASecondRecordIsRefusedUnlessTheCallerStatesTheDeparture()
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());
        using EvidenceRecordCreation first = await CreateRecordAsync([signature.AsReadOnlySpan().ToArray()], FirstArchiveTime).ConfigureAwait(false);
        using CmsSignedData carrying = EvidenceRecordCmsIntegration.Attach(
            signature, first.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);

        using EvidenceRecordCreation second = await CreateRecordAsync([carrying.AsReadOnlySpan().ToArray()], SecondArchiveTime).ConfigureAwait(false);

        EvidenceRecordCreationException refused = Assert.Throws<EvidenceRecordCreationException>(() => EvidenceRecordCmsIntegration.Attach(
            carrying, second.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared));
        Assert.AreEqual(EvidenceRecordCreationFailureKind.EvidenceRecordAlreadyAttached, refused.FailureKind);

        using CmsSignedData carryingBoth = EvidenceRecordCmsIntegration.Attach(
            carrying, second.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.ChronologicalSequence, BaseMemoryPool.Shared);
        Assert.HasCount(2, EvidenceRecordCmsIntegration.LocateEvidenceRecords(carryingBoth, signerIndex: 0));
    }


    /// <summary>
    /// Two nested records verify: the earlier one proves the object with neither record in it, the later one
    /// proves the object holding the earlier one. Both positions are reported, and the wider view's record is
    /// the one whose time-stamp is later.
    /// </summary>
    [TestMethod]
    public async Task NestedRecordsProveTheViewsTheAppendixDescribes()
    {
        using CmsSignedData carryingBoth = await AttachTwoNestedRecordsAsync(FirstArchiveTime, SecondArchiveTime).ConfigureAwait(false);

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(carryingBoth, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, verification.Status);
        Assert.HasCount(2, verification.EvidenceRecords);

        EvidenceRecordCmsRecordVerification earliest = FindByProvedViewCount(verification, 0);
        EvidenceRecordCmsRecordVerification later = FindByProvedViewCount(verification, 1);
        Assert.AreEqual(0, earliest.ChronologicalPosition);
        Assert.AreEqual(1, later.ChronologicalPosition);
        Assert.AreEqual(FirstArchiveTime, earliest.Verification?.InitialArchiveTime);
        Assert.AreEqual(SecondArchiveTime, later.Verification?.InitialArchiveTime, "The record proving the wider view is the one taken later.");
    }


    /// <summary>
    /// The decisive statement of the ruling this stage settled: the chronology is discovered from the views the
    /// records prove, never read off the order the attributes sit in. Re-ordering the two attributes of a
    /// finished object — which is exactly what a producer canonicalising the <c>SET OF</c> is entitled to do,
    /// and what third-party objects carrying two records under one identifier actually exhibit — changes nothing
    /// about what the verifier concludes.
    /// </summary>
    [TestMethod]
    public async Task TheChronologyIsDiscoveredEvenWhenTheSetHoldsTheRecordsInReverseOrder()
    {
        using CmsSignedData carryingBoth = await AttachTwoNestedRecordsAsync(FirstArchiveTime, SecondArchiveTime).ConfigureAwait(false);

        using CmsSignedData reordered = CmsSignedData.FromBytes(SwapTheLastTwoUnsignedAttributes(carryingBoth.AsReadOnlySpan().ToArray()), BaseMemoryPool.Shared);
        int carryingOctetCount = carryingBoth.AsReadOnlySpan().Length;
        int reorderedOctetCount = reordered.AsReadOnlySpan().Length;
        Assert.AreEqual(carryingOctetCount, reorderedOctetCount, "Swapping two members of a SET OF changes no length.");
        Assert.IsFalse(reordered.AsReadOnlySpan().SequenceEqual(carryingBoth.AsReadOnlySpan()), "The two orders really are different octets.");

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(reordered, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, verification.Status);

        EvidenceRecordCmsRecordVerification earliest = FindByProvedViewCount(verification, 0);
        EvidenceRecordCmsRecordVerification later = FindByProvedViewCount(verification, 1);
        Assert.AreEqual(FirstArchiveTime, earliest.Verification?.InitialArchiveTime);
        Assert.AreEqual(SecondArchiveTime, later.Verification?.InitialArchiveTime);
        Assert.AreEqual(
            1,
            verification.EvidenceRecords[0].ChronologicalPosition,
            "The record encoded first is now the later one, and its discovered position says so rather than its place in the set.");
    }


    /// <summary>
    /// Two records may prove the same view. Appendix A describes a nested chain and third-party objects carry
    /// parallel records instead, so a verifier that insisted on a strict chain would refuse a legitimate object.
    /// </summary>
    [TestMethod]
    public async Task TwoRecordsProvingTheSameViewAreBothAccepted()
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());
        byte[] signatureOctets = signature.AsReadOnlySpan().ToArray();

        using EvidenceRecordCreation first = await CreateRecordAsync([signatureOctets], FirstArchiveTime).ConfigureAwait(false);
        using EvidenceRecordCreation second = await CreateRecordAsync([signatureOctets], SecondArchiveTime).ConfigureAwait(false);

        using CmsSignedData carryingFirst = EvidenceRecordCmsIntegration.Attach(
            signature, first.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);
        using CmsSignedData carryingBoth = EvidenceRecordCmsIntegration.Attach(
            carryingFirst, second.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.ChronologicalSequence, BaseMemoryPool.Shared);

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(carryingBoth, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.Verified, verification.Status);
        Assert.HasCount(2, verification.EvidenceRecords);
        Assert.AreEqual(0, verification.EvidenceRecords[0].ChronologicalPosition);
        Assert.AreEqual(0, verification.EvidenceRecords[1].ChronologicalPosition, "Both records prove the view holding neither of them.");
        Assert.AreEqual(0, verification.EvidenceRecords[0].ProvedViewEvidenceRecordCount);
        Assert.AreEqual(0, verification.EvidenceRecords[1].ProvedViewEvidenceRecordCount);
    }


    /// <summary>
    /// Appendix A's own consistency requirement: "The verification of the nth one EvidenceRecord must result in
    /// a point of time when the document must have existed with the first n attributes. The verification of the
    /// n+1th attribute must prove that this requirement has been met." A record proving the object with another
    /// record already in it cannot assert an instant before that record's own.
    /// </summary>
    [TestMethod]
    public async Task ARecordProvingAWiderViewMayNotAssertAnEarlierInstant()
    {
        using CmsSignedData carryingBoth = await AttachTwoNestedRecordsAsync(SecondArchiveTime, FirstArchiveTime).ConfigureAwait(false);

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(carryingBoth, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.ChronologyBroken, verification.Status);
        Assert.AreEqual(
            EvidenceRecordCmsVerificationStatus.Verified,
            verification.EvidenceRecords[0].Status,
            "Each record proves a view the object genuinely had; what fails is the two of them together.");
    }


    /// <summary>
    /// An attribute value that is not an Evidence Record is a conclusion about attacker-supplied octets, not an
    /// exception escaping the seam, and it is never retained in a reconstructed view — so nothing else the
    /// object carries is verified against a view that quietly dropped it.
    /// </summary>
    [TestMethod]
    public async Task AnAttributeValueThatIsNotAnEvidenceRecordIsReportedRatherThanThrown()
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());

        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString("not an Evidence Record"u8);
        using CmsAttribute bogus = CmsAttribute.Create(EvidenceRecordWellKnown.InternalEvidenceRecordAttributeOid, writer.Encode(), BaseMemoryPool.Shared);
        using CmsSignedData carrying = CmsSignedDataAugmentation.AppendUnsignedAttributes(signature, signerIndex: 0, [bogus], BaseMemoryPool.Shared);

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(carrying, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.EvidenceRecordMalformed, verification.Status);
        Assert.HasCount(1, verification.EvidenceRecords);
        Assert.IsNull(verification.EvidenceRecords[0].Verification, "Nothing was concluded about a value that could not be read.");
    }


    /// <summary>
    /// An object carrying no Evidence Record attribute is the case the appendix describes as the record having
    /// "been provided externally": there is nothing embedded to verify, and the archived data object is the
    /// complete object within its existing coding.
    /// </summary>
    [TestMethod]
    public async Task AnObjectCarryingNoRecordHasNothingEmbeddedToVerify()
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());

        Assert.IsEmpty(EvidenceRecordCmsIntegration.LocateEvidenceRecords(signature, signerIndex: 0));

        using(CmsSignedData view = EvidenceRecordCmsIntegration.BuildArchivedDataObject(signature, signerIndex: 0, [], BaseMemoryPool.Shared))
        {
            Assert.AreSequenceEqual(signature.AsReadOnlySpan().ToArray(), view.AsReadOnlySpan().ToArray());
        }

        using EvidenceRecordCmsVerification verification = await VerifyEmbeddedAsync(signature, detachedContent: null).ConfigureAwait(false);
        Assert.AreEqual(EvidenceRecordCmsVerificationStatus.NoEvidenceRecord, verification.Status);
        Assert.IsEmpty(verification.EvidenceRecords);
    }


    /// <summary>
    /// Signs content as a CAdES-B-B signature over a ring leaf, through the shipped W4 test factory.
    /// </summary>
    /// <param name="content">The content the signature encapsulates and covers.</param>
    /// <returns>The signature carrier. The caller disposes it.</returns>
    private static CmsSignedData SignBaseline(byte[] content)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        return CAdESSignatureTestFactory.SignBaseline(content, signer, SigningTime);
    }


    /// <summary>
    /// Signs content as a detached CAdES-B-B signature over a ring leaf, so the content is a data object beside
    /// the CMS object rather than inside it.
    /// </summary>
    /// <param name="content">The content the signature covers without carrying it.</param>
    /// <returns>The signature carrier. The caller disposes it.</returns>
    private static CmsSignedData SignBaselineDetached(byte[] content)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: NotBefore, notAfter: NotAfter);

        return CAdESSignatureTestFactory.SignBaselineDetached(content, signer, SigningTime);
    }


    /// <summary>
    /// Creates one Evidence Record over one data object group through the shipped surface, against a
    /// Time-Stamping Authority that mints a genuine token over whatever imprint the request states.
    /// </summary>
    /// <param name="dataObjects">The data objects of the single group the record covers.</param>
    /// <param name="archiveTime">The <c>genTime</c> the acquired token asserts.</param>
    /// <returns>The creation result. The caller disposes it.</returns>
    private async ValueTask<EvidenceRecordCreation> CreateRecordAsync(IReadOnlyList<byte[]> dataObjects, DateTimeOffset archiveTime)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        var responder = new MintingTimestampResponder(authority, [authority, root], archiveTime);

        var group = new List<ReadOnlyMemory<byte>>(dataObjects.Count);
        for(int i = 0; i < dataObjects.Count; ++i)
        {
            group.Add(new ReadOnlyMemory<byte>(dataObjects[i]));
        }

        return await EvidenceRecords.CreateInitialAsync(
            new EvidenceRecordCreationContext
            {
                DataObjectGroups = [new EvidenceRecordDataObjectGroup { DataObjects = group }],
                DigestAlgorithm = Algorithm,
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the nested two-record object the appendix describes: a record over the bare signature is attached,
    /// then a record over the object that attachment produced is attached beside it.
    /// </summary>
    /// <param name="firstArchiveTime">The <c>genTime</c> the first record's token asserts.</param>
    /// <param name="secondArchiveTime">The <c>genTime</c> the second record's token asserts.</param>
    /// <returns>The object carrying both records. The caller disposes it.</returns>
    private async ValueTask<CmsSignedData> AttachTwoNestedRecordsAsync(DateTimeOffset firstArchiveTime, DateTimeOffset secondArchiveTime)
    {
        using CmsSignedData signature = SignBaseline("the archived signature's content"u8.ToArray());
        using EvidenceRecordCreation first = await CreateRecordAsync([signature.AsReadOnlySpan().ToArray()], firstArchiveTime).ConfigureAwait(false);
        using CmsSignedData carryingFirst = EvidenceRecordCmsIntegration.Attach(
            signature, first.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.SingleOccurrence, BaseMemoryPool.Shared);

        using EvidenceRecordCreation second = await CreateRecordAsync([carryingFirst.AsReadOnlySpan().ToArray()], secondArchiveTime).ConfigureAwait(false);

        return EvidenceRecordCmsIntegration.Attach(
            carryingFirst, second.EvidenceRecords[0], EvidenceRecordCmsSelectionMethod.CmsObject, EvidenceRecordCmsAttachmentPolicy.ChronologicalSequence, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Verifies every Evidence Record an object carries through the shipped surface.
    /// </summary>
    /// <param name="signedData">The object.</param>
    /// <param name="detachedContent">The detached content the object signs, or <see langword="null"/> to skip the group check.</param>
    /// <returns>The conclusion. The caller disposes it.</returns>
    /// <remarks>
    /// The parameter is the nullable memory itself rather than an array the helper wraps, deliberately.
    /// <c>ReadOnlyMemory&lt;byte&gt;</c> converts implicitly from an array, so a <c>null</c> literal in a
    /// conditional expression whose other branch is an array converts through that operator to an EMPTY memory
    /// rather than to no memory at all — which would state a detached content of zero octets and turn "skip the
    /// group check" into "check the group against a member the record never bound".
    /// </remarks>
    private async ValueTask<EvidenceRecordCmsVerification> VerifyEmbeddedAsync(CmsSignedData signedData, ReadOnlyMemory<byte>? detachedContent)
    {
        return await EvidenceRecordCmsIntegration.VerifyEmbeddedAsync(
            new EvidenceRecordCmsVerificationContext
            {
                SignedData = signedData,
                SignerIndex = 0,
                DetachedContent = detachedContent
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Decodes the Evidence Record an object carries with the independent oracle, walks its reduced hash tree
    /// from the hash of the reconstructed view, and states that the walk reaches what the embedded time-stamp
    /// token's message imprint binds.
    /// </summary>
    /// <param name="carrying">The object carrying the record.</param>
    /// <param name="placement">Where the record sits.</param>
    /// <param name="reconstructedView">The octets of the view the record was computed over.</param>
    private static void AssertTheIndependentWalkReachesTheTokensImprint(
        CmsSignedData carrying,
        EvidenceRecordCmsPlacement placement,
        byte[] reconstructedView)
    {
        byte[] encoded = CmsSignedDataAugmentation.ReadUnsignedAttributeValue(
            carrying, signerIndex: 0, placement.Location.AttributeIndex, placement.Location.ValueIndex).ToArray();

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(encoded);
        Assert.AreEqual(1, parsed.Version);
        Assert.HasCount(1, parsed.Chains);

        OracleArchiveTimeStamp archiveTimeStamp = parsed.Chains[0][0];
        byte[] viewHash = EvidenceRecordOracle.Hash(reconstructedView, Algorithm);
        byte[]? recomputed = EvidenceRecordOracle.RecomputeRoot(viewHash, archiveTimeStamp.ReducedHashtree, Algorithm);

        Assert.IsNotNull(recomputed, "The independent walk reaches a root from the record's own reduced hash tree.");
        Assert.AreSequenceEqual(
            archiveTimeStamp.MessageImprint,
            recomputed,
            "What the embedded token binds is the root the independent walk reaches from the reconstructed view.");
    }


    /// <summary>
    /// The one conclusion of a verification whose proved view holds the stated number of Evidence Records.
    /// </summary>
    /// <param name="verification">The verification.</param>
    /// <param name="provedViewEvidenceRecordCount">The number of Evidence Records the proved view holds.</param>
    /// <returns>The conclusion.</returns>
    private static EvidenceRecordCmsRecordVerification FindByProvedViewCount(EvidenceRecordCmsVerification verification, int provedViewEvidenceRecordCount)
    {
        EvidenceRecordCmsRecordVerification? found = null;
        for(int i = 0; i < verification.EvidenceRecords.Count; ++i)
        {
            if(verification.EvidenceRecords[i].ProvedViewEvidenceRecordCount == provedViewEvidenceRecordCount)
            {
                Assert.IsNull(found, "Exactly one record proves a view of this width.");
                found = verification.EvidenceRecords[i];
            }
        }

        Assert.IsNotNull(found, $"A record proving a view holding {provedViewEvidenceRecordCount} Evidence Records was expected.");

        return found;
    }


    /// <summary>
    /// Swaps the last two <c>Attribute</c> structures of a signer's <c>unsignedAttrs</c> set, which is a
    /// re-ordering of a <c>SET OF</c> and therefore changes no length octet anywhere in the structure — the
    /// change a producer canonicalising the set performs.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <returns>The same structure with the two attributes exchanged.</returns>
    private static byte[] SwapTheLastTwoUnsignedAttributes(byte[] signedData)
    {
        List<CmsTlvBounds> attributes = CmsStructureOracle.UnsignedAttributes(signedData, signerIndex: 0);
        Assert.IsGreaterThanOrEqualTo(2, attributes.Count, "The swap needs two attributes to exchange.");

        CmsTlvBounds first = attributes[^2];
        CmsTlvBounds second = attributes[^1];
        Assert.AreEqual(first.End, second.Start, "The two attributes are adjacent in the set's content.");

        var swapped = new List<byte>(signedData.Length);
        swapped.AddRange(signedData[..first.Start]);
        swapped.AddRange(signedData[second.Start..second.End]);
        swapped.AddRange(signedData[first.Start..first.End]);
        swapped.AddRange(signedData[second.End..]);

        return [.. swapped];
    }


    /// <summary>
    /// Widens the outer <c>ContentInfo</c>'s definite length by one octet without changing what it states, which
    /// is a legal BER encoding of the same value and a non-minimal one under DER — the shape a re-encoded
    /// ancestor arrives in.
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
}
