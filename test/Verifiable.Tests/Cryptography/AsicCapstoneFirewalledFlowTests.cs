using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Tsp;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcCmsException = Org.BouncyCastle.Cms.CmsException;
using BcCmsProcessableByteArray = Org.BouncyCastle.Cms.CmsProcessableByteArray;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcSignerInformation = Org.BouncyCastle.Cms.SignerInformation;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;
using PkiAlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The firewalled capstone for Associated Signature Containers of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> and Evidence Records of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see>: an archiving party mints data
/// objects, wraps them in an ASiC-E container with a detached CAdES signature, raises that signature to B-LTA,
/// starts and renews the container-level long-term chain of Annex A.7, attaches an Evidence Record, renews it
/// once by Timestamp Renewal and once by Hash-Tree Renewal into a stronger algorithm — all through the shipped
/// surfaces — and emits nothing but the container's own octets and public instants. A verifying party that
/// never saw any of the archiving party's objects reconstructs everything from those octets and reaches
/// <c>TOTAL-PASSED</c> through the validation process of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> clause 5.6, with the proofs of existence coming from the Evidence Record's
/// chains and from the Annex A.7 archive chain.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The firewall.</strong> <see cref="MintCapstoneWorldAsync"/> builds the Root certification authority,
/// the Time-Stamping Authority and the signer entirely inside a local scope, performs the whole archiving flow
/// over that material, copies out the container's octets, the trust anchor's octets and the public instants
/// into an <see cref="AsicCapstoneWireMessage"/>, and disposes every certificate, key and carrier before
/// returning. The verifying party (<see cref="ReconstructedAsicVerifyingParty"/>) rents its own carriers from
/// its own pool and reads them out of the received container alone — an assertion that passes here cannot be
/// passing because the two sides share an object.
/// </para>
/// <para>
/// <strong>Leg 3 — "Verifiable creates → independent oracle verifies."</strong>
/// <see cref="MintCapstoneWorldAsync"/> checks its own output, before the firewall closes, against readers that
/// share no code with the creation, augmentation or Evidence Record surfaces: the raw-octet
/// <see cref="AsicZipStructureOracle"/> for the archive itself, the independent BouncyCastle CMS reader for the
/// detached CAdES object, the independent BouncyCastle Time-Stamp Protocol validator for every token, and the
/// from-spec-text <see cref="EvidenceRecordOracle"/> for every link of the Evidence Record's two chains.
/// </para>
/// <para>
/// <strong>Why the Evidence Record protects the CAdES object too.</strong>
/// <see cref="AsicContainerValidation"/> feeds a container's own Evidence Record into the per-signature EN 319
/// 102-1 run only when the record's <c>ASiCEvidenceRecordManifest</c> names the signature entry among its
/// targets. The record here therefore covers the two data files AND
/// <c>META-INF/signature1.p7s</c>, which is what makes step 1) of clause 5.6.3.4 reachable through the shipped
/// container path rather than through a hand-assembled engine input.
/// </para>
/// <para>
/// <strong>The order of operations is Annex A.7's own.</strong> Every signature reaches the level it is to be
/// preserved at first (item 1 a), the archive chain is started over the container afterwards, and the Evidence
/// Record is attached last — so no archive manifest ever states a digest for an object a later step rewrites,
/// which is exactly what lets the record be renewed twice without breaking anything already committed to.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicCapstoneFirewalledFlowTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.asic-capstone.example.test/";

    /// <summary>The DNS name the signer's leaf certificate carries.</summary>
    private const string SignerDnsName = "asic-capstone-signer.example.test";

    /// <summary>The first data object the container carries and every protective object covers.</summary>
    private static byte[] FirstDataObject { get; } = [.. "the first archived data object of the capstone"u8];

    /// <summary>The second data object the container carries and every protective object covers.</summary>
    private static byte[] SecondDataObject { get; } = [.. "the second archived data object of the capstone"u8];

    /// <summary>The entry names the two data objects are carried under.</summary>
    private static string[] DataObjectEntryNames { get; } = ["first.txt", "records/second.bin"];

    /// <summary>The algorithm the container's manifests, its signature and the Evidence Record's first chain use.</summary>
    private static PkiDigestAlgorithm InitialAlgorithm { get; } = PkiDigestAlgorithm.Sha256;

    /// <summary>The algorithm the Evidence Record's Hash-Tree Renewal moves to, which is the point of that procedure.</summary>
    private static PkiDigestAlgorithm RenewalAlgorithm { get; } = PkiDigestAlgorithm.Sha512;


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The capstone: the container's wire octets alone carry a verifying party to
    /// <c>AsicContainerValidationStatus.Valid</c>, the detached CAdES object inside it to <c>TOTAL-PASSED</c>
    /// through the process for Signatures providing Long Term Availability and Integrity of Validation Material
    /// of clause 5.6, and the protected-objects report to a proof of existence for every file object — from the
    /// Evidence Record for the objects its manifest names, and from the Annex A.7 archive chain for the objects
    /// the archive manifest names.
    /// </summary>
    [TestMethod]
    public async Task FirewalledCapstoneReachesTotalPassedFromContainerBytesAloneWithProofsFromTheRecordAndTheArchiveChain()
    {
        AsicCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using ReconstructedAsicVerifyingParty verifier = await ReconstructedAsicVerifyingParty.CreateAsync(
            message, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            verifier.ValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Status,
            $"Clause 4.4.4.2: the container the archiving party wrote validates from its own octets ({result.FailureReason}).");
        Assert.AreEqual(AsicContainerShape.Extended, result.Facts!.Shape, "Clause 4.4.4.1 item 2: the media type states the shape.");
        Assert.AreEqual(AsicContainerProfile.ExtendedGeneral, result.Facts.Profile,
            "Clause 4.4.4.2 NOTE 1: a container carrying both a CAdES object and an Evidence Record conforms to no single EN 319 162-2 profile, and that is a fact a validator states rather than an error.");
        Assert.IsTrue(result.Facts.MediaTypeReadableAtOffset38, "Annex A.1 NOTE: the media type is where an operating system sniffs for it.");

        //=== The detached CAdES object, validated by the engine with the container's own Evidence Record as an
        //input to step 1) of clause 5.6.3.4. ===
        AsicSignatureValidation signature = result.Signatures.Single();
        Assert.AreEqual(AsicContainerValidationStatus.Valid, signature.Status, $"The CAdES object validates ({signature.FailureReason}).");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, signature.Outcome!.Conclusion.Indication,
            "Clause 4.4.4.2 item a): the referenced CAdES signature is validated against the ASiCManifest file content, and reaches TOTAL-PASSED.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermAvailability, signature.Outcome.Conclusion.ProcessIdentifier,
            "The conclusion states the process that produced it, which is the one of clause 5.6.3.");

        LongTermValidationResult longTerm = signature.Outcome.LongTermValidation!;
        EvidenceRecordValidationResult record = longTerm.EvidenceRecordValidations.Single();
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, record.Status,
            "Step 1) of clause 5.6.3.4: the container's Evidence Record verifies per RFC 4998 over the CAdES object it names as a target.");
        Assert.IsTrue(record.EstablishedProofOfExistence, "A record that verified and whose most recent Archive Timestamp validated establishes proofs of existence.");
        Assert.AreEqual(message.EvidenceRecordInitialArchiveTime, record.InitialArchiveTime,
            "RFC 4998 clause 4.3: the instant a record proves its objects existed at is its INITIAL Archive Timestamp's genTime, not the latest renewal's.");
        Assert.AreEqual(message.EvidenceRecordHashTreeRenewalTime, record.LatestArchiveTime,
            "The most recent Archive Timestamp is the Hash-Tree Renewal's, which is the one clause 5.3 requires valid at the time the verification is performed.");
        Assert.IsNotNull(record.ArchiveTimestampValidation, "Step 1) validates that most recent Archive Timestamp through the building block of clause 5.4.");
        Assert.AreEqual(BuildingBlockIndication.Passed, record.ArchiveTimestampValidation!.Conclusion.Indication,
            "The renewal token's own validation is what carries the record's proofs into the present.");
        Assert.IsTrue(longTerm.HasLongTermAvailabilityAttributes,
            "EN 319 162-1 clause 4.4.5 item 2 offers an Evidence Record as the alternative to a time-stamp chain, so it IS long-term availability material.");

        //=== What the container itself says it protects, and since when. ===
        List<AsicProtectedObject> protectedObjects = [.. result.ProtectedObjects];
        foreach(string dataObject in DataObjectEntryNames)
        {
            AsicProtectedObject byRecord = protectedObjects.Single(o => o.EntryName == dataObject && o.ProtectedBy == AsicProtectionKind.EvidenceRecord);
            Assert.AreEqual(message.EvidenceRecordInitialArchiveTime, byRecord.ProvenAt,
                "The Evidence Record proves its targets existed at its initial Archive Timestamp's instant.");

            List<DateTimeOffset?> byArchiveChain = [.. protectedObjects
                .Where(o => o.EntryName == dataObject && o.ProtectedBy == AsicProtectionKind.ArchiveTimeAssertion)
                .Select(o => o.ProvenAt)];
            Assert.HasCount(2, byArchiveChain,
                "Annex A.7 item 1 c b) and item 2 b) iii): every link of the chain references every file object the container carried when that link was added, so a data file is proved by both links.");
            Assert.Contains((DateTimeOffset?)message.ContainerArchiveTimestampTime, byArchiveChain,
                "The first link proves the data file existed at the instant its own token asserts.");
            Assert.Contains((DateTimeOffset?)message.ContainerArchiveRenewalTime, byArchiveChain,
                "And the renewal's token proves it again at the later instant, which is what a renewed chain is for.");
        }

        AsicEvidenceRecordValidation containerRecord = result.EvidenceRecords.Single();
        Assert.AreEqual(AsicEvidenceRecordForm.Binary, containerRecord.Form, "Clause 4.4.4.2 item 4 a): a '.ers' entry is the RFC 4998 form.");
        Assert.AreEqual(AsicContainerValidationStatus.Valid, containerRecord.Status, $"The record proves everything the container states it protects ({containerRecord.FailureReason}).");
        Assert.Contains(message.SignatureEntryName, containerRecord.ProtectedEntryNames.ToList(),
            "The record's manifest names the CAdES object among its targets, which is what put the record into the engine's own inputs above.");
        Assert.DoesNotContain(message.EvidenceRecordManifestEntryName, containerRecord.ProtectedEntryNames.ToList(),
            "Clause 4.4.4.2 NOTE 2: the manifest referencing an Evidence Record is not itself covered by that record.");

        //=== The Annex A.7 chain, walked from the container's octets. ===
        Assert.HasCount(2, result.ArchiveManifestChain, "One addition and one renewal leave two links.");
        Assert.AreEqual(AsicManifestNaming.FixedArchiveManifestEntryName, result.ArchiveManifestChain[0].EntryName,
            "Annex A.7 item 2 a): the newest link always carries the fixed name.");
        Assert.AreEqual(result.ArchiveManifestChain[1].EntryName, result.ArchiveManifestChain[0].PreviousEntryName,
            "Annex A.7 item 2 b) iv): the Rootfile reference of a link names the manifest renamed out of the fixed name.");
        Assert.IsNull(result.ArchiveManifestChain[1].PreviousEntryName, "The first link ever added points back at nothing.");

        foreach(AsicArchiveManifestChainLink link in result.ArchiveManifestChain)
        {
            AsicTimeAssertionValidation token = result.TimeAssertions.Single(t => t.EntryName == link.TimestampEntryName);
            Assert.AreEqual(AsicContainerValidationStatus.Valid, token.Status, $"The token of '{link.EntryName}' still binds it ({token.FailureReason}).");
            Assert.AreEqual(link.EntryName, token.ProtectedEntryName, "A chain link's token is applied to that link's own octets.");
        }
    }


    /// <summary>
    /// The preservation property of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">RFC 4998 clause 5.2</see>, stated from the
    /// wire octets alone: after both renewals the record still carries every chain it ever had, each covering
    /// every data object it ever covered, and each chain resolving to the algorithm it was built under. A
    /// renewal that re-encoded any prior Archive Timestamp would break exactly this.
    /// </summary>
    [TestMethod]
    public async Task EveryPriorChainOfTheRenewedRecordStillVerifiesFromTheContainerBytesAlone()
    {
        AsicCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using AsicZipReadResult read = AsicZipReading.Read(message.Container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsTrue(read.IsRead, $"The received octets have to be a container the reader accepts ({read.Status}).");

        AsicZipEntry recordEntry = read.Container!.FindEntry(message.EvidenceRecordEntryName)!;
        using EvidenceRecord received = EvidenceRecord.Read(recordEntry.Content.AsReadOnlySpan(), BaseMemoryPool.Shared);
        Assert.HasCount(2, received.ArchiveTimeStampSequence.Chains, "The Hash-Tree Renewal started a second chain; the Timestamp Renewal appended to the first.");
        Assert.HasCount(2, received.ArchiveTimeStampSequence.Chains[0].ArchiveTimeStamps, "The initial Archive Timestamp and the Timestamp Renewal share one chain.");
        Assert.HasCount(1, received.ArchiveTimeStampSequence.Chains[1].ArchiveTimeStamps, "Clause 5.2 step 6: the Hash-Tree Renewal's Archive Timestamp is alone in its new chain.");
        Assert.HasCount(2, received.DigestAlgorithms, "Clause 3.1: the record names every algorithm its chains were built under.");

        foreach(string entryName in DataObjectEntryNames.Append(message.SignatureEntryName))
        {
            AsicZipEntry target = read.Container.FindEntry(entryName)!;
            using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
                new EvidenceRecordVerificationContext { EvidenceRecord = received, DataObject = target.Content.AsReadOnlyMemory() },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Status, $"'{entryName}' is still proved after both renewals.");
            Assert.HasCount(2, verification.Chains, "Verification walks every chain the record carries.");
            Assert.IsTrue(verification.Chains[0].CoversDataObject, "The chain written before either renewal still covers the object it always covered.");
            Assert.IsTrue(verification.Chains[1].CoversDataObject, "And the chain the Hash-Tree Renewal started covers it as well.");
            Assert.AreEqual(PkiAlgorithmIdentifier.Sha256, verification.Chains[0].DigestAlgorithm, "Each chain resolves to its own algorithm.");
            Assert.AreEqual(PkiAlgorithmIdentifier.Sha512, verification.Chains[1].DigestAlgorithm,
                "Clause 5.2's Hash-Tree Renewal exists to move an archive to a stronger algorithm, and the renewed chain states the new one.");
            Assert.AreEqual(message.EvidenceRecordInitialArchiveTime, verification.InitialArchiveTime);
            Assert.AreEqual(message.EvidenceRecordHashTreeRenewalTime, verification.LatestArchiveTime);
            Assert.AreEqual(message.EvidenceRecordHashTreeRenewalTime, verification.CoveredUntil,
                "An unbroken run of proofs carries the object from the initial Archive Timestamp to the most recent one.");
        }
    }


    /// <summary>
    /// Fail-closed at the container layer: one changed octet in a data file, or in the archive manifest a later
    /// link of the Annex A.7 chain states a digest for, makes that digest comparison fail — and clause 4.4.4.2
    /// item d) makes the failure terminal for the whole container whatever anything else concluded. Both are
    /// asserted on the received wire octets, rewritten through the shipped container author so that what fails
    /// is the covered content rather than the archive structure.
    /// </summary>
    /// <param name="entryNameToTamper">The entry whose first octet is flipped.</param>
    /// <param name="reason">Why that entry's octets are load-bearing.</param>
    [TestMethod]
    [DataRow("first.txt", "Clause 4.4.4.2 item d): a validation application shall raise an error whenever a digest value mismatch is detected.", DisplayName = "A covered data file")]
    [DataRow("META-INF/ASiCArchiveManifest1.xml", "Annex A.7 item 2 b) iii): a renewal states a digest for the predecessor it renamed, so the predecessor's octets are load-bearing forever after.", DisplayName = "The renamed prior archive manifest")]
    public async Task ChangingOneOctetOfAnObjectAManifestStatesADigestForFailsTheContainerClosed(string entryNameToTamper, string reason)
    {
        AsicCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory tampered = RewriteWithChangedEntry(message.Container, entryNameToTamper);

        using ReconstructedAsicVerifyingParty verifier = await ReconstructedAsicVerifyingParty.CreateAsync(
            message with { Container = tampered.AsReadOnlySpan().ToArray() }, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            verifier.ValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.DigestMismatch, result.Status, reason);
    }


    /// <summary>
    /// Fail-closed at the Evidence Record layer, precisely: one changed octet INSIDE the chain the Hash-Tree
    /// Renewal hashed as <c>atsc(i)</c> — located in the stored record by the octets the record's own model
    /// states for that chain, not guessed at — leaves the renewal proving nothing, because
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">RFC 4998 clause 5.2 step 3</see> binds the
    /// prior chain's exact encoding into every renewed value. No manifest of the container states a digest for
    /// the Evidence Record file, so nothing but the record's own arithmetic can catch this.
    /// </summary>
    [TestMethod]
    public async Task ChangingOneOctetInsideThePriorChainOfTheEvidenceRecordBreaksTheRenewalBuiltOnIt()
    {
        AsicCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        byte[] recordOctets = EntryPayloads(message.Container)[message.EvidenceRecordEntryName];
        using EvidenceRecord received = EvidenceRecord.Read(recordOctets, BaseMemoryPool.Shared);
        byte[] priorChain = received.ArchiveTimeStampSequence.Chains[0].Encoding.ToArray();
        int offset = LocateSubsequence(recordOctets, priorChain);
        Assert.IsGreaterThanOrEqualTo(0, offset, "The chain encoding the model states has to occur verbatim inside the octets it was read from.");

        byte[] changed = (byte[])recordOctets.Clone();
        changed[offset + priorChain.Length - 1] ^= 0xFF;
        using PooledMemory tampered = AsicEvidenceRecordAttaching.ReplaceEntry(
            message.Container, message.EvidenceRecordEntryName, changed, TestClock.CanonicalEpoch, BaseMemoryPool.Shared);

        using ReconstructedAsicVerifyingParty verifier = await ReconstructedAsicVerifyingParty.CreateAsync(
            message with { Container = tampered.AsReadOnlySpan().ToArray() }, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerValidationResult result = await AsicContainerValidation.ValidateAsync(
            verifier.ValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.EvidenceRecordNotVerified, result.Status,
            "A record whose prior chain no longer hashes to what the renewal committed to proves nothing, and a container relying on it is not valid.");

        AsicEvidenceRecordValidation record = result.EvidenceRecords.Single();
        Assert.AreNotEqual(EvidenceRecordVerificationStatus.Verified, record.VerificationStatus,
            "The record's own status names the RFC 4998 reason rather than a container-shaped one.");
        Assert.IsEmpty(record.ProtectedEntryNames, "Nothing is reported as proved by a record that proves nothing.");
        Assert.IsEmpty(result.ProtectedObjects.Where(o => o.ProtectedBy == AsicProtectionKind.EvidenceRecord).ToList(),
            "And nothing is reported as protected by it.");
        Assert.AreEqual(AsicContainerValidationStatus.Valid, result.Signatures.Single().Status,
            "The damage is confined to the record: the B-LTA CAdES object and the Annex A.7 chain state their own proofs and still validate.");
    }


    /// <summary>
    /// Leg 3 of the charter's testing architecture — "Verifiable creates → independent oracle verifies" — stated
    /// as its own test. The assertions live inside <see cref="MintCapstoneWorldAsync"/> (see its remarks): the
    /// raw-octet archive oracle takes the container apart, the independent BouncyCastle CMS reader verifies the
    /// detached CAdES object over the manifest octets the container stores, the independent Time-Stamp Protocol
    /// validator accepts every token, and the from-spec-text Evidence Record oracle recomputes every link of
    /// both chains — the initial tree, the Timestamp Renewal's whole-<c>timeStamp</c> value, and the Hash-Tree
    /// Renewal's positional combination — from the octets that were written.
    /// </summary>
    [TestMethod]
    public async Task MintedArtifactsPassTheIndependentOracleChainAcrossTheArchiveTheSignatureTheTokensAndBothRenewals()
    {
        AsicCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotEmpty(message.Container, "Minting completed and produced a container; the leg-3 assertions above already ran against it.");
    }


    /// <summary>
    /// The archiving party: mints a Root certification authority, a Time-Stamping Authority and a signer leaf of
    /// one <see cref="X509ChainTestRing"/>, runs the whole capstone flow through the shipped surfaces, checks the
    /// result against the independent oracle chain (leg 3), and releases every certificate, key and carrier
    /// before returning the wire message.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The wire message. Nothing else survives this call.</returns>
    private static async ValueTask<AsicCapstoneWireMessage> MintCapstoneWorldAsync(CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset containerInstant = signingTime;
        DateTimeOffset signatureTimestampTime = signingTime.AddHours(1);
        DateTimeOffset validationDataTime = signingTime.AddHours(2);
        DateTimeOffset signatureArchiveTimestampTime = signingTime.AddHours(3);
        DateTimeOffset containerArchiveTimestampTime = signingTime.AddHours(4);
        DateTimeOffset containerArchiveRenewalTime = signingTime.AddHours(5);
        DateTimeOffset evidenceRecordArchiveTime = signingTime.AddHours(6);
        DateTimeOffset evidenceRecordTimestampRenewalTime = signingTime.AddHours(7);
        DateTimeOffset evidenceRecordHashTreeRenewalTime = signingTime.AddHours(8);
        DateTimeOffset validationTime = signingTime.AddDays(30);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = validationDataTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: notBefore, notAfter: notAfter);

        using PkiCertificateMemory signerCertificate = ToCarrier(signer.Certificate.RawData, PkiCertificateTags.X509Certificate);
        using PkiCertificateMemory rootCertificate = ToCarrier(root.Certificate.RawData, PkiCertificateTags.X509Certificate);

        //=== The ASiC-E container, through the data-to-sign/signature-value split: phase (1) writes the
        //ASiCManifest and states the octets to sign, the leaf's own platform key signs them — the shape a remote
        //signer uses — and phase (3) assembles the container (clause 4.4.4.2 item 3 a, Annex A.4.1). ===
        using AsicContainerSignaturePreparation preparation = await AsicContainerCreation.PrepareSignatureAsync(
            new AsicContainerSignatureContext
            {
                Shape = AsicContainerShape.Extended,
                DataObjects =
                [
                    new AsicDataObject { Name = DataObjectEntryNames[0], Content = FirstDataObject, MediaType = "text/plain" },
                    new AsicDataObject { Name = DataObjectEntryNames[1], Content = SecondDataObject }
                ],
                SignerCertificate = signerCertificate,
                SigningTime = signingTime,
                LastModified = containerInstant,
                ManifestDigestAlgorithm = InitialAlgorithm,
                SignatureDigestAlgorithm = InitialAlgorithm,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        byte[] signatureValueP1363 = signer.SigningKey.SignData(
            preparation.SignaturePreparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> signatureValueDer = EcdsaSignatureEncoding.ConvertP1363ToDer(
            signatureValueP1363, BaseMemoryPool.Shared, out int derLength);
        using AsicContainerCreationResult created = AsicContainerCreation.CompleteSignature(
            preparation, signerCertificate, CryptoAlgorithm.P256, signatureValueDer.Memory[..derLength],
            additionalCertificates: null, BaseMemoryPool.Shared);

        string manifestEntryName = created.ManifestEntryName!;
        string signatureEntryName = created.SignatureEntryName!;

        //=== The incorporated signature reaches B-LTA before the archive chain starts (Annex A.7 item 1 a). ===
        var signatureTimestampResponder = new MintingTimestampResponder(authority, [authority, root], signatureTimestampTime);
        using AsicContainerAugmentationResult timestamped = await AsicContainerAugmentation.AddSignatureTimestampsAsync(
            new AsicContainerSignatureTimestampContext
            {
                Container = created.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = signatureTimestampResponder.FetchAsync,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, revocationThisUpdate, revocationNextUpdate, []);
        using AsicContainerAugmentationResult longTerm = AsicContainerAugmentation.AddSignatureValidationData(
            new AsicContainerValidationDataContext
            {
                Container = timestamped.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                ValidationMaterial = new CAdESValidationMaterial { Certificates = [rootCertificate], CertificateRevocationLists = [revocationList] }
            },
            BaseMemoryPool.Shared);

        var signatureArchiveResponder = new MintingTimestampResponder(authority, [authority, root], signatureArchiveTimestampTime);
        using AsicContainerAugmentationResult archived = await AsicContainerAugmentation.AddSignatureArchiveTimestampsAsync(
            new AsicContainerSignatureArchiveTimestampContext
            {
                Container = longTerm.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = signatureArchiveResponder.FetchAsync,
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                SigningCertificate = signerCertificate
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            AsicContainerLevel.BaselineLTA,
            AsicContainerAugmentation.StateContainerLevel(archived.Container.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared).Level,
            "Clause 5.1 item 2: a container's level is the lowest of its incorporated signatures', and the only one here is now B-LTA.");

        //=== The container-level chain of Annex A.7: one addition, then one renewal that renames the predecessor
        //and points back at it. ===
        var containerArchiveResponder = new MintingTimestampResponder(authority, [authority, root], containerArchiveTimestampTime);
        using AsicContainerAugmentationResult firstLink = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            new AsicContainerArchiveTimestampContext
            {
                Container = archived.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = containerArchiveResponder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync,
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                DigestAlgorithm = InitialAlgorithm
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        var containerRenewalResponder = new MintingTimestampResponder(authority, [authority, root], containerArchiveRenewalTime);
        using AsicContainerAugmentationResult secondLink = await AsicContainerAugmentation.AddContainerArchiveTimestampAsync(
            new AsicContainerArchiveTimestampContext
            {
                Container = firstLink.Container.AsReadOnlyMemory(),
                LastModified = containerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = containerRenewalResponder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync,
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                DigestAlgorithm = InitialAlgorithm
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        //=== The Evidence Record, over the data files AND the CAdES object, as one data object group. The
        //container it is attached to already carries its signature, its manifests and its archive chain, which
        //is why the attachment is a composition of shipped surfaces rather than one call (see
        //AsicEvidenceRecordAttaching's own remarks). ===
        string[] protectedEntryNames = [.. DataObjectEntryNames, signatureEntryName];
        var evidenceRecordResponder = new MintingTimestampResponder(authority, [authority, root], evidenceRecordArchiveTime);
        AsicAttachedEvidenceRecord attachment = await AsicEvidenceRecordAttaching.AttachAsync(
            new AsicEvidenceRecordAttachmentContext
            {
                Container = secondLink.Container.AsReadOnlyMemory(),
                ProtectedEntryNames = protectedEntryNames,
                LastModified = containerInstant,
                TsaUri = TsaUri,
                FetchTimestampResponse = evidenceRecordResponder.FetchAsync,
                EncodeManifest = AsicManifestXmlBinding.EncodeAsync,
                DigestAlgorithm = InitialAlgorithm
            },
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(evidenceRecordArchiveTime, attachment.ArchiveTime, "The record's initial Archive Timestamp asserts the instant the authority was configured to mint at.");

        using(attachment.Container)
        using(attachment.EvidenceRecord)
        {
            //=== Timestamp Renewal: the record's most recent Archive Timestamp is re-timestamped into the chain
            //it belongs to (clause 5.2). ===
            var timestampRenewalResponder = new MintingTimestampResponder(authority, [authority, root], evidenceRecordTimestampRenewalTime);
            using EvidenceRecordRenewal timestampRenewal = await EvidenceRecords.RenewTimestampAsync(
                new EvidenceRecordTimestampRenewalContext
                {
                    EvidenceRecords = [attachment.EvidenceRecord],
                    TsaUri = TsaUri,
                    FetchTimestampResponse = timestampRenewalResponder.FetchAsync
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);
            using PooledMemory afterTimestampRenewal = AsicEvidenceRecordAttaching.ReplaceEntry(
                attachment.Container.AsReadOnlyMemory(), attachment.EvidenceRecordEntryName,
                timestampRenewal.EvidenceRecords[0].AsReadOnlyMemory(), containerInstant, BaseMemoryPool.Shared);

            //=== Hash-Tree Renewal: the data objects and every prior chain are re-hashed under a stronger
            //algorithm into a new chain (clause 5.2 steps 1 to 6). ===
            using AsicZipReadResult forRenewal = AsicZipReading.Read(afterTimestampRenewal.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
            Assert.IsTrue(forRenewal.IsRead, $"The container has to read before its record can be renewed against its entries ({forRenewal.Status}).");
            var renewalObjects = new List<ReadOnlyMemory<byte>>(protectedEntryNames.Length);
            for(int i = 0; i < protectedEntryNames.Length; ++i)
            {
                renewalObjects.Add(forRenewal.Container!.FindEntry(protectedEntryNames[i])!.Content.AsReadOnlyMemory());
            }

            var hashTreeRenewalResponder = new MintingTimestampResponder(authority, [authority, root], evidenceRecordHashTreeRenewalTime);
            using EvidenceRecordRenewal hashTreeRenewal = await EvidenceRecords.RenewHashTreeAsync(
                new EvidenceRecordHashTreeRenewalContext
                {
                    DataObjectGroups =
                    [
                        new EvidenceRecordHashTreeRenewalGroup
                        {
                            EvidenceRecord = timestampRenewal.EvidenceRecords[0],
                            DataObjects = renewalObjects
                        }
                    ],
                    DigestAlgorithm = RenewalAlgorithm,
                    TsaUri = TsaUri,
                    FetchTimestampResponse = hashTreeRenewalResponder.FetchAsync
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);
            using PooledMemory finalContainer = AsicEvidenceRecordAttaching.ReplaceEntry(
                afterTimestampRenewal.AsReadOnlyMemory(), attachment.EvidenceRecordEntryName,
                hashTreeRenewal.EvidenceRecords[0].AsReadOnlyMemory(), containerInstant, BaseMemoryPool.Shared);

            byte[] containerBytes = finalContainer.AsReadOnlySpan().ToArray();

            AssertIndependentOraclesAccept(containerBytes, manifestEntryName, signatureEntryName, attachment.EvidenceRecordEntryName, protectedEntryNames);

            return new AsicCapstoneWireMessage
            {
                Container = containerBytes,
                TrustAnchorCertificate = root.Certificate.RawData,
                ValidationTime = validationTime,
                SigningTime = signingTime,
                SignatureEntryName = signatureEntryName,
                ManifestEntryName = manifestEntryName,
                EvidenceRecordEntryName = attachment.EvidenceRecordEntryName,
                EvidenceRecordManifestEntryName = attachment.ManifestEntryName,
                ContainerArchiveTimestampTime = containerArchiveTimestampTime,
                ContainerArchiveRenewalTime = containerArchiveRenewalTime,
                EvidenceRecordInitialArchiveTime = evidenceRecordArchiveTime,
                EvidenceRecordTimestampRenewalTime = evidenceRecordTimestampRenewalTime,
                EvidenceRecordHashTreeRenewalTime = evidenceRecordHashTreeRenewalTime
            };
        }
    }


    /// <summary>
    /// Checks the minted container against readers that share no code with the surfaces that wrote it: the
    /// raw-octet archive oracle, the independent BouncyCastle CMS reader, the independent Time-Stamp Protocol
    /// validator and the from-spec-text Evidence Record oracle.
    /// </summary>
    /// <param name="containerBytes">The finished container.</param>
    /// <param name="manifestEntryName">The <c>ASiCManifest</c> the CAdES object is detached across.</param>
    /// <param name="signatureEntryName">The CAdES object's entry name.</param>
    /// <param name="evidenceRecordEntryName">The Evidence Record's entry name.</param>
    /// <param name="protectedEntryNames">The entries the Evidence Record's group holds, as the flow stated them.</param>
    private static void AssertIndependentOraclesAccept(
        byte[] containerBytes,
        string manifestEntryName,
        string signatureEntryName,
        string evidenceRecordEntryName,
        string[] protectedEntryNames)
    {
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, AsicZipStructureOracle.MediaTypeAtOffset38(containerBytes),
            "Annex A.1: the independent reader finds the media type where an operating system's magic-number recognition looks for it.");

        Dictionary<string, byte[]> payloads = EntryPayloads(containerBytes);
        Assert.IsTrue(VerifiesDetached(payloads[signatureEntryName], payloads[manifestEntryName]),
            "Leg 3: the independent CMS reader verifies the CAdES object DETACHED over the manifest octets the container stores (Annex A.4.1).");

        foreach(KeyValuePair<string, byte[]> entry in payloads)
        {
            if(AsicManifestNaming.IsTimestampEntryName(entry.Key))
            {
                Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(entry.Value),
                    $"Leg 3: the independent Time-Stamp Protocol validator accepts '{entry.Key}' under a certificate the token itself carries.");
            }
        }

        //Every link of both chains of the Evidence Record, recomputed from the clause text by the independent
        //oracle over the octets that were written: the initial tree, the Timestamp Renewal's whole-timeStamp
        //value, and the Hash-Tree Renewal's positional combination.
        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(payloads[evidenceRecordEntryName]);
        Assert.HasCount(2, parsed.Chains, "The oracle's own decoder finds the two chains the two renewals produced.");

        OracleArchiveTimeStamp initial = parsed.Chains[0][0];
        OracleArchiveTimeStamp timestampRenewal = parsed.Chains[0][1];
        OracleArchiveTimeStamp hashTreeRenewal = parsed.Chains[1][0];

        for(int i = 0; i < protectedEntryNames.Length; ++i)
        {
            byte[] dataObject = payloads[protectedEntryNames[i]];

            byte[]? initialRoot = EvidenceRecordOracle.RecomputeRoot(
                EvidenceRecordOracle.Hash(dataObject, InitialAlgorithm), initial.ReducedHashtree, InitialAlgorithm);
            Assert.IsNotNull(initialRoot, $"The independent walk reaches a root for '{protectedEntryNames[i]}' from the record's own reduced hash tree.");
            Assert.IsTrue(initialRoot.AsSpan().SequenceEqual(initial.MessageImprint),
                "RFC 4998 clause 4.3: the independent Merkle recomputation reaches exactly the root the initial Archive Timestamp binds.");

            byte[] positional = EvidenceRecordOracle.HashTreeRenewalValue(dataObject, [parsed.ChainEncodings[0]], RenewalAlgorithm);
            byte[]? renewedRoot = EvidenceRecordOracle.RecomputeRoot(positional, hashTreeRenewal.ReducedHashtree, RenewalAlgorithm);
            Assert.IsNotNull(renewedRoot, $"The independent walk reaches a root for '{protectedEntryNames[i]}' in the renewed chain.");
            Assert.IsTrue(renewedRoot.AsSpan().SequenceEqual(hashTreeRenewal.MessageImprint),
                "Clause 5.2 step 4: h(i)' = H(h(i) + ha(i)), the data object's hash first and the standalone encoding of the prior chain sequence second.");
        }

        byte[] renewalValue = EvidenceRecordOracle.TimestampRenewalValue(initial.TimeStampEncoding, InitialAlgorithm);
        Assert.IsTrue(EvidenceRecordOracle.ContainsValue(timestampRenewal.ReducedHashtree[0], renewalValue),
            "Clause 5.3 step 2: the Timestamp Renewal's first hash value list holds the hash of the whole timeStamp element of the Archive Timestamp before it.");
        byte[]? timestampRenewalRoot = EvidenceRecordOracle.RecomputeRoot(renewalValue, timestampRenewal.ReducedHashtree, InitialAlgorithm);
        Assert.IsNotNull(timestampRenewalRoot);
        Assert.IsTrue(timestampRenewalRoot.AsSpan().SequenceEqual(timestampRenewal.MessageImprint),
            "The renewal's own token binds the root that value walks to.");
    }


    /// <summary>
    /// Rewrites a container with one entry's first octet flipped, recomputing the archive's own checksums so
    /// that what fails is the covered content rather than the ZIP structure.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <param name="entryName">The entry to change.</param>
    /// <returns>The rewritten container. The caller owns and disposes it.</returns>
    private static PooledMemory RewriteWithChangedEntry(ReadOnlyMemory<byte> container, string entryName)
    {
        using AsicZipReadResult read = AsicZipReading.Read(container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsTrue(read.IsRead, $"The container has to read before it can be changed ({read.Status}).");

        AsicZipEntry target = read.Container!.FindEntry(entryName)
            ?? throw new InvalidOperationException($"The container carries no entry named '{entryName}'.");
        byte[] changed = target.Content.AsReadOnlySpan().ToArray();
        changed[0] ^= 0x01;

        return AsicEvidenceRecordAttaching.ReplaceEntry(container, entryName, changed, TestClock.CanonicalEpoch, BaseMemoryPool.Shared);
    }


    /// <summary>Finds the first byte offset at which <paramref name="needle"/> occurs verbatim inside <paramref name="haystack"/>.</summary>
    /// <param name="haystack">The array to search.</param>
    /// <param name="needle">The byte sequence to locate.</param>
    /// <returns>The zero-based offset, or <c>-1</c> when no occurrence exists.</returns>
    private static int LocateSubsequence(byte[] haystack, byte[] needle)
    {
        if(needle.Length == 0 || needle.Length > haystack.Length)
        {
            return -1;
        }

        for(int start = 0; start <= haystack.Length - needle.Length; ++start)
        {
            if(haystack.AsSpan(start, needle.Length).SequenceEqual(needle))
            {
                return start;
            }
        }

        return -1;
    }


    /// <summary>
    /// Reads every entry's octets out of a container through the independent raw-ZIP oracle.
    /// </summary>
    /// <param name="container">The container's octets.</param>
    /// <returns>The payloads, keyed by entry name.</returns>
    private static Dictionary<string, byte[]> EntryPayloads(byte[] container)
    {
        OracleZipArchive archive = AsicZipStructureOracle.Parse(container);
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach(OracleZipEntry header in archive.LocalHeaders)
        {
            payloads.Add(header.Name, AsicZipStructureOracle.ReadEntryContent(container, header));
        }

        return payloads;
    }


    /// <summary>
    /// Verifies a detached CMS signature over the supplied content with the independent BouncyCastle reader.
    /// </summary>
    /// <param name="signature">The DER-encoded CMS <c>SignedData</c>.</param>
    /// <param name="content">The detached content the signature is claimed to cover.</param>
    /// <returns><see langword="true"/> when a signer verifies over that content under a certificate the object embeds.</returns>
    private static bool VerifiesDetached(byte[] signature, byte[] content)
    {
        var signedData = new BcCmsSignedData(new BcCmsProcessableByteArray(content), signature);
        foreach(BcSignerInformation signer in signedData.GetSignerInfos().GetSigners())
        {
            foreach(BcX509Certificate candidate in signedData.GetCertificates().EnumerateMatches(signer.SignerID))
            {
                try
                {
                    if(signer.Verify(candidate))
                    {
                        return true;
                    }
                }
                catch(BcCmsException)
                {
                    //This embedded certificate is not the signer's; try the next one the object carries.
                }
            }
        }

        return false;
    }


    /// <summary>
    /// Checks a time-stamp token against the independent BouncyCastle Time-Stamp Protocol validator, trying each
    /// certificate the token itself embeds until one authenticates it.
    /// </summary>
    /// <param name="token">The DER-encoded RFC 3161 <c>TimeStampToken</c>.</param>
    /// <returns><see langword="true"/> when the independent validator accepts the token under one of its own embedded certificates.</returns>
    private static bool VerifiesUnderAnyEmbeddedCertificate(byte[] token)
    {
        var parsed = new TimeStampToken(new BcCmsSignedData(token));
        foreach(BcX509Certificate candidate in parsed.GetCertificates().EnumerateMatches(null))
        {
            try
            {
                parsed.Validate(candidate);

                return true;
            }
            catch(TspException)
            {
                //This embedded certificate is not the authority's own; try the next.
            }
        }

        return false;
    }


    /// <summary>Copies octets into a pooled carrier of the stated kind — the shared helper every wire-boundary crossing in this class goes through.</summary>
    /// <param name="derBytes">The octets to copy.</param>
    /// <param name="tag">The kind discriminator the carrier states.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCarrier(byte[] derBytes, Tag tag)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag);
    }


    /// <summary>
    /// Everything that crosses the firewall: the container's own octets, the trust anchor's octets, and the
    /// public instants and entry names a verifying party would learn from its own clock and from what it was
    /// told about the archive.
    /// </summary>
    /// <remarks>Deliberately nothing but octets, instants and names — no carrier, no key, no record of the archiving party's model.</remarks>
    private sealed record AsicCapstoneWireMessage
    {
        /// <summary>The Associated Signature Container the archiving party produced.</summary>
        public required byte[] Container { get; init; }

        /// <summary>The DER-encoded Root certification authority certificate the verifier is configured to trust.</summary>
        public required byte[] TrustAnchorCertificate { get; init; }

        /// <summary>The instant the verifier validates at.</summary>
        public required DateTimeOffset ValidationTime { get; init; }

        /// <summary>The claimed signing time the container's signature states.</summary>
        public required DateTimeOffset SigningTime { get; init; }

        /// <summary>The entry name of the CAdES object the container carries.</summary>
        public required string SignatureEntryName { get; init; }

        /// <summary>The entry name of the <c>ASiCManifest</c> the CAdES object is detached across.</summary>
        public required string ManifestEntryName { get; init; }

        /// <summary>The entry name of the Evidence Record.</summary>
        public required string EvidenceRecordEntryName { get; init; }

        /// <summary>The entry name of the <c>ASiCEvidenceRecordManifest</c> naming the Evidence Record.</summary>
        public required string EvidenceRecordManifestEntryName { get; init; }

        /// <summary>The generation time of the token applied to the first <c>ASiCArchiveManifest</c> of the Annex A.7 chain.</summary>
        public required DateTimeOffset ContainerArchiveTimestampTime { get; init; }

        /// <summary>The generation time of the token applied to the chain's renewal — the newest link.</summary>
        public required DateTimeOffset ContainerArchiveRenewalTime { get; init; }

        /// <summary>The generation time of the Evidence Record's initial Archive Timestamp.</summary>
        public required DateTimeOffset EvidenceRecordInitialArchiveTime { get; init; }

        /// <summary>The generation time of the Evidence Record's Timestamp Renewal.</summary>
        public required DateTimeOffset EvidenceRecordTimestampRenewalTime { get; init; }

        /// <summary>The generation time of the Evidence Record's Hash-Tree Renewal.</summary>
        public required DateTimeOffset EvidenceRecordHashTreeRenewalTime { get; init; }
    }


    /// <summary>
    /// The verifying party: it owns everything it built from the received octets and nothing else, and exposes
    /// the context one run of the container validation of clause 4.4.4.2 takes.
    /// </summary>
    /// <remarks>
    /// The revocation material this party decides with is read out of the received container itself — the
    /// certificate revocation list the B-LT augmentation placed inside the CAdES object's own <c>SignedData</c>,
    /// surfaced back out through the shipped <see cref="CAdESSignatureFacts"/> binding. Nothing is handed to it
    /// beside the container except the trust anchor's octets, which is what a Driving Application configures
    /// rather than receives.
    /// </remarks>
    private sealed class ReconstructedAsicVerifyingParty: IDisposable
    {
        /// <summary>The carriers this party rented, released in reverse order.</summary>
        private readonly List<IDisposable> owned = [];

        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>The container's octets, as received.</summary>
        public ReadOnlyMemory<byte> Container { get; private set; }

        /// <summary>The instant this party validates at.</summary>
        public DateTimeOffset CurrentTime { get; private set; }

        /// <summary>The trust anchor rebuilt from the received octets.</summary>
        public PkiCertificateMemory TrustAnchor { get; private set; } = null!;

        /// <summary>The certificate revocation lists this party read out of the container's own embedded material.</summary>
        public IReadOnlyList<PkiCertificateMemory> EmbeddedRevocationLists { get; private set; } = [];

        /// <summary>The inputs of Tables 18, 20 and 27 the container layer states per embedded object.</summary>
        public SignatureValidationInputs Inputs { get; private set; } = null!;

        /// <summary>The seams the embedded objects' validation composes.</summary>
        public SignatureValidationSeams Seams { get; private set; } = null!;


        /// <summary>
        /// Reconstructs a verifying party from a wire message.
        /// </summary>
        /// <param name="message">The octets and public instants the party received.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The party, which the caller disposes.</returns>
        public static async ValueTask<ReconstructedAsicVerifyingParty> CreateAsync(
            AsicCapstoneWireMessage message,
            CancellationToken cancellationToken)
        {
            var party = new ReconstructedAsicVerifyingParty();
            try
            {
                await party.BuildAsync(message, cancellationToken).ConfigureAwait(false);

                return party;
            }
            catch
            {
                party.Dispose();

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
            for(int i = owned.Count - 1; i >= 0; --i)
            {
                owned[i].Dispose();
            }

            owned.Clear();
        }


        /// <summary>
        /// States the validation context this party runs the container through.
        /// </summary>
        /// <returns>The context.</returns>
        public AsicContainerValidationContext ValidationContext() =>
            new()
            {
                Container = Container,
                CurrentTime = CurrentTime,
                ParseManifest = AsicManifestXmlBinding.ParseAsync,
                SignatureInputs = Inputs,
                SignatureSeams = Seams,

                //Clause 5.6.3.4 step 3): with the current-time process already Passed and this left false, the
                //process for Signatures providing Long Term Availability returns immediately without ever
                //walking the archive time-stamp or the Evidence Record — nothing this capstone is chartered to
                //demonstrate would run. Asserting it exercises both for real, which is the policy choice a
                //Driving Application makes when it wants long-term material validated regardless of whether the
                //simpler process already sufficed.
                ProcessSelection = SignatureValidationProcessSelection.LongTermAvailability
            };


        /// <summary>
        /// Rebuilds every carrier from the received container and assembles the inputs and seams.
        /// </summary>
        /// <param name="message">The received message.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        private async ValueTask BuildAsync(AsicCapstoneWireMessage message, CancellationToken cancellationToken)
        {
            Container = message.Container;
            CurrentTime = message.ValidationTime;
            TrustAnchor = Own(ToCarrier(message.TrustAnchorCertificate, PkiCertificateTags.X509Certificate));

            List<PkiCertificateMemory> revocationLists = [];
            using(AsicContainerReadResult read = AsicContainerReading.Read(Container, AsicZipReadLimits.Conformant, BaseMemoryPool.Shared))
            {
                Assert.IsTrue(read.IsRead, $"The received octets have to be a container the reader accepts ({read.Status}).");

                AsicZipEntry signature = read.Facts!.FindEntry(message.SignatureEntryName)
                    ?? throw new InvalidOperationException($"The received container carries no entry named '{message.SignatureEntryName}'.");
                using CmsSignedData signedData = CmsSignedData.FromBytes(signature.Content.AsReadOnlySpan(), BaseMemoryPool.Shared);
                using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
                    new SignatureFactsExtractionContext { SignedDataObject = signedData },
                    BaseMemoryPool.Shared,
                    cancellationToken).ConfigureAwait(false);
                Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status,
                    "The container's CAdES entry has to be a CMS SignedData the shipped binding can read.");

                for(int i = 0; i < facts.EmbeddedCertificateRevocationLists.Count; ++i)
                {
                    revocationLists.Add(Own(ToCarrier(facts.EmbeddedCertificateRevocationLists[i].AsReadOnlySpan().ToArray(), PkiCertificateTags.X509Crl)));
                }
            }

            EmbeddedRevocationLists = [.. revocationLists];
            Assert.IsNotEmpty(EmbeddedRevocationLists,
                "The received container carries the certificate revocation list the B-LT augmentation placed inside its CAdES object, which is the only revocation material this party has.");

            AssembleInputs();
        }


        /// <summary>
        /// Assembles this party's own X.509 and cryptographic constraints, the seams the embedded objects'
        /// validation composes, and the inputs template the container layer states per object.
        /// </summary>
        private void AssembleInputs()
        {
            var x509Constraints = new X509ValidationConstraints
            {
                TrustAnchors = [new TrustAnchorConstraint(TrustAnchor, SunsetDate: null)]
            };

            var cryptographicConstraints = new CryptographicConstraints
            {
                Entries =
                [
                    new AlgorithmReliabilityEntry(
                        new PkiAlgorithmIdentifier(X509ChainTestRing.EcdsaWithSha256SignatureOid),
                        MinimumKeySizeBits: X509ChainTestRing.SigningKeySizeBits,
                        TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha256, MinimumKeySizeBits: null, TrustedUntil: null),
                    new AlgorithmReliabilityEntry(PkiAlgorithmIdentifier.Sha512, MinimumKeySizeBits: null, TrustedUntil: null)
                ]
            };

            var constraints = new SignatureValidationConstraints
            {
                Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
                X509 = x509Constraints,
                Cryptographic = cryptographicConstraints,
                SignatureElements = new SignatureElementsConstraints { RequireLongTermAvailabilityAttributeValidity = true }
            };

            var completer = new CertificateChainCompleter([TrustAnchor]);
            var revocationChecker = new CrlRevocationChecker(EmbeddedRevocationLists);

            Seams = new SignatureValidationSeams
            {
                Format = CAdESSignatureFacts.Seam,
                CompleteCertificateChain = completer.CompleteAsync,
                ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync,
                CheckRevocation = revocationChecker.CheckAsync
            };

            //The container layer replaces SignedDataObject, SignerDocuments and EvidenceRecords per embedded
            //object; what this template carries that matters is the constraints and the trust anchor. The trust
            //anchor stands in as the placeholder Signed Data Object for the same reason the stage-8 world's
            //signer certificate did — every object actually validated comes out of the container.
            Inputs = new SignatureValidationInputs
            {
                SignedDataObject = TrustAnchor,
                Constraints = constraints,
                TimestampConstraints = constraints,
                CertificateValidationData = [TrustAnchor, .. EmbeddedRevocationLists]
            };
        }


        /// <summary>Takes ownership of one carrier.</summary>
        /// <typeparam name="T">The carrier's type.</typeparam>
        /// <param name="carrier">The carrier.</param>
        /// <returns>The same carrier.</returns>
        private T Own<T>(T carrier) where T: IDisposable
        {
            owned.Add(carrier);

            return carrier;
        }
    }
}
