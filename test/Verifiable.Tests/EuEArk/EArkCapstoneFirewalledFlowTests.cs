using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Schema;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Tsp;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcCmsException = Org.BouncyCastle.Cms.CmsException;
using BcCmsProcessableByteArray = Org.BouncyCastle.Cms.CmsProcessableByteArray;
using BcCmsSignedData = Org.BouncyCastle.Cms.CmsSignedData;
using BcSignerInformation = Org.BouncyCastle.Cms.SignerInformation;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// The firewalled capstone of the eArchiving arc (contract R-9.5): an archiving party mints content, writes the
/// digital-provenance document of
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>, seals both into a
/// preservation container of the "ASiC with Evidence Records" profile of Annex A.3.1 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>, places that container by this library's own evidence-placement convention, and
/// writes an Archival Information Package of
/// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> around them — and then emits nothing but the
/// package archive's own octets. A verifying party that never saw any of the archiving party's objects rebuilds
/// everything from those octets and reaches the package's claims conclusion, <c>TOTAL-PASSED</c> for the
/// container's embedded signature, and a verified Evidence Record.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The firewall.</strong> <see cref="MintCapstoneWorldAsync"/> builds the Root certification authority,
/// the Time-Stamping Authority and the signer entirely inside a local scope, performs the whole archiving flow
/// over that material, copies out the archive's octets and the trust anchor's octets, and disposes every
/// certificate, key and carrier before returning. <see cref="ReconstructedEArkVerifyingParty"/> reads those
/// octets and nothing else — even the revocation material it decides with is the certificate revocation list the
/// container's own B-LT augmentation placed inside the signature it received.
/// </para>
/// <para>
/// <strong>Leg 3 — "Verifiable creates → independent oracle verifies."</strong>
/// <see cref="AssertIndependentOraclesAccept"/> takes the minted archive apart with readers that share no code
/// with the surfaces that wrote it: the raw-octet <see cref="AsicZipStructureOracle"/> for both archives, the
/// from-spec-text <see cref="EvidenceRecordOracle"/> for the hash tree and for every fixity the manifest states,
/// the independent BouncyCastle CMS reader for the detached signature, the independent Time-Stamp Protocol
/// validator for the token, and <see cref="EArkSchemaOracle"/> for the manifest and the provenance document
/// against the vocabularies' own schemas.
/// </para>
/// <para>
/// <strong>The fixed point the package cannot escape, asserted rather than hidden.</strong> The manifest states
/// a digest over the preservation container, so the container cannot prove the manifest: any evidence covering
/// the manifest would have to exist before the digest the manifest states over it. The provenance document is a
/// different matter — the placement convention identifies an artifact by its entry NAME — so the document IS
/// inside what the container proves, and
/// <see cref="AProvenanceDocumentIsInsideTheEvidenceWhileTheManifestStatingItsDigestCannotBe"/> asserts both
/// halves at once.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkCapstoneFirewalledFlowTests
{
    /// <summary>The address handed to the transport delegate; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.eark-capstone.example.test/";

    /// <summary>The DNS name the signer's leaf certificate carries.</summary>
    private const string SignerDnsName = "eark-capstone-signer.example.test";

    /// <summary>The identifier the capstone's claim issuer states as its own.</summary>
    private const string IssuerId = "eark-capstone-validator";

    /// <summary>The correlation identifier the capstone's claim issuer carries through a run.</summary>
    private const string CorrelationId = "eark-capstone-validation";


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The capstone: the package archive's wire octets alone carry a verifying party to the archival package's
    /// claims conclusion, to the preservation object container profile of Annex A.3.1, to <c>TOTAL-PASSED</c> for
    /// the container's detached CAdES signature through the validation process of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
    /// ETSI EN 319 102-1 V1.4.1</see>, and to a verified Evidence Record of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see>.
    /// </summary>
    /// <returns>A task that completes when the received package has been judged.</returns>
    [TestMethod]
    public async Task FirewalledCapstoneReachesTheArchivalClaimsConclusionAndTotalPassedFromThePackageBytesAlone()
    {
        EArkCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using ReconstructedEArkVerifyingParty verifier = await ReconstructAsync(message).ConfigureAwait(false);

        //=== The preservation container, read out of the package and judged as the profile's container. ===
        PreservationContainerProfileReport profile = PreservationContainerProfile.StateProfile(verifier.ProfileContext());
        Assert.AreEqual(PreservationContainerProfileStatus.Conformant, profile.Status,
            "Annex A.3.1.3: the container the package carries satisfies all six numbered requirements of the preservation object container profile.");
        Assert.HasCount(1, profile.Manifests, "Requirement 2: one ASiCEvidenceRecordManifest names the record.");
        Assert.AreEqual(AsicEvidenceRecordForm.Binary, profile.Manifests[0].EvidenceRecordForm,
            "Requirement 4: a '.ers' file name states the ASN.1 form of RFC 4998.");
        Assert.AreEqual(message.ContainerEvidenceRecordEntryName, profile.Manifests[0].EvidenceRecordEntryName,
            "Requirement 6: the SigReference resolves to the evidence record file the container really carries.");
        Assert.IsEmpty(profile.Manifests[0].CriticalityDepartures,
            "Clause 5.5: the manifest carries no extension departing from its own criticality recommendation.");

        //=== The container's own validation: the embedded signature and the Evidence Record. ===
        using AsicContainerValidationResult container = await AsicContainerValidation.ValidateAsync(
            verifier.ContainerValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, container.Status,
            $"Clause 4.4.4.2: the preservation container validates from the octets the package carries ({container.FailureReason}).");
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, container.Signatures.Single().Outcome!.Conclusion.Indication,
            "Clause 4.4.4.2 item a): the referenced CAdES signature validates against the ASiCManifest content and reaches TOTAL-PASSED.");

        AsicEvidenceRecordValidation record = container.EvidenceRecords.Single();
        Assert.AreEqual(AsicContainerValidationStatus.Valid, record.Status, $"The record proves what the container states it protects ({record.FailureReason}).");
        Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, record.VerificationStatus, "RFC 4998 clause 4.3: every target's tree path reaches the root the token binds.");
        Assert.AreEqual(message.EvidenceRecordArchiveTime, record.InitialArchiveTime,
            "The instant the record proves its targets existed at is its initial archive time-stamp's.");
        Assert.AreSequenceEqual(new[] { message.ProvenanceEntryName }, record.ProtectedEntryNames.ToArray(),
            "RFC 4998 clause 4.2: the record's data object group is exactly the digital provenance, because that is the statement an archival provenance anchor makes.");

        //=== The package's own claims conclusion, over the whole archival rule list. ===
        verifier.StateArtifactFacts(message.ContainerEntryName, [.. record.ProtectedEntryNames]);
        ClaimIssueResult claims = await RunAsync(verifier.ValidationContext()).ConfigureAwait(false);

        Assert.AreEqual(ClaimIssueCompletionStatus.Complete, claims.CompletionStatus, "Every rule of the archival list ran to completion.");
        AssertNoRuleFailed(claims);

        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.CsipStr1, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.CsipStr2, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.PackageReferencesResolve, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.PackageIdentifiersAreNCNames, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, EArkClaimIds.PackageEvidenceSelfDescription, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(claims, PreservationClaimIds.Ovr92Item04, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //The evidence policy identifier the container carries sits in the attributes of the record's only chain,
        //and clause 5.2 of RFC 4998 makes an attribute protected by a LATER chain — so a record that has not been
        //renewed protects none of its own attributes. The wire flow renews one and asserts the other answer.
        EArkStructuralRuleTests.AssertOutcome(claims, PreservationClaimIds.Ovr92Item05, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
    }


    /// <summary>
    /// Leg 3 of the arc's testing architecture stated as its own test: the assertions live inside
    /// <see cref="MintCapstoneWorldAsync"/>, which runs every one of them before the firewall closes.
    /// </summary>
    /// <returns>A task that completes when the mint has produced an archive.</returns>
    [TestMethod]
    public async Task TheMintedPackagePassesTheIndependentOracleChainAcrossBothArchivesTheSignatureTheTokenAndTheSchemas()
    {
        EArkCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotEmpty(message.Archive, "Minting completed and produced a package archive; the leg-3 assertions above already ran against it.");
    }


    /// <summary>
    /// Both halves of the anchoring statement at once: the digital-provenance document IS inside what the
    /// preservation container proves, and the manifest — which states a digest over that very container — cannot
    /// be, because the digest it states is part of the octets any such evidence would have to have been created
    /// over.
    /// </summary>
    /// <returns>A task that completes when both verifications have run.</returns>
    /// <remarks>
    /// This is not a defect of the mint but a property of the two requirements together, and it is why the
    /// package's anchoring claim reads as a recommendation the package partly met rather than as a requirement it
    /// broke: <c>PackageEvidencePlacement</c> obliges the manifest to name the artifact with a digest this library
    /// recomputes, while the anchoring convention would have the artifact prove the manifest.
    /// </remarks>
    [TestMethod]
    public async Task AProvenanceDocumentIsInsideTheEvidenceWhileTheManifestStatingItsDigestCannotBe()
    {
        EArkCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using ReconstructedEArkVerifyingParty verifier = await ReconstructAsync(message).ConfigureAwait(false);

        using EArkProvenanceAnchorVerification withoutManifest = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = verifier.ContainerEvidenceRecord,
                Package = verifier.AnchorContext() with { CoverManifest = false },
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.Anchored, withoutManifest.Status,
            "The provenance document the manifest references is inside what the container's Evidence Record proves, verified against the octets the package now holds.");
        Assert.AreSequenceEqual(
            new[] { EArkCapstoneSource.ProvenanceEntryName },
            withoutManifest.Plan!.CoveredEntryNames(),
            "One provenance section, one document.");

        using EArkProvenanceAnchorVerification withManifest = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = verifier.ContainerEvidenceRecord,
                Package = verifier.AnchorContext(),
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.ProvenanceNotCovered, withManifest.Status,
            "A manifest that states the container's digest cannot be inside what that container proves; the fixed point does not exist.");
        Assert.AreEqual(EArkWellKnown.PackageManifestFileName, withManifest.UncoveredEntryName,
            "And the verification names exactly which entry it is, rather than failing wholesale.");

        //The package's own claim says the same thing in the rule list's own words.
        using AsicContainerValidationResult container = await AsicContainerValidation.ValidateAsync(
            verifier.ContainerValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        verifier.StateArtifactFacts(message.ContainerEntryName, [.. container.EvidenceRecords.Single().ProtectedEntryNames]);
        ClaimIssueResult claims = await RunAsync(verifier.ValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            claims, EArkClaimIds.PackageProvenanceAnchored, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
    }


    /// <summary>
    /// Fail-closed at the package layer: one changed octet of a content file makes the manifest's own digest
    /// comparison fail, and the same octets no longer walk to the root the container's Evidence Record binds.
    /// </summary>
    /// <returns>A task that completes when both failures have been observed.</returns>
    [TestMethod]
    public async Task ChangingOneOctetOfAContentFileFailsTheFixityRuleAndTheEvidenceOverTheSameOctets()
    {
        EArkCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        byte[] original = EntryPayload(message.Archive, message.RootFolderName, EArkCapstoneSource.ContentEntryNames[0]);
        byte[] tampered = RewriteEntry(message, EArkCapstoneSource.ContentEntryNames[0], Flip(original));

        using ReconstructedEArkVerifyingParty verifier = await ReconstructAsync(message with { Archive = tampered }).ConfigureAwait(false);
        using AsicContainerValidationResult container = await AsicContainerValidation.ValidateAsync(
            verifier.ContainerValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AsicContainerValidationStatus.Valid, container.Status,
            "The container carries its own copy of what it proves, so a change to the package's copy leaves the container itself intact — which is precisely why the package's own rules have to catch it.");

        verifier.StateArtifactFacts(message.ContainerEntryName, [.. container.EvidenceRecords.Single().ProtectedEntryNames]);
        ClaimIssueResult claims = await RunAsync(verifier.ValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            claims, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Failure, EArkClaimReason.FixityMismatch);

        EArkPackageEntry changed = verifier.Snapshot.FindEntry(EArkCapstoneSource.ContentEntryNames[0])!;
        using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
            new EvidenceRecordVerificationContext
            {
                EvidenceRecord = verifier.ContainerEvidenceRecord,
                DataObject = changed.Content.AsReadOnlyMemory()
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(EvidenceRecordVerificationStatus.Verified, verification.Status,
            "RFC 4998 clause 4.3: the changed octets hash to something the reduced hash tree has no path for.");
    }


    /// <summary>
    /// Fail-closed at the manifest layer: one changed hexadecimal digit inside a checksum the manifest states —
    /// a document that is still well-formed and still parses — fails the recomputation rule and nothing else.
    /// </summary>
    /// <returns>A task that completes when the failure has been observed.</returns>
    [TestMethod]
    public async Task ChangingOneDigitOfAChecksumTheManifestStatesFailsTheRecomputationRule()
    {
        EArkCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        byte[] manifestOctets = EntryPayload(message.Archive, message.RootFolderName, EArkWellKnown.PackageManifestFileName);
        byte[] tampered = RewriteEntry(message, EArkWellKnown.PackageManifestFileName, ChangeOneChecksumDigit(manifestOctets));

        using ReconstructedEArkVerifyingParty verifier = await ReconstructAsync(message with { Archive = tampered }).ConfigureAwait(false);
        using AsicContainerValidationResult container = await AsicContainerValidation.ValidateAsync(
            verifier.ContainerValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        verifier.StateArtifactFacts(message.ContainerEntryName, [.. container.EvidenceRecords.Single().ProtectedEntryNames]);
        ClaimIssueResult claims = await RunAsync(verifier.ValidationContext()).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            claims, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Failure, EArkClaimReason.FixityMismatch);
        EArkStructuralRuleTests.AssertOutcome(
            claims, EArkClaimIds.PackageReferencesResolve, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(
            claims, EArkClaimIds.PackageEvidencePlacement, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// The sharpest property of the whole arc, at package scale: a producer rewrites one preservation event AND
    /// the digest the manifest states over the document holding it, so that every plain-text rule of both
    /// specifications reaches the identical conclusion — and the evidence created over those same octets does
    /// not, and names the document that moved.
    /// </summary>
    /// <returns>A task that completes when both halves have been asserted.</returns>
    [TestMethod]
    public async Task RewritingAProvenanceEventBreaksTheEvidenceWhileEveryPlainTextRuleReachesTheSameConclusion()
    {
        EArkCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        byte[] originalProvenance = EntryPayload(message.Archive, message.RootFolderName, EArkCapstoneSource.ProvenanceEntryName);
        byte[] rewrittenProvenance = RewriteEventOutcome(originalProvenance);
        Assert.AreNotEqual(
            Convert.ToHexStringLower(originalProvenance),
            Convert.ToHexStringLower(rewrittenProvenance),
            "The two provenance documents really differ, so nothing below is vacuous.");

        string originalChecksum = await EArkEvidenceSource.ChecksumOfAsync(originalProvenance, TestContext.CancellationToken).ConfigureAwait(false);
        string rewrittenChecksum = await EArkEvidenceSource.ChecksumOfAsync(rewrittenProvenance, TestContext.CancellationToken).ConfigureAwait(false);

        EArkCapstoneWireMessage withNewProvenance = message with
        {
            Archive = RewriteEntry(message, EArkCapstoneSource.ProvenanceEntryName, rewrittenProvenance)
        };

        byte[] manifestOctets = EntryPayload(withNewProvenance.Archive, message.RootFolderName, EArkWellKnown.PackageManifestFileName);
        byte[] tampered = RewriteEntry(
            withNewProvenance,
            EArkWellKnown.PackageManifestFileName,
            ReplaceText(manifestOctets, originalChecksum, rewrittenChecksum));

        using ReconstructedEArkVerifyingParty honest = await ReconstructAsync(message).ConfigureAwait(false);
        using ReconstructedEArkVerifyingParty rewritten = await ReconstructAsync(message with { Archive = tampered }).ConfigureAwait(false);

        using AsicContainerValidationResult honestContainer = await AsicContainerValidation.ValidateAsync(
            honest.ContainerValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using AsicContainerValidationResult rewrittenContainer = await AsicContainerValidation.ValidateAsync(
            rewritten.ContainerValidationContext(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        honest.StateArtifactFacts(message.ContainerEntryName, [.. honestContainer.EvidenceRecords.Single().ProtectedEntryNames]);
        rewritten.StateArtifactFacts(message.ContainerEntryName, [.. rewrittenContainer.EvidenceRecords.Single().ProtectedEntryNames]);

        //Direction one: every rule of both specifications, and this library's own, says exactly the same thing.
        ClaimIssueResult honestClaims = await RunAsync(honest.ValidationContext()).ConfigureAwait(false);
        ClaimIssueResult rewrittenClaims = await RunAsync(rewritten.ValidationContext()).ConfigureAwait(false);
        AssertSameConclusions(honestClaims, rewrittenClaims);
        EArkStructuralRuleTests.AssertOutcome(
            rewrittenClaims, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //Direction two: the evidence over the same octets fails, and it names what moved.
        using EArkProvenanceAnchorVerification verification = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = rewritten.ContainerEvidenceRecord,
                Package = rewritten.AnchorContext() with { CoverManifest = false },
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.ProvenanceNotCovered, verification.Status,
            "The plain-text provenance chain alone proves nothing; the Evidence Record over the same octets is what does.");
        Assert.AreEqual(EArkCapstoneSource.ProvenanceEntryName, verification.UncoveredEntryName);
    }


    /// <summary>
    /// Fail-closed at the evidence layer: one changed octet inside the preservation container makes the package's
    /// own fixity rule fail and the container unreadable — the two independent statements a package makes about
    /// the artifact it carries.
    /// </summary>
    /// <returns>A task that completes when both failures have been observed.</returns>
    [TestMethod]
    public async Task ChangingOneOctetOfThePreservationContainerFailsBothTheFixityRuleAndTheContainersOwnReading()
    {
        EArkCapstoneWireMessage message = await MintCapstoneWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        byte[] original = EntryPayload(message.Archive, message.RootFolderName, EArkCapstoneSource.ContainerEntryName);
        byte[] tampered = RewriteEntry(message, EArkCapstoneSource.ContainerEntryName, Flip(original));

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            tampered, EArkPackageLimits.Conformant, BaseMemoryPool.Shared);
        Assert.IsNotNull(read.Snapshot, $"The package archive itself is still well-formed ({read.Status}).");

        EArkPackageEntry containerEntry = read.Snapshot.FindEntry(EArkCapstoneSource.ContainerEntryName)!;
        using AsicContainerReadResult container = AsicContainerReading.Read(
            containerEntry.Content.AsReadOnlyMemory(), AsicZipReadLimits.Conformant, BaseMemoryPool.Shared);

        Assert.IsFalse(container.IsRead,
            "A changed octet inside the container breaks the container's own archive integrity before any signature or record is reached.");

        using MetsParseResult manifest = await ParseManifestAsync(read.Snapshot).ConfigureAwait(false);
        Assert.IsTrue(manifest.IsValid, $"The package's manifest is untouched and still parses ({manifest.Status}).");

        ClaimIssueResult claims = await RunAsync(
            new EArkValidationContext
            {
                EntryNames = EntryNames(read.Snapshot),
                CurrentTime = message.ValidationTime,
                PackageFacts = EArkPackageReading.StateFacts(read.Snapshot),
                PackageManifest = manifest.Document,
                MemoryPool = BaseMemoryPool.Shared,
            },
            [.. EArkValidationProfiles.PackageFixityAndReferenceRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            claims, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Failure, EArkClaimReason.FixityMismatch);
    }


    /// <summary>
    /// The archiving party: mints a Root certification authority, a Time-Stamping Authority and a signer leaf of
    /// one <see cref="X509ChainTestRing"/>, runs the whole archiving flow through the shipped surfaces, checks the
    /// result against the independent oracle chain (leg 3), and releases every certificate, key and carrier before
    /// returning the wire message.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The wire message. Nothing else survives this call.</returns>
    private static async ValueTask<EArkCapstoneWireMessage> MintCapstoneWorldAsync(CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        DateTimeOffset signingTime = timeProvider.GetUtcNow();
        DateTimeOffset timestampTime = signingTime.AddHours(1);
        DateTimeOffset validationTime = signingTime.AddDays(30);
        DateTimeOffset notBefore = signingTime.AddYears(-1);
        DateTimeOffset notAfter = signingTime.AddYears(9);
        DateTimeOffset revocationThisUpdate = signingTime.AddMinutes(-30);
        DateTimeOffset revocationNextUpdate = signingTime.AddYears(1);

        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: notBefore, notAfter: notAfter);
        using X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, SignerDnsName, timeProvider, notBefore: notBefore, notAfter: notAfter);

        using PkiCertificateMemory signerCertificate = OcspTestFixtures.ToCertificateCarrier(signer.Certificate);
        using PkiCertificateMemory rootCertificate = OcspTestFixtures.ToCertificateCarrier(root.Certificate);
        using PkiCertificateMemory revocationList = X509ChainTestRingRevocation.MintCertificateRevocationList(
            root, revocationThisUpdate, revocationNextUpdate, []);

        var responder = new MintingTimestampResponder(authority, [authority, root], timestampTime);

        using EArkCapstonePackage package = await EArkCapstoneSource.MintAsync(
            new EArkCapstoneMintContext
            {
                Signer = signer,
                SignerCertificate = signerCertificate,
                ValidationMaterial = new CAdESValidationMaterial
                {
                    Certificates = [rootCertificate],
                    CertificateRevocationLists = [revocationList]
                },
                TsaUri = TsaUri,
                FetchTimestampResponse = responder.FetchAsync,
                SigningTime = signingTime,
                PackageInstant = signingTime,
                MetadataInstant = signingTime,
                TimestampGenerationTime = timestampTime,
            },
            cancellationToken).ConfigureAwait(false);

        byte[] archive = package.ArchiveBytes();

        //---- Leg 3: "Verifiable creates → independent oracle verifies". ----
        AssertIndependentOraclesAccept(archive, package);
        //---- end leg 3 ----

        return new EArkCapstoneWireMessage
        {
            Archive = archive,
            TrustAnchorCertificate = root.Certificate.RawData,
            RootFolderName = package.RootFolderName,
            ContainerEntryName = package.ContainerEntryName,
            ProvenanceEntryName = package.ProvenanceEntryName,
            ContainerSignatureEntryName = package.ContainerSignatureEntryName,
            ContainerEvidenceRecordEntryName = package.ContainerEvidenceRecordEntryName,
            EvidenceRecordArchiveTime = package.EvidenceRecordArchiveTime,
            ValidationTime = validationTime,
        };
    }


    /// <summary>
    /// Checks the minted package against readers that share no code with the surfaces that wrote it.
    /// </summary>
    /// <param name="archive">The finished package archive.</param>
    /// <param name="package">What the mint reported about it.</param>
    private static void AssertIndependentOraclesAccept(byte[] archive, EArkCapstonePackage package)
    {
        Dictionary<string, byte[]> entries = EntryPayloads(archive, package.RootFolderName);

        //The manifest's own fixity values, recomputed by the independent hasher rather than by the digest seam.
        byte[] manifestOctets = entries[EArkWellKnown.PackageManifestFileName];
        string manifestText = Encoding.UTF8.GetString(manifestOctets);
        foreach(string entryName in new[]
        {
            package.ProvenanceEntryName,
            package.ContainerEntryName,
            EArkCapstoneSource.ContentEntryNames[0],
            EArkCapstoneSource.ContentEntryNames[1]
        })
        {
            string independent = Convert.ToHexStringLower(
                EvidenceRecordOracle.Hash(entries[entryName], EArkCapstoneSource.DigestAlgorithm));
            Assert.Contains(independent, manifestText, StringComparison.Ordinal,
                $"Leg 3: the manifest states, for '{entryName}', exactly the digest an independent hasher computes over the octets the archive carries.");
        }

        //The container, taken apart by the raw-octet oracle and judged by the independent CMS, Time-Stamp
        //Protocol and Evidence Record readers.
        byte[] containerOctets = entries[package.ContainerEntryName];
        Dictionary<string, byte[]> containerEntries = EntryPayloads(containerOctets, rootFolderName: null);
        Assert.AreEqual(AsicWellKnown.AsicExtendedMediaType, AsicZipStructureOracle.MediaTypeAtOffset38(containerOctets),
            "Annex A.1: the independent reader finds the container's media type where an operating system's magic-number recognition looks for it.");

        string signatureManifestEntryName = ManifestOf(containerEntries, package.ContainerSignatureEntryName);
        Assert.IsTrue(VerifiesDetached(containerEntries[package.ContainerSignatureEntryName], containerEntries[signatureManifestEntryName]),
            "Leg 3: the independent CMS reader verifies the CAdES object DETACHED over the manifest octets the container stores (Annex A.4.1).");

        foreach(KeyValuePair<string, byte[]> entry in containerEntries)
        {
            if(AsicManifestNaming.IsTimestampEntryName(entry.Key))
            {
                Assert.IsTrue(VerifiesUnderAnyEmbeddedCertificate(entry.Value),
                    $"Leg 3: the independent Time-Stamp Protocol validator accepts '{entry.Key}' under a certificate the token itself carries.");
            }
        }

        OracleEvidenceRecord parsed = EvidenceRecordOracle.ParseEvidenceRecord(containerEntries[package.ContainerEvidenceRecordEntryName]);
        Assert.HasCount(1, parsed.Chains, "One chain, because nothing has been renewed yet.");

        OracleArchiveTimeStamp initial = parsed.Chains[0][0];
        foreach(string entryName in new[] { package.ProvenanceEntryName })
        {
            byte[]? root = EvidenceRecordOracle.RecomputeRoot(
                EvidenceRecordOracle.Hash(containerEntries[entryName], EArkCapstoneSource.DigestAlgorithm),
                initial.ReducedHashtree,
                EArkCapstoneSource.DigestAlgorithm);

            Assert.IsNotNull(root, $"The independent walk reaches a root for '{entryName}'.");
            Assert.IsTrue(root.AsSpan().SequenceEqual(initial.MessageImprint),
                "RFC 4998 clause 4.3: the independent Merkle recomputation reaches exactly the root the archive time-stamp binds.");
        }

        //Both documents against the vocabularies' own schemas.
        XmlSchemaSet? metsSchemas = EArkSchemaOracle.TryBuildMetsSchemas();
        if(metsSchemas is null)
        {
            Assert.Inconclusive(EArkSchemaOracle.MissingSchemaMessage);

            return;
        }

        List<string> manifestProblems = EArkSchemaOracle.Validate(manifestOctets, metsSchemas);
        Assert.IsEmpty(manifestProblems,
            $"Leg 3: the manifest the package carries validates against the base vocabulary's own schema and the profile's extension schema ({string.Join("; ", manifestProblems)}).");

        XmlSchemaSet? premisSchemas = EArkSchemaOracle.TryBuildAuthenticPremisSchemas();
        if(premisSchemas is null)
        {
            Assert.Inconclusive(EArkSchemaOracle.MissingPremisSchemaMessage);

            return;
        }

        List<string> provenanceProblems = EArkSchemaOracle.Validate(entries[package.ProvenanceEntryName], premisSchemas);
        Assert.IsEmpty(provenanceProblems,
            $"Leg 3: the digital-provenance document validates against the preservation vocabulary's own schema ({string.Join("; ", provenanceProblems)}).");
    }


    /// <summary>Reconstructs a verifying party from a wire message.</summary>
    /// <param name="message">The octets and public names the party received.</param>
    /// <returns>The party, which the caller disposes.</returns>
    private async Task<ReconstructedEArkVerifyingParty> ReconstructAsync(EArkCapstoneWireMessage message) =>
        await ReconstructedEArkVerifyingParty.CreateAsync(
            message.Archive,
            message.TrustAnchorCertificate,
            message.ContainerEntryName,
            message.ProvenanceEntryName,
            message.ValidationTime,
            checkRevocation: null,
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>Runs the whole archival rule list over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunAsync(EArkValidationContext context) =>
        await RunAsync(context, [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);


    /// <summary>Runs one rule list over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="rules">The rules to run.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunAsync(
        EArkValidationContext context,
        IList<ClaimDelegate<EArkValidationContext>> rules)
    {
        var issuer = new ClaimIssuer<EArkValidationContext>(IssuerId, rules, new FakeTimeProvider(TestClock.CanonicalEpoch));

        return await issuer.GenerateClaimsAsync(context, CorrelationId, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Asserts that no rule of the archival list reported a requirement as broken.</summary>
    /// <param name="result">What the issuer concluded.</param>
    private static void AssertNoRuleFailed(ClaimIssueResult result)
    {
        var failed = new List<string>();
        for(int i = 0; i < result.Claims.Count; ++i)
        {
            if(result.Claims[i].Outcome == ClaimOutcome.Failure)
            {
                failed.Add(result.Claims[i].Id.ToString());
            }
        }

        Assert.IsEmpty(failed, $"The received package broke {failed.Count} requirement(s): {string.Join(", ", failed)}.");
    }


    /// <summary>
    /// Asserts that two claim sets state the same thing about every requirement: the same requirements, each with
    /// the same outcome and the same reason.
    /// </summary>
    /// <param name="expected">What the first package was judged to be.</param>
    /// <param name="actual">What the second package was judged to be.</param>
    private static void AssertSameConclusions(ClaimIssueResult expected, ClaimIssueResult actual)
    {
        Assert.HasCount(expected.Claims.Count, actual.Claims, "The same rule list ran over both packages.");

        for(int i = 0; i < expected.Claims.Count; ++i)
        {
            Claim first = expected.Claims[i];
            Claim second = actual.Claims[i];

            Assert.AreEqual(first.Id.Code, second.Id.Code, "The rules answer in the order they were run.");
            Assert.AreEqual(first.Outcome, second.Outcome,
                $"{first.Id} concluded differently after the provenance was rewritten, which the plain-text rules cannot see.");

            var firstReason = Assert.IsInstanceOfType<EArkClaimContext>(first.Context);
            var secondReason = Assert.IsInstanceOfType<EArkClaimContext>(second.Context);
            Assert.AreEqual(firstReason.Reason, secondReason.Reason, $"{first.Id} reached its outcome for a different reason.");
        }
    }


    /// <summary>Parses a package's own manifest out of a snapshot, without demanding that it parse.</summary>
    /// <param name="snapshot">The package as a value snapshot.</param>
    /// <returns>What the parse concluded. The caller disposes it.</returns>
    private async Task<MetsParseResult> ParseManifestAsync(EArkPackageSnapshot snapshot)
    {
        EArkPackageEntry entry = snapshot.FindEntry(EArkWellKnown.PackageManifestFileName)!;
        using PooledMemory document = PooledMemory.FromBytes(
            entry.Content.AsReadOnlySpan(), BaseMemoryPool.Shared, EArkTags.PackageEntry);

        return await Verifiable.Cryptography.Pki.Xml.MetsXmlBinding.ParseAsync(
            new MetsParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>States a snapshot's entry names, in the snapshot's own order.</summary>
    /// <param name="snapshot">The package as a value snapshot.</param>
    /// <returns>The names.</returns>
    private static List<string> EntryNames(EArkPackageSnapshot snapshot)
    {
        var names = new List<string>(snapshot.Entries.Count);
        for(int i = 0; i < snapshot.Entries.Count; ++i)
        {
            names.Add(snapshot.Entries[i].Name);
        }

        return names;
    }


    /// <summary>Reads every entry's octets out of an archive through the independent raw-ZIP oracle.</summary>
    /// <param name="archive">The archive's octets.</param>
    /// <param name="rootFolderName">The root folder to strip from every name, or <see langword="null"/> to keep names as written.</param>
    /// <returns>The payloads, keyed by entry name.</returns>
    private static Dictionary<string, byte[]> EntryPayloads(byte[] archive, string? rootFolderName)
    {
        OracleZipArchive parsed = AsicZipStructureOracle.Parse(archive);
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        string prefix = rootFolderName is null ? string.Empty : rootFolderName + "/";
        foreach(OracleZipEntry header in parsed.LocalHeaders)
        {
            if(!header.Name.StartsWith(prefix, StringComparison.Ordinal) || header.Name.EndsWith('/'))
            {
                continue;
            }

            payloads[header.Name[prefix.Length..]] = AsicZipStructureOracle.ReadEntryContent(archive, header);
        }

        return payloads;
    }


    /// <summary>Reads one entry's octets out of a package archive through the independent raw-ZIP oracle.</summary>
    /// <param name="archive">The archive's octets.</param>
    /// <param name="rootFolderName">The archive's root folder.</param>
    /// <param name="entryName">The entry name, relative to the root folder.</param>
    /// <returns>The entry's octets.</returns>
    private static byte[] EntryPayload(byte[] archive, string rootFolderName, string entryName) =>
        EntryPayloads(archive, rootFolderName)[entryName];


    /// <summary>Names the <c>ASiCManifest</c> the container's detached signature is taken across.</summary>
    /// <param name="containerEntries">The container's entries.</param>
    /// <param name="signatureEntryName">The signature's entry name.</param>
    /// <returns>The manifest's entry name.</returns>
    private static string ManifestOf(Dictionary<string, byte[]> containerEntries, string signatureEntryName)
    {
        foreach(string name in containerEntries.Keys)
        {
            if(AsicManifestNaming.IsSignatureManifestEntryName(name))
            {
                return name;
            }
        }

        throw new InvalidOperationException($"The container carries no signature manifest for '{signatureEntryName}'.");
    }


    /// <summary>
    /// Rewrites one entry of a package archive, recomputing the archive's own checksums so that what a validator
    /// sees is changed content rather than a broken archive.
    /// </summary>
    /// <param name="message">The message whose archive is rewritten.</param>
    /// <param name="entryName">The entry to rewrite, relative to the package root.</param>
    /// <param name="content">What the entry's octets become.</param>
    /// <returns>The rewritten archive.</returns>
    private static byte[] RewriteEntry(EArkCapstoneWireMessage message, string entryName, byte[] content)
    {
        using PooledMemory rewritten = AsicEvidenceRecordAttaching.ReplaceEntry(
            message.Archive,
            message.RootFolderName + "/" + entryName,
            content,
            TestClock.CanonicalEpoch,
            BaseMemoryPool.Shared);

        return rewritten.AsReadOnlySpan().ToArray();
    }


    /// <summary>Flips one octet of a copy of the supplied content.</summary>
    /// <param name="content">The octets to change.</param>
    /// <returns>The changed copy.</returns>
    private static byte[] Flip(byte[] content)
    {
        byte[] changed = (byte[])content.Clone();
        changed[0] ^= 0x01;

        return changed;
    }


    /// <summary>
    /// Changes one hexadecimal digit of the first checksum a manifest states, leaving a document that is still
    /// well-formed and still states a checksum of the right length under the right algorithm.
    /// </summary>
    /// <param name="manifestOctets">The manifest's octets.</param>
    /// <returns>The changed manifest.</returns>
    private static byte[] ChangeOneChecksumDigit(byte[] manifestOctets)
    {
        string text = Encoding.UTF8.GetString(manifestOctets);
        int marker = text.IndexOf("CHECKSUM=\"", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, marker, "The manifest states a checksum attribute.");

        int valueStart = marker + "CHECKSUM=\"".Length;
        char current = text[valueStart];
        char replacement = current == '0' ? '1' : '0';

        return Encoding.UTF8.GetBytes(string.Concat(text.AsSpan(0, valueStart), replacement.ToString(), text.AsSpan(valueStart + 1)));
    }


    /// <summary>
    /// Rewrites one preservation event's outcome, keeping the document exactly as long as it was so that nothing
    /// but the event's content differs.
    /// </summary>
    /// <param name="provenanceOctets">The provenance document's octets.</param>
    /// <returns>The rewritten document.</returns>
    private static byte[] RewriteEventOutcome(byte[] provenanceOctets)
    {
        string text = Encoding.UTF8.GetString(provenanceOctets);
        Assert.Contains("success", text, StringComparison.Ordinal, "The provenance document records an event outcome to rewrite.");

        return Encoding.UTF8.GetBytes(text.Replace("success", "FAILURE", StringComparison.Ordinal));
    }


    /// <summary>Replaces one piece of text inside a document's octets.</summary>
    /// <param name="octets">The document's octets.</param>
    /// <param name="original">The text to replace.</param>
    /// <param name="replacement">The text to replace it with.</param>
    /// <returns>The rewritten document.</returns>
    private static byte[] ReplaceText(byte[] octets, string original, string replacement)
    {
        string text = Encoding.UTF8.GetString(octets);
        Assert.Contains(original, text, StringComparison.Ordinal, "The document states the text the rewrite replaces.");

        return Encoding.UTF8.GetBytes(text.Replace(original, replacement, StringComparison.Ordinal));
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
    /// <returns><see langword="true"/> when the independent validator accepts the token.</returns>
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


    /// <summary>
    /// Everything that crosses the firewall: the package archive's own octets, the trust anchor's octets, and the
    /// public names and instants a receiving party would be told about the archive it received.
    /// </summary>
    /// <remarks>Deliberately nothing but octets, instants and names — no carrier, no key, no model of the archiving party's.</remarks>
    private sealed record EArkCapstoneWireMessage
    {
        /// <summary>The package as one archive.</summary>
        public required byte[] Archive { get; init; }

        /// <summary>The DER-encoded Root certification authority certificate the verifier is configured to trust.</summary>
        public required byte[] TrustAnchorCertificate { get; init; }

        /// <summary>The name of the root folder the archive unpacks to.</summary>
        public required string RootFolderName { get; init; }

        /// <summary>The entry name the preservation container sits under.</summary>
        public required string ContainerEntryName { get; init; }

        /// <summary>The entry name the digital-provenance document sits under.</summary>
        public required string ProvenanceEntryName { get; init; }

        /// <summary>The container-internal entry name of the detached signature.</summary>
        public required string ContainerSignatureEntryName { get; init; }

        /// <summary>The container-internal entry name of the Evidence Record.</summary>
        public required string ContainerEvidenceRecordEntryName { get; init; }

        /// <summary>The instant the Evidence Record's initial archive time-stamp asserts.</summary>
        public required DateTimeOffset EvidenceRecordArchiveTime { get; init; }

        /// <summary>The instant the verifier validates at.</summary>
        public required DateTimeOffset ValidationTime { get; init; }
    }
}
