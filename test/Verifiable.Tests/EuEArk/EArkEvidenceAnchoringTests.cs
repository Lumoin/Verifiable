using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the archival provenance anchor: binding an Information Package's digital-provenance
/// content into the evidence an Evidence Record covers, which is the cryptographic anchor
/// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> leaves out of its own scope.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The wave's sharpest test lives here, and it asserts both directions.</strong> An archival package's
/// provenance is a chain of preservation events pointing at one another in plain text, and the manifest's stated
/// digests over those documents are plain text too — so a producer that rewrites a provenance document and its
/// stated digest together leaves a package that satisfies every structural, metadata and fixity rule of both
/// specifications. The test below builds exactly that package and asserts <em>both</em> facts about it at once:
/// every plain-text rule still passes, and the evidence over the same octets fails. Either half alone would be
/// half a statement.
/// </para>
/// <para>
/// Nothing here computes a digest, a tree or a time-stamp of its own: the anchor decides which octets, and the
/// shipped Evidence Record surfaces do the rest against a Time-Stamping Authority that signs real tokens.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkEvidenceAnchoringTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The identifier the test issuer states as its own.</summary>
    private const string IssuerId = "eark-anchor-validator";

    /// <summary>The correlation identifier the test issuer carries through a run.</summary>
    private const string CorrelationId = "eark-anchor-validation";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);

    /// <summary>The content a tampered package's provenance document carries instead of the one it was anchored with.</summary>
    private static string TamperedProvenanceContent { get; } =
        "<premis version=\"3.0\"><event><eventType>ingestion-that-never-happened</eventType></event></premis>";

    /// <summary>The artifact octets the anchoring tests place in the package; the anchor itself is the record they build.</summary>
    private static string PlaceholderArtifactContent { get; } = "the package's evidential artifact";


    /// <summary>
    /// A plan names the manifest and every digital-provenance document the manifest references, in that order,
    /// and resolves each against the package the caller handed over.
    /// </summary>
    /// <returns>A task that completes when the plan has been stated.</returns>
    [TestMethod]
    public async Task APlanNamesTheManifestAndEveryProvenanceDocumentItReferences()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);

        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());

        Assert.AreEqual(EArkProvenanceAnchorStatus.Stated, plan.Status);
        Assert.IsTrue(plan.IsStated);
        Assert.IsNull(plan.UnresolvedReference);
        Assert.AreSequenceEqual(
            new[] { EArkWellKnown.PackageManifestFileName, EArkEvidenceSource.ProvenanceEntryName },
            plan.CoveredEntryNames(),
            "The manifest is inside the anchor because the references and their digests live in it.");

        //A plan is a pure function of what it was handed: stating it twice answers the same, and no clock is read.
        EArkProvenanceAnchorPlan again = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());
        Assert.AreSequenceEqual(plan.CoveredEntryNames(), again.CoveredEntryNames());
        Assert.AreEqual(plan.Status, again.Status);
    }


    /// <summary>
    /// Covering the manifest is the default and turning it off is the caller's own statement — an anchor over the
    /// referenced documents alone would leave a producer free to change which documents are referenced.
    /// </summary>
    /// <returns>A task that completes when both plans have been stated.</returns>
    [TestMethod]
    public async Task TheManifestIsInsideTheAnchorByDefaultAndLeavingItOutIsTheCallersStatement()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);

        Assert.IsTrue(package.ToAnchorContext().CoverManifest);

        EArkProvenanceAnchorPlan withoutManifest = EArkEvidenceAnchoring.StatePlan(
            package.ToAnchorContext() with { CoverManifest = false });

        Assert.AreEqual(EArkProvenanceAnchorStatus.Stated, withoutManifest.Status);
        Assert.AreSequenceEqual(new[] { EArkEvidenceSource.ProvenanceEntryName }, withoutManifest.CoveredEntryNames());
    }


    /// <summary>
    /// An entry named twice — by the caller and by a provenance section — is covered once, because a data object
    /// group states each of its members once.
    /// </summary>
    /// <returns>A task that completes when the plan has been stated.</returns>
    [TestMethod]
    public async Task AnEntryNamedTwiceIsCoveredOnce()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);

        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext() with
        {
            AdditionalEntryNames = [EArkEvidenceSource.ProvenanceEntryName, "./" + EArkEvidenceSource.ProvenanceEntryName, EArkWellKnown.PackageManifestFileName],
        });

        Assert.AreEqual(EArkProvenanceAnchorStatus.Stated, plan.Status);
        Assert.AreSequenceEqual(
            new[] { EArkWellKnown.PackageManifestFileName, EArkEvidenceSource.ProvenanceEntryName },
            plan.CoveredEntryNames(),
            "The relative marker names the same entry, and an entry already covered is not covered twice.");
    }


    /// <summary>
    /// A plan that cannot be stated says which way it could not be stated and covers nothing — never a plan over
    /// a subset of what was asked for, which would prove less than the caller believes while looking as though it
    /// proved it.
    /// </summary>
    /// <returns>A task that completes when every refusal has been observed.</returns>
    [TestMethod]
    public async Task APlanThatCannotBeStatedCoversNothingAndSaysWhy()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorContext conformant = package.ToAnchorContext();

        MetsDocument noProvenance = package.Manifest with
        {
            AdministrativeMetadata = package.Manifest.AdministrativeMetadata! with { DigitalProvenanceSections = [] },
        };

        EArkProvenanceAnchorPlan none = EArkEvidenceAnchoring.StatePlan(conformant with { PackageManifest = noProvenance });
        Assert.AreEqual(EArkProvenanceAnchorStatus.NoProvenanceReferenced, none.Status);
        Assert.IsFalse(none.IsStated);
        Assert.IsEmpty(none.CoveredEntries);

        MetsDocument danglingReference = package.Manifest with
        {
            AdministrativeMetadata = package.Manifest.AdministrativeMetadata! with
            {
                DigitalProvenanceSections =
                [
                    package.Manifest.AdministrativeMetadata!.DigitalProvenanceSections[0] with
                    {
                        Reference = EArkValidationSource.Reference("metadata/preservation/absent.xml"),
                    }
                ],
            },
        };

        EArkProvenanceAnchorPlan missing = EArkEvidenceAnchoring.StatePlan(conformant with { PackageManifest = danglingReference });
        Assert.AreEqual(EArkProvenanceAnchorStatus.ReferencedEntryMissing, missing.Status);
        Assert.AreEqual("metadata/preservation/absent.xml", missing.UnresolvedReference);
        Assert.IsEmpty(missing.CoveredEntries);

        EArkProvenanceAnchorPlan manifestMissing = EArkEvidenceAnchoring.StatePlan(
            conformant with { ManifestEntryName = "SomeOtherManifest.xml" });
        Assert.AreEqual(EArkProvenanceAnchorStatus.ManifestMissing, manifestMissing.Status);
        Assert.AreEqual("SomeOtherManifest.xml", manifestMissing.UnresolvedReference);

        EArkProvenanceAnchorPlan overTheLimit = EArkEvidenceAnchoring.StatePlan(conformant with { MaximumCoveredEntries = 1 });
        Assert.AreEqual(EArkProvenanceAnchorStatus.LimitExceeded, overTheLimit.Status);
        Assert.IsEmpty(overTheLimit.CoveredEntries);

        Assert.AreEqual(nameof(EArkProvenanceAnchorStatus.NotEvaluated), Enum.GetName(default(EArkProvenanceAnchorStatus)));
        Assert.AreEqual(
            nameof(EArkProvenanceAnchorVerificationStatus.NotEvaluated),
            Enum.GetName(default(EArkProvenanceAnchorVerificationStatus)));

        Assert.IsFalse(new EArkProvenanceAnchorPlan { Status = default }.IsStated,
            "A default-initialised plan never reads as one that was stated.");

        _ = Assert.Throws<ArgumentException>(() => EArkEvidenceAnchoring.ToDataObjectGroups(none));
        _ = Assert.Throws<ArgumentException>(() => EArkEvidenceAnchoring.ToDataObjects(none));
        _ = Assert.Throws<ArgumentException>(() => EArkEvidenceAnchoring.ToContainerDataObjects(none));
    }


    /// <summary>
    /// The plan's entries become ONE data object group, because clause 4.2 of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">IETF RFC 4998</see> makes a group's members
    /// "proved to have existed together" and that togetherness is the whole statement a provenance chain needs.
    /// </summary>
    /// <returns>A task that completes when the group has been stated.</returns>
    [TestMethod]
    public async Task ThePlansEntriesBecomeOneDataObjectGroup()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());

        List<EvidenceRecordDataObjectGroup> groups = EArkEvidenceAnchoring.ToDataObjectGroups(plan);
        Assert.HasCount(1, groups, "A provenance chain proved document by document, each at a time of its own, is not a chain.");
        Assert.HasCount(plan.CoveredEntries.Count, groups[0].DataObjects);

        List<ReadOnlyMemory<byte>> objects = EArkEvidenceAnchoring.ToDataObjects(plan);
        for(int i = 0; i < objects.Count; ++i)
        {
            Assert.IsTrue(
                objects[i].Span.SequenceEqual(plan.CoveredEntries[i].Content.AsReadOnlySpan()),
                "The octets are views into the snapshot, in the plan's own order.");
        }

        List<AsicDataObject> containerObjects = EArkEvidenceAnchoring.ToContainerDataObjects(plan);
        Assert.HasCount(plan.CoveredEntries.Count, containerObjects);
        for(int i = 0; i < containerObjects.Count; ++i)
        {
            Assert.AreEqual(plan.CoveredEntries[i].Name, containerObjects[i].Name,
                "The container route carries the same octets under the same names; the two anchors differ in what a package ends up holding, not in what is proven.");
        }
    }


    /// <summary>
    /// A package whose provenance was anchored and has not moved since verifies as anchored, entry by entry.
    /// </summary>
    /// <returns>A task that completes when the anchor has been verified.</returns>
    [TestMethod]
    public async Task APackageWhoseProvenanceWasAnchoredVerifiesAsAnchored()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());

        using EvidenceRecordCreation creation = await EArkEvidenceSource.CreateProvenanceEvidenceAsync(
            plan, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, creation.EvidenceRecords, "One group, one record.");

        using EArkProvenanceAnchorVerification verification = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = creation.EvidenceRecords[0],
                Package = package.ToAnchorContext(),
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.Anchored, verification.Status);
        Assert.IsTrue(verification.IsAnchored);
        Assert.IsNull(verification.UncoveredEntryName);
        Assert.HasCount(plan.CoveredEntries.Count, verification.Verifications);

        for(int i = 0; i < verification.Verifications.Count; ++i)
        {
            Assert.AreEqual(EvidenceRecordVerificationStatus.Verified, verification.Verifications[i].Status,
                $"Every covered entry is verified, not one — '{plan.CoveredEntries[i].Name}' was not.");
        }
    }


    /// <summary>
    /// <strong>Both directions, in one test.</strong> A package whose provenance document was rewritten together
    /// with the digest the manifest states over it is judged <em>identically</em> by every plain-text rule the
    /// two specifications have — claim for claim, outcome for outcome, reason for reason, including the fixity
    /// recomputation and the archival provenance rows — while the evidence created over those same octets fails
    /// and names the document that moved. The plain-text chain alone proves nothing; the anchor is what proves
    /// anything at all.
    /// </summary>
    /// <returns>A task that completes when both halves have been asserted.</returns>
    [TestMethod]
    public async Task TamperingWithTheProvenanceBreaksTheEvidenceWhileEveryPlainTextRuleReachesTheSameConclusion()
    {
        using EArkEvidencePackage anchored = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(anchored.ToAnchorContext());

        using EvidenceRecordCreation creation = await EArkEvidenceSource.CreateProvenanceEvidenceAsync(
            plan, TestContext.CancellationToken).ConfigureAwait(false);

        //The same package with one preservation event rewritten and the manifest's digest over it rewritten to
        //match — which is precisely what a producer able to edit the package would do.
        using EArkEvidencePackage tampered = await BuildPackageAsync(TamperedProvenanceContent).ConfigureAwait(false);

        Assert.IsFalse(
            anchored.Snapshot.FindEntry(EArkEvidenceSource.ProvenanceEntryName)!.Content.AsReadOnlySpan()
                .SequenceEqual(tampered.Snapshot.FindEntry(EArkEvidenceSource.ProvenanceEntryName)!.Content.AsReadOnlySpan()),
            "The two packages really do hold different provenance octets, so nothing below is vacuous.");

        //Direction one: every plain-text rule reaches the same conclusion on both packages, so nothing either
        //specification states notices that a preservation event was rewritten.
        ClaimIssueResult beforeTampering = await RunAsync(
            anchored.ToValidationContext(), [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        ClaimIssueResult afterTampering = await RunAsync(
            tampered.ToValidationContext(), [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        AssertSameConclusions(beforeTampering, afterTampering);

        //Named individually as well, because these are the rows a reader would expect to catch it: the fixity the
        //manifest states over the document, the reference that names it, and the archival provenance pointer.
        EArkStructuralRuleTests.AssertOutcome(afterTampering, EArkClaimIds.PackageReferencesResolve, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(afterTampering, AipClaimIds.Aipm5, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(afterTampering, AipClaimIds.Aipm6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(afterTampering, AipClaimIds.Aipm7, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //Direction two: the evidence over the same octets fails, and it names what moved.
        EArkProvenanceAnchorPlan tamperedPlan = EArkEvidenceAnchoring.StatePlan(tampered.ToAnchorContext());
        Assert.AreSequenceEqual(plan.CoveredEntryNames(), tamperedPlan.CoveredEntryNames(),
            "The two packages name the same entries, so what differs is the octets and nothing else.");

        using EArkProvenanceAnchorVerification verification = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = creation.EvidenceRecords[0],
                Package = tampered.ToAnchorContext(),
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.ProvenanceNotCovered, verification.Status);
        Assert.IsFalse(verification.IsAnchored);
        Assert.IsNotNull(verification.UncoveredEntryName);

        int provenanceIndex = tamperedPlan.CoveredEntryNames().IndexOf(EArkEvidenceSource.ProvenanceEntryName);
        Assert.IsGreaterThanOrEqualTo(0, provenanceIndex);
        Assert.AreNotEqual(
            EvidenceRecordVerificationStatus.Verified,
            verification.Verifications[provenanceIndex].Status,
            "The document that was rewritten is not inside what the evidence proves.");

        //And the untampered package still verifies against the same record, so what failed is the tampering and
        //not the evidence.
        using EArkProvenanceAnchorVerification original = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = creation.EvidenceRecords[0],
                Package = anchored.ToAnchorContext(),
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.Anchored, original.Status);
    }


    /// <summary>
    /// A document added to what the anchor covers breaks it too, which is what the group check is for: altering
    /// one covered document fails that document's own walk, and adding or removing one fails every member's.
    /// </summary>
    /// <returns>A task that completes when the enlarged group has been verified.</returns>
    [TestMethod]
    public async Task ADocumentAddedToTheCoveredSetFailsTheGroupCheck()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());

        using EvidenceRecordCreation creation = await EArkEvidenceSource.CreateProvenanceEvidenceAsync(
            plan, TestContext.CancellationToken).ConfigureAwait(false);

        EArkProvenanceAnchorContext enlarged = package.ToAnchorContext() with
        {
            AdditionalEntryNames = ["metadata/descriptive/EAD.xml"],
        };

        EArkProvenanceAnchorPlan enlargedPlan = EArkEvidenceAnchoring.StatePlan(enlarged);
        Assert.HasCount(plan.CoveredEntries.Count + 1, enlargedPlan.CoveredEntries);

        using EArkProvenanceAnchorVerification verification = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = creation.EvidenceRecords[0],
                Package = enlarged,
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.ProvenanceNotCovered, verification.Status);
        Assert.IsNotNull(verification.UncoveredEntryName);
    }


    /// <summary>
    /// A package no plan can be stated from is reported as such rather than as an unanchored one — the two are
    /// different facts, and neither reads as anchored.
    /// </summary>
    /// <returns>A task that completes when the verification has been performed.</returns>
    [TestMethod]
    public async Task APackageNoPlanCanBeStatedFromIsReportedAsSuchAndNeverAsAnchored()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());

        using EvidenceRecordCreation creation = await EArkEvidenceSource.CreateProvenanceEvidenceAsync(
            plan, TestContext.CancellationToken).ConfigureAwait(false);

        MetsDocument noProvenance = package.Manifest with
        {
            AdministrativeMetadata = package.Manifest.AdministrativeMetadata! with { DigitalProvenanceSections = [] },
        };

        using EArkProvenanceAnchorVerification verification = await EArkEvidenceAnchoring.VerifyProvenanceAnchorAsync(
            new EArkProvenanceAnchorVerificationContext
            {
                EvidenceRecord = creation.EvidenceRecords[0],
                Package = package.ToAnchorContext() with { PackageManifest = noProvenance },
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EArkProvenanceAnchorVerificationStatus.PlanNotStated, verification.Status);
        Assert.IsFalse(verification.IsAnchored);
        Assert.IsEmpty(verification.Verifications);
        Assert.AreEqual(EArkProvenanceAnchorStatus.NoProvenanceReferenced, verification.Plan!.Status);
    }


    /// <summary>
    /// The anchor rule reads whether the package's provenance is inside what one of its artifacts proves: met
    /// when the evidence verifies the package's own octets, declined when no artifact even names them, and never
    /// triggered when the package references no provenance at all.
    /// </summary>
    /// <returns>A task that completes when all three shapes have been validated.</returns>
    /// <remarks>
    /// The met shape states the Evidence Record the coverage rests on, because that is what the rule decides
    /// from. A shape stating names alone is the subject of
    /// <see cref="CoverageStatedWithoutTheEvidenceItRestsOnLeavesTheAnchorRowUndecided"/>, and a shape whose
    /// names still match after the octets moved is the subject of
    /// <see cref="AProvenanceRewrittenAfterTheAnchorFailsTheRuleAlthoughEveryCoveredNameStillMatches"/>.
    /// </remarks>
    [TestMethod]
    public async Task TheAnchorRuleReadsWhetherTheProvenanceIsInsideWhatAnArtifactProves()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());

        using EvidenceRecordCreation creation = await EArkEvidenceSource.CreateProvenanceEvidenceAsync(
            plan, TestContext.CancellationToken).ConfigureAwait(false);

        EArkValidationContext anchoredContext = package.ToValidationContext() with
        {
            EvidenceArtifacts =
            [
                package.Artifact with
                {
                    CoveredEntryNames = plan.CoveredEntryNames(),
                    Evidence = creation.EvidenceRecords[0],
                }
            ],
        };

        ClaimIssueResult anchored = await RunAsync(anchoredContext, [.. EArkValidationProfiles.EvidencePlacementRules()]).ConfigureAwait(false);
        EArkStructuralRuleTests.AssertOutcome(anchored, EArkClaimIds.PackageProvenanceAnchored, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        ClaimIssueResult unanchored = await RunAsync(package.ToValidationContext(), [.. EArkValidationProfiles.EvidencePlacementRules()]).ConfigureAwait(false);
        EArkStructuralRuleTests.AssertOutcome(unanchored, EArkClaimIds.PackageProvenanceAnchored, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);

        MetsDocument noProvenance = package.Manifest with
        {
            AdministrativeMetadata = package.Manifest.AdministrativeMetadata! with { DigitalProvenanceSections = [] },
        };

        ClaimIssueResult nothingToAnchor = await RunAsync(
            package.ToValidationContext() with { PackageManifest = noProvenance },
            [.. EArkValidationProfiles.EvidencePlacementRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(nothingToAnchor, EArkClaimIds.PackageProvenanceAnchored, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
    }


    /// <summary>
    /// <strong>The adversarial case the name comparison cannot see.</strong> A producer rewrites a preservation
    /// event and the manifest's digest over it, and states exactly the coverage the honest package stated — the
    /// same entry names, in the same order, because the plan is a function of the manifest and the manifest still
    /// names the same documents. The anchor rule must nevertheless refuse the rewritten package, because the
    /// question it answers is about octets and the only thing that answers it is the evidence.
    /// </summary>
    /// <returns>A task that completes when both packages have been judged.</returns>
    /// <remarks>
    /// The control matters as much as the case: the same Evidence Record is stated for the honest package, whose
    /// claim reads met. Without it a rule that refused everything would pass this test.
    /// </remarks>
    [TestMethod]
    public async Task AProvenanceRewrittenAfterTheAnchorFailsTheRuleAlthoughEveryCoveredNameStillMatches()
    {
        using EArkEvidencePackage anchored = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(anchored.ToAnchorContext());

        using EvidenceRecordCreation creation = await EArkEvidenceSource.CreateProvenanceEvidenceAsync(
            plan, TestContext.CancellationToken).ConfigureAwait(false);

        using EArkEvidencePackage rewritten = await BuildPackageAsync(TamperedProvenanceContent).ConfigureAwait(false);

        //The two packages really do differ in their octets and really do not differ in their names, which is what
        //makes a name comparison unable to tell them apart.
        Assert.IsFalse(
            anchored.Snapshot.FindEntry(EArkEvidenceSource.ProvenanceEntryName)!.Content.AsReadOnlySpan()
                .SequenceEqual(rewritten.Snapshot.FindEntry(EArkEvidenceSource.ProvenanceEntryName)!.Content.AsReadOnlySpan()),
            "The two packages hold different provenance octets, so nothing below is vacuous.");

        List<string> coveredNames = plan.CoveredEntryNames();
        Assert.AreSequenceEqual(
            coveredNames,
            EArkEvidenceAnchoring.StatePlan(rewritten.ToAnchorContext()).CoveredEntryNames(),
            "The rewritten package names exactly what the honest one names.");

        EArkEvidenceArtifactFacts statedAnchor = anchored.Artifact with
        {
            CoveredEntryNames = coveredNames,
            Evidence = creation.EvidenceRecords[0],
        };

        ClaimIssueResult rewrittenClaims = await RunAsync(
            rewritten.ToValidationContext() with { EvidenceArtifacts = [statedAnchor] },
            [.. EArkValidationProfiles.EvidencePlacementRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            rewrittenClaims,
            EArkClaimIds.PackageProvenanceAnchored,
            ClaimOutcome.Inconclusive,
            EArkClaimReason.RecommendedRequirementUnmet);

        ClaimIssueResult honestClaims = await RunAsync(
            anchored.ToValidationContext() with { EvidenceArtifacts = [statedAnchor] },
            [.. EArkValidationProfiles.EvidencePlacementRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            honestClaims,
            EArkClaimIds.PackageProvenanceAnchored,
            ClaimOutcome.Success,
            EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A caller that states coverage and no evidence to verify it against leaves the anchor row undecided rather
    /// than met — the fail-closed reading of a fact nothing in the package establishes.
    /// </summary>
    /// <returns>A task that completes when the package has been judged.</returns>
    /// <remarks>
    /// The names come from a plan stated over the package's own manifest, which is exactly the shape a caller
    /// reaches for first, and it is the shape that proves nothing at all: the package produced both the manifest
    /// and the plan.
    /// </remarks>
    [TestMethod]
    public async Task CoverageStatedWithoutTheEvidenceItRestsOnLeavesTheAnchorRowUndecided()
    {
        using EArkEvidencePackage package = await BuildPackageAsync().ConfigureAwait(false);
        EArkProvenanceAnchorPlan plan = EArkEvidenceAnchoring.StatePlan(package.ToAnchorContext());

        EArkValidationContext context = package.ToValidationContext() with
        {
            EvidenceArtifacts = [package.Artifact with { CoveredEntryNames = plan.CoveredEntryNames() }],
        };

        ClaimIssueResult claims = await RunAsync(context, [.. EArkValidationProfiles.EvidencePlacementRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            claims,
            EArkClaimIds.PackageProvenanceAnchored,
            ClaimOutcome.Inconclusive,
            EArkClaimReason.SubjectNotSupplied);
    }


    /// <summary>
    /// Asserts that two claim sets state the same thing about every requirement: the same requirements, each
    /// with the same outcome and the same reason.
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


    /// <summary>
    /// Builds one package carrying one evidential artifact placed by the convention, optionally with a provenance
    /// document other than the one the anchored package holds.
    /// </summary>
    /// <param name="provenanceContent">The provenance document's octets, or <see langword="null"/> for the default.</param>
    /// <returns>The package. The caller owns and disposes it.</returns>
    private async Task<EArkEvidencePackage> BuildPackageAsync(string? provenanceContent = null)
    {
        string entryName = EArkEvidenceSource.EntryNameFor(EArkEvidenceKind.EvidenceRecord);
        var facts = new EArkEvidenceArtifactFacts
        {
            Kind = EArkEvidenceKind.EvidenceRecord,
            EntryName = entryName,
            SelfDescription = EArkEvidenceSource.SelfDescription,
            SelfDescriptionCarrier = EArkEvidenceSelfDescriptionCarrier.ArchiveTimeStampAttributes,
            SelfDescriptionIsProtected = true,
        };

        return await EArkEvidenceSource.BuildAsync(
            Encoding.UTF8.GetBytes(PlaceholderArtifactContent),
            facts,
            TestContext.CancellationToken,
            provenanceContent: provenanceContent).ConfigureAwait(false);
    }


    /// <summary>Runs one rule list over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="rules">The rules to run.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunAsync(
        EArkValidationContext context,
        IList<ClaimDelegate<EArkValidationContext>> rules)
    {
        var issuer = new ClaimIssuer<EArkValidationContext>(IssuerId, rules, IssuerTime);

        return await issuer.GenerateClaimsAsync(context, CorrelationId, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
