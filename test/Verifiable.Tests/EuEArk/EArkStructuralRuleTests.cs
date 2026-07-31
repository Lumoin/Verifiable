using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the folder-structure rules of
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
/// 4.1</see>, <c>CSIPSTR1</c> to <c>CSIPSTR16</c>, over the classified package facts.
/// </summary>
/// <remarks>
/// <para>
/// The catalogue's sharp edge is what these tests are mostly about: only <c>CSIPSTR1</c> and <c>CSIPSTR4</c> are
/// MUSTs. A minimal package holding nothing but its manifest is conformant, and every folder rule it declines
/// reports a deviation rather than a failure — so a test that asserted "a package without representations is
/// invalid" would be asserting a requirement the specification does not state.
/// </para>
/// <para>
/// Every assertion here reads both halves of a claim: the outcome, and the reason the claim carries. Two
/// different findings reach <see cref="ClaimOutcome.Inconclusive"/> — a package that declined a recommendation
/// and a rule the caller gave nothing to judge — and a test that only read the outcome could not tell them
/// apart, which is exactly the confusion the reason exists to remove.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkStructuralRuleTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier the test issuer states as its own.</summary>
    private const string IssuerId = "eark-structural-validator";

    /// <summary>The correlation identifier the test issuer carries through a run.</summary>
    private const string CorrelationId = "eark-structural-validation";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);

    /// <summary>The name a conformant archived package unpacks to, which is its own package identifier.</summary>
    private static string RootFolder { get; } = EArkValidationSource.PortablePackageIdentifier;


    /// <summary>
    /// A package filling every position the catalogue names satisfies all sixteen rows: the two MUSTs, the
    /// eleven SHOULDs and the three permissions it exercised.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AConformantPackageSatisfiesEveryFolderRequirement()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            EArkValidationSource.ConformantPackageEntries(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        //Every folder position the catalogue names is filled, and the extension permission was not exercised.
        AssertOutcome(result, EArkClaimIds.CsipStr4, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr5, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr7, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr8, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr9, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr10, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr11, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr12, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr13, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr14, ClaimOutcome.NotApplicable, EArkClaimReason.OptionalSubjectAbsent);
        AssertOutcome(result, EArkClaimIds.CsipStr15, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr16, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //Nothing failed, so the assessor's conclusion is that the package conforms.
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// The minimal package the catalogue admits — a root folder holding nothing but the manifest — fails
    /// nothing at all. Every folder rule it declines is a recommendation it may decline, and the specification
    /// says so by stating fourteen of the sixteen rows as SHOULD or MAY.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task TheMinimalPackageFailsNothing()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
        AssertOutcome(result, EArkClaimIds.CsipStr4, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr5, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        AssertOutcome(result, EArkClaimIds.CsipStr9, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        AssertOutcome(result, EArkClaimIds.CsipStr15, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);

        //With no representations, the four per-representation rows have no subject at all rather than an unmet one.
        AssertOutcome(result, EArkClaimIds.CsipStr10, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        AssertOutcome(result, EArkClaimIds.CsipStr11, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        AssertOutcome(result, EArkClaimIds.CsipStr12, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        AssertOutcome(result, EArkClaimIds.CsipStr13, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);

        //The manifest of this fixture states both a descriptive section and a PREMIS provenance section, so
        //both metadata antecedents hold and the two folder rows really are departures rather than untriggered.
        AssertOutcome(result, EArkClaimIds.CsipStr6, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        AssertOutcome(result, EArkClaimIds.CsipStr7, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
    }


    /// <summary>
    /// The two metadata-folder rows are conditional and are issued as conditional: the requirements read "If
    /// preservation metadata are available, they SHOULD be included in sub-folder preservation" and "If
    /// descriptive metadata are available, they SHOULD be included in sub-folder descriptive"
    /// (<see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0
    /// clause 4.1</see>, <c>CSIPSTR6</c> and <c>CSIPSTR7</c>), so a package that has no such metadata at all
    /// never triggered either requirement and cannot have departed from one.
    /// </summary>
    /// <remarks>
    /// The specification's own minimal example is exactly this package: a manifest carrying <c>metsHdr</c>,
    /// <c>fileSec</c> and <c>structMap</c> and neither a <c>dmdSec</c> nor an <c>amdSec</c>. Reading the rows
    /// unconditionally made that package indistinguishable, claim for claim, from one that holds preservation
    /// metadata and files it in the wrong folder — same identifier, same outcome, same reason, same subject.
    /// </remarks>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task TheMetadataFolderRowsBindOnlyWhenTheMetadataExists()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("METS.xml", "<mets/>")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        using MetsDocument withoutMetadata = ManifestWithoutMetadataSections();

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        ClaimIssueResult result = await RunAsync(ContextFor(facts, withoutMetadata)).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr6, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        AssertOutcome(result, EArkClaimIds.CsipStr7, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));

        //A package whose manifest states the metadata and whose tree does not hold the folder is the shape the
        //untriggered one has to stay distinguishable from.
        using MetsDocument withMetadata = EArkValidationSource.ConformantManifest();
        ClaimIssueResult misplaced = await RunAsync(ContextFor(facts, withMetadata)).ConfigureAwait(false);

        AssertOutcome(misplaced, EArkClaimIds.CsipStr6, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        AssertOutcome(misplaced, EArkClaimIds.CsipStr7, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);

        //With no manifest at all the rules say they were given nothing, which is the third answer the shape
        //admits and the one an unconditional presence test can never reach.
        ClaimIssueResult unsupplied = await RunAsync(ContextFor(facts, manifest: null)).ConfigureAwait(false);

        AssertOutcome(unsupplied, EArkClaimIds.CsipStr6, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        AssertOutcome(unsupplied, EArkClaimIds.CsipStr7, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);

        //A conformant manifest with both metadata sections taken out of it, which is the shape the
        //specification's own minimal example has. Ownership of everything in it transfers to the caller.
        static MetsDocument ManifestWithoutMetadataSections()
        {
            MetsDocument conformant = EArkValidationSource.ConformantManifest();

            return conformant with
            {
                DescriptiveMetadataSections = [],
                AdministrativeMetadata = conformant.AdministrativeMetadata! with { DigitalProvenanceSections = [] }
            };
        }
    }


    /// <summary>
    /// A package missing its root manifest fails the one folder MUST that a package built from stated entries
    /// can fail, and fails nothing else.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task APackageWithoutItsRootManifestFailsTheOnlyFolderMustItCan()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile("representations/rep1/data/record.bin", "the bits themselves")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr4, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        Assert.AreEqual(1, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A representation missing one of the three folders the catalogue recommends inside it reports exactly
    /// that recommendation as unmet, and the two it holds as met — the rule reads every representation rather
    /// than the first.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task ASecondRepresentationMissingItsRecommendedFoldersIsReportedByItself()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [
                EArkPackageSource.TextFile("METS.xml", "<mets/>"),
                EArkPackageSource.TextFile("representations/rep1/METS.xml", "<mets/>"),
                EArkPackageSource.TextFile("representations/rep1/metadata/summary.txt", "about rep1"),
                EArkPackageSource.TextFile("representations/rep1/data/record.bin", "the bits themselves"),
                EArkPackageSource.TextFile("representations/rep2/data/record.bin", "a second representation"),
            ],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        //Both representations carry a data folder; only the first carries a manifest and a metadata folder.
        AssertOutcome(result, EArkClaimIds.CsipStr11, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr12, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        AssertOutcome(result, EArkClaimIds.CsipStr13, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A file sitting directly under the representations folder, where the catalogue puts one sub-folder per
    /// representation, is reported as a deviation from <c>CSIPSTR10</c> rather than passed over.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AFileDirectlyUnderTheRepresentationsFolderDeviatesFromTheOneSubFolderRule()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [
                EArkPackageSource.TextFile("METS.xml", "<mets/>"),
                EArkPackageSource.TextFile("representations/stray.txt", "a file where a folder belongs"),
                EArkPackageSource.TextFile("representations/rep1/data/record.bin", "the bits themselves"),
            ],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr10, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
    }


    /// <summary>
    /// A folder the catalogue names no position for is the extension point <c>CSIPSTR14</c> expressly admits,
    /// so a package carrying one succeeds rather than deviating.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AFolderTheCatalogueNamesNoPositionForExercisesTheExtensionPermission()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            [
                EArkPackageSource.TextFile("METS.xml", "<mets/>"),
                EArkPackageSource.TextFile("houseconvention/notes.txt", "a folder of this archive's own"),
            ],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr14, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// An archived package unpacking to a single root folder named with the package's own identifier satisfies
    /// <c>CSIPSTR1</c>, <c>CSIPSTR2</c> and <c>CSIPSTR3</c> at once — the three rows only an archived package
    /// has a subject for.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AnArchivedPackageUnderItsOwnIdentifierSatisfiesTheRootFolderRows()
    {
        using PooledMemory archive = EArkPackageSource.WriteArchive(
            EArkValidationSource.ConformantPackageEntries(),
            RootFolder,
            EArkValidationSource.Instant,
            BaseMemoryPool.Shared);

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead);
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest(objectIdentifier: RootFolder);

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr1, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr2, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr3, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A package whose identifier is a uniform resource name cannot follow the root-folder naming
    /// recommendation inside an archive at all: the colon a URN carries is a volume qualifier on some file
    /// systems, and every entry-name rule in this repository refuses it before an archive can be written.
    /// </summary>
    /// <remarks>
    /// The tension is between two requirements, not a defect in either: the naming recommendation says to use
    /// the package identifier, and the reference material's own worked packages state that identifier as a
    /// URN. A package writer that wants both has to derive a portable folder name from the identifier — the
    /// same derivation the archival specification asks for by name in its own file-naming rows — and the
    /// recommendation then reports as a deviation rather than as met.
    /// </remarks>
    [TestMethod]
    public void APackageIdentifierThatIsAUniformResourceNameCannotNameAnArchiveRootFolder()
    {
        var refused = Assert.Throws<AsicZipAuthoringException>(() => EArkPackageSource.WriteArchive(
            EArkValidationSource.ConformantPackageEntries(),
            EArkValidationSource.UrnPackageIdentifier,
            EArkValidationSource.Instant,
            BaseMemoryPool.Shared));

        Assert.Contains(EArkValidationSource.UrnPackageIdentifier, refused.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// An archived package unpacking to a root folder named something other than its own identifier deviates
    /// from the naming recommendation without failing anything.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AnArchivedPackageUnderSomeOtherNameDeviatesFromTheNamingRecommendation()
    {
        using PooledMemory archive = EArkPackageSource.WriteArchive(
            EArkValidationSource.ConformantPackageEntries(),
            "a-folder-named-something-else",
            EArkValidationSource.Instant,
            BaseMemoryPool.Shared);

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive.AsReadOnlyMemory(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr1, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        AssertOutcome(result, EArkClaimIds.CsipStr2, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// A package stated entry by entry rather than unpacked from an archive gives the two root-folder-name rows
    /// no subject: it did not arrive under a folder of its own, so the recommendation to name that folder and
    /// the permission to archive it are not applicable rather than unmet.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AStatedPackageGivesTheArchiveRowsNoSubject()
    {
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            EArkValidationSource.ConformantPackageEntries(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(ContextFor(facts, manifest)).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr2, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        AssertOutcome(result, EArkClaimIds.CsipStr3, ClaimOutcome.NotApplicable, EArkClaimReason.OptionalSubjectAbsent);
    }


    /// <summary>
    /// A caller that classified no package gets every facts-reading row reported as undecided for want of a
    /// subject, and never as a package defect — the distinction the claim reason exists to carry.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task WithoutClassifiedFactsEveryFactsReadingRowSaysSoRatherThanFailing()
    {
        var context = new EArkValidationContext
        {
            EntryNames = ["METS.xml"],
            CurrentTime = EArkValidationSource.Instant,
        };

        ClaimIssueResult result = await RunAsync(context).ConfigureAwait(false);

        AssertOutcome(result, EArkClaimIds.CsipStr1, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        AssertOutcome(result, EArkClaimIds.CsipStr2, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        AssertOutcome(result, EArkClaimIds.CsipStr9, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        AssertOutcome(result, EArkClaimIds.CsipStr14, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        AssertOutcome(result, EArkClaimIds.CsipStr16, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);

        //The three rows a name snapshot alone answers still answer.
        AssertOutcome(result, EArkClaimIds.CsipStr4, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(result, ClaimOutcome.Failure));
    }


    /// <summary>
    /// The two assessors differ on exactly the undecided claims: the reading the specification states calls a
    /// partly-assessed package conformant, and the stricter reading a caller adopts when it has supplied every
    /// document does not.
    /// </summary>
    /// <returns>A task that completes when both assessments have run.</returns>
    [TestMethod]
    public async Task TheTwoAssessorsDifferOnlyOnTheUndecidedClaims()
    {
        var context = new EArkValidationContext
        {
            EntryNames = ["METS.xml"],
            CurrentTime = EArkValidationSource.Instant,
        };

        ClaimIssueResult result = await RunAsync(context).ConfigureAwait(false);

        AssessmentResult specificationReading = await EArkAssessors.ConformantPackageAssessorAsync(
            result,
            IssuerId,
            EArkValidationSource.Instant.UtcDateTime,
            traceId: null,
            spanId: null,
            baggage: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        AssessmentResult stricterReading = await EArkAssessors.FullyAssessedPackageAssessorAsync(
            result,
            IssuerId,
            EArkValidationSource.Instant.UtcDateTime,
            traceId: null,
            spanId: null,
            baggage: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(specificationReading.IsSuccess);
        Assert.IsFalse(stricterReading.IsSuccess);
        Assert.IsGreaterThan(0, EArkAssessors.CountReason(result, EArkClaimReason.SubjectNotSupplied));
    }


    /// <summary>
    /// The claim set an assessment's conclusion was folded from cannot be changed after the fold: the
    /// assessment carries a snapshot of its own, so a holder of the issuer's list adding a failed claim to it
    /// leaves the assessment's evidence exactly as it was judged.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="EArkAssessors"/> opens by stating that the conclusion is a fold over the claims and that
    /// anyone holding the claim set can recompute it. That property is only worth stating if the claim set the
    /// assessment carries is the one the boolean was computed from — an evidence list that keeps changing
    /// underneath a stored conclusion makes the recomputation disagree with the record, which is the one thing
    /// an audit trail must not do.
    /// </para>
    /// <para>
    /// Both halves are asserted: the assessment does not see a mutation of the issuer's list (it holds a copy),
    /// and the assessment's own list refuses to be mutated in place (the copy is read-only).
    /// </para>
    /// </remarks>
    /// <returns>A task that completes when the assessment has run.</returns>
    [TestMethod]
    public async Task MutatingTheIssuedClaimsAfterTheFoldLeavesTheAssessmentsEvidenceUnchanged()
    {
        var context = new EArkValidationContext
        {
            EntryNames = ["METS.xml"],
            CurrentTime = EArkValidationSource.Instant,
        };

        ClaimIssueResult issued = await RunAsync(context).ConfigureAwait(false);
        int issuedClaimCount = issued.Claims.Count;

        AssessmentResult assessed = await EArkAssessors.ConformantPackageAssessorAsync(
            issued,
            IssuerId,
            EArkValidationSource.Instant.UtcDateTime,
            traceId: null,
            spanId: null,
            baggage: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(assessed.IsSuccess);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(assessed.ClaimsResult, ClaimOutcome.Failure));

        //A holder of the issuer's own list adds a failed MUST after the conclusion was folded. Re-running the
        //documented fold over the assessment's claim set has to keep answering what the stored boolean says.
        issued.Claims.Add(new Claim(
            EArkClaimIds.CsipStr1,
            ClaimOutcome.Failure,
            new EArkClaimContext(EArkClaimReason.MandatoryRequirementUnmet, "a claim added after the fold"),
            Claim.NoSubClaims));

        Assert.HasCount(
            issuedClaimCount,
            assessed.ClaimsResult.Claims,
            "The assessment's evidence grew after its conclusion was folded, so it no longer holds the claim set it judged.");
        Assert.AreEqual(
            0,
            EArkAssessors.CountOutcome(assessed.ClaimsResult, ClaimOutcome.Failure),
            "Re-running the fold over the assessment's own claim set contradicts the boolean the assessment stored.");

        //And the snapshot is not merely a copy that could be edited in its turn.
        Assert.Throws<NotSupportedException>(() => assessed.ClaimsResult.Claims.Clear());
        Assert.HasCount(issuedClaimCount, assessed.ClaimsResult.Claims);
    }


    /// <summary>
    /// The two assessors read an undecided claim exactly as their remarks state: the specification's own
    /// reading concludes on failed requirements alone, so a claim set holding nothing but undecided and
    /// departed-from rows reads as conformance there, while the stricter reading refuses it — and refuses it
    /// only for the claims whose subject was never supplied, never for a departure from a recommendation.
    /// </summary>
    /// <remarks>
    /// The claim set is stated here rather than issued by a rule list, so the three cases separate cleanly:
    /// a deviation from a recommendation, a rule that was given nothing to judge, and the two together. It is
    /// the behavioural pin for the paragraph of <see cref="EArkAssessors.ConformantPackageAssessorAsync"/>
    /// that says which of the two assessors insists on an answered catalogue.
    /// </remarks>
    /// <returns>A task that completes when the assessments have run.</returns>
    [TestMethod]
    public async Task AnUndecidedClaimReadsAsConformanceUnderTheSpecificationsOwnReadingAndNotUnderTheStricterOne()
    {
        Claim departure = new(
            EArkClaimIds.CsipStr2,
            ClaimOutcome.Inconclusive,
            new EArkClaimContext(EArkClaimReason.RecommendedRequirementUnmet, "the root folder's name"),
            Claim.NoSubClaims);

        Claim undecided = new(
            EArkClaimIds.CsipStr1,
            ClaimOutcome.Inconclusive,
            new EArkClaimContext(EArkClaimReason.SubjectNotSupplied, "no classified package"),
            Claim.NoSubClaims);

        //A departure from a recommendation is not a failure under either reading: reading a SHOULD as a MUST
        //is a thing no policy may do on the specification's behalf.
        Assert.IsTrue((await SpecificationReadingOfAsync([departure]).ConfigureAwait(false)).IsSuccess);
        Assert.IsTrue((await StricterReadingOfAsync([departure]).ConfigureAwait(false)).IsSuccess);

        //A rule the caller gave nothing to judge is where the two readings part.
        Assert.IsTrue((await SpecificationReadingOfAsync([undecided]).ConfigureAwait(false)).IsSuccess);
        Assert.IsFalse((await StricterReadingOfAsync([undecided]).ConfigureAwait(false)).IsSuccess);

        AssessmentResult both = await SpecificationReadingOfAsync([departure, undecided]).ConfigureAwait(false);
        Assert.IsTrue(both.IsSuccess);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(both.ClaimsResult, ClaimOutcome.Failure));
        Assert.AreEqual(1, EArkAssessors.CountReason(both.ClaimsResult, EArkClaimReason.SubjectNotSupplied));
        Assert.IsFalse((await StricterReadingOfAsync([departure, undecided]).ConfigureAwait(false)).IsSuccess);
    }


    /// <summary>
    /// Every rule of the structural profile answers with exactly one claim, whatever it was given — the
    /// property the profile's composition rests on, re-asserted now that the profile carries all sixteen rows.
    /// </summary>
    /// <returns>A task that completes when every rule has run.</returns>
    [TestMethod]
    public async Task EveryStructuralRuleAnswersWithExactlyOneClaimForTheRequirementItOwns()
    {
        var context = new EArkValidationContext
        {
            EntryNames = [],
            CurrentTime = EArkValidationSource.Instant,
        };

        foreach(var rule in EArkValidationProfiles.CsipStructuralRules())
        {
            var claims = await rule.Delegate(context, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.HasCount(1, claims);
            Assert.AreEqual(rule.ExpectedClaimIds[0].Code, claims[0].Id.Code);
            Assert.IsInstanceOfType<EArkClaimContext>(claims[0].Context);
        }
    }


    /// <summary>Builds a validation context over classified facts and a parsed manifest.</summary>
    /// <param name="facts">What the package's layout states about itself.</param>
    /// <param name="manifest">The package's own root manifest, or <see langword="null"/> when the caller supplied none.</param>
    /// <returns>The context the rules run over.</returns>
    private static EArkValidationContext ContextFor(EArkPackageFacts facts, MetsDocument? manifest)
    {
        var entryNames = new List<string>(facts.Snapshot.EntryCount);
        for(int i = 0; i < facts.Snapshot.Entries.Count; ++i)
        {
            entryNames.Add(facts.Snapshot.Entries[i].Name);
        }

        return new EArkValidationContext
        {
            EntryNames = entryNames,
            CurrentTime = EArkValidationSource.Instant,
            PackageFacts = facts,
            PackageManifest = manifest,
            MemoryPool = BaseMemoryPool.Shared,
        };
    }


    /// <summary>Runs the structural profile over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunAsync(EArkValidationContext context)
    {
        var issuer = new ClaimIssuer<EArkValidationContext>(
            IssuerId,
            EArkValidationProfiles.CsipStructuralRules(),
            IssuerTime);

        return await issuer.GenerateClaimsAsync(context, CorrelationId, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Assesses a stated claim set with the reading the requirement catalogues themselves state.</summary>
    /// <param name="claims">The claims the assessment folds.</param>
    /// <returns>What the assessor concluded.</returns>
    private ValueTask<AssessmentResult> SpecificationReadingOfAsync(IReadOnlyList<Claim> claims) =>
        EArkAssessors.ConformantPackageAssessorAsync(
            CompletedIssueOf(claims),
            IssuerId,
            EArkValidationSource.Instant.UtcDateTime,
            traceId: null,
            spanId: null,
            baggage: null,
            TestContext.CancellationToken);


    /// <summary>Assesses a stated claim set with the stricter reading, which also refuses an unanswered rule.</summary>
    /// <param name="claims">The claims the assessment folds.</param>
    /// <returns>What the assessor concluded.</returns>
    private ValueTask<AssessmentResult> StricterReadingOfAsync(IReadOnlyList<Claim> claims) =>
        EArkAssessors.FullyAssessedPackageAssessorAsync(
            CompletedIssueOf(claims),
            IssuerId,
            EArkValidationSource.Instant.UtcDateTime,
            traceId: null,
            spanId: null,
            baggage: null,
            TestContext.CancellationToken);


    /// <summary>Wraps a stated claim set as a claim generation that ran to completion.</summary>
    /// <param name="claims">The claims the generation is said to have issued.</param>
    /// <returns>The claim issue result an assessor is given.</returns>
    /// <remarks>
    /// The completion status matters to the fold — an incomplete generation is not conformance under either
    /// assessor — so it is stated rather than defaulted.
    /// </remarks>
    private static ClaimIssueResult CompletedIssueOf(IReadOnlyList<Claim> claims) =>
        new(
            ClaimIssueResultId: "eark-structural-stated-claims",
            ClaimIssuerId: IssuerId,
            CorrelationId: CorrelationId,
            Claims: [.. claims],
            CreationTimestampInUtc: EArkValidationSource.Instant.UtcDateTime,
            CompletionStatus: ClaimIssueCompletionStatus.Complete,
            RulesExecuted: claims.Count,
            TotalRules: claims.Count);


    /// <summary>Asserts both halves of one requirement's claim: the outcome, and the reason it reached it.</summary>
    /// <param name="result">What the issuer concluded.</param>
    /// <param name="claimId">The requirement whose claim is read.</param>
    /// <param name="outcome">The outcome the claim is expected to carry.</param>
    /// <param name="reason">The reason the claim is expected to carry.</param>
    internal static void AssertOutcome(ClaimIssueResult result, ClaimId claimId, ClaimOutcome outcome, EArkClaimReason reason)
    {
        foreach(var claim in result.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                Assert.AreEqual(outcome, claim.Outcome, $"{claimId} reached {claim.Outcome}.");
                var context = Assert.IsInstanceOfType<EArkClaimContext>(claim.Context);
                Assert.AreEqual(reason, context.Reason, $"{claimId} reached {claim.Outcome} because of {context.Reason} ({context.Subject}).");

                return;
            }
        }

        Assert.Fail($"The result carries no claim for {claimId}.");
    }
}
