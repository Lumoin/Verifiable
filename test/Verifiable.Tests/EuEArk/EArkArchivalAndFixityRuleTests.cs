using System.Diagnostics.CodeAnalysis;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the archival preservation layer of
/// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> — <c>AIPM5</c>…<c>AIPM7</c>, <c>AIP12</c>,
/// <c>AIP13</c>, <c>AIP15</c>…<c>AIP18</c> and the parent-chain obligation its prose states with no identifier —
/// and for this library's own rules over a package's integrity: fixity recomputed through the registered digest
/// seam, the strength of the algorithm it was computed under, references resolved, and identifiers legal.
/// </summary>
/// <remarks>
/// The fixity tests are the ones that matter most. A stated checksum is not evidence of anything until someone
/// recomputes it, and the enclosing specification never asks anyone to — so the recomputation is this library's
/// obligation, its claim is a house claim, and both halves of the weak-algorithm ruling get a test: a weak
/// algorithm is flagged under the secure default and fails only when the caller raises the floor.
/// </remarks>
[TestClass]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "A test states its one departure from a conformant document as a record copy, and a record copy shares every carrier of the instance it was copied from. Exactly one instance of each carrier set is disposed — the copy actually put under test, held in a using — and disposing the instance it was copied from as well would return the same rented memory twice.")]
internal sealed class EArkArchivalAndFixityRuleTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier the test issuer states as its own.</summary>
    private const string IssuerId = "eark-archival-validator";

    /// <summary>The correlation identifier the test issuer carries through a run.</summary>
    private const string CorrelationId = "eark-archival-validation";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);

    /// <summary>The name of the one data file the fixity tests recompute over.</summary>
    private static string DataEntryName { get; } = "representations/rep1/data/record.bin";

    /// <summary>The content of that file.</summary>
    private static string DataContent { get; } = "the bits themselves";

    /// <summary>
    /// The name of a folder entry the package holds. The snapshot materialises the ancestors a stated name
    /// implies, so this entry is as real as the file below it and a location naming it resolves.
    /// </summary>
    private static string FolderEntryName { get; } = "representations/rep1/data/";


    /// <summary>
    /// A manifest referencing its provenance metadata as the archival profile asks, and naming the
    /// preservation-metadata vocabulary and its major version, satisfies all three rows.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AConformantProvenanceReferenceSatisfiesTheThreeArchivalRows()
    {
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(
            ManifestContext(manifest),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aipm5, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aipm6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aipm7, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A provenance reference naming some other metadata vocabulary deviates from the two recommendations that
    /// ask for the preservation one, without failing the mandatory row that only asks for a reference at all.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AProvenanceReferenceOfAnotherVocabularyDeviatesWithoutFailing()
    {
        using MetsDocument manifest = EArkValidationSource.ConformantManifest(
            provenanceReference: EArkValidationSource.Reference("metadata/preservation/other.xml"));

        ClaimIssueResult result = await RunAsync(
            ManifestContext(manifest),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aipm5, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aipm6, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aipm7, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
    }


    /// <summary>
    /// A manifest whose administrative section carries no provenance sub-section at all fails the one archival
    /// row that is mandatory — the pointer mechanism the whole preservation layer hangs from.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AManifestWithoutProvenanceMetadataFailsTheMandatoryPointerRow()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        using MetsDocument manifest = conformant with
        {
            AdministrativeMetadata = conformant.AdministrativeMetadata! with { DigitalProvenanceSections = [] },
        };

        ClaimIssueResult result = await RunAsync(
            ManifestContext(manifest),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aipm5, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// A preservation-metadata document whose event names an agent the document also describes satisfies the
    /// cross-entity rule, which is the one archival row worth having: a provenance record cannot point at a
    /// performer nothing identifies.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    [TestMethod]
    public async Task AnEventNamingADescribedAgentSatisfiesTheCrossEntityRow()
    {
        using PremisDocument document = EArkValidationSource.ConformantPreservationMetadata();

        ClaimIssueResult result = await RunAsync(
            PreservationContext(document),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip12, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip13, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip15, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip16, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip17, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip18, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// An event naming an agent the document does not describe fails the cross-entity rule, and only that
    /// rule: the event is otherwise well formed, so the finding is precisely the dangling link.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    [TestMethod]
    public async Task AnEventNamingAnUndescribedAgentFailsTheCrossEntityRow()
    {
        PremisDocument conformant = EArkValidationSource.ConformantPreservationMetadata();
        using PremisDocument document = conformant with { Agents = [] };

        ClaimIssueResult result = await RunAsync(
            PreservationContext(document),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip16, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip18, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// An event describing no performer at all fails the archival row that asks every described event to name
    /// the agent that caused it.
    /// </summary>
    /// <returns>A task that completes when the document has been validated.</returns>
    [TestMethod]
    public async Task AnEventWithoutAPerformerFailsTheRowThatAsksForOne()
    {
        PremisDocument conformant = EArkValidationSource.ConformantPreservationMetadata();
        using PremisDocument document = conformant with
        {
            Events = [conformant.Events[0] with { LinkingAgentIdentifiers = [] }],
        };

        ClaimIssueResult result = await RunAsync(
            PreservationContext(document),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip16, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, AipClaimIds.Aip18, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
    }


    /// <summary>
    /// The parent-chain rule reads the package pointers the manifest carries and answers about their form; a
    /// manifest pointing at one representation carries one well-formed pointer in a division of its own.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AWellFormedPackagePointerSatisfiesTheParentChainRule()
    {
        using MetsDocument manifest = EArkValidationSource.ConformantManifest();

        ClaimIssueResult result = await RunAsync(
            ManifestContext(manifest),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            result,
            AipClaimIds.ArchivalPackageParentChainListed,
            ClaimOutcome.Success,
            EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A package pointer naming no target fails the parent-chain rule: a list of children that names nothing
    /// lists nothing.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task APackagePointerNamingNoTargetFailsTheParentChainRule()
    {
        MetsDocument conformant = EArkValidationSource.ConformantManifest();
        MetsDivision root = conformant.StructuralMaps[0].RootDivision;
        using MetsDocument manifest = conformant with
        {
            StructuralMaps =
            [
                conformant.StructuralMaps[0] with
                {
                    RootDivision = root with
                    {
                        Divisions =
                        [
                            root.Divisions[0], root.Divisions[1], root.Divisions[2], root.Divisions[3],
                            root.Divisions[4] with
                            {
                                MetsPointers =
                                [
                                    new MetsPointer(string.Empty, MetsWellKnown.UrlLocatorType, MetsWellKnown.SimpleLinkType, "rep1")
                                ],
                            }
                        ],
                    },
                }
            ],
        };

        ClaimIssueResult result = await RunAsync(
            ManifestContext(manifest),
            [.. EArkValidationProfiles.ArchivalPackageRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            result,
            AipClaimIds.ArchivalPackageParentChainListed,
            ClaimOutcome.Failure,
            EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// A manifest whose stated checksum is the digest of the octets the package actually holds passes the
    /// recomputation, and the algorithm it was computed under is one this library treats as evidence.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AStatedChecksumThatMatchesTheOctetsPassesTheRecomputation()
    {
        string checksum = await ChecksumOfAsync(DataContent).ConfigureAwait(false);
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = ManifestStating(checksum);

        ClaimIssueResult result = await RunFixityAsync(facts, manifest).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageFixityAlgorithmStrength, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A manifest whose stated checksum is not the digest of the octets the package holds fails the
    /// recomputation — which is what makes the test above a comparison rather than a formality.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task AStatedChecksumThatDoesNotMatchTheOctetsFailsTheRecomputation()
    {
        string checksum = await ChecksumOfAsync("some other content entirely").ConfigureAwait(false);
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = ManifestStating(checksum);

        ClaimIssueResult result = await RunFixityAsync(facts, manifest).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Failure, EArkClaimReason.FixityMismatch);
    }


    /// <summary>
    /// A checksum stated under an algorithm this library will not treat as evidence — the enumeration admits
    /// broken hash functions and error-detection codes alike — is flagged under the secure default and fails
    /// the package only when the caller raises the floor. Both halves of the ruling, one test.
    /// </summary>
    /// <param name="checksumType">The algorithm the manifest states.</param>
    /// <returns>A task that completes when both policies have run.</returns>
    [TestMethod]
    [DataRow("MD5", DisplayName = "A broken hash function")]
    [DataRow("SHA-1", DisplayName = "A hash function whose collision resistance is broken")]
    [DataRow("CRC32", DisplayName = "An error-detection code")]
    [DataRow("Adler-32", DisplayName = "A second error-detection code")]
    public async Task AWeakFixityAlgorithmIsFlaggedByDefaultAndFailsOnlyWhenTheCallerRaisesTheFloor(string checksumType)
    {
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = ManifestStating(fixity: EArkValidationSource.WeakFixity(checksumType));

        ClaimIssueResult flagged = await RunFixityAsync(facts, manifest).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            flagged,
            EArkClaimIds.PackageFixityAlgorithmStrength,
            ClaimOutcome.Inconclusive,
            EArkClaimReason.FixityAlgorithmFlagged);
        Assert.AreEqual(0, EArkAssessors.CountOutcome(flagged, ClaimOutcome.Failure));

        ClaimIssueResult refused = await RunFixityAsync(
            facts,
            manifest,
            new EArkValidationDeviations { WeakFixityAlgorithmFailsThePackage = true }).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            refused,
            EArkClaimIds.PackageFixityAlgorithmStrength,
            ClaimOutcome.Failure,
            EArkClaimReason.FixityAlgorithmFlagged);
    }


    /// <summary>
    /// A package whose every fixity is stated under an algorithm this library does not compute leaves the
    /// recomputation undecided by default, and fails it when the caller states that an unrecomputable fixity
    /// is not good enough for its own policy.
    /// </summary>
    /// <returns>A task that completes when both policies have run.</returns>
    [TestMethod]
    public async Task AnUnrecomputableFixityIsUndecidedByDefaultAndFailsUnderTheStricterPolicy()
    {
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = ManifestStating(fixity: EArkValidationSource.WeakFixity(MetsWellKnown.Md5ChecksumType));

        ClaimIssueResult undecided = await RunFixityAsync(facts, manifest).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            undecided,
            EArkClaimIds.PackageFixityRecomputed,
            ClaimOutcome.Inconclusive,
            EArkClaimReason.SubjectNotSupplied);

        ClaimIssueResult refused = await RunFixityAsync(
            facts,
            manifest,
            new EArkValidationDeviations { UnrecomputableFixityFailsThePackage = true }).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            refused,
            EArkClaimIds.PackageFixityRecomputed,
            ClaimOutcome.Failure,
            EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// A manifest that states a fixity over a location naming a folder entry is refused rather than passed with
    /// the fixity quietly left out of the count. A folder is not a file, so nothing can be recomputed from it,
    /// and the file-section rows of
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> make a
    /// <c>&lt;file&gt;</c> element denote a file — but the catalogue gives no requirement identifier for "the
    /// location must not name a directory", so the refusal is this library's own and belongs to the claim that
    /// says what was recomputed.
    /// </summary>
    /// <remarks>
    /// The sibling case — a location that resolves to nothing at all — is caught by the reference rule of the
    /// same list, which reports <see cref="EArkClaimReason.ReferenceUnresolved"/> over the identical set of
    /// locations. A location that resolves to a folder was caught by nothing: the recomputation reported
    /// success over a smaller number of values than the manifest stated, and the claim set carried no
    /// denominator a reader could notice the difference by.
    /// </remarks>
    /// <returns>A task that completes when both packages have been validated.</returns>
    [TestMethod]
    public async Task AStatedFixityOverAFolderIsRefusedRatherThanDropped()
    {
        string checksum = await ChecksumOfAsync(DataContent).ConfigureAwait(false);
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        //The package really does hold the folder entry the location names, which is what makes it resolve.
        Assert.IsNotNull(read.Snapshot!.FindEntry(FolderEntryName));
        Assert.IsTrue(read.Snapshot!.FindEntry(FolderEntryName)!.IsFolder);

        using MetsDocument overAFolder = ManifestStating(checksum, alsoStatingHref: FolderEntryName);
        ClaimIssueResult result = await RunFixityAsync(facts, overAFolder).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            result,
            EArkClaimIds.PackageFixityRecomputed,
            ClaimOutcome.Failure,
            EArkClaimReason.ReferenceUnresolved);

        //The same manifest with the second location naming the file beside it recomputes both and passes, so
        //the refusal is about the folder and not about there being two entries.
        using MetsDocument overTwoFiles = ManifestStating(checksum, alsoStatingHref: "METS.xml", alsoStatingChecksum: await ChecksumOfAsync("<mets/>").ConfigureAwait(false));
        ClaimIssueResult both = await RunFixityAsync(facts, overTwoFiles).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            both,
            EArkClaimIds.PackageFixityRecomputed,
            ClaimOutcome.Success,
            EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// A manifest naming a file the package does not hold fails the reference rule, and a manifest whose every
    /// reference resolves passes it.
    /// </summary>
    /// <returns>A task that completes when both packages have been validated.</returns>
    [TestMethod]
    public async Task AReferenceToAFileThePackageDoesNotHoldFailsTheReferenceRule()
    {
        string checksum = await ChecksumOfAsync(DataContent).ConfigureAwait(false);
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        using MetsDocument resolvable = ManifestStating(checksum);
        ClaimIssueResult resolved = await RunFixityAsync(facts, resolvable).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(resolved, EArkClaimIds.PackageReferencesResolve, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        using MetsDocument dangling = ManifestStating(checksum, href: "representations/rep1/data/absent.bin");
        ClaimIssueResult unresolved = await RunFixityAsync(facts, dangling).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(unresolved, EArkClaimIds.PackageReferencesResolve, ClaimOutcome.Failure, EArkClaimReason.ReferenceUnresolved);
    }


    /// <summary>
    /// A manifest carrying an identifier that is not a legal <c>NCName</c> fails the identifier rule, which
    /// stands for the second obligation the specification states in prose and gives no identifier of its own.
    /// </summary>
    /// <returns>A task that completes when the manifest has been validated.</returns>
    [TestMethod]
    public async Task AnIdentifierThatIsNotALegalNameFailsTheIdentifierRule()
    {
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        MetsDocument conformant = ManifestStating(EArkValidationSource.PlaceholderChecksum);
        using MetsDocument manifest = conformant with
        {
            FileSection = conformant.FileSection! with
            {
                Id = "1-file-section",
            },
        };

        ClaimIssueResult result = await RunFixityAsync(facts, manifest).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(
            result,
            EArkClaimIds.PackageIdentifiersAreNCNames,
            ClaimOutcome.Failure,
            EArkClaimReason.MandatoryRequirementUnmet);
    }


    /// <summary>
    /// A caller that supplied no memory pool gets both fixity rows reported as undecided for want of a
    /// subject: nothing can be recomputed without one, and reporting a failure would blame the package for the
    /// caller's omission.
    /// </summary>
    /// <returns>A task that completes when the rules have run.</returns>
    [TestMethod]
    public async Task WithoutAMemoryPoolTheFixityRowsSaySoRatherThanFailing()
    {
        using EArkPackageSnapshotResult read = ReadPackage();
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsDocument manifest = ManifestStating(EArkValidationSource.PlaceholderChecksum);

        var context = new EArkValidationContext
        {
            EntryNames = [],
            CurrentTime = EArkValidationSource.Instant,
            PackageFacts = facts,
            PackageManifest = manifest,
        };

        ClaimIssueResult result = await RunAsync(
            context,
            [.. EArkValidationProfiles.PackageFixityAndReferenceRules()]).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageFixityRecomputed, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageFixityAlgorithmStrength, ClaimOutcome.Inconclusive, EArkClaimReason.SubjectNotSupplied);
    }


    /// <summary>Reads the package the fixity tests recompute over.</summary>
    /// <returns>The snapshot result. The caller disposes it.</returns>
    private static EArkPackageSnapshotResult ReadPackage() =>
        EArkPackageSnapshotReading.Create(
            [
                EArkPackageSource.TextFile("METS.xml", "<mets/>"),
                EArkPackageSource.TextFile(DataEntryName, DataContent),
            ],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);


    /// <summary>
    /// Builds a manifest whose one file entry states the checksum given, and whose descriptive, provenance and
    /// rights references are dropped so that only the file entry's fixity is under test.
    /// </summary>
    /// <param name="checksum">The checksum the file entry states.</param>
    /// <param name="fixity">A fixity of the caller's own, which overrides <paramref name="checksum"/>.</param>
    /// <param name="href">The location the file entry names, or <see langword="null"/> for the data file.</param>
    /// <param name="alsoStatingHref">A second location the manifest states a fixity over, or <see langword="null"/> for a manifest with one file entry.</param>
    /// <param name="alsoStatingChecksum">The checksum the second file entry states, or <see langword="null"/> for the placeholder.</param>
    /// <returns>The manifest. The caller owns and disposes it.</returns>
    private static MetsDocument ManifestStating(
        string? checksum = null,
        EArkFixity? fixity = null,
        string? href = null,
        string? alsoStatingHref = null,
        string? alsoStatingChecksum = null)
    {
        List<MetsFile> files = [EArkValidationSource.File("file-data-1", href ?? DataEntryName, checksum, fixity)];
        if(alsoStatingHref is not null)
        {
            files.Add(EArkValidationSource.File("file-data-2", alsoStatingHref, alsoStatingChecksum));
        }

        MetsDocument conformant = EArkValidationSource.ConformantManifest(files: files);

        return conformant with
        {
            DescriptiveMetadataSections = [],
            AdministrativeMetadata = conformant.AdministrativeMetadata! with
            {
                DigitalProvenanceSections =
                [
                    conformant.AdministrativeMetadata!.DigitalProvenanceSections[0] with { Reference = null }
                ],
                RightsSections = [],
            },
            FileSection = conformant.FileSection! with
            {
                FileGroups = [conformant.FileSection!.FileGroups[2]],
            },
        };
    }


    /// <summary>Computes the checksum of some text through the registered digest seam.</summary>
    /// <param name="content">The text.</param>
    /// <returns>The digest as lowercase hexadecimal, which is what a checksum attribute carries.</returns>
    private async Task<string> ChecksumOfAsync(string content)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            Encoding.UTF8.GetBytes(content).AsMemory(),
            PkiDigestAlgorithm.Sha256.OutputByteLength,
            PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return Convert.ToHexStringLower(digest.AsReadOnlyMemory().Span[..PkiDigestAlgorithm.Sha256.OutputByteLength]);
    }


    /// <summary>Runs the fixity and reference rules over one package.</summary>
    /// <param name="facts">What the package's layout states about itself.</param>
    /// <param name="manifest">The package's own root manifest.</param>
    /// <param name="deviations">The deviation policy in force, or <see langword="null"/> for the default.</param>
    /// <returns>What the issuer concluded.</returns>
    private Task<ClaimIssueResult> RunFixityAsync(
        EArkPackageFacts facts,
        MetsDocument manifest,
        EArkValidationDeviations? deviations = null)
    {
        var context = new EArkValidationContext
        {
            EntryNames = [],
            CurrentTime = EArkValidationSource.Instant,
            PackageFacts = facts,
            PackageManifest = manifest,
            MemoryPool = BaseMemoryPool.Shared,
            Deviations = deviations ?? EArkValidationDeviations.Conformant,
        };

        return RunAsync(context, [.. EArkValidationProfiles.PackageFixityAndReferenceRules()]);
    }


    /// <summary>Builds a validation context over one parsed manifest.</summary>
    /// <param name="manifest">The package's own root manifest.</param>
    /// <returns>The context the rules run over.</returns>
    private static EArkValidationContext ManifestContext(MetsDocument manifest) => new()
    {
        EntryNames = [],
        CurrentTime = EArkValidationSource.Instant,
        PackageManifest = manifest,
    };


    /// <summary>Builds a validation context over one parsed preservation-metadata document.</summary>
    /// <param name="document">The preservation-metadata document.</param>
    /// <returns>The context the rules run over.</returns>
    private static EArkValidationContext PreservationContext(PremisDocument document) => new()
    {
        EntryNames = [],
        CurrentTime = EArkValidationSource.Instant,
        PreservationMetadata = [document],
    };


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
