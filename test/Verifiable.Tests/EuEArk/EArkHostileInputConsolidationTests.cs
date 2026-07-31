using System.Globalization;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// The hostile-input prong of the wave, consolidated where the per-component tests left a gap: the two ways a
/// package can arrive answering the same refusals, the container-format edge the archive path inherits, one
/// attack shape carried by three different mechanisms, and what the rule lists do when the document they judge
/// never reaches them.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What this class deliberately does not repeat.</strong> The bounds of the value snapshot, the
/// duplicate and collision rules, and a name deeper than any stack are the package-reading tests'
/// (<see cref="EArkPackageSnapshotTests"/>); malformed, truncated, wrongly-rooted, wrongly-namespaced and
/// entity-bearing documents are the two binding tests' (<see cref="MetsXmlBindingTests"/>,
/// <see cref="PremisXmlBindingTests"/>); a fixity under a weak algorithm and an unrecomputable one are the
/// rule tests' (<see cref="EArkArchivalAndFixityRuleTests"/>); the protocol vocabulary's numeric bounds and its
/// four untypable obligations are the seam tests' (<see cref="PreservationSeamTests"/>). What was missing is
/// what sits BETWEEN those components, which is what each test below is about.
/// </para>
/// <para>
/// <strong>The shape the wave's ancestor established.</strong> An attack is built once and run through every
/// mechanism that could answer it, and the assertions are about how the answers relate — identical where the
/// two package paths must agree, different where three mechanisms answer three different questions. A test that
/// exercised each mechanism in isolation would pass just as well if two of them had been collapsed into one.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkHostileInputConsolidationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier the issuer of this class states as its own.</summary>
    private const string IssuerId = "eark-hostile-input";

    /// <summary>The correlation identifier the issuer carries through a run.</summary>
    private const string CorrelationId = "eark-hostile-input";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);

    /// <summary>A path that leads out of the package, whichever carrier states it.</summary>
    private static string EscapingPath { get; } = "../outside.txt";

    /// <summary>Octets that are not a document at all, for the manifest an attacker hands a validator.</summary>
    private static string OctetsThatAreNotADocument { get; } = ">>> not a document, just octets <<<";


    /// <summary>
    /// Every entry-name rule refuses on BOTH package paths and names the same rule on each — the property that
    /// makes "a package is admitted the same way whichever way it arrived" true of the refusals as well as of
    /// the successes.
    /// </summary>
    /// <param name="entryName">The hostile name.</param>
    /// <param name="expected">The rule that has to refuse it.</param>
    /// <remarks>
    /// The package-reading tests exercise every rule on the stated path and five of them on the archive path,
    /// which leaves open the one thing an attacker would try: reaching the classifier by the other door. All
    /// eight refusals of the generic archive-safety layer ruling R-4 reuses —
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
    /// ETSI EN 319 162-1</see>'s entry-name rules, and nothing above them — are exercised here on both, and the
    /// two paths are asserted to answer with the same rule rather than merely to refuse.
    /// </remarks>
    [TestMethod]
    [DataRow("../outside.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a parent segment")]
    [DataRow("./here.txt", AsicZipEntryNameStatus.Traversal, DisplayName = "a current-folder segment")]
    [DataRow("/METS.xml", AsicZipEntryNameStatus.Absolute, DisplayName = "a path from a file-system root")]
    [DataRow("data\\record.bin", AsicZipEntryNameStatus.BackslashSeparator, DisplayName = "a native path separator")]
    [DataRow("C:/METS.xml", AsicZipEntryNameStatus.VolumeQualified, DisplayName = "a volume qualifier")]
    [DataRow("data//record.bin", AsicZipEntryNameStatus.EmptySegment, DisplayName = "an empty segment")]
    [DataRow("data/\u0001.bin", AsicZipEntryNameStatus.ControlCharacter, DisplayName = "a control character")]
    [DataRow("", AsicZipEntryNameStatus.Empty, DisplayName = "no name at all")]
    public void EveryEntryNameRuleRefusesOnBothPackagePathsAndNamesTheSameRule(string entryName, AsicZipEntryNameStatus expected)
    {
        using(EArkPackageSnapshotResult stated = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile(entryName, "content")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared))
        {
            Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameRefused, stated.Status);
            Assert.AreEqual(expected, stated.RejectedEntryNameStatus);
            Assert.IsNull(stated.Snapshot);
        }

        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [new RawZipEntrySpec { Name = entryName, Content = Encoding.UTF8.GetBytes("content") }]
        });

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.ArchiveRefused, read.Status);
        Assert.AreEqual(AsicZipReadStatus.EntryNameRejected, read.ArchiveStatus);
        Assert.AreEqual(expected, read.RejectedEntryNameStatus, "The two package paths refuse the same name under the same rule.");
        Assert.IsNull(read.Snapshot);
    }


    /// <summary>
    /// A name over the stated bound is refused on both paths under the same rule, and the bound the archive
    /// path applies is the shared record's own rather than the archive layer's default.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The bound is the one place where the two paths could legitimately differ — the archive layer carries a
    /// name bound of its own — and ruling R-4's "ONE shared limits record" is exactly the promise that they do
    /// not. A caller who tightens the record has to see the tighter bound applied through the archive as well,
    /// which is what this asserts by refusing a name the archive layer's own default would have admitted.
    /// </para>
    /// <para>
    /// Both paths reach the SAME refusal, status for status, because the bound decides in one place: where the
    /// snapshot is built, over names relative to the package root. The archive layer holds an archive to that
    /// bound plus the headroom a root folder can occupy, so a name inside the headroom and over the bound is
    /// carried as far as the shared check rather than refused earlier under a different status —
    /// <see cref="EArkPackageSnapshotTests.TheTwoPathsAdmitTheSamePackageAtTheSharedBounds"/> is the other half
    /// of that property, the admitting one.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void ANameOverTheSharedBoundIsRefusedOnBothPathsUnderTheSameRule()
    {
        var limits = new EArkPackageLimits { MaximumEntryNameByteLength = 32 };
        string name = new('n', 64);

        using(EArkPackageSnapshotResult stated = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile(name, "content")],
            limits,
            BaseMemoryPool.Shared))
        {
            Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameRefused, stated.Status);
            Assert.AreEqual(AsicZipEntryNameStatus.TooLong, stated.RejectedEntryNameStatus);
        }

        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries = [new RawZipEntrySpec { Name = name, Content = Encoding.UTF8.GetBytes("content") }]
        });

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(archive, limits, BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameRefused, read.Status, "The same status the folder path reached, from the same check.");
        Assert.AreEqual(AsicZipEntryNameStatus.TooLong, read.RejectedEntryNameStatus);
        Assert.AreEqual(64, limits.ToArchiveLimits().MaximumEntryNameByteLength, "The shared record's bound governs the archive layer, with the root-folder headroom on top.");
        Assert.IsLessThan(
            AsicZipReadLimits.Conformant.MaximumEntryNameByteLength,
            limits.ToArchiveLimits().MaximumEntryNameByteLength,
            "…and the name refused here is one the archive layer's own default would have admitted.");
    }


    /// <summary>
    /// A package archived with a root entry carrying the container format's reserved name is judged by that
    /// format's own rules and refused, and the refusal reaches the caller verbatim instead of being
    /// reinterpreted as a package finding.
    /// </summary>
    /// <remarks>
    /// This is the one place where the archive path is not format-neutral, and it is documented at the reading
    /// method rather than hidden: the shipped archive reader applies
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
    /// ETSI EN 319 162-1 Annex A.1</see>'s rules whenever the central directory names that entry, so an
    /// Information Package archived with one is held to a container format it never claimed. It fails CLOSED —
    /// a refusal, never a silent reinterpretation — and the archive layer's own status is what the caller sees,
    /// which is what this test pins so the edge cannot quietly change shape.
    /// </remarks>
    [TestMethod]
    public void AnArchivedPackageCarryingTheContainerFormatsReservedEntryIsRefusedWithThatFormatsOwnStatus()
    {
        byte[] archive = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries =
            [
                new RawZipEntrySpec { Name = "METS.xml", Content = Encoding.UTF8.GetBytes("<mets/>") },
                new RawZipEntrySpec { Name = "mimetype", Content = Encoding.UTF8.GetBytes("application/octet-stream") }
            ]
        });

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.ReadArchive(
            archive,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.AreEqual(EArkPackageSnapshotStatus.ArchiveRefused, read.Status);
        Assert.AreNotEqual(AsicZipReadStatus.Read, read.ArchiveStatus, "The container format's own reading refused it.");
        Assert.IsNull(read.Snapshot, "Nothing of a refused archive reaches the classifier.");

        //The same entries without that one name are read, which is what makes the finding about the name.
        byte[] neutral = AsicZipStructureOracle.BuildRawArchive(new RawZipArchiveSpec
        {
            Entries =
            [
                new RawZipEntrySpec { Name = "METS.xml", Content = Encoding.UTF8.GetBytes("<mets/>") },
                new RawZipEntrySpec { Name = "documentation/manual.txt", Content = Encoding.UTF8.GetBytes("how") }
            ]
        });

        using EArkPackageSnapshotResult admitted = EArkPackageSnapshotReading.ReadArchive(
            neutral,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(admitted.IsRead, $"A package archived without that entry is read: {admitted.Status}.");
    }


    /// <summary>
    /// ONE path leading out of the package, carried by three different mechanisms, answered three different
    /// ways — and none of the three opens anything outside.
    /// </summary>
    /// <returns>A task that completes when all three mechanisms have answered.</returns>
    /// <remarks>
    /// <para>
    /// The same string is (1) an entry name, which the naming rules refuse outright so the package never comes
    /// into being; (2) a reference inside a manifest, which the reference rule reports as resolving to nothing
    /// because it resolves references against the snapshot's own entries and nothing else; and (3) a name the
    /// classifier can never see, because a snapshot carrying it cannot exist — so the classifier's answer is
    /// that there is no such entry rather than that the entry is somewhere unusual.
    /// </para>
    /// <para>
    /// The three answers are asserted to DIFFER. A design in which the reference rule refused the same way the
    /// naming rule does would look safer and would be worse: a manifest naming a resource the package does not
    /// hold is a finding about the package, not a reason to refuse to read it.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task APathLeadingOutOfThePackageIsRefusedAsANameReportedAsAReferenceAndUnknownToTheClassifier()
    {
        //(1) As an entry name: the package cannot be built at all.
        using(EArkPackageSnapshotResult named = EArkPackageSnapshotReading.Create(
            [EArkPackageSource.TextFile(EscapingPath, "the octets an attacker wants written")],
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared))
        {
            Assert.AreEqual(EArkPackageSnapshotStatus.EntryNameRefused, named.Status);
            Assert.AreEqual(AsicZipEntryNameStatus.Traversal, named.RejectedEntryNameStatus);
        }

        //(2) As a reference inside a manifest of an otherwise conformant package: a finding, not a refusal.
        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            EArkValidationSource.ConformantPackageEntries(),
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The package itself is sound: {read.Status}.");

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsFile escaping = EArkValidationSource.File("ID_escape", EscapingPath);
        using MetsDocument manifest = EArkValidationSource.ConformantManifest([escaping]);

        ClaimIssueResult result = await RunAsync(
            ContextFor(facts, manifest),
            [.. EArkValidationProfiles.PackageFixityAndReferenceRules()]).ConfigureAwait(false);

        Claim references = ClaimFor(result, EArkClaimIds.PackageReferencesResolve);
        var context = Assert.IsInstanceOfType<EArkClaimContext>(references.Context);

        Assert.AreEqual(ClaimOutcome.Failure, references.Outcome);
        Assert.AreEqual(EArkClaimReason.ReferenceUnresolved, context.Reason);

        //(3) To the classifier: there is no such entry, and nothing was normalised into one either.
        Assert.IsNull(facts.Snapshot.FindEntry(EscapingPath), "No entry of that name can exist in a snapshot.");
        Assert.IsNull(facts.Snapshot.FindEntry("outside.txt"), "…and nothing was silently normalised into one.");

        foreach(EArkClassifiedEntry classified in facts.Entries)
        {
            Assert.DoesNotContain(
                "..",
                classified.Entry.Name,
                StringComparison.Ordinal,
                "No entry the classifier sees carries a parent segment, whichever path the package arrived by.");
        }

        //The three answers differ: refused, reported, absent.
        Assert.AreNotEqual(
            EArkClaimReason.MandatoryRequirementUnmet,
            context.Reason,
            "A reference that resolves to nothing is reported under its own reason, not as a bare requirement failure.");
    }


    /// <summary>
    /// A package that stays inside every stated bound and is still adversarially shaped — a thousand
    /// representations, a metadata tree as deep as the bound allows, and entries named to look like positions
    /// they are not at — is classified completely and judged completely, with no rule left unanswered.
    /// </summary>
    /// <returns>A task that completes when the package has been judged.</returns>
    /// <remarks>
    /// The bounds tests prove what a package beyond a bound cannot do. This proves what a package inside every
    /// bound cannot do either: no entry escapes classification, no rule of the whole package profile fails to
    /// answer, no claim carries the unset reason, and nothing recurses — the classifier and the rules walk what
    /// they are given with explicit stacks and loops, so a wide, deep, name-confusing tree costs time and
    /// nothing else.
    /// </remarks>
    [TestMethod]
    public async Task AnAdversarialButLegalTreeIsClassifiedAndJudgedWithEveryRuleAnswering()
    {
        var entries = new List<EArkPackageEntrySource>
        {
            EArkPackageSource.TextFile("METS.xml", "<mets/>")
        };

        //A thousand representations, each with the package's own shape.
        for(int i = 0; i < 1000; ++i)
        {
            string label = string.Create(CultureInfo.InvariantCulture, $"rep{i}");
            entries.Add(EArkPackageSource.TextFile($"representations/{label}/METS.xml", "<mets/>"));
            entries.Add(EArkPackageSource.TextFile($"representations/{label}/data/record.bin", "the bits themselves"));
        }

        //A metadata tree as deep as the shared bound admits, named at every level like something else.
        var deep = new StringBuilder("metadata");
        for(int i = 0; i < EArkPackageLimits.Conformant.MaximumFolderDepth - 3; ++i)
        {
            _ = deep.Append("/representations");
        }

        entries.Add(EArkPackageSource.TextFile($"{deep}/METS.xml", "<mets/>"));

        //And entries whose names are the ones the specification fixes, at positions it does not fix them at.
        entries.Add(EArkPackageSource.TextFile("data/loose.bin", "a package-level data file"));
        entries.Add(EArkPackageSource.TextFile("representations/loose.bin", "a file directly under the representations folder"));

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            entries,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The tree stays inside every bound: {read.Status}.");

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        Assert.HasCount(1000, facts.Representations, "Every representation is its own level.");
        foreach(EArkClassifiedEntry classified in facts.Entries)
        {
            Assert.AreNotEqual(
                EArkPackageEntryPlacement.NotEvaluated,
                classified.Placement,
                $"The entry {classified.Entry.Name} reached no position.");
        }

        Assert.IsNotEmpty(facts.Package.MisplacedEntries, "The two fixed names at unfixed positions are reported as misplaced.");

        ClaimIssueResult result = await RunAsync(
            ContextFor(facts, manifest: null),
            [.. EArkValidationProfiles.CsipPackageRules()]).ConfigureAwait(false);

        Assert.AreEqual(ClaimIssueCompletionStatus.Complete, result.CompletionStatus, "Every rule ran to completion.");
        foreach(Claim claim in result.Claims)
        {
            Assert.AreNotEqual(ClaimId.FailedClaim.Code, claim.Id.Code, "No rule threw.");
            var context = Assert.IsInstanceOfType<EArkClaimContext>(claim.Context, $"The claim {claim.Id} carries no reason.");
            Assert.AreNotEqual(EArkClaimReason.NotEvaluated, context.Reason, $"The claim {claim.Id} carries the unset reason.");
        }
    }


    /// <summary>
    /// When the document a profile judges never reaches it, every row of that profile says it was given
    /// nothing and not one of them says the requirement is met — the fail-closed property the whole corpus
    /// sweep leans on, asserted here directly rather than inferred from a corpus package.
    /// </summary>
    /// <returns>A task that completes when the package has been judged.</returns>
    /// <remarks>
    /// A manifest that is not a document at all is the cheapest attack there is: hand a validator octets it
    /// cannot parse and hope the rules read the absence of a finding as the absence of a fault. The staged
    /// binding refuses the octets, the caller therefore states no manifest, and every one of the catalogue's
    /// rows answers <see cref="EArkClaimReason.SubjectNotSupplied"/> with
    /// <see cref="ClaimOutcome.Inconclusive"/> — never success, which would report a conformance nothing
    /// established, and never failure, which would report a package defect where a document was merely
    /// unreadable.
    /// </remarks>
    [TestMethod]
    public async Task WhenTheManifestIsNotADocumentEveryProfileRowSaysItWasGivenNothing()
    {
        var entries = new List<EArkPackageEntrySource>(EArkValidationSource.ConformantPackageEntries())
        {
            [0] = EArkPackageSource.TextFile("METS.xml", OctetsThatAreNotADocument)
        };

        using EArkPackageSnapshotResult read = EArkPackageSnapshotReading.Create(
            entries,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The package is read; only its manifest is unreadable: {read.Status}.");

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        EArkPackageEntry manifestEntry = facts.Package.Manifest!;

        using(PooledMemory document = PooledMemory.FromBytes(
            manifestEntry.Content.AsReadOnlySpan(),
            BaseMemoryPool.Shared,
            EArkTags.PackageEntry))
        {
            using MetsParseResult parsed = await MetsXmlBinding.ParseAsync(
                new MetsParseContext { Document = document },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(parsed.IsValid, "The binding refuses octets that are not a document.");
            Assert.IsNotEmpty(parsed.FailureReason ?? string.Empty, "…and says why.");
        }

        ClaimIssueResult result = await RunAsync(
            ContextFor(facts, manifest: null),
            [.. EArkValidationProfiles.CsipMetsProfileRules()]).ConfigureAwait(false);

        int rows = 0;
        foreach(Claim claim in result.Claims)
        {
            ++rows;
            var context = Assert.IsInstanceOfType<EArkClaimContext>(claim.Context);
            Assert.AreEqual(ClaimOutcome.Inconclusive, claim.Outcome, $"The claim {claim.Id} reached {claim.Outcome}.");
            Assert.AreEqual(EArkClaimReason.SubjectNotSupplied, context.Reason, $"The claim {claim.Id} states {context.Reason}.");
        }

        Assert.AreEqual(116, rows, "Every row of the METS profile catalogue answered.");

        //The folder rows, which read the tree rather than the document, still answer about the package.
        ClaimIssueResult structural = await RunAsync(
            ContextFor(facts, manifest: null),
            [.. EArkValidationProfiles.CsipStructuralRules()]).ConfigureAwait(false);

        bool anySuccess = false;
        foreach(Claim claim in structural.Claims)
        {
            anySuccess |= claim.Outcome == ClaimOutcome.Success;
        }

        Assert.IsTrue(anySuccess, "A package whose manifest is unreadable is still judged by its folder structure.");
    }


    /// <summary>Builds a validation context over classified facts and an optional manifest.</summary>
    /// <param name="facts">What the package's layout states about itself.</param>
    /// <param name="manifest">The package's own root manifest, or <see langword="null"/> when none was read.</param>
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
            MemoryPool = BaseMemoryPool.Shared
        };
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


    /// <summary>Reads one requirement's claim out of a result.</summary>
    /// <param name="result">What the issuer concluded.</param>
    /// <param name="claimId">The requirement whose claim is read.</param>
    /// <returns>The claim.</returns>
    private static Claim ClaimFor(ClaimIssueResult result, ClaimId claimId)
    {
        foreach(Claim claim in result.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim;
            }
        }

        Assert.Fail($"The result carries no claim for {claimId}.");

        throw new InvalidOperationException("Unreachable: the assertion above always throws.");
    }
}
