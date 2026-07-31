using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// The first slice of the reference-artefact leg: a handful of Information Packages nothing in this repository
/// wrote, read from disk, parsed through the staged manifest binding, and put through the rule lists.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is a slice, not the sweep.</strong> The reference material states its expected outcomes against
/// an earlier edition of the requirement catalogue than the one these rules are written against, so the full
/// sweep needs a requirement-identifier delta table before any case can be called green or red on the
/// specification's own authority. That table and the sweep belong to a later stage. What this slice establishes
/// now is that the rule lists run end to end over real packages — read from a folder, classified, parsed,
/// judged — and that the findings they report on those packages are the ones the packages really carry.
/// </para>
/// <para>
/// The packages chosen are the two the material reuses across dozens of requirement directories, which makes
/// them the closest thing it has to a canonical conformant package, plus the one that carries preservation
/// metadata. Every assertion below names the requirement it is about; none asserts a blanket verdict.
/// </para>
/// <para>
/// The whole class reports itself inconclusive when the optional reference material is absent, which is the
/// discipline every reference leg in this repository follows — a leg that silently passes on missing material
/// is worse than no leg.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkCorpusValidationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier the test issuer states as its own.</summary>
    private const string IssuerId = "eark-corpus-validator";

    /// <summary>The correlation identifier the test issuer carries through a run.</summary>
    private const string CorrelationId = "eark-corpus-validation";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);


    /// <summary>
    /// The reference material's minimal conformant package satisfies the folder requirements a minimal package
    /// can satisfy, and the manifest it carries satisfies the mandatory rows of the METS profile catalogue that
    /// a package of that edition and this one agree on.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task TheReferenceMinimalPackageSatisfiesTheRequirementsAMinimalPackageCan()
    {
        string? packageRoot = FindPackage("minimal_IP_with_1_representation");
        if(packageRoot is null)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);
            return;
        }

        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The package was not read: {read.Status}.");
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        using MetsParseResult parsed = await ParseManifestAsync(facts).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The manifest was not parsed: {parsed.Status} — {parsed.FailureReason}.");

        ClaimIssueResult result = await RunAsync(ContextFor(facts, parsed.Document!)).ConfigureAwait(false);

        //The two folder requirements the catalogue states as MUSTs.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr1, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr4, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //The package really is what its name says: one representation, holding its own data.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr9, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr10, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr11, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        Assert.HasCount(1, facts.Representations);

        //The manifest's own mandatory root and header rows, which every edition of the catalogue states alike.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip1, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip2, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip117, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip9, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip10, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip11, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip12, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip13, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip14, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip15, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip16, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //The structural map the catalogue mandates, found by its label and holding its four named divisions.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip80, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip81, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip82, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip88, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //A finding about the reference material rather than about these rules: its canonical minimal package
        //carries NO per-representation division at all. It names its one representation only through the
        //content division's file pointer into the representations file group, so the division the catalogue
        //recommends is absent and the package-to-representation pointer chain the mandatory rows below it fix
        //has no subject. The recommendation reports as declined and the chain rows as not applicable — which
        //is the correct reading of a 0..n SHOULD whose children are 1..1 MUSTs.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip105, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip109, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip110, ClaimOutcome.NotApplicable, EArkClaimReason.ConditionNotTriggered);

        //Every identifier the manifest carries is a legal name — one of the two obligations the specification
        //states in prose and gives no identifier to. The other, that references resolve, has its own test
        //below, because this package does not satisfy it.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageIdentifiersAreNCNames, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// The reference material's minimal package carries a reference that does not resolve: its manifest names
    /// the schema file with a capitalised name while the package holds it under a lowercase one. On a
    /// case-insensitive file system nobody notices; on a case-sensitive one the reference dangles, and the
    /// package cannot be read by a conforming reader there.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    /// <remarks>
    /// This is a finding about the reference material, and it is the reason the reference rule compares
    /// ordinally rather than folding case: folding it would resolve the reference to a file the producer did
    /// not name, and would report a package as sound that a conforming reader cannot open. Exactly one of the
    /// package's five references is affected, which is what the claim says.
    /// </remarks>
    [TestMethod]
    public async Task TheReferenceMinimalPackageNamesASchemaFileItHoldsUnderAnotherCase()
    {
        string? packageRoot = FindPackage("minimal_IP_with_1_representation");
        if(packageRoot is null)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);
            return;
        }

        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsParseResult parsed = await ParseManifestAsync(facts).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The manifest was not parsed: {parsed.Status} — {parsed.FailureReason}.");

        ClaimIssueResult result = await RunAsync(ContextFor(facts, parsed.Document!)).ConfigureAwait(false);

        Claim references = ClaimFor(result, EArkClaimIds.PackageReferencesResolve);
        var context = Assert.IsInstanceOfType<EArkClaimContext>(references.Context);

        Assert.AreEqual(ClaimOutcome.Failure, references.Outcome);
        Assert.AreEqual(EArkClaimReason.ReferenceUnresolved, context.Reason);
        Assert.AreEqual("1 of 5 references", context.Subject);

        //The file really is there, under the name the package holds it by and not the one the manifest names.
        Assert.IsNotNull(facts.Snapshot.FindEntry("schemas/mets.xsd"));
        Assert.IsNull(facts.Snapshot.FindEntry("schemas/METS.xsd"));
    }


    /// <summary>
    /// The reference material's fuller package — the one exercising the recommendations and permissions the
    /// minimal one declines — satisfies the folder recommendations the minimal one does not, which is the
    /// difference between the two the material names them for.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task TheReferenceFullerPackageSatisfiesTheRecommendationsTheMinimalOneDeclines()
    {
        string? packageRoot = FindPackage("valid_IP_with_SHOULD_MAY_1_rep");
        if(packageRoot is null)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);
            return;
        }

        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The package was not read: {read.Status}.");
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        using MetsParseResult parsed = await ParseManifestAsync(facts).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The manifest was not parsed: {parsed.Status} — {parsed.FailureReason}.");

        ClaimIssueResult result = await RunAsync(ContextFor(facts, parsed.Document!)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr4, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr5, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr7, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr13, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr15, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr16, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //A second finding about the reference material: the package the material names for exercising the
        //recommendations and permissions gives its one representation no manifest of its own, so the
        //recommendation the specification's companion text calls "the recommended best practice to always
        //have" reports as declined. That is what the package carries; the rule is reading it correctly.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr12, ClaimOutcome.Inconclusive, EArkClaimReason.RecommendedRequirementUnmet);

        //It carries descriptive and administrative metadata, which the minimal package does not.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip17, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip31, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.Csip32, ClaimOutcome.Success, EArkClaimReason.RequirementMet);

        //And every reference it makes resolves inside the package.
        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.PackageReferencesResolve, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// The reference material's packages state their fixity under an algorithm this library recomputes, and
    /// the recomputation over the octets on disk agrees with what the manifests state — the leg that makes the
    /// fixity rule a check of real bytes rather than of a test's own arithmetic.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task TheReferencePackagesStatedFixityAgreesWithARecomputationOverItsOwnOctets()
    {
        string? packageRoot = FindPackage("valid_IP_with_SHOULD_MAY_1_rep");
        if(packageRoot is null)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);
            return;
        }

        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        using MetsParseResult parsed = await ParseManifestAsync(facts).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The manifest was not parsed: {parsed.Status} — {parsed.FailureReason}.");

        ClaimIssueResult result = await RunAsync(ContextFor(facts, parsed.Document!)).ConfigureAwait(false);

        //Whichever of the two the material's own producer chose, the claim says which and never stays silent.
        Claim strength = ClaimFor(result, EArkClaimIds.PackageFixityAlgorithmStrength);
        Claim recomputation = ClaimFor(result, EArkClaimIds.PackageFixityRecomputed);
        var strengthContext = Assert.IsInstanceOfType<EArkClaimContext>(strength.Context);
        var recomputationContext = Assert.IsInstanceOfType<EArkClaimContext>(recomputation.Context);

        Assert.AreNotEqual(EArkClaimReason.NotEvaluated, strengthContext.Reason);
        Assert.AreNotEqual(EArkClaimReason.NotEvaluated, recomputationContext.Reason);

        //Nothing mismatched: a stated value that could be recomputed was recomputed and agreed.
        Assert.AreNotEqual(EArkClaimReason.FixityMismatch, recomputationContext.Reason, recomputationContext.Subject);
    }


    /// <summary>
    /// The reference material's package carrying preservation metadata puts it where the specification says
    /// it goes and moors it to the manifest the way the archival profile asks — the two facts the whole
    /// preservation layer rests on.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task TheReferencePackageWithPreservationMetadataMoorsItToItsManifest()
    {
        string? packageRoot = FindPackage("valid_IP_with_SHOULD_MAY_1_rep_3_premis");
        if(packageRoot is null)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);
            return;
        }

        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The package was not read: {read.Status}.");
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        using MetsParseResult parsed = await ParseManifestAsync(facts).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, $"The manifest was not parsed: {parsed.Status} — {parsed.FailureReason}.");

        //The preservation metadata is in the folder the specification puts it in.
        EArkStructuralRuleTests.AssertOutcome(
            await RunAsync(ContextFor(facts, parsed.Document!)).ConfigureAwait(false),
            EArkClaimIds.CsipStr6,
            ClaimOutcome.Success,
            EArkClaimReason.RequirementMet);

        //And the manifest moors it through a digital-provenance reference naming the vocabulary.
        ClaimIssueResult archival = await RunArchivalAsync(ContextFor(facts, parsed.Document!)).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(archival, AipClaimIds.Aipm5, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
        EArkStructuralRuleTests.AssertOutcome(archival, AipClaimIds.Aipm6, ClaimOutcome.Success, EArkClaimReason.RequirementMet);
    }


    /// <summary>
    /// The reference material's own invalid case for the root-manifest requirement really is invalid by this
    /// library's reading of it: the package names its manifest with a different case, which a reader on a
    /// case-sensitive file system cannot find. The material declares the case invalid and so does this rule.
    /// </summary>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    public async Task TheReferenceInvalidRootManifestCaseFailsTheRootManifestRequirement()
    {
        string? packageRoot = FindPackage("IP_18000_CSIPSTR4_1");
        if(packageRoot is null)
        {
            Assert.Inconclusive(EArkPackageSource.MissingPackagesMessage);
            return;
        }

        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The package was not read: {read.Status}.");
        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);

        var context = new EArkValidationContext
        {
            EntryNames = EntryNamesOf(facts),
            CurrentTime = EArkValidationSource.Instant,
            PackageFacts = facts,
            MemoryPool = BaseMemoryPool.Shared,
        };

        ClaimIssueResult result = await RunAsync(context).ConfigureAwait(false);

        EArkStructuralRuleTests.AssertOutcome(result, EArkClaimIds.CsipStr4, ClaimOutcome.Failure, EArkClaimReason.MandatoryRequirementUnmet);
        Assert.IsFalse(facts.Package.HasManifest);
    }


    /// <summary>Finds one reference package by the folder name the material gives it.</summary>
    /// <param name="packageFolderName">The package folder's own name.</param>
    /// <returns>The package root, or <see langword="null"/> when the optional reference material is absent.</returns>
    /// <remarks>
    /// The search runs over the roots the layout discovery finds, so a package the discovery excludes — one
    /// whose manifest is not named exactly as the specification states — is reached through its enclosing
    /// requirement directory instead, which is what the invalid case above needs.
    /// </remarks>
    private static string? FindPackage(string packageFolderName)
    {
        foreach(string root in EArkPackageSource.FindPackageRoots())
        {
            if(string.Equals(Path.GetFileName(root), packageFolderName, StringComparison.Ordinal))
            {
                return root;
            }
        }

        string? corpus = FindCorpusRoot();
        if(corpus is null)
        {
            return null;
        }

        foreach(string candidate in Directory.EnumerateDirectories(corpus, packageFolderName, SearchOption.AllDirectories))
        {
            return candidate;
        }

        return null;
    }


    /// <summary>Finds the reference material's own corpus folder by walking up to the solution file.</summary>
    /// <returns>The corpus folder, or <see langword="null"/> when the optional material is absent.</returns>
    private static string? FindCorpusRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while(directory is not null && !File.Exists(Path.Combine(directory.FullName, "Verifiable.slnx")))
        {
            directory = directory.Parent;
        }

        if(directory is null)
        {
            return null;
        }

        string corpus = Path.Combine(directory.FullName, "tempdocs", "earchiving-reference", "eark-ip-test-corpus", "corpus");

        return Directory.Exists(corpus) ? corpus : null;
    }


    /// <summary>Parses the package's own root manifest through the staged binding.</summary>
    /// <param name="facts">What the package's layout states about itself.</param>
    /// <returns>The parse result. The caller disposes it.</returns>
    private async Task<MetsParseResult> ParseManifestAsync(EArkPackageFacts facts)
    {
        EArkPackageEntry manifest = facts.Package.Manifest
            ?? throw new InvalidOperationException("The package carries no root manifest to parse.");

        using PooledMemory document = PooledMemory.FromBytes(
            manifest.Content.AsReadOnlySpan(),
            BaseMemoryPool.Shared,
            EArkTags.PackageEntry);

        return await MetsXmlBinding.ParseAsync(
            new MetsParseContext { Document = document },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Builds a validation context over classified facts and a parsed manifest.</summary>
    /// <param name="facts">What the package's layout states about itself.</param>
    /// <param name="manifest">The package's own root manifest.</param>
    /// <returns>The context the rules run over.</returns>
    private static EArkValidationContext ContextFor(EArkPackageFacts facts, MetsDocument manifest) => new()
    {
        EntryNames = EntryNamesOf(facts),
        CurrentTime = EArkValidationSource.Instant,
        PackageFacts = facts,
        PackageManifest = manifest,
        MemoryPool = BaseMemoryPool.Shared,
    };


    /// <summary>Reads the entry names out of a classified package.</summary>
    /// <param name="facts">What the package's layout states about itself.</param>
    /// <returns>The names, in the snapshot's own order.</returns>
    private static List<string> EntryNamesOf(EArkPackageFacts facts)
    {
        var entryNames = new List<string>(facts.Snapshot.EntryCount);
        for(int i = 0; i < facts.Snapshot.Entries.Count; ++i)
        {
            entryNames.Add(facts.Snapshot.Entries[i].Name);
        }

        return entryNames;
    }


    /// <summary>Runs the whole package profile over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private Task<ClaimIssueResult> RunAsync(EArkValidationContext context) =>
        RunAsync(context, [.. EArkValidationProfiles.CsipPackageRules()]);


    /// <summary>Runs the archival package profile over one context.</summary>
    /// <param name="context">The package validation is given.</param>
    /// <returns>What the issuer concluded.</returns>
    private Task<ClaimIssueResult> RunArchivalAsync(EArkValidationContext context) =>
        RunAsync(context, [.. EArkValidationProfiles.ArchivalPackageRules()]);


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
