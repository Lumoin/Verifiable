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
/// The reference-artifact prong of the wave: every requirement-keyed case of the Information Package reference
/// corpus that this wave's profiles can answer, driven through the shipped rule lists and asserted against the
/// outcome the corpus itself states for it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What the corpus is as an oracle.</strong> Each requirement directory carries a case document stating
/// the requirement, the rules derived from it, the severity a violation is reported at, and — per rule — the
/// packages that exercise it, each declared conformant or not and declared built or merely planned. That is a
/// per-package expected outcome written by the specification family rather than by this repository, which is
/// what makes it an oracle at all. Nothing here computes an expectation; every expectation is read out of the
/// case document.
/// </para>
/// <para>
/// <strong>The edition skew, and why the delta table comes first.</strong> The cases cite editions from a draft
/// of 2.0 through 2.2.0 while every shipped rule reads
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>.
/// <see cref="EArkCorpusDeltaTable"/> states what moved between them, is itself asserted against the two
/// published catalogues by <see cref="EArkCorpusDeltaTableTests"/>, and every case a delta row governs cites
/// that row here rather than being quietly passed or quietly failed.
/// </para>
/// <para>
/// <strong>Nothing is skipped silently.</strong> Every case reaches exactly one disposition of
/// <see cref="EArkCorpusCaseDisposition"/>; the dispositions are counted and the counts asserted, so a case that
/// stopped being swept would change a number rather than disappear. The declared-but-unbuilt packages, the
/// package types this wave defers, and the retired requirement numbers are the three reasons a case is not
/// swept, and each is a disposition with its own count.
/// </para>
/// <para>
/// The whole class reports itself inconclusive when the optional reference material is absent, which is the
/// discipline every reference leg in this repository follows.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkCorpusSweepTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier the sweep's issuer states as its own.</summary>
    private const string IssuerId = "eark-corpus-sweep";

    /// <summary>The correlation identifier the sweep's issuer carries through a run.</summary>
    private const string CorrelationId = "eark-corpus-sweep";

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(EArkValidationSource.Instant);

    /// <summary>The severity a corpus rule states for a requirement that binds.</summary>
    private static string ErrorSeverity { get; } = "ERROR";

    /// <summary>The severity a corpus rule states for a requirement that recommends.</summary>
    private static string WarningSeverity { get; } = "WARNING";

    /// <summary>The severity a corpus rule states for a finding that is neither.</summary>
    private static string InformationalSeverity { get; } = "INFO";

    /// <summary>What the sweep holds a case to when the catalogue states the requirement as a permission.</summary>
    private static string PermissionSeverity { get; } = "PERMISSION";


    /// <summary>
    /// The corpus's own census: how many cases it carries, how many package references those cases state, how
    /// many of them are built, and how the built ones divide between the conformant and the non-conformant.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The figures are asserted rather than printed because they are what every other number in this class is
    /// measured against: a corpus that grew or shrank changes them, and a sweep whose subset silently moved
    /// under it would otherwise still report itself green.
    /// </para>
    /// <para>
    /// <strong>A finding this census settles.</strong> Counting package references by searching the case
    /// documents' raw text gives three more than the documents actually state, because three references sit
    /// inside XML comments — one planned package of a content-category rule, and two of a whole commented-out
    /// rule about a creation date in the future. A reader that parses the documents does not see them, and this
    /// class is that reader.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void TheCorpusCensusIsWhatTheSweepIsMeasuredAgainst()
    {
        IReadOnlyList<EArkCorpusTestCase> cases = EArkCorpusSource.FindTestCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        Assert.HasCount(147, cases, "The corpus carries one case document per requirement directory.");

        int commonSpecification = 0;
        int structural = 0;
        int submission = 0;
        int dissemination = 0;
        int casesWithoutRules = 0;
        int casesWithoutPackages = 0;
        int references = 0;
        int built = 0;
        int planned = 0;
        int conformant = 0;
        int nonConformant = 0;
        int builtButAbsentFromDisk = 0;
        int plannedYetOnDisk = 0;

        foreach(EArkCorpusTestCase testCase in cases)
        {
            _ = testCase.Family switch
            {
                EArkCorpusFamily.CommonSpecification => ++commonSpecification,
                EArkCorpusFamily.CommonSpecificationStructure => ++structural,
                EArkCorpusFamily.SubmissionPackage => ++submission,
                EArkCorpusFamily.DisseminationPackage => ++dissemination,
                _ => 0
            };

            if(testCase.Rules.Count == 0)
            {
                ++casesWithoutRules;
            }

            int packagesOfCase = 0;
            foreach(EArkCorpusRule rule in testCase.Rules)
            {
                foreach(EArkCorpusPackageReference package in rule.Packages)
                {
                    ++references;
                    ++packagesOfCase;

                    if(package.IsImplemented)
                    {
                        ++built;
                        if(package.PackageRoot is null)
                        {
                            ++builtButAbsentFromDisk;
                        }
                    }
                    else
                    {
                        ++planned;
                        if(package.PackageRoot is not null)
                        {
                            ++plannedYetOnDisk;
                        }
                    }

                    if(package.IsValid)
                    {
                        ++conformant;
                    }
                    else
                    {
                        ++nonConformant;
                    }
                }
            }

            if(packagesOfCase == 0)
            {
                ++casesWithoutPackages;
            }
        }

        Assert.AreEqual(118, commonSpecification, "The METS profile catalogue's own requirement directories, including the two retired numbers.");
        Assert.AreEqual(15, structural, "The folder-structure catalogue's requirement directories.");
        Assert.AreEqual(12, submission, "The submission-package deltas.");
        Assert.AreEqual(2, dissemination, "The dissemination-package deltas, which are scaffolding: two cases, no rules, no packages.");
        Assert.AreEqual(27, casesWithoutRules, "Cases that derive no rule at all, so state no expected outcome for anything.");
        Assert.AreEqual(27, casesWithoutPackages, "A case names a package exactly when it derives a rule, which the two counts agreeing says.");
        Assert.AreEqual(474, references, "Package references the case documents really state, comments excluded.");
        Assert.AreEqual(385, built, "References the corpus declares built.");
        Assert.AreEqual(89, planned, "References the corpus declares planned rather than built.");
        Assert.AreEqual(188, conformant, "References the corpus declares conformant to the rule that names them.");
        Assert.AreEqual(286, nonConformant, "References the corpus declares non-conformant to the rule that names them.");
        Assert.AreEqual(0, builtButAbsentFromDisk, "Everything the corpus declares built really is on disk.");
        Assert.AreEqual(1, plannedYetOnDisk, "One package the corpus declares planned is nevertheless on disk, and is not swept on that account.");
    }


    /// <summary>
    /// Every case of the corpus reaches exactly one disposition, and the dispositions add up to the census — the
    /// property that makes a skip a recorded decision rather than an omission.
    /// </summary>
    [TestMethod]
    public void EveryCaseIsSweptOrSkippedForOneStatedReason()
    {
        List<EArkCorpusCase> cases = BuildCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        var counts = new Dictionary<EArkCorpusCaseDisposition, int>();
        foreach(EArkCorpusCase corpusCase in cases)
        {
            Assert.AreNotEqual(
                EArkCorpusCaseDisposition.NotEvaluated,
                corpusCase.Disposition,
                $"{corpusCase.Describe()} reached no disposition, which is the one answer the sweep may never give.");

            counts[corpusCase.Disposition] = counts.TryGetValue(corpusCase.Disposition, out int existing) ? existing + 1 : 1;
        }

        Assert.HasCount(474, cases, "One case per package reference the corpus states.");
        Assert.AreEqual(6, Count(counts, EArkCorpusCaseDisposition.RequirementRetired), "Every reference of the two retired requirement numbers, built or not.");
        Assert.AreEqual(56, Count(counts, EArkCorpusCaseDisposition.SpecificationDeferred), "Every reference of the package types this wave defers by contract.");
        Assert.AreEqual(80, Count(counts, EArkCorpusCaseDisposition.PackageNotBuilt), "The remaining references the corpus declares planned rather than built.");
        Assert.AreEqual(6, Count(counts, EArkCorpusCaseDisposition.RequirementIsAPermission), "Non-conformant packages named by a rule over a requirement the catalogue states as a permission.");
        Assert.AreEqual(326, Count(counts, EArkCorpusCaseDisposition.Swept), "The swept subset.");
        Assert.AreEqual(0, Count(counts, EArkCorpusCaseDisposition.RuleInformational), "No built Common Specification case states an informational rule with a non-conformant package.");

        //The four dispositions partition the whole, so no case can be counted twice or dropped.
        int total = 0;
        foreach(KeyValuePair<EArkCorpusCaseDisposition, int> disposition in counts)
        {
            total += disposition.Value;
        }

        Assert.AreEqual(cases.Count, total);
    }


    /// <summary>
    /// The sweep itself: every case of the swept subset driven through the shipped rule lists, with the outcome
    /// the corpus states for it asserted against the claim the requirement's own rule issued.
    /// </summary>
    /// <returns>A task that completes when every case has been driven.</returns>
    /// <remarks>
    /// <para>
    /// One package is read, classified, parsed and judged once however many cases name it, because a package's
    /// claim set does not depend on which requirement is asking. The reading is the shipped one — the value
    /// snapshot, the tree classifier, the staged manifest binding and the whole
    /// <see cref="EArkValidationProfiles.CsipPackageRules"/> list — so what is asserted is what a caller of this
    /// library would get.
    /// </para>
    /// <para>
    /// <strong>The expectations are the corpus's own, held at the catalogue's level.</strong> A package the
    /// corpus declares conformant to a rule may not fail that rule's requirement, and may not depart from it
    /// either where the requirement recommends; a package it declares non-conformant must fail the requirement
    /// where the requirement binds, and must depart from it where it recommends. Which of the two the
    /// requirement is comes from the published catalogue rather than from the corpus's reporting severity, for
    /// the reason written at <see cref="EffectiveSeverityOf"/>.
    /// </para>
    /// <para>
    /// <strong>Two ways of agreeing that are not the same as the claim matching.</strong> A package whose
    /// manifest the staged binding refuses never reaches a rule at all — the document is not a manifest of the
    /// profile, so the library refuses the package at an earlier gate and the rules honestly report that they
    /// were given nothing. That is counted as a refusal, not as a pass, and the run asserts separately that no
    /// package the corpus declares conformant is refused that way. And where the shipped rules answer something
    /// else on purpose, <see cref="EArkCorpusKnownDeviations"/> states what they answer and why; the sweep holds
    /// the claim to that reading letter for letter and, where the ledger names a claim of this library's own
    /// that catches the same violation, asserts that claim really failed.
    /// </para>
    /// <para>
    /// Disagreements are collected and reported together rather than one per run, and each names the case, the
    /// package, what was expected and what the claim said — a sweep that stopped at the first disagreement would
    /// take one run per finding.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task EverySweptCaseReachesTheOutcomeTheCorpusStatesForIt()
    {
        List<EArkCorpusCase> cases = BuildCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        var byPackage = new Dictionary<string, List<EArkCorpusCase>>(StringComparer.Ordinal);
        foreach(EArkCorpusCase corpusCase in cases)
        {
            if(corpusCase.Disposition != EArkCorpusCaseDisposition.Swept)
            {
                continue;
            }

            string root = corpusCase.Package.PackageRoot!;
            if(!byPackage.TryGetValue(root, out List<EArkCorpusCase>? group))
            {
                group = [];
                byPackage.Add(root, group);
            }

            group.Add(corpusCase);
        }

        var disagreements = new List<string>();
        var exercised = new List<string>();
        var categories = new Dictionary<EArkCorpusDeviationCategory, int>();
        int asserted = 0;
        int agreed = 0;
        int refusedByTheBinding = 0;
        int unjudgeable = 0;
        foreach(KeyValuePair<string, List<EArkCorpusCase>> package in byPackage)
        {
            EArkCorpusPackageReading reading = await JudgePackageAsync(package.Key).ConfigureAwait(false);
            foreach(EArkCorpusCase corpusCase in package.Value)
            {
                ++asserted;

                //A rule of the METS profile catalogue is a question about a document. When the binding refuses
                //that document and the corpus nevertheless declares the package conformant to this rule, the
                //case cannot be judged at all — the corpus's flag is per rule, so a package it calls conformant
                //to one requirement may violate another badly enough that no manifest reaches the rules. That is
                //recorded here, never counted as a pass.
                if(corpusCase.Family == EArkCorpusFamily.CommonSpecification
                    && corpusCase.Package.IsValid
                    && !reading.ManifestParsed)
                {
                    ++unjudgeable;
                    Assert.IsNotEmpty(reading.ParseFailure, $"{corpusCase.Describe()}: a refused manifest states why it was refused.");
                    continue;
                }

                string? disagreement = StateDisagreement(corpusCase, reading.Claims);
                if(disagreement is null)
                {
                    ++agreed;
                    continue;
                }

                if(corpusCase.Family == EArkCorpusFamily.CommonSpecification
                    && !corpusCase.Package.IsValid
                    && !reading.ManifestParsed
                    && reading.Claims.TryGetValue(corpusCase.ClaimCode, out EArkCorpusClaimReading? refused)
                    && refused.Outcome == ClaimOutcome.Inconclusive
                    && refused.Reason == EArkClaimReason.SubjectNotSupplied)
                {
                    ++refusedByTheBinding;
                    continue;
                }

                if(EArkCorpusKnownDeviations.Find(corpusCase.RequirementId, corpusCase.RuleId) is not { } ledger)
                {
                    disagreements.Add(disagreement);
                    continue;
                }

                string? ledgerDisagreement = StateLedgerDisagreement(corpusCase, ledger.Group, ledger.Member, reading.Claims);
                if(ledgerDisagreement is not null)
                {
                    disagreements.Add(ledgerDisagreement);
                    continue;
                }

                string member = $"{ledger.Member.RequirementId}/{ledger.Member.RuleId}";
                if(!exercised.Contains(member))
                {
                    exercised.Add(member);
                }

                categories[ledger.Group.Category] = categories.TryGetValue(ledger.Group.Category, out int existing) ? existing + 1 : 1;
            }
        }

        Assert.IsEmpty(disagreements, BuildDisagreementReport(disagreements));
        Assert.AreEqual(326, asserted, "Every case of the swept subset was really driven.");
        Assert.HasCount(280, byPackage, "The distinct packages the swept subset names, each read and judged once.");

        //The swept subset's statistics, in one line so that a case moving between them changes the line rather
        //than one number silently compensating for another.
        Assert.AreEqual(
            "agreed=243 refused-by-the-binding=29 unjudgeable=1 ledger=53",
            $"agreed={agreed} refused-by-the-binding={refusedByTheBinding} unjudgeable={unjudgeable} ledger={asserted - agreed - refusedByTheBinding - unjudgeable}",
            "The swept subset's statistics.");

        //No ledger row may go unexercised, which is what keeps the ledger from outliving the difference it states.
        var stale = new List<string>();
        foreach(EArkCorpusDeviationGroup group in EArkCorpusKnownDeviations.Groups)
        {
            foreach(EArkCorpusDeviationMember member in group.Members)
            {
                if(!exercised.Contains($"{member.RequirementId}/{member.RuleId}"))
                {
                    stale.Add($"{member.RequirementId} rule {member.RuleId} ({group.Category})");
                }
            }
        }

        Assert.IsEmpty(stale, $"Deviation ledger rows that no swept case exercises: {string.Join("; ", stale)}.");
        Assert.HasCount(12, categories, "Every category of the ledger is exercised.");
    }


    /// <summary>
    /// The cases a level-softening delta row governs are held to the later edition's level, not to the severity
    /// the corpus states — the one place in the sweep where an expectation is shifted rather than read straight
    /// off the case document, and therefore the one that has to be enumerated rather than described.
    /// </summary>
    /// <remarks>
    /// All six affected cases state their rule at the binding severity, because the corpus never carried the
    /// softening through to its own rules: three of them name a package the corpus declares non-conformant, and
    /// those three are the cases whose expectation really moves — from a violated requirement to a departed-from
    /// recommendation. The other three name the conformant package, for which both readings expect the same
    /// thing.
    /// </remarks>
    [TestMethod]
    public void TheCasesALevelSofteningRowGovernsAreHeldToTheLaterEditionsLevel()
    {
        List<EArkCorpusCase> cases = BuildCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        var governed = new List<EArkCorpusCase>();
        foreach(EArkCorpusCase corpusCase in cases)
        {
            if(corpusCase.Delta is not null && corpusCase.Delta.Kind == EArkCorpusDeltaKind.RequirementLevelSoftened)
            {
                governed.Add(corpusCase);
            }
        }

        Assert.HasCount(6, governed, "The corpus states two package references for each of the three softened requirements.");

        var requirements = new List<string>();
        int shifted = 0;
        foreach(EArkCorpusCase corpusCase in governed)
        {
            Assert.AreEqual(EArkCorpusCaseDisposition.Swept, corpusCase.Disposition, $"{corpusCase.Describe()} is shifted, not skipped.");
            Assert.AreEqual(ErrorSeverity, corpusCase.Severity, $"{corpusCase.Describe()} states the severity the earlier edition's level gave it.");
            Assert.AreEqual("SHOULD", corpusCase.CatalogueLevel, $"{corpusCase.Describe()} is a recommendation in the edition the shipped rules read.");
            Assert.AreEqual(WarningSeverity, corpusCase.EffectiveSeverity, $"{corpusCase.Describe()} is held to the later edition's level.");

            if(!requirements.Contains(corpusCase.RequirementId))
            {
                requirements.Add(corpusCase.RequirementId);
            }

            if(!corpusCase.Package.IsValid)
            {
                ++shifted;
            }
        }

        requirements.Sort(StringComparer.Ordinal);
        Assert.AreSequenceEqual(["CSIP100", "CSIP104", "CSIP96"], requirements, "The three requirements the two published catalogues differ on.");
        Assert.AreEqual(3, shifted, "One non-conformant package per softened requirement, whose expectation the row really moves.");
    }


    /// <summary>
    /// The corpus's rule severities and the published catalogue's requirement levels disagree in both
    /// directions, which is why the sweep holds a case to the catalogue and counts the disagreements instead of
    /// assuming there are none.
    /// </summary>
    /// <remarks>
    /// The disagreement is not the edition skew: the three requirements the later edition softened are only
    /// three of these, and the rest are rules reported more or less severely than the level the catalogue has
    /// stated in every edition this material carries. Both directions occur, so neither can be explained as the
    /// corpus being uniformly stricter or uniformly laxer.
    /// </remarks>
    [TestMethod]
    public void TheCorpusSeverityAndTheCatalogueLevelDisagreeInBothDirections()
    {
        List<EArkCorpusCase> cases = BuildCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        var reportedMoreSeverely = new List<string>();
        var reportedLessSeverely = new List<string>();
        var withoutCatalogueLevel = new List<string>();
        foreach(EArkCorpusCase corpusCase in cases)
        {
            if(corpusCase.Disposition != EArkCorpusCaseDisposition.Swept)
            {
                continue;
            }

            if(corpusCase.CatalogueLevel.Length == 0)
            {
                if(!withoutCatalogueLevel.Contains(corpusCase.RequirementId))
                {
                    withoutCatalogueLevel.Add(corpusCase.RequirementId);
                }

                continue;
            }

            if(string.Equals(corpusCase.Severity, corpusCase.EffectiveSeverity, StringComparison.Ordinal))
            {
                continue;
            }

            string entry = $"{corpusCase.RequirementId} rule {corpusCase.RuleId}";
            if(string.Equals(corpusCase.Severity, ErrorSeverity, StringComparison.Ordinal))
            {
                if(!reportedMoreSeverely.Contains(entry))
                {
                    reportedMoreSeverely.Add(entry);
                }
            }
            else if(!reportedLessSeverely.Contains(entry))
            {
                reportedLessSeverely.Add(entry);
            }
        }

        Assert.IsNotEmpty(reportedMoreSeverely, "Rules the corpus reports as errors over requirements the catalogue states as recommendations or permissions.");
        Assert.IsNotEmpty(reportedLessSeverely, "Rules the corpus reports as warnings over requirements the catalogue states as binding.");
        Assert.AreEqual(
            "more-severely=25 less-severely=9",
            $"more-severely={reportedMoreSeverely.Count} less-severely={reportedLessSeverely.Count}",
            "How far the corpus's reporting severities and the catalogue's requirement levels are apart.");

        foreach(string requirementId in withoutCatalogueLevel)
        {
            Assert.StartsWith(
                "CSIPSTR",
                requirementId,
                "The METS profile catalogue states a level for every requirement of its own numbering, so only the folder-structure rows fall back to the corpus's severity.");
        }
    }


    /// <summary>
    /// Every case the sweep skips names the delta row or the contract clause that justifies the skip, and the
    /// skipped requirement identifiers are the ones those rows and clauses name — never some other set.
    /// </summary>
    [TestMethod]
    public void EverySkippedCaseNamesWhyItIsSkipped()
    {
        List<EArkCorpusCase> cases = BuildCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        var retired = new List<string>();
        var deferred = new List<string>();
        foreach(EArkCorpusCase corpusCase in cases)
        {
            if(corpusCase.Disposition == EArkCorpusCaseDisposition.Swept)
            {
                continue;
            }

            Assert.IsNotEmpty(corpusCase.SkipReason, $"{corpusCase.Describe()} is skipped with no reason stated.");

            if(corpusCase.Disposition == EArkCorpusCaseDisposition.RequirementRetired)
            {
                Assert.IsNotNull(
                    EArkCorpusDeltaTable.Find(corpusCase.RequirementId),
                    $"{corpusCase.Describe()} is skipped as retired and no delta row states the retirement.");

                if(!retired.Contains(corpusCase.RequirementId))
                {
                    retired.Add(corpusCase.RequirementId);
                }
            }

            if(corpusCase.Disposition == EArkCorpusCaseDisposition.SpecificationDeferred && !deferred.Contains(corpusCase.RequirementId))
            {
                deferred.Add(corpusCase.RequirementId);
            }
        }

        retired.Sort(StringComparer.Ordinal);
        Assert.AreSequenceEqual(
            ["CSIP86"],
            retired,
            "Of the two retired numbers the corpus keeps a directory for, only one names a package at all; the other derives no rule.");
        Assert.IsNotEmpty(deferred, "The deferred package type really is exercised by the corpus.");

        foreach(string requirementId in deferred)
        {
            Assert.StartsWith("SIP", requirementId, "Only the submission-package deltas are deferred with a package to skip.");
        }
    }


    /// <summary>
    /// The two packages the corpus declares conformant to a rule their own descriptions say they violate really
    /// do carry the absence the rule is about — read out of the parsed manifest rather than out of the
    /// description's wording, so the finding is about the packages and not about how they are described.
    /// </summary>
    /// <returns>A task that completes when both packages have been read.</returns>
    /// <remarks>
    /// This is the evidence behind the <see cref="EArkCorpusDeviationCategory.CorpusPackageContradictsItsOwnDescription"/>
    /// rows of the deviation ledger: one package built to carry no descriptive metadata section at all is
    /// declared conformant to the rule that asks for one, and one built to carry that section with no reference
    /// inside it is declared conformant to the rule that asks for the reference. The shipped rules report both
    /// as departures from a recommendation, which is what the packages really are.
    /// </remarks>
    [TestMethod]
    public async Task TheTwoPackagesFlaggedConformantReallyCarryTheAbsenceTheirRuleIsAbout()
    {
        List<EArkCorpusCase> cases = BuildCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        string missingSection = RootOf(cases, "CSIP17", "1");
        string missingReference = RootOf(cases, "CSIP21", "2");

        using(MetsParseResult parsed = await ParseManifestOfAsync(missingSection).ConfigureAwait(false))
        {
            Assert.IsTrue(parsed.IsValid, $"The manifest of the package was not parsed: {parsed.Status} — {parsed.FailureReason}.");
            Assert.IsEmpty(
                parsed.Document!.DescriptiveMetadataSections,
                "The package the corpus declares conformant to the rule asking for a descriptive metadata section carries none.");
        }

        using(MetsParseResult parsed = await ParseManifestOfAsync(missingReference).ConfigureAwait(false))
        {
            Assert.IsTrue(parsed.IsValid, $"The manifest of the package was not parsed: {parsed.Status} — {parsed.FailureReason}.");
            Assert.IsNotEmpty(
                parsed.Document!.DescriptiveMetadataSections,
                "The package the corpus declares conformant to the rule asking for a reference carries the section the reference belongs in.");

            foreach(MetsDescriptiveMetadataSection section in parsed.Document.DescriptiveMetadataSections)
            {
                Assert.IsNull(section.Reference, "…and that section carries no reference, which is exactly what the rule asks for.");
            }
        }
    }


    /// <summary>
    /// The requirement identifiers the sweep asserts against resolve to claims the shipped profiles really
    /// issue — the check that keeps the sweep from quietly asserting nothing because it looked up a claim
    /// nothing ever states.
    /// </summary>
    [TestMethod]
    public void EverySweptRequirementResolvesToAClaimTheShippedProfilesIssue()
    {
        List<EArkCorpusCase> cases = BuildCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        var issued = new HashSet<int>();
        foreach(ClaimDelegate<EArkValidationContext> rule in EArkValidationProfiles.CsipPackageRules())
        {
            foreach(ClaimId claimId in rule.ExpectedClaimIds)
            {
                _ = issued.Add(claimId.Code);
            }
        }

        var swept = new HashSet<string>(StringComparer.Ordinal);
        foreach(EArkCorpusCase corpusCase in cases)
        {
            if(corpusCase.Disposition != EArkCorpusCaseDisposition.Swept)
            {
                continue;
            }

            _ = swept.Add(corpusCase.RequirementId);
            Assert.Contains(
                corpusCase.ClaimCode,
                issued,
                $"{corpusCase.Describe()} names a requirement no rule of the package profile issues.");
        }

        Assert.HasCount(87, swept, "The requirement identifiers the swept subset covers.");
    }


    /// <summary>
    /// Builds every case of the corpus with the disposition the sweep gives it.
    /// </summary>
    /// <returns>The cases, in the corpus's own order. Empty when the reference material is absent.</returns>
    private static List<EArkCorpusCase> BuildCases()
    {
        IReadOnlyList<EArkCorpusTestCase> testCases = EArkCorpusSource.FindTestCases();
        EArkProfileCatalogue? catalogue = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.RuleVersion);
        var cases = new List<EArkCorpusCase>();
        foreach(EArkCorpusTestCase testCase in testCases)
        {
            foreach(EArkCorpusRule rule in testCase.Rules)
            {
                foreach(EArkCorpusPackageReference package in rule.Packages)
                {
                    cases.Add(BuildCase(testCase, rule, package, catalogue));
                }
            }
        }

        return cases;
    }


    /// <summary>
    /// Gives one package reference of one rule its disposition.
    /// </summary>
    /// <param name="testCase">The case the rule belongs to.</param>
    /// <param name="rule">The rule naming the package.</param>
    /// <param name="package">The package reference.</param>
    /// <param name="catalogue">The published catalogue the shipped rules read, when the material carries it.</param>
    /// <returns>The case.</returns>
    /// <remarks>
    /// <para>
    /// The reasons are taken in the order of how permanently they stop the sweep, not in the order they are
    /// cheapest to check: a retired requirement could not be judged however well the package was built; a
    /// deferred package type has no rule list at all; only then does it matter whether the package exists; and
    /// an informational rule states no conformance outcome to compare a claim against. Taking them the other
    /// way round would report a retired requirement's unbuilt package as merely unbuilt, which is the weaker of
    /// two true statements.
    /// </para>
    /// <para>
    /// A case whose requirement a level-softening delta row governs is still swept — the row shifts the
    /// expectation rather than removing it, and the case carries the row so a reader of a failure sees which.
    /// </para>
    /// </remarks>
    private static EArkCorpusCase BuildCase(
        EArkCorpusTestCase testCase,
        EArkCorpusRule rule,
        EArkCorpusPackageReference package,
        EArkProfileCatalogue? catalogue)
    {
        EArkCorpusDeltaRow? delta = EArkCorpusDeltaTable.Find(testCase.RequirementId);
        string catalogueLevel = catalogue?.Find(testCase.RequirementId)?.Level ?? string.Empty;
        string effectiveSeverity = EffectiveSeverityOf(rule.ErrorLevel, catalogueLevel);
        EArkCorpusCaseDisposition disposition;
        string skipReason;
        if(delta is not null && delta.Kind == EArkCorpusDeltaKind.RequirementRetired)
        {
            disposition = EArkCorpusCaseDisposition.RequirementRetired;
            skipReason = $"Delta row {delta.Id}: the edition the shipped rules read states no such requirement, and this repository allocates no claim identifier for it.";
        }
        else if(testCase.Family is EArkCorpusFamily.SubmissionPackage or EArkCorpusFamily.DisseminationPackage)
        {
            disposition = EArkCorpusCaseDisposition.SpecificationDeferred;
            skipReason = "The wave contract puts the submission and dissemination package types out of scope, recognised in the requirements matrix and not validated here.";
        }
        else if(!package.IsImplemented || package.PackageRoot is null)
        {
            disposition = EArkCorpusCaseDisposition.PackageNotBuilt;
            skipReason = "The corpus declares the package planned rather than built, so there is nothing on disk to read.";
        }
        else if(!package.IsValid && string.Equals(rule.ErrorLevel, InformationalSeverity, StringComparison.Ordinal))
        {
            disposition = EArkCorpusCaseDisposition.RuleInformational;
            skipReason = "The rule states its finding at the informational severity, which is not one of the conformance levels the specification's own keywords define.";
        }
        else if(!package.IsValid && string.Equals(effectiveSeverity, PermissionSeverity, StringComparison.Ordinal))
        {
            disposition = EArkCorpusCaseDisposition.RequirementIsAPermission;
            skipReason = $"The published catalogue states the requirement at the permission level ({catalogueLevel}), and a package cannot violate a permission — whatever severity the corpus rule states for it.";
        }
        else
        {
            disposition = EArkCorpusCaseDisposition.Swept;
            skipReason = string.Empty;
        }

        return new EArkCorpusCase
        {
            RequirementId = testCase.RequirementId,
            Family = testCase.Family,
            StatedVersion = testCase.StatedVersion,
            RuleId = rule.RuleId,
            Severity = rule.ErrorLevel,
            CatalogueLevel = catalogueLevel,
            EffectiveSeverity = effectiveSeverity,
            Package = package,
            ClaimCode = ClaimCodeFor(testCase.RequirementId),
            Delta = delta,
            Disposition = disposition,
            SkipReason = skipReason
        };
    }


    /// <summary>
    /// States the severity the sweep holds a rule to: the one the requirement's own level in the published
    /// catalogue gives it, and the corpus rule's own severity only where the catalogue states no level.
    /// </summary>
    /// <param name="statedSeverity">The severity the corpus rule states.</param>
    /// <param name="catalogueLevel">The requirement level the published catalogue states, or the empty string.</param>
    /// <returns>The severity the expectation is taken at.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Why the catalogue decides and the corpus's severity does not.</strong> A corpus rule's severity
    /// is a validator's reporting choice; the requirement level is the specification's own normative statement,
    /// and ruling R-5 of the wave contract binds this library's outcomes to exactly that — a MUST that does not
    /// hold fails, a SHOULD that does not hold is a departure. Holding a case to the catalogue's level is
    /// therefore holding it to the specification, while what the corpus alone states — that this package
    /// violates this rule — is never derived and always read straight off the case document.
    /// </para>
    /// <para>
    /// The two disagree in both directions across the corpus, which
    /// <see cref="TheCorpusSeverityAndTheCatalogueLevelDisagreeInBothDirections"/> counts rather than hides. The
    /// folder-structure catalogue has no rows in the METS profile at all, so its cases fall back to the corpus's
    /// severity, which is the only statement available for them.
    /// </para>
    /// </remarks>
    private static string EffectiveSeverityOf(string statedSeverity, string catalogueLevel) => catalogueLevel switch
    {
        "MUST" => ErrorSeverity,
        "SHOULD" => WarningSeverity,
        "MAY" => PermissionSeverity,
        _ => statedSeverity
    };


    /// <summary>
    /// States the claim code this repository allocates for one requirement identifier.
    /// </summary>
    /// <param name="requirementId">The requirement identifier.</param>
    /// <returns>The code, or zero when this repository allocates none.</returns>
    /// <remarks>
    /// The arithmetic is the one the allocation sites document as stable — a band start plus the requirement's
    /// own number — so the sweep names a claim the same way a consuming graph would, rather than through a
    /// lookup table that could drift from the allocations.
    /// </remarks>
    private static int ClaimCodeFor(string requirementId)
    {
        if(requirementId.StartsWith("CSIPSTR", StringComparison.Ordinal)
            && int.TryParse(requirementId.AsSpan("CSIPSTR".Length), NumberStyles.None, CultureInfo.InvariantCulture, out int structural))
        {
            return EArkClaimIds.FolderStructureRangeStart + structural;
        }

        if(requirementId.StartsWith("CSIP", StringComparison.Ordinal)
            && int.TryParse(requirementId.AsSpan("CSIP".Length), NumberStyles.None, CultureInfo.InvariantCulture, out int profile))
        {
            return EArkClaimIds.MetsProfileRangeStart + profile;
        }

        return 0;
    }


    /// <summary>
    /// Finds the package root one corpus rule's only conformant case names.
    /// </summary>
    /// <param name="cases">Every case the corpus states.</param>
    /// <param name="requirementId">The requirement identifier.</param>
    /// <param name="ruleId">The rule's own identifier within its case.</param>
    /// <returns>The package's root folder.</returns>
    private static string RootOf(List<EArkCorpusCase> cases, string requirementId, string ruleId)
    {
        for(int i = 0; i < cases.Count; ++i)
        {
            EArkCorpusCase corpusCase = cases[i];
            if(string.Equals(corpusCase.RequirementId, requirementId, StringComparison.Ordinal)
                && string.Equals(corpusCase.RuleId, ruleId, StringComparison.Ordinal)
                && corpusCase.Package.IsValid
                && corpusCase.Package.PackageRoot is not null)
            {
                return corpusCase.Package.PackageRoot;
            }
        }

        Assert.Fail($"The corpus states no conformant package for {requirementId} rule {ruleId}.");

        throw new InvalidOperationException("Unreachable: the assertion above always throws.");
    }


    /// <summary>
    /// Reads one package's root manifest through the staged binding.
    /// </summary>
    /// <param name="packageRoot">The package's root folder.</param>
    /// <returns>The parse result. The caller disposes it.</returns>
    private async Task<MetsParseResult> ParseManifestOfAsync(string packageRoot)
    {
        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The reference package at {packageRoot} was not read: {read.Status}.");

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
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


    /// <summary>
    /// Reads one package off disk, judges it with the shipped package profile, and states what every claim said.
    /// </summary>
    /// <param name="packageRoot">The package's root folder.</param>
    /// <returns>What the claims said, and whether the manifest reached them at all.</returns>
    private async Task<EArkCorpusPackageReading> JudgePackageAsync(string packageRoot)
    {
        using EArkPackageSnapshotResult read = EArkPackageSource.ReadFolder(
            packageRoot,
            EArkPackageLimits.Conformant,
            BaseMemoryPool.Shared);

        Assert.IsTrue(read.IsRead, $"The reference package at {packageRoot} was not read: {read.Status}.");

        EArkPackageFacts facts = EArkPackageReading.StateFacts(read.Snapshot!);
        var entryNames = new List<string>(facts.Snapshot.EntryCount);
        for(int i = 0; i < facts.Snapshot.Entries.Count; ++i)
        {
            entryNames.Add(facts.Snapshot.Entries[i].Name);
        }

        MetsParseResult? parsed = null;
        try
        {
            if(facts.Package.Manifest is EArkPackageEntry manifest)
            {
                using PooledMemory document = PooledMemory.FromBytes(
                    manifest.Content.AsReadOnlySpan(),
                    BaseMemoryPool.Shared,
                    EArkTags.PackageEntry);

                parsed = await MetsXmlBinding.ParseAsync(
                    new MetsParseContext { Document = document },
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).ConfigureAwait(false);
            }

            var context = new EArkValidationContext
            {
                EntryNames = entryNames,
                CurrentTime = EArkValidationSource.Instant,
                PackageFacts = facts,
                PackageManifest = parsed is { IsValid: true } ? parsed.Document : null,
                MemoryPool = BaseMemoryPool.Shared
            };

            var issuer = new ClaimIssuer<EArkValidationContext>(
                IssuerId,
                [.. EArkValidationProfiles.CsipPackageRules()],
                IssuerTime);

            ClaimIssueResult result = await issuer.GenerateClaimsAsync(context, CorrelationId, TestContext.CancellationToken).ConfigureAwait(false);

            var readings = new Dictionary<int, EArkCorpusClaimReading>();
            foreach(Claim claim in result.Claims)
            {
                EArkClaimReason reason = claim.Context is EArkClaimContext claimContext ? claimContext.Reason : EArkClaimReason.NotEvaluated;
                string subject = claim.Context is EArkClaimContext stated ? stated.Subject : string.Empty;
                readings[claim.Id.Code] = new EArkCorpusClaimReading { Outcome = claim.Outcome, Reason = reason, Subject = subject };
            }

            return new EArkCorpusPackageReading
            {
                Claims = readings,
                ManifestParsed = parsed is { IsValid: true },
                ParseFailure = parsed is null
                    ? "the package carries no root manifest"
                    : parsed.IsValid ? string.Empty : $"{parsed.Status} — {parsed.FailureReason}"
            };
        }
        finally
        {
            parsed?.Dispose();
        }
    }


    /// <summary>
    /// States how one case the deviation ledger covers disagrees with the reading the ledger records for it, if
    /// it does.
    /// </summary>
    /// <param name="corpusCase">The case.</param>
    /// <param name="group">The ledger group covering the case's rule.</param>
    /// <param name="member">The ledger row covering the case's rule.</param>
    /// <param name="claims">What every claim of the package said.</param>
    /// <returns>The disagreement, or <see langword="null"/> when the ledger describes the case exactly.</returns>
    /// <remarks>
    /// A ledger row states a reading, not a licence: the claim has to carry the outcome and the reason the row
    /// records, and where the row names a claim of this library's own that catches the same violation, that
    /// claim has to have failed. Both halves are what keeps the ledger from turning into "whatever the code
    /// happens to do".
    /// </remarks>
    private static string? StateLedgerDisagreement(
        EArkCorpusCase corpusCase,
        EArkCorpusDeviationGroup group,
        EArkCorpusDeviationMember member,
        IReadOnlyDictionary<int, EArkCorpusClaimReading> claims)
    {
        if(!claims.TryGetValue(corpusCase.ClaimCode, out EArkCorpusClaimReading? reading))
        {
            return $"{corpusCase.Describe()}: the ledger covers this rule and the package profile issued no claim for the requirement.";
        }

        if(reading.Outcome != group.ShippedOutcome || reading.Reason != group.ShippedReason)
        {
            return $"{corpusCase.Describe()}: the ledger records {group.ShippedOutcome}/{group.ShippedReason} under {group.Category}, and the claim says {reading.Describe()}.";
        }

        if(member.DetectingClaimCode == 0)
        {
            return null;
        }

        if(!claims.TryGetValue(member.DetectingClaimCode, out EArkCorpusClaimReading? detecting))
        {
            return $"{corpusCase.Describe()}: the ledger names claim {member.DetectingClaimCode} as carrying the finding and the profile issued no such claim.";
        }

        return detecting.Outcome == member.DetectingClaimOutcome && detecting.Reason == member.DetectingClaimReason
            ? null
            : $"{corpusCase.Describe()}: the ledger records claim {member.DetectingClaimCode} as saying {member.DetectingClaimOutcome}/{member.DetectingClaimReason}, and it says {detecting.Describe()}.";
    }


    /// <summary>
    /// States how one swept case disagrees with the claim its requirement's rule issued, if it does.
    /// </summary>
    /// <param name="corpusCase">The case.</param>
    /// <param name="claims">What every claim of the package said.</param>
    /// <returns>The disagreement, or <see langword="null"/> when the claim is what the corpus states.</returns>
    private static string? StateDisagreement(EArkCorpusCase corpusCase, IReadOnlyDictionary<int, EArkCorpusClaimReading> claims)
    {
        if(!claims.TryGetValue(corpusCase.ClaimCode, out EArkCorpusClaimReading? reading))
        {
            return $"{corpusCase.Describe()}: the package profile issued no claim for this requirement.";
        }

        if(corpusCase.Package.IsValid)
        {
            if(reading.Outcome == ClaimOutcome.Failure)
            {
                return $"{corpusCase.Describe()}: corpus says conformant, claim says {reading.Describe()}.";
            }

            if(string.Equals(corpusCase.EffectiveSeverity, WarningSeverity, StringComparison.Ordinal)
                && reading.Reason == EArkClaimReason.RecommendedRequirementUnmet)
            {
                return $"{corpusCase.Describe()}: corpus says the recommendation is satisfied, claim says {reading.Describe()}.";
            }

            return null;
        }

        if(string.Equals(corpusCase.EffectiveSeverity, ErrorSeverity, StringComparison.Ordinal))
        {
            return reading.Outcome == ClaimOutcome.Failure
                ? null
                : $"{corpusCase.Describe()}: corpus says the requirement is violated, claim says {reading.Describe()}.";
        }

        if(string.Equals(corpusCase.EffectiveSeverity, WarningSeverity, StringComparison.Ordinal))
        {
            return reading.Reason == EArkClaimReason.RecommendedRequirementUnmet
                ? null
                : $"{corpusCase.Describe()}: corpus says the recommendation is departed from, claim says {reading.Describe()}.";
        }

        return $"{corpusCase.Describe()}: the rule states the severity {corpusCase.Severity}, which the sweep has no expectation for.";
    }


    /// <summary>
    /// Builds the report a disagreeing sweep fails with.
    /// </summary>
    /// <param name="disagreements">What disagreed.</param>
    /// <returns>The report.</returns>
    private static string BuildDisagreementReport(List<string> disagreements)
    {
        var report = new StringBuilder();
        _ = report.Append(CultureInfo.InvariantCulture, $"{disagreements.Count} swept cases disagree with the corpus:");
        for(int i = 0; i < disagreements.Count; ++i)
        {
            _ = report.Append(CultureInfo.InvariantCulture, $"\n  {disagreements[i]}");
        }

        return report.ToString();
    }


    /// <summary>Reads one disposition's count out of the tally, answering zero when it never occurred.</summary>
    /// <param name="counts">The tally.</param>
    /// <param name="disposition">The disposition to read.</param>
    /// <returns>The count.</returns>
    private static int Count(Dictionary<EArkCorpusCaseDisposition, int> counts, EArkCorpusCaseDisposition disposition) =>
        counts.TryGetValue(disposition, out int count) ? count : 0;
}


/// <summary>
/// What the sweep did with one package reference of one corpus rule.
/// </summary>
/// <remarks>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised disposition never reads as a case that was
/// swept.
/// </remarks>
internal enum EArkCorpusCaseDisposition
{
    /// <summary>No disposition reached. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>The case was driven through the shipped rule lists and asserted.</summary>
    Swept = 1,

    /// <summary>The corpus declares the package planned rather than built, so nothing is on disk to read.</summary>
    PackageNotBuilt = 2,

    /// <summary>The case belongs to a package type this wave's contract defers.</summary>
    SpecificationDeferred = 3,

    /// <summary>The requirement was retired by the edition the shipped rules read.</summary>
    RequirementRetired = 4,

    /// <summary>The rule states its finding at the informational severity, which names no conformance level.</summary>
    RuleInformational = 5,

    /// <summary>
    /// The published catalogue states the requirement at the permission level, so a package cannot violate it
    /// however the corpus rule reports the finding.
    /// </summary>
    RequirementIsAPermission = 6
}


/// <summary>
/// One package reference of one corpus rule, with what the sweep decided to do about it.
/// </summary>
internal sealed record EArkCorpusCase
{
    /// <summary>Gets the requirement identifier the case is keyed by.</summary>
    public required string RequirementId { get; init; }

    /// <summary>Gets the specification family the identifier belongs to.</summary>
    public required EArkCorpusFamily Family { get; init; }

    /// <summary>Gets the specification version the case states, verbatim.</summary>
    public required string StatedVersion { get; init; }

    /// <summary>Gets the rule's own identifier within its case.</summary>
    public required string RuleId { get; init; }

    /// <summary>Gets the severity the rule states a violation at.</summary>
    public required string Severity { get; init; }

    /// <summary>
    /// Gets the requirement level the published catalogue states, or the empty string where it states none.
    /// </summary>
    public required string CatalogueLevel { get; init; }

    /// <summary>
    /// Gets the severity the sweep holds the rule to, which is what the catalogue's own requirement level gives
    /// it wherever the catalogue states one.
    /// </summary>
    public required string EffectiveSeverity { get; init; }

    /// <summary>Gets the package the rule names.</summary>
    public required EArkCorpusPackageReference Package { get; init; }

    /// <summary>Gets the claim code this repository allocates for the requirement, or zero when it allocates none.</summary>
    public required int ClaimCode { get; init; }

    /// <summary>Gets the delta row governing the requirement, or <see langword="null"/> when the editions agree.</summary>
    public EArkCorpusDeltaRow? Delta { get; init; }

    /// <summary>Gets what the sweep did with the case.</summary>
    public required EArkCorpusCaseDisposition Disposition { get; init; }

    /// <summary>Gets why the case was not swept, or the empty string when it was.</summary>
    public required string SkipReason { get; init; }


    /// <summary>Names the case the way a failure message should name it.</summary>
    /// <returns>The description.</returns>
    public string Describe() =>
        Delta is null
            ? $"{RequirementId} rule {RuleId} [corpus {Severity}, catalogue {CatalogueLevel}, held to {EffectiveSeverity}, edition {StatedVersion}] over {Package.Name}"
            : $"{RequirementId} rule {RuleId} [corpus {Severity}, catalogue {CatalogueLevel}, held to {EffectiveSeverity} under delta row {Delta.Id}, edition {StatedVersion}] over {Package.Name}";
}


/// <summary>
/// What judging one package answered: every claim the package profile issued, and whether the manifest reached
/// the rules at all.
/// </summary>
internal sealed record EArkCorpusPackageReading
{
    /// <summary>Gets what every claim said, keyed by requirement code.</summary>
    public required IReadOnlyDictionary<int, EArkCorpusClaimReading> Claims { get; init; }

    /// <summary>Gets whether the staged manifest binding read the package's root manifest.</summary>
    public required bool ManifestParsed { get; init; }

    /// <summary>Gets why it did not, or the empty string when it did.</summary>
    public required string ParseFailure { get; init; }
}


/// <summary>
/// What one claim of a judged package said.
/// </summary>
internal sealed record EArkCorpusClaimReading
{
    /// <summary>Gets the outcome the rule reached.</summary>
    public required ClaimOutcome Outcome { get; init; }

    /// <summary>Gets why it reached it.</summary>
    public required EArkClaimReason Reason { get; init; }

    /// <summary>Gets the short phrase naming what the rule looked at.</summary>
    public required string Subject { get; init; }


    /// <summary>Names the reading the way a failure message should name it.</summary>
    /// <returns>The description.</returns>
    public string Describe() => $"{Outcome}/{Reason} ({Subject})";
}
