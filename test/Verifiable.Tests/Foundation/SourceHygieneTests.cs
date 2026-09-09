using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Foundation;

/// <summary>
/// One gate per standing house rule, each a source-text scan over every <c>.cs</c> file under <c>src/</c>
/// and/or <c>test/</c> from a located repository root, each failing by listing <c>file:line</c> rather than
/// by any reflection over the loaded type system. The fourteen rules: banner-divider comments, planning-process
/// vocabulary, the spec-line shorthand, and internal coordination-process pointers are one four-way scan
/// (<see cref="SourceHygieneScanner"/>, proven live by <see cref="ScannerReportsEmbeddedSamplesWithFileAndLineShape"/>'s
/// embedded samples); production code threads its caller's memory pool
/// (<see cref="ProductionSourceThreadsTheCallersPoolInsteadOfHardcodingTheSharedDefault"/>), its caller's
/// <see cref="TimeProvider"/> (<see cref="ProductionConstructorsTakeTheirClockInsteadOfDefaultingToTheSystemClock"/>),
/// and its caller's entropy source (<see cref="ProductionSourceThreadsTheCallersEntropyInsteadOfDefaultingToThePlatformCsprng"/>)
/// rather than a hidden default; a unit test counts instead of timing itself on a wall clock
/// (<see cref="TestsCountOperationsInsteadOfTimingThemOnAWallClock"/>); a value is exposed through a getter,
/// never a naked <c>readonly</c> field, outside the reasoned exceptions
/// (<see cref="SourceTreeExposesValuesThroughGettersNeverNakedFieldsExceptTheReasonedExceptions"/>); TPM 2.0
/// Library Part 2 clause 6.6.2 Table 15's format-one designation is applied except at the documented bare
/// sites (<see cref="TpmFormatOneResponseCodesAreDesignatedExceptTheDocumentedBareSites"/>); a spec case is
/// proved directly or by source scan, never by reflecting over the runtime type system, outside MSTest's own
/// forced sites (<see cref="SourceTreeProvesSpecCasesWithoutEnumeratingTheRuntimeTypeSystem"/>); a clause
/// citation uses the current v185 numbering, never a retired pre-v184 one
/// (<see cref="SourceCitesTheV185ClauseNumberingNeverARetiredPreV184Number"/>); and a private get-only or
/// init-only property is named in PascalCase, never a lowercase or underscore-prefixed survivor of a field
/// conversion or a declined rename
/// (<see cref="PrivateGetOrInitOnlyPropertiesArePascalCaseNeverACamelCaseOrUnderscoreSurvivor"/>); a comment
/// or doc comment naming a bundled TPM 2.0 reference-implementation source file names the reference
/// FUNCTION it mirrors, in <c>src/**</c>, and names no such file at all, function or none, in <c>test/**</c>
/// (<see cref="SourceNamesTheReferenceFunctionNeverTheBareReferenceFileAlone"/>). Runs on a clean clone: the
/// root is located by walking up from <see cref="AppContext.BaseDirectory"/> to the directory containing
/// <c>Verifiable.slnx</c>, no environment variable or hardcoded path involved.
/// </summary>
/// <remarks>
/// The banned substrings this class checks for would, if written literally, make this file flag itself the
/// next time the scanner runs. Every such substring below — the pattern definitions themselves AND the
/// embedded RED sample lines <see cref="ScannerReportsEmbeddedSamplesWithFileAndLineShape"/> scans over — is
/// therefore assembled from fragments at the call site (string concatenation, never a single contiguous
/// literal) so the source text on disk never contains the substring the scanner is built to reject.
/// </remarks>
[TestClass]
internal sealed class SourceHygieneTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Every offending line in the current tree is reported by file-relative-path and line number.</summary>
    [TestMethod]
    public void SourceTreeHasNoBannerDividersPlanningVocabularyOrSpecLineShorthand()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        IReadOnlyList<string> sourceFiles = SourceHygieneScanner.EnumerateSourceFiles(repositoryRoot);
        IReadOnlyList<SourceHygieneViolation> violations = SourceHygieneScanner.ScanFiles(sourceFiles, repositoryRoot);

        List<(string FilePath, int LineNumber, string LineText)> bareSliceNounHits = [];
        List<SourceHygieneViolation> unrecordedViolations = [];

        foreach(SourceHygieneViolation violation in violations)
        {
            bool isBareSliceNounShape = violation.Kind == SourceHygieneViolationKind.InternalProvenancePointer
                && BareSliceNounShapePattern.IsMatch(violation.LineText);

            if(isBareSliceNounShape)
            {
                bareSliceNounHits.Add((violation.FilePath.Replace('\\', '/'), violation.LineNumber, violation.LineText.Trim()));
            }
            else
            {
                unrecordedViolations.Add(violation);
            }
        }

        List<string> failures = [];
        AssertLineTextHitsMatchAllowlistExactly(
            bareSliceNounHits,
            BareSliceNounAllowlist,
            "state the ordinary grammatical sense at the site's own doc comment instead of leaving an unrecorded bare mention",
            failures);
        failures.AddRange(unrecordedViolations.Select(static v => v.ToString()));

        Assert.IsEmpty(failures, string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Proves the scanner actually fires: it is run here over embedded sample lines (never a repository file),
    /// each sample built from fragments for the same self-tripping reason stated on the class, and the result
    /// must report each violation with the <c>file:line</c> shape the standing test relies on.
    /// </summary>
    [TestMethod]
    public void ScannerReportsEmbeddedSamplesWithFileAndLineShape()
    {
        string dividerLine = "// " + new string('-', 8) + " section " + new string('-', 8);
        string equalsDividerLine = "// " + new string('=', 4);
        string starDividerLine = "// " + new string('*', 4);
        string underscoreDividerLine = "// " + new string('_', 4);
        string vocabularyWord = "hand" + "over";
        string shorthand = "P" + "-" + "L" + "4";
        string amendmentsPluralLine = "// see " + "amend" + "ments" + " for the originating clause";
        string thisWaveLine = "// a note added " + "this" + " wave" + " with no nearby identifier";
        string thisArcLine = "// a note scoped to " + "this" + " arc" + " with no nearby identifier";
        string fixSpecLine = "// see the " + "fix" + "spec" + " for the repair scope";
        string lessonLine = "// a " + "les" + "son" + " recorded here with no nearby identifier";
        string carriedInLine = "// content " + "carried" + "-in" + " verbatim from another document";
        string internalWaveTokenLine = "// internal citation " + "wave" + "cb S3 noted here";
        string internalWaveDashDigitLine = "// internal citation " + "wave" + "-7 recorded here";
        string fxLine = "// defect tag " + "FX" + "-A observed here";
        string xsArtifactLine = "// artifact ref " + "XS" + "4-R6 cited here";
        string rulingsXsLine = "// see " + "ruling" + "s XS for the context";
        string knownHashLine = "// see " + "KNOWN" + " #3 for the detail";
        string sessionDashLine = "// per " + "session" + "-12 notes";
        string scoutDashLine = "// via " + "scout" + "-alpha review";
        string contractMdLine = "// see " + "foo" + "-contract.md for detail";
        string fixspecMdLine = "// see " + "foo" + "-fix" + "spec.md for detail";
        string contractRLine = "// see " + "contract" + " R5 for the rule";
        string contractRHyphenLine = "// see " + "contract" + " R" + "-6 for the rule";
        string bareRHyphenLine = "// see " + "R" + "-4 for the rule";
        string vbcLine = "// see " + "vbc" + "-3 cited here";
        string rjLine = "// see " + "RJ" + "-2 cited here";
        string jdLine = "// see " + "JD" + "7 cited here";
        string jsLine = "// see " + "J-S" + "4 cited here";
        string rwLetterLine = "// see " + "RW" + "2a cited here";
        string rwDashDLine = "// see " + "RW" + "3-D1 cited here";
        string psLine = "// see " + "P-S" + "5 cited here";
        string secLine = "// see " + "SEC" + "-9 cited here";
        string majorLine = "// see " + "MAJOR" + "-1 cited here";
        string dodLine = "// see " + "DoD" + " 2 for detail";
        string flagLine = "// see " + "flag" + " 5 for detail";
        string theStagesLine = "// a note about " + "the stage" + "'s own scope";
        string futureWaveLine = "// a note deferred to " + "a future" + " wave";
        string stageDashDigitLine = "// see " + "stage" + "-9 for scope";
        string legDashDigitLine = "// see " + "leg" + "-3 for scope";
        string tornRowLine = "// see " + "TORN row" + " 4 for detail";
        string rulingBareLine = "// see " + "ruling" + " 5 for the detail";
        string trapLine = "// see " + "trap" + " 5 recorded here";
        string theWavesOwnLine = "// a note citing " + "the" + " wave" + "'s own scope";
        string minorLine = "// see " + "MINOR" + "-3 cited here";
        string scoutSpaceLine = "// via " + "bio" + " scout review";
        string xsBareLine = "// citation " + "XS" + "2-N1 observed here";
        string spacedWaveDigitLine = "// a note citing " + "wave" + " 4 for detail";
        string ownerRulingLine = "// see the " + "owner" +
            " ruling for the context";
        string coordinatorsRulingLine = "// see the " + "coordinator" +
            "'s ruling for the context";
        string testPlanBlockLine = "// see " + "test plan" + " block 2 for detail";
        string preflightLegLine = "// see " + "preflight" + " leg 3 for detail";
        string tempdocsPathLine = "// see " + "tempdocs" + "/roadmap for detail";
        string sampleCtapWaveBareLine = "// old fixture named " + "Ctap" + "Wave here";
        string sampleCtapWaveDigitSuffixLine = "// old fixture named " + "Ctap" + "Wave" + "7 here";
        string waveDashLetterLine = "// internal citation " + "wave" + "-c command pending here";
        string rulingProximityExpandedLine = "// per the " + "owner" +
            "'s previously stated design ruling here";
        string rulingParenLine = "// see " + "ruling" + " (4) for the context";
        string decisionDigitLine = "// see " + "decision" + " 5 for the detail";
        string contractDecisionMultiDigitLine = "// see " + "contract" + " decision 12 for the detail";
        string phase9Line = "// old citation " + "Phase" + "9a noted here";
        string chunkDigitLine = "// see " + "chunk" + " 4 for the detail";
        string auditDriftLine = "// see " + "audit" + " drift noted here";
        string surveyMdLine = "// see " + "foo" + "-survey.md for detail";
        string bareBuildLogLine = "// see the " + "build" + "log for detail";
        string hyphenatedBuildLogLine = "// see this library's " + "build" + "-log for detail";
        string dvRegisterLine = "// see " + "DV" + "3-2 for the detail";
        string findingHashLine = "// see " + "finding" + " #3 for the detail";
        string legPreflightLine = "// see " + "leg" + " 3 preflight for detail";
        string preflightReportLine = "// see the " + "preflight" + " report for detail";
        string rulingSplitFirstLine = "// see the " + "ruling";
        string rulingSplitSecondLine = "// " + "2" + " for the wrapped detail";
        string stageSplitFirstLine = "// a note spanning " + "the";
        string stageSplitSecondLine = "// " + "stage" + "'s own wrapped scope";
        string preWaveContractCommentLine = "// see the " + "pre-" + "wave contract for detail";
        string seamsFindingLine = "// see " + "seams" + " Finding" + " D noted here";
        string findingLetterLine = "// see " + "Finding" + " A noted here";
        string sectionLNumberLine = "// see " + "§" + "2.1 L237-242 for detail";
        string preFixLine = "// describes the " + "pre" + "-fix state of a repair here";
        string postFixLine = "// describes the " + "post" + "-fix state of a repair here";
        string[] sampleLines =
        [
            "namespace Sample;",
            "",
            dividerLine,
            "// a note that mentions " + vocabularyWord + " with no nearby identifier",
            "// see " + shorthand + " for the originating clause",
            equalsDividerLine,
            starDividerLine,
            underscoreDividerLine,
            amendmentsPluralLine,
            thisWaveLine,
            thisArcLine,
            fixSpecLine,
            lessonLine,
            carriedInLine,
            internalWaveTokenLine,
            internalWaveDashDigitLine,
            fxLine,
            xsArtifactLine,
            rulingsXsLine,
            knownHashLine,
            sessionDashLine,
            scoutDashLine,
            contractMdLine,
            fixspecMdLine,
            contractRLine,
            contractRHyphenLine,
            vbcLine,
            rjLine,
            jdLine,
            jsLine,
            rwLetterLine,
            rwDashDLine,
            psLine,
            secLine,
            majorLine,
            dodLine,
            flagLine,
            theStagesLine,
            futureWaveLine,
            stageDashDigitLine,
            legDashDigitLine,
            tornRowLine,
            rulingBareLine,
            trapLine,
            theWavesOwnLine,
            minorLine,
            scoutSpaceLine,
            xsBareLine,
            spacedWaveDigitLine,
            ownerRulingLine,
            coordinatorsRulingLine,
            testPlanBlockLine,
            preflightLegLine,
            tempdocsPathLine,
            sampleCtapWaveBareLine,
            sampleCtapWaveDigitSuffixLine,
            waveDashLetterLine,
            rulingProximityExpandedLine,
            rulingParenLine,
            decisionDigitLine,
            contractDecisionMultiDigitLine,
            phase9Line,
            chunkDigitLine,
            auditDriftLine,
            surveyMdLine,
            bareBuildLogLine,
            hyphenatedBuildLogLine,
            dvRegisterLine,
            findingHashLine,
            legPreflightLine,
            preflightReportLine,
            rulingSplitFirstLine,
            rulingSplitSecondLine,
            stageSplitFirstLine,
            stageSplitSecondLine,
            preWaveContractCommentLine,
            seamsFindingLine,
            findingLetterLine,
            sectionLNumberLine,
            bareRHyphenLine,
            preFixLine,
            postFixLine,
        ];

        IReadOnlyList<SourceHygieneViolation> violations = SourceHygieneScanner.ScanLines("Sample.cs", sampleLines);

        Assert.HasCount(79, violations);
        Assert.IsTrue(violations.All(static v => v.FilePath == "Sample.cs"));
        Assert.Contains(static v => v.LineNumber == 3 && v.Kind == SourceHygieneViolationKind.BannerDivider, violations);
        Assert.Contains(static v => v.LineNumber == 4 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 5 && v.Kind == SourceHygieneViolationKind.SpecLineShorthand, violations);
        Assert.Contains(static v => v.LineNumber == 6 && v.Kind == SourceHygieneViolationKind.BannerDivider, violations);
        Assert.Contains(static v => v.LineNumber == 7 && v.Kind == SourceHygieneViolationKind.BannerDivider, violations);
        Assert.Contains(static v => v.LineNumber == 8 && v.Kind == SourceHygieneViolationKind.BannerDivider, violations);
        Assert.Contains(static v => v.LineNumber == 9 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 10 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 11 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 12 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 13 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 14 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 15 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 16 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 17 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 18 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 19 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 20 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 21 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 22 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 23 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 24 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 24 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.Contains(static v => v.LineNumber == 25 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 26 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 27 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 28 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 29 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 30 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 31 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 32 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 33 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 34 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 35 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 36 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 37 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 38 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 39 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 40 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 41 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 42 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 43 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 44 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 45 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 46 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 47 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 48 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 49 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 50 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 51 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 52 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 53 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 54 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 55 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 56 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 57 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 58 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 59 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 60 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 61 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 62 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 63 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 64 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 65 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 66 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 67 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 68 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 69 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 70 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.Contains(static v => v.LineNumber == 71 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);

        //The two line-wrap evasion pairs: the joined-adjacent-comment-line scan reports each at its
        //pair's first line number (72 for the ruling/digit split, 74 for the the/stage's split); the
        //second line of each pair (73, 75) carries no violation of its own, proving the join — not a
        //coincidental single-line match — is what fired.
        Assert.Contains(static v => v.LineNumber == 72 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.HasCount(0, violations.Where(static v => v.LineNumber == 73));
        Assert.Contains(static v => v.LineNumber == 74 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.HasCount(0, violations.Where(static v => v.LineNumber == 75));
        Assert.Contains(static v => v.LineNumber == 76 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 76));
        Assert.Contains(static v => v.LineNumber == 77 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 77));
        Assert.Contains(static v => v.LineNumber == 78 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 78));
        Assert.Contains(static v => v.LineNumber == 79 && v.Kind == SourceHygieneViolationKind.SpecLineShorthand, violations);
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 79));
        Assert.Contains(static v => v.LineNumber == 80 && v.Kind == SourceHygieneViolationKind.InternalProvenancePointer, violations);
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 80));
        Assert.Contains(static v => v.LineNumber == 81 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 81));
        Assert.Contains(static v => v.LineNumber == 82 && v.Kind == SourceHygieneViolationKind.PlanningVocabulary, violations);
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 82));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 23));
        Assert.HasCount(2, violations.Where(static v => v.LineNumber == 24));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 26));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 42));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 43));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 44));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 45));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 46));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 47));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 48));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 49));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 50));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 51));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 52));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 53));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 54));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 55));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 56));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 57));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 58));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 59));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 60));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 61));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 62));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 63));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 64));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 65));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 66));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 67));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 68));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 69));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 70));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 71));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 72));
        Assert.HasCount(1, violations.Where(static v => v.LineNumber == 74));

        foreach(SourceHygieneViolation violation in violations)
        {
            Assert.IsTrue(violation.ToString().StartsWith("Sample.cs:" + violation.LineNumber, StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// Matches a line that reaches for the library-wide default memory pool — <c>BaseMemoryPool.Shared</c> —
    /// in any expression position (a field initializer, a null-coalescing fallback, an argument), or that
    /// declares an optional <c>BaseMemoryPool?</c> parameter defaulted to <see langword="null"/> or
    /// <see langword="default"/> — the same hidden default one hop up, since the parameter's own body
    /// invariably resolves the unset case to the shared pool. Built with an escaped dot so this pattern's own
    /// definition does not read as a live occurrence of the shape it detects.
    /// </summary>
    private static Regex ProductionPoolHardcodePattern { get; } = new(
        @"BaseMemoryPool\.Shared|BaseMemoryPool\?\s+\w+\s*=\s*(?:null|default)\b", RegexOptions.Compiled);

    /// <summary>
    /// Matches a line that starts or reads a wall-clock timer — <c>Stopwatch.StartNew()</c>,
    /// <c>Stopwatch.GetTimestamp()</c>, <c>Stopwatch.GetElapsedTime(</c>, <c>new Stopwatch()</c>, or a
    /// target-typed <c>Stopwatch name = new();</c> declaration — instead of counting the operation under
    /// test. The target-typed alternative requires whitespace, never a dot, between <c>Stopwatch</c> and the
    /// declared name, so it never matches <c>Stopwatch.Frequency</c> (the one legitimate reference-tick use
    /// in this tree) or this pattern's own identifier, which runs the two words together with no space. Built
    /// with escaped punctuation so this pattern's own definition does not read as a live occurrence of the
    /// shape it detects when this file is itself scanned.
    /// </summary>
    private static Regex StopwatchStartNewPattern { get; } = new(
        @"Stopwatch\.(StartNew\(\)|GetTimestamp\(\)|GetElapsedTime\()|new Stopwatch\(\)|Stopwatch\s+\w+\s*=\s*new\(\)",
        RegexOptions.Compiled);

    /// <summary>
    /// Matches an assertion made against elapsed wall-clock time rather than a counted quantity: an
    /// <c>Assert.IsLessThan</c>/<c>IsGreaterThan</c>/<c>IsTrue</c>/<c>IsFalse</c> call whose arguments read
    /// an <c>.Elapsed</c> member on the same line.
    /// </summary>
    private static Regex ElapsedTimeAssertionPattern { get; } = new(
        @"Assert\..*(IsLessThan|IsGreaterThan|IsTrue|IsFalse).*\.Elapsed", RegexOptions.Compiled);

    /// <summary>
    /// Matches a line whose <see cref="TimeProvider"/> resolves to the real system clock — a
    /// null-coalescing fallback, a bare property initializer, a direct call through the static instance, or an
    /// optional <c>TimeProvider?</c> parameter defaulted to <see langword="null"/> or <see langword="default"/> —
    /// instead of a clock supplied by the caller. Built with an escaped dot so this pattern's own definition
    /// does not read as a live occurrence of the shape it detects.
    /// </summary>
    private static Regex SystemClockDefaultPattern { get; } = new(
        @"TimeProvider\.System|TimeProvider\?\s+\w+\s*=\s*(?:null|default)\b", RegexOptions.Compiled);

    /// <summary>
    /// Matches a line reaching for the platform CSPRNG directly — a <c>RandomNumberGenerator.Fill</c>/
    /// <c>GetBytes</c>/<c>GetInt32</c> call OR bare method-group reference (no parenthesis required, since a
    /// provider registration passes <c>RandomNumberGenerator.Fill</c> itself as a delegate value) — or an
    /// optional <c>FillEntropyDelegate?</c> parameter defaulted to <see langword="null"/> or
    /// <see langword="default"/>, the same hidden default one hop up. Built with an escaped dot so this
    /// pattern's own definition does not read as a live occurrence of the shape it detects.
    /// </summary>
    private static Regex SystemEntropyDefaultPattern { get; } = new(
        @"RandomNumberGenerator\.(?:Fill|GetBytes|GetInt32)\b|FillEntropyDelegate\?\s+\w+\s*=\s*(?:null|default)\b", RegexOptions.Compiled);

    /// <summary>
    /// The standing record of every <c>src/**</c> line that still reaches for <see cref="BaseMemoryPool"/>'s
    /// shared default pool instead of taking one from its caller, or that declares an optional
    /// <c>BaseMemoryPool?</c> parameter hiding that same default one hop up — production code accepts the
    /// memory pool it rents from as a required parameter; it never falls back to a process-wide default and
    /// never makes that parameter optional. The record is empty: every production site takes its pool from
    /// its own caller, up to the CLI's and the MCP host's composition roots in <c>Program.cs</c>, which
    /// construct the pool once and thread it down. This list only shrinks and must never gain an entry.
    /// </summary>
    private static IReadOnlyDictionary<string, int> ProductionPoolHardcodeAllowlist { get; } = new Dictionary<string, int>();

    /// <summary>
    /// Matches the demonstrative pronoun immediately followed by <see cref="TpmSlice"/>'s own noun — a
    /// labeled byte range within a buffer — regardless of which sense it is used in. Deliberately narrower
    /// than every other <see cref="InternalProvenancePointerPattern"/> alternative: it is the SHAPE
    /// <see cref="BareSliceNounAllowlist"/> exempts, so a match on this pattern is what qualifies a hit for
    /// that exemption, never the file alone. Built without a literal contiguous occurrence of its own two
    /// matched words (separated by <c>\s+</c> rather than a literal space) so this pattern's own definition
    /// does not read as a live occurrence of the shape it detects.
    /// </summary>
    private static Regex BareSliceNounShapePattern { get; } = new(@"\bthis\s+slice\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// The standing record of every line where <see cref="BareSliceNounShapePattern"/>'s shape — the
    /// demonstrative pronoun immediately followed by <see cref="TpmSlice"/>'s own noun — appears in its
    /// ordinary grammatical sense (the type "is empty", or a member "extracts" one "from a buffer"), never
    /// the build-stage sense <see cref="InternalProvenancePointerPattern"/>'s bare alternative for that
    /// two-word shape exists to catch. Keyed by (file, line text): the exemption covers only a hit whose own
    /// line matches this specific shape, so a different <see cref="InternalProvenancePointerPattern"/>
    /// alternative firing in the same file is never exempted by riding on this record's file. This list only
    /// shrinks and must never gain an entry.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> BareSliceNounAllowlist { get; } =
    [
        ("src/Verifiable.Tpm/Infrastructure/TpmSlice.cs", "/// Gets a value indicating whether " + "this" + " slice" + " is empty."),
        ("src/Verifiable.Tpm/Infrastructure/TpmSlice.cs", "/// Extracts " + "this" + " slice" + " from a buffer."),
        ("src/Verifiable.Tpm/Infrastructure/TpmSlice.cs", "/// Extracts " + "this" + " slice" + " from a buffer (alias for SliceFrom)."),
        ("src/Verifiable.Tpm/Infrastructure/TpmSlice.cs", "/// Extracts " + "this" + " slice" + " from a byte array."),
        ("src/Verifiable.Tpm/Infrastructure/TpmSlice.cs", "/// Extracts " + "this" + " slice" + " from a memory buffer."),
    ];

    /// <summary>
    /// The standing record of every <c>test/**</c> line that starts or reads a wall-clock
    /// <see cref="System.Diagnostics.Stopwatch"/> — <c>Stopwatch.StartNew()</c>, <c>Stopwatch.GetTimestamp()</c>,
    /// <c>Stopwatch.GetElapsedTime(</c>, or <c>new Stopwatch()</c> — instead of counting the operation under
    /// test: a unit test proves its cost by counting something (a pool rental, a comparison, a list entry) it
    /// can derive from the production code, or by a benchmark under <c>Verifiable.Benchmarks</c>; it never
    /// times itself against a wall-clock ceiling inside a unit test. The record is empty: the DIDComm
    /// exchange-timeout race test realizes the session's own timeout against a per-iteration
    /// <see cref="TimeProvider"/> (a <see cref="System.Threading.CancellationTokenSource"/> constructed with
    /// that provider) on its own task, so the race is between two threads' scheduling, never between a
    /// spinner and a real deadline — a unit test counts; it never reads the wall clock. This list only
    /// shrinks and must never gain an entry.
    /// </summary>
    private static IReadOnlyDictionary<string, int> StopwatchStartNewAllowlist { get; } = new Dictionary<string, int>();

    /// <summary>
    /// The standing record of every <c>test/**</c> assertion made against elapsed wall-clock time (an
    /// <c>Assert.IsLessThan</c>/<c>IsGreaterThan</c>/<c>IsTrue</c>/<c>IsFalse</c> reading a <c>.Elapsed</c>
    /// member) rather than a counted quantity — the same rule as <see cref="StopwatchStartNewAllowlist"/>,
    /// tracked separately because a timer can be started without its elapsed value ever being asserted on.
    /// The record is empty: cost characterisation lives in <c>Verifiable.Benchmarks</c>, a unit test keeps
    /// correctness and pooled-custody assertions, and a test that checks a production elapsed-time property
    /// (<c>ApduExchange.Elapsed</c>, arithmetic over synthetic ticks) reads it into a local before asserting,
    /// which is what tells that correctness check apart from a wall-clock reading. This list only shrinks; it
    /// must never gain an entry.
    /// </summary>
    private static IReadOnlyDictionary<string, int> ElapsedTimeAssertionAllowlist { get; } = new Dictionary<string, int>();

    /// <summary>
    /// The standing record of every <c>src/**</c> line whose <see cref="TimeProvider"/> resolves to the real
    /// system clock — a null-coalescing fallback, a bare property initializer, a direct call through the
    /// static instance, or an optional <c>TimeProvider?</c> parameter defaulted to <see langword="null"/> or
    /// <see langword="default"/> — instead of a clock supplied by the caller: a production constructor or
    /// method takes its clock as a required parameter; it never defaults to the system clock. The two
    /// entries are the CLI's and the MCP host's shared composition root: each of <c>Program.cs</c>'s two
    /// entry points (the CLI runner and the MCP server runner) builds <see cref="TimeProvider.System"/>
    /// exactly once, beside its memory pool and entropy source, and threads that single instance down
    /// through every registration and operation call rather than letting any downstream site read the system
    /// clock itself. Each entry keys exactly one declaration's own trimmed line text against its file, so a
    /// fixed site can never pay for a newly system-clocked one in the same file — a hit whose (file, line
    /// text) pair is not here fails, and an entry matched by no hit fails as a stale record to remove. This
    /// list only shrinks and never grows.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> SystemClockDefaultAllowlist { get; } =
    [
        ("src/Verifiable/Program.cs", "TimeProvider timeProvider = TimeProvider.System;"),
        ("src/Verifiable/Program.cs", "TimeProvider timeProvider = TimeProvider.System;"),
    ];

    /// <summary>
    /// The standing record of every <c>src/**</c> line reaching for the platform CSPRNG directly — a
    /// <c>RandomNumberGenerator.Fill</c>/<c>GetBytes</c>/<c>GetInt32</c> call or bare method-group reference,
    /// or an optional <c>FillEntropyDelegate?</c> parameter defaulted to <see langword="null"/> or
    /// <see langword="default"/> — instead of an entropy source supplied by the caller. Every entry names a
    /// genuine platform boundary rather than a hidden default: the Microsoft and BouncyCastle key-agreement/
    /// entropy providers are the leaf functions registered against <see cref="FillEntropyDelegate"/> that
    /// must, somewhere, name the platform CSPRNG they wrap; and <c>Program.cs</c>'s two composition roots
    /// build the one <see cref="FillEntropyDelegate"/> instance each threads down, mirroring
    /// <see cref="SystemClockDefaultAllowlist"/>'s own composition-root entries. Each entry keys exactly one
    /// declaration's own trimmed line text against its file, so a fixed site can never pay for a newly
    /// CSPRNG-reaching one in the same file — a hit whose (file, line text) pair is not here fails, and an
    /// entry matched by no hit fails as a stale record to remove. This list only shrinks and never grows.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> SystemEntropyDefaultAllowlist { get; } =
    [
        ("src/Verifiable.Microsoft/MicrosoftEntropyFunctions.cs", "Nonce result = Nonce.Generate(byteLength, stamped, RandomNumberGenerator.Fill,"),
        ("src/Verifiable.Microsoft/MicrosoftEntropyFunctions.cs", "Salt result = Salt.Generate(byteLength, stamped, RandomNumberGenerator.Fill,"),
        ("src/Verifiable.Microsoft/MicrosoftKeyAgreementFunctions.cs", "RandomNumberGenerator.Fill(ivOwner.Memory.Span[..AesCbcIvLength]);"),
        ("src/Verifiable.Microsoft/MicrosoftKeyAgreementFunctions.cs", "RandomNumberGenerator.Fill(ivOwner.Memory.Span[..AesGcmIvLength]);"),
        ("src/Verifiable.BouncyCastle/BouncyCastleKeyAgreementFunctions.cs", "RandomNumberGenerator.Fill(ivOwner.Memory.Span[..AesGcmIvLength]);"),
        ("src/Verifiable.BouncyCastle/BouncyCastleKeyAgreementFunctions.cs", "RandomNumberGenerator.Fill(ivOwner.Memory.Span[..XChaCha20NonceLength]);"),
        ("src/Verifiable/Program.cs", "builder.Services.AddSingleton<FillEntropyDelegate>(RandomNumberGenerator.Fill);"),
        ("src/Verifiable/Program.cs", "FillEntropyDelegate rng = RandomNumberGenerator.Fill;"),
    ];

    /// <summary>
    /// Production code takes the memory pool it rents scratch buffers from as a parameter; it never falls
    /// back to <see cref="BaseMemoryPool.Shared"/>, the process-wide default, when the caller already has a
    /// pool to hand it. <see cref="ProductionPoolHardcodeAllowlist"/> is the standing record of every
    /// <c>src/**</c> line still doing so — the record shrinks as each site is threaded to a caller-supplied
    /// pool, and never grows.
    /// </summary>
    [TestMethod]
    public void ProductionSourceThreadsTheCallersPoolInsteadOfHardcodingTheSharedDefault()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertNoUnrecordedOrGrownSites(
            repositoryRoot,
            "src",
            ProductionPoolHardcodePattern,
            SourceHygieneViolationKind.PoolHardcodedDefault,
            ProductionPoolHardcodeAllowlist,
            "thread the pool from the caller instead of hardcoding the shared default");
    }

    /// <summary>
    /// A unit test proves its performance cost by counting a discrete operation (a pool rental, a
    /// comparison, a list entry) it can derive from the production code; it never asserts a loose wall-clock
    /// ceiling against a <see cref="System.Diagnostics.Stopwatch"/>. <see cref="StopwatchStartNewAllowlist"/>
    /// and <see cref="ElapsedTimeAssertionAllowlist"/> are the standing record of every <c>test/**</c> timer
    /// start and elapsed-time assertion still doing so — each shrinks as a site gains a countable formula,
    /// and neither grows.
    /// </summary>
    [TestMethod]
    public void TestsCountOperationsInsteadOfTimingThemOnAWallClock()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertNoUnrecordedOrGrownSites(
            repositoryRoot,
            "test",
            StopwatchStartNewPattern,
            SourceHygieneViolationKind.WallClockStopwatchStart,
            StopwatchStartNewAllowlist,
            "count the operation under test instead of starting a wall-clock timer");

        AssertNoUnrecordedOrGrownSites(
            repositoryRoot,
            "test",
            ElapsedTimeAssertionPattern,
            SourceHygieneViolationKind.ElapsedTimeAssertion,
            ElapsedTimeAssertionAllowlist,
            "assert the counted quantity instead of the timer's elapsed value");
    }

    /// <summary>
    /// A production constructor takes its <see cref="TimeProvider"/> as a required parameter; it never
    /// defaults to <see cref="TimeProvider.System"/>, the real system clock, when no caller-supplied clock is
    /// given. <see cref="SystemClockDefaultAllowlist"/> is the standing record of every <c>src/**</c> line
    /// still resolving to the system clock this way — it shrinks as each constructor's clock becomes
    /// required, and never grows.
    /// </summary>
    [TestMethod]
    public void ProductionConstructorsTakeTheirClockInsteadOfDefaultingToTheSystemClock()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertNoUnrecordedOrGrownLineTextSites(
            repositoryRoot,
            "src",
            SystemClockDefaultPattern,
            SourceHygieneViolationKind.SystemClockDefault,
            SystemClockDefaultAllowlist,
            "the clock must be a required constructor parameter, never a system-clock default");
    }

    /// <summary>
    /// Production code takes the entropy source it draws key material and identifiers from as a required
    /// parameter; it never falls back to <see cref="RandomNumberGenerator.Fill"/>,
    /// <see cref="RandomNumberGenerator.GetBytes(int)"/>, or <see cref="RandomNumberGenerator.GetInt32(int, int)"/>
    /// directly, and never leaves an optional <see cref="FillEntropyDelegate"/> parameter defaulted to
    /// <see langword="null"/> or <see langword="default"/>. <see cref="SystemEntropyDefaultAllowlist"/> is the standing record of every
    /// <c>src/**</c> line still reaching for the platform CSPRNG this way — every entry names a genuine
    /// platform boundary rather than a hidden default (see the allowlist's own remarks); the list shrinks as
    /// a further site is found not to need the platform call after all, and never grows.
    /// </summary>
    [TestMethod]
    public void ProductionSourceThreadsTheCallersEntropyInsteadOfDefaultingToThePlatformCsprng()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertNoUnrecordedOrGrownLineTextSites(
            repositoryRoot,
            "src",
            SystemEntropyDefaultPattern,
            SourceHygieneViolationKind.SystemEntropyDefault,
            SystemEntropyDefaultAllowlist,
            "the entropy source must be a required parameter, never a platform-CSPRNG default");
    }

    /// <summary>
    /// Matches a <c>readonly</c> FIELD declaration — never a <c>readonly struct</c>/<c>record struct</c>/
    /// <c>ref struct</c>/<c>partial</c> TYPE declaration (excluded by the negative lookahead immediately
    /// after <c>readonly</c>), and never a <c>readonly</c> INSTANCE MEMBER on a readonly struct (an
    /// expression-bodied property or method, or a get-only property, all of which put <c>=&gt;</c> or
    /// <c>(</c> immediately after the declared name rather than a bare end-of-line, a <c>;</c>, or a
    /// plain-assignment <c>=</c>). Any same-line attribute is consumed first; the accessibility is optional
    /// (an implicit-<c>private</c> field carries none) and repeats up to twice so <c>protected internal</c>
    /// and <c>private protected</c> are covered, each accessibility and modifier keyword separated by
    /// required whitespace so adjacent keywords cannot run together; then any of <c>static</c>/<c>new</c>/
    /// <c>unsafe</c>/<c>volatile</c>/<c>required</c> in any order and count, then <c>readonly</c>, then the
    /// field's own type and name. The declaration HEAD is matched independently of its terminator: the name
    /// may be followed by a bare <c>;</c>, by a plain-assignment <c>=</c> (never the first character of
    /// <c>=&gt;</c>) and then anything through end of line — covering a single-line initializer, a
    /// multi-line <c>= new()</c>/collection-expression body, and a bare trailing <c>=</c> that wraps to the
    /// next line — or by nothing at all when the line ends at the name itself. Built with escaped
    /// punctuation so this pattern's own definition does not read as a live occurrence of the shape it
    /// detects.
    /// </summary>
    private static Regex NakedReadonlyFieldPattern { get; } = new(
        @"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|internal|protected|private)\s+){0,2}" +
        @"(?:(?:static|new|unsafe|volatile|required)\s+)*readonly\b\s+" +
        @"(?!struct\b|record\b|ref\b|partial\b)[A-Za-z_][\w<>\[\],\.\? ]*?\s+[A-Za-z_]\w*\s*(?:;|=(?!>).*)?$",
        RegexOptions.Compiled);

    /// <summary>
    /// The standing record of every <c>readonly</c> FIELD declaration in <c>src/**</c> the language itself
    /// forces to stay a field rather than a get-only property — each entry's own doc comment (at the field's
    /// site, not here) states which of the two reasons applies: a validating <c>init</c> accessor needs a
    /// sibling field of its own declaring type to assign outside a constructor (a get-only auto-property's
    /// compiler-generated backing field accepts assignment only from a constructor of the declaring type,
    /// never from another member's accessor), or an <c>init</c> accessor assigns it through a computed
    /// re-mapping the auto-property syntax cannot express; a <c>lock</c> target is a third reason — a
    /// get-only auto-property returns the same instance every read today, but nothing stops a later edit
    /// from turning its initializer into an expression body that re-mints one per read and silently destroys
    /// mutual exclusion, so a monitor or <see cref="System.Threading.Lock"/> object stays a field. Every other
    /// value in the tree is exposed through a get-only property or, for a compile-time literal nothing
    /// addresses and no cross-assembly inlining concern is documented for, a <c>const</c>. Each entry keys
    /// exactly one declaration's own trimmed line text against its file, so a fixed site can never pay for a
    /// newly naked one in the same file — a hit whose (file, line text) pair is not here fails, and an entry
    /// matching nothing fails as a stale record to remove. This list only shrinks and never grows.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> NakedReadonlyFieldAllowlist { get; } =
    [
        ("src/Verifiable.Core/StatusList/CredentialStatusRefusal.cs", "private readonly IReadOnlyList<RefusedCredentialStatus> credentials = [];"),
        ("src/Verifiable.Core/StatusList/StatusListToken.cs", "private readonly long? timeToLive;"),
        ("src/Verifiable.DidComm/Transport/DidCommSocketSessionOptions.cs", "private readonly long? maxReceiveBytes;"),
        ("src/Verifiable.DidComm/Transport/DidCommSocketSessionOptions.cs", "private readonly TimeSpan? exchangeTimeout;"),
        ("src/Verifiable.Tpm/Infrastructure/Commands/StartAuthSessionInput.cs", "private readonly TpmtSymDef symmetric;"),
        ("src/Verifiable.Apdu/ApduRecorder.cs", "private readonly Lock gate = new();"),
        ("src/Verifiable.Apdu/ApduDevice.cs", "private readonly Lock observerLock = new();"),
        ("src/Verifiable.Apdu/VirtualCard.cs", "private readonly Lock gate = new();"),
        ("src/Verifiable.Cryptography/CryptographicKeyEvents.cs", "private readonly object gate = new();"),
        ("src/Verifiable.OAuth/Dpop/DpopKey.cs", "private readonly object thumbprintLock = new();"),
        ("src/Verifiable.OAuth/Server/Keys/InProcessKeySet.cs", "private readonly Lock transitionLock = new();"),
        ("src/Verifiable.OAuth/Server/AuthorizationServerIntegration.cs", "private readonly object gate = new();"),
        ("src/Verifiable.Tpm/TpmVirtualDevice.cs", "private readonly Lock gate = new();"),
        ("src/Verifiable.Tpm/TpmRecorder.cs", "private readonly Lock recorderLock = new();"),
        ("src/Verifiable.Tpm/TpmDevice.cs", "private readonly Lock observerLock = new();"),
        ("src/Verifiable.Core/Assessment/ClaimId.cs", "private static readonly Lock descriptionsLock = new();"),
    ];

    /// <summary>
    /// The <c>test/**</c> half of <see cref="NakedReadonlyFieldAllowlist"/>'s record, kept as its own list
    /// because the two scopes are asserted separately: both entries are lock-target fields this tree's test
    /// helpers declare, for the same reason as their <c>src/**</c> siblings, each keyed by its own (file,
    /// line text) pair.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> NakedReadonlyFieldTestAllowlist { get; } =
    [
        ("test/Verifiable.Tests/TestInfrastructure/TestObserver.cs", "private readonly Lock gate = new();"),
        ("test/Verifiable.Tests/TestInfrastructure/MeteredHousePool.cs", "private readonly Lock sizeGate = new();"),
    ];

    /// <summary>
    /// A value is exposed through a getter, never a naked field: <see cref="NakedReadonlyFieldAllowlist"/>
    /// records every <c>src/**</c> line kept a field for a stated reason, and
    /// <see cref="NakedReadonlyFieldTestAllowlist"/> records the same for <c>test/**</c> — either the language
    /// forcing it (a validating <c>init</c> accessor's own backing store) or a lock target that must be one
    /// instance no accessor can re-mint. Each entry's own doc comment, at the field's site, states which
    /// reason applies there. The two records shrink as a further site is found not to need the field after
    /// all, and never grow.
    /// </summary>
    [TestMethod]
    public void SourceTreeExposesValuesThroughGettersNeverNakedFieldsExceptTheReasonedExceptions()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertNoUnrecordedOrGrownLineTextSites(
            repositoryRoot,
            "src",
            NakedReadonlyFieldPattern,
            SourceHygieneViolationKind.NakedReadonlyField,
            NakedReadonlyFieldAllowlist,
            "expose the value through a get-only property (or a const) instead of a naked readonly field");

        AssertNoUnrecordedOrGrownLineTextSites(
            repositoryRoot,
            "test",
            NakedReadonlyFieldPattern,
            SourceHygieneViolationKind.NakedReadonlyField,
            NakedReadonlyFieldTestAllowlist,
            "expose the value through a get-only property (or a const) instead of a naked readonly field");
    }

    /// <summary>
    /// Matches a private (optionally <c>static</c>) get-only or init-only property declaration whose own
    /// name starts with a lowercase letter or an underscore — the shape a field-to-property conversion
    /// leaves behind when it is left half finished, or that a mechanical PascalCase rename leaves behind
    /// when it silently declines a collision rather than resolving it. A property's own name is PascalCase;
    /// this is the strictest of four candidate forms verified to carry no false positive over the current
    /// tree: a same-line attribute list repeats first, then <c>private</c>, an optional <c>static</c>, an
    /// optional <c>readonly</c> (a member modifier on a struct's own property, never the field keyword this
    /// pattern is not matching), the declared type, and finally the lowercase- or underscore-led name
    /// immediately followed by <c>{ get</c> or <c>{ init</c>. Built with escaped punctuation so this
    /// pattern's own definition does not read as a live occurrence of the shape it detects.
    /// </summary>
    private static Regex LowercasePrivatePropertyNamePattern { get; } = new(
        @"^\s*(?:\[[^\]]*\]\s*)*private\s+(?:static\s+)?(?:readonly\s+)?[\w<>\[\]?,.\s]+?\s+([a-z_]\w*)\s*\{\s*(?:get|init)\b",
        RegexOptions.Compiled);

    /// <summary>
    /// The standing record of every private get-only or init-only property in <c>src/**</c> or <c>test/**</c>
    /// whose own name starts with a lowercase letter or an underscore. Empty: a property's own name is
    /// PascalCase; a lowercase or underscore-prefixed name is either a field that was never converted or a
    /// rename that silently declined a collision and left the mechanical first-letter-only form in place —
    /// both are defects this test catches directly rather than a to-do the allowlist quietly grows to cover.
    /// This list only shrinks and must never gain an entry.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> LowercasePrivatePropertyNameAllowlist { get; } = [];

    /// <summary>
    /// A private get-only or init-only property is named in PascalCase, the same as every public one;
    /// <see cref="LowercasePrivatePropertyNameAllowlist"/> is the standing record — kept empty — of every
    /// site in <c>src/**</c> or <c>test/**</c> whose own name starts with a lowercase letter or an
    /// underscore instead. A field name that survives a conversion to a property, or a mechanical rename
    /// that declined a collision and left the original casing in place, is caught here rather than left to
    /// reappear.
    /// </summary>
    [TestMethod]
    public void PrivateGetOrInitOnlyPropertiesArePascalCaseNeverACamelCaseOrUnderscoreSurvivor()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertNoUnrecordedOrGrownLineTextSites(
            repositoryRoot,
            "src",
            LowercasePrivatePropertyNamePattern,
            SourceHygieneViolationKind.LowercasePrivatePropertyName,
            LowercasePrivatePropertyNameAllowlist,
            "expose the property in PascalCase instead of a lowercase or underscore-prefixed name");

        AssertNoUnrecordedOrGrownLineTextSites(
            repositoryRoot,
            "test",
            LowercasePrivatePropertyNamePattern,
            SourceHygieneViolationKind.LowercasePrivatePropertyName,
            LowercasePrivatePropertyNameAllowlist,
            "expose the property in PascalCase instead of a lowercase or underscore-prefixed name");
    }

    /// <summary>
    /// The 40 RC_FMT1 response-code names TPM 2.0 Library Part 2, clause 6.6.2, Table 15 designates
    /// (<c>src/Verifiable.Tpm.Spec/Constants/TpmRcConstants.cs:242-448</c>) — every member between
    /// <c>TPM_RC_ASYMMETRIC</c> and <c>TPM_RC_CHANNEL_KEY</c>, read from that file rather than retyped from
    /// memory.
    /// </summary>
    private static string FormatOneResponseCodeNames { get; } =
        "ASYMMETRIC|ATTRIBUTES|HASH|VALUE|HIERARCHY|KEY_SIZE|MGF|MODE|TYPE|HANDLE|KDF|RANGE|AUTH_FAIL|" +
        "NONCE|PP|SCHEME|SIZE|SYMMETRIC|TAG|SELECTOR|INSUFFICIENT|SIGNATURE|KEY|POLICY_FAIL|INTEGRITY|" +
        "TICKET|RESERVED_BITS|BAD_AUTH|EXPIRED|POLICY_CC|BINDING|CURVE|ECC_POINT|FW_LIMITED|SVN_LIMITED|" +
        "PARMS|EXT_MU|ONE_SHOT_SIGNATURE|SIGN_CONTEXT_KEY|CHANNEL|CHANNEL_KEY";

    /// <summary>Matches a code-line reference to one of <see cref="FormatOneResponseCodeNames"/>'s 40 RC_FMT1 members.</summary>
    private static Regex FormatOneResponseCodePattern { get; } = new(
        @"TpmRcConstants\.TPM_RC_(?:" + FormatOneResponseCodeNames + @")\b", RegexOptions.Compiled);

    /// <summary>
    /// Matches the shapes TPM 2.0 Library Part 2, clause 6.6.2, Table 15's designation is applied from at a
    /// command's own final answer in this tree: a <c>Reject(</c>/<c>Refuse(</c> call, a <c>Fail(</c> call (a
    /// decrypt-session continuation's own local forwarding closure — each such continuation declares one, and
    /// every call site within it hands the closure the code to answer with), a single-equals assignment (never <c>==</c>, <c>!=</c>,
    /// <c>&lt;=</c>, <c>&gt;=</c>, or a <c>=&gt;</c> switch/lambda arrow), or a bare
    /// <c>return TpmRcConstants.TPM_RC_…;</c> of the code itself. A <c>return</c> that constructs a NEW value
    /// carrying the code as one field among others (an intermediate effect or action record a later
    /// continuation designates) is deliberately excluded — requiring the code immediately after <c>return</c>
    /// is what tells a command's own final bare answer apart from a shared validation helper's or an action
    /// record's bare field, both of which a caller or continuation elsewhere wraps.
    /// </summary>
    private static Regex FormatOneDesignationPositionPattern { get; } = new(
        @"\bReject\w*\(|\bRefuse\w*\(|\bFail\w*\(|\breturn\s+TpmRcConstants\.TPM_RC_|(?<![=!<>])=(?![=>])", RegexOptions.Compiled);

    /// <summary>
    /// The <c>Reject(</c>/<c>Refuse(</c>/<c>Fail(</c>/bare-<c>return</c> subset of
    /// <see cref="FormatOneDesignationPositionPattern"/>, without its single-equals-assignment alternative —
    /// the one for deciding candidacy on a JOINED line (a call head wrapping its bare code onto the next
    /// line). The assignment alternative is excluded there because an unrelated <c>==</c> comparison naming a
    /// code two lines away from an assignment's own <c>=</c> (an object initializer whose value is a
    /// multi-line ternary, for example) would otherwise present as a false candidate; a call head or a bare
    /// <c>return</c> wrapping its own argument list carries no such ambiguity.
    /// </summary>
    private static Regex FormatOneCallOrReturnPositionPattern { get; } = new(
        @"\bReject\w*\(|\bRefuse\w*\(|\bFail\w*\(|\breturn\s+TpmRcConstants\.TPM_RC_", RegexOptions.Compiled);

    /// <summary>Matches a call through one of the three Table 15 designation encoders.</summary>
    private static Regex FormatOneEncoderWrapPattern { get; } = new(
        @"HandleEncodedRc\(|ParameterEncodedRc\(|SessionEncodedRc\(", RegexOptions.Compiled);

    /// <summary>
    /// The two <c>Verifiable.Tpm.Automata</c> files <see cref="ScanFormatOneDesignationHits"/> scans for a
    /// bare format-one designation site — Table 15's scope in this tree, TPM 2.0 Library Part 2, clause
    /// 6.6.2. Independent of <see cref="FormatOneDesignationAllowlist"/>'s own key set: the scan always
    /// covers both files, so an emptied allowlist, or one missing a file's entry, never shrinks what gets
    /// scanned, and a new file added here starts at zero recorded sites — any bare hit in it fails
    /// immediately rather than passing because the allowlist never mentioned it.
    /// </summary>
    private static IReadOnlyList<string> FormatOneScanFiles { get; } =
    [
        "src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs",
        "src/Verifiable.Tpm/Automata/TpmSimulator.cs",
    ];

    /// <summary>
    /// The standing record of every bare format-one designation site TPM 2.0 Library Part 2, clause 6.6.2,
    /// Table 15 permits in the two <see cref="FormatOneScanFiles"/> files, keyed by (file, line text) rather
    /// than by a per-file count: the exemption covers only a hit whose own line matches a recorded entry, so
    /// a newly-bare site can never pass by netting against a site that got fixed elsewhere in the same file,
    /// and a fixed site's entry with no remaining match is reported as stale. Three reasons make a site
    /// legitimately bare rather than a defect this test must catch: the reference itself answers with no
    /// <c>RC_</c> modifier because no single field is attributable (a generic header/tag or whole-area
    /// trailing-octets check, a joint two-parameter overflow, a literal reference return the source's own
    /// comment at the site names as unattributable); a shared reader or validation helper's own bare return
    /// is correct because every call site, or the exactly-one downstream continuation that reads it, applies
    /// Table 15's designation afterward, never on the same joined line; or a decrypt-session continuation's
    /// own framing failure is bare at the site because the claiming session slot's own designation is applied
    /// downstream. The record proves the SET of bare sites is exactly this one; a line-text key carries no
    /// kind of its own, so it does not, and cannot, attest which of the three reasons any individual entry
    /// obeys. This list only shrinks and must never gain an entry outside these three reasons.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> FormatOneDesignationAllowlist { get; } =
    [
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "rejectCode = TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_ATTRIBUTES, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_ATTRIBUTES, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_SCHEME;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_SCHEME;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_SCHEME;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_SCHEME;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_SYMMETRIC;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_SYMMETRIC;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "rejectionCode = TpmRcConstants.TPM_RC_TYPE;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_RANGE, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorizeNV, TpmRcConstants.TPM_RC_INSUFFICIENT, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorizeNV, TpmRcConstants.TPM_RC_HASH, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorizeNV, TpmRcConstants.TPM_RC_INSUFFICIENT, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorizeNV, TpmRcConstants.TPM_RC_HASH, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorizeNV, TpmRcConstants.TPM_RC_VALUE, request);"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_ATTRIBUTES;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_ATTRIBUTES;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_ATTRIBUTES;"),
        ("src/Verifiable.Tpm/Automata/TpmLifecycleTransitions.cs", "return TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_SYMMETRIC;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_MODE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_HASH;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_SYMMETRIC;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_MODE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_SCHEME;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_HASH;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_CURVE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_KDF;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_HASH;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_HASH;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_KDF;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return TpmRcConstants.TPM_RC_TYPE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Fail(TpmRcConstants.TPM_RC_INSUFFICIENT, sizeBlamesDecryptSession: action.HasDecryptSession);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Fail(TpmRcConstants.TPM_RC_SIZE, sizeBlamesDecryptSession: action.HasDecryptSession);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Fail(TpmRcConstants.TPM_RC_SIZE, sizeBlamesDecryptSession: false);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Fail(TpmRcConstants.TPM_RC_INSUFFICIENT);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Fail(TpmRcConstants.TPM_RC_SIZE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Fail(TpmRcConstants.TPM_RC_INSUFFICIENT);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Fail(TpmRcConstants.TPM_RC_SIZE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_TYPE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_SIZE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_KEY);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_VALUE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_KEY_SIZE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_BINDING);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_KEY);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_ECC_POINT);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_KEY_SIZE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_BINDING);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_KEY);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_SCHEME);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_KEY_SIZE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_KEY_SIZE);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "return Refuse(TpmRcConstants.TPM_RC_BINDING);"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_HASH;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
        ("src/Verifiable.Tpm/Automata/TpmSimulator.cs", "malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;"),
    ];

    /// <summary>
    /// Scans <paramref name="lines"/> for a code line carrying one of <see cref="FormatOneResponseCodeNames"/>'s
    /// 40 RC_FMT1 members in a <see cref="FormatOneDesignationPositionPattern"/> position (a
    /// <c>Reject(</c>/<c>Refuse(</c> call, a single-equals assignment, or a <c>return</c>) — joining the line
    /// with its successor first when it ends in <c>(</c> or <c>,</c>, the shape a multi-argument call wraps
    /// across, and testing candidacy on THAT joined text too, using <see cref="FormatOneCallOrReturnPositionPattern"/>'s
    /// narrower call/return-only subset there, so a bare code wrapped onto the line after a
    /// <c>Reject(</c>/<c>Refuse(</c>/<c>Fail(</c>/<c>return</c> head is a candidate too, not only a bare code
    /// and its position both landing on the very same physical line. Reports a hit when the joined text (the
    /// line alone when it is not joinable) carries none of the three Table 15 designation encoders. A
    /// <c>//</c> comment line is never a hit.
    /// </summary>
    /// <param name="lines">The file's lines, one-based when reported.</param>
    /// <returns>Every hit's one-based line number and trimmed text.</returns>
    private static List<(int LineNumber, string Text)> ScanFormatOneDesignationHits(string[] lines)
    {
        List<(int, string)> hits = [];

        for(int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            string leading = line.TrimStart();
            if(leading.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            string trailing = line.TrimEnd();
            bool isJoinable = (trailing.EndsWith('(') || trailing.EndsWith(',')) && i + 1 < lines.Length;
            string joined = isJoinable ? line + lines[i + 1] : line;

            bool isCandidateOnOwnLine = FormatOneResponseCodePattern.IsMatch(line) && FormatOneDesignationPositionPattern.IsMatch(line);
            bool isCandidateOnJoinedLine = isJoinable
                && FormatOneResponseCodePattern.IsMatch(joined)
                && FormatOneCallOrReturnPositionPattern.IsMatch(joined);

            if(!isCandidateOnOwnLine && !isCandidateOnJoinedLine)
            {
                continue;
            }

            if(!FormatOneEncoderWrapPattern.IsMatch(joined))
            {
                hits.Add((i + 1, line.Trim()));
            }
        }

        return hits;
    }

    /// <summary>
    /// TPM 2.0 Library Part 2, clause 6.6.2, Table 15: a format-one answer designates the handle, session, or
    /// parameter in error whenever the implementation is able to. <see cref="FormatOneScanFiles"/> names the
    /// scanned files independently of <see cref="FormatOneDesignationAllowlist"/>'s own (file, line-text)
    /// entries, so a bare site outside that record is a defect this test catches rather than a to-do the
    /// allowlist quietly grows to cover, and a fixed site's line disappearing from the scan is caught too
    /// (its own entry then matches nothing and is reported as stale) — a site can never pay for a newly bare
    /// one, since each entry is consumed by at most the one hit whose own line text equals it.
    /// </summary>
    [TestMethod]
    public void TpmFormatOneResponseCodesAreDesignatedExceptTheDocumentedBareSites()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        List<(string FilePath, int LineNumber, string LineText)> hits = [];

        foreach(string relativePath in FormatOneScanFiles)
        {
            string fullPath = Path.Join(repositoryRoot, relativePath.Replace('/', Path.DirectorySeparatorChar));
            string[] lines = File.ReadAllLines(fullPath);

            hits.AddRange(ScanFormatOneDesignationHits(lines).Select(hit => (relativePath, hit.LineNumber, hit.Text)));
        }

        List<string> failures = [];
        AssertLineTextHitsMatchAllowlistExactly(
            hits,
            FormatOneDesignationAllowlist,
            "designate the code through Table 15 at the command's own final answer instead of leaving it bare",
            failures);

        Assert.IsEmpty(failures, string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Matches every shape by which source enumerates or reaches into the runtime type system
    /// standing in for a spec-derived test or a source scan: an import of <c>System.Reflection</c>, a
    /// <c>BindingFlags</c> value, a <c>GetProperties</c>/<c>GetFields</c>/<c>GetMethods</c>/<c>GetMethod</c>/
    /// <c>GetConstructors</c>/<c>GetMembers</c> call, <c>Assembly.GetTypes</c>, a <c>GetCustomAttribute</c>
    /// call, <c>Activator.CreateInstance</c>, or a <c>typeof(...).GetProperty(</c>/<c>typeof(...).GetField(</c>
    /// lookup. Every alternative but two carries an escaped dot or parenthesis of its own, which already keeps
    /// this pattern's own definition from reading as a live occurrence of the shape it detects (the disk text
    /// has a literal backslash where the shape it matches has none); the two bare-word alternatives with no
    /// punctuation to escape (<c>BindingFlags</c>, <c>GetCustomAttribute</c>) are assembled from fragments for
    /// the same reason.
    /// </summary>
    private static Regex ReflectionOverTheTypeSystemPattern { get; } = new(
        @"using System\.Reflection" +
        "|" + "Binding" + "Flags" +
        "|" + @"\.GetProperties\(" +
        "|" + @"\.GetFields\(" +
        "|" + @"\.GetMethods\(" +
        "|" + @"\.GetMethod\(" +
        "|" + @"\.GetConstructors\(" +
        "|" + @"\.GetMembers\(" +
        "|" + @"Assembly\.GetTypes" +
        "|" + "GetCustom" + "Attribute" +
        "|" + @"Activator\.CreateInstance" +
        "|" + @"typeof\([^)]+\)\.GetProperty\(" +
        "|" + @"typeof\([^)]+\)\.GetField\(",
        RegexOptions.Compiled);

    /// <summary>
    /// The standing record of every <c>test/**</c> line still reaching into the runtime type system by
    /// reflection instead of proving its case directly or as a source scan of the declaring file's own text.
    /// Each entry is one of MSTest's own test-infrastructure contracts: <see cref="FilesDataAttribute"/> and
    /// the <c>IgnoreIfAttribute</c> of <see cref="PlatformTestAttributes"/> implement <c>ITestDataSource</c>,
    /// whose <c>GetData</c>/<c>GetDisplayName</c> members are handed a <c>MethodInfo</c> by MSTest itself;
    /// <c>Oid4VpSchemeFormatMatrixTests.MatrixDisplayName</c> takes the same <c>MethodInfo</c> parameter
    /// <c>DynamicDataAttribute.DynamicDataDisplayName</c> requires; and <see cref="ConditionalTestMethodAttribute"/>
    /// walks a test's declaring-type hierarchy for a class-level skip attribute because MSTest's own
    /// <c>ITestMethod</c> exposes only a method's own attributes, never its declaring type's — each reason is
    /// also recorded on the member itself. No <c>src/**</c> line reaches this pattern at all: production code
    /// proves nothing by reflecting over its own type system. Each entry keys exactly one line's own trimmed
    /// text against its file, so a fixed site can never pay for a newly-reflecting one in the same file — a
    /// hit whose (file, line text) pair is not here fails, and an entry matched by no hit fails as a stale
    /// record to remove. This list only shrinks and must never gain an entry outside these framework-forced
    /// sites. Every entry's own text is assembled from fragments wherever it would otherwise repeat one of
    /// <see cref="ReflectionOverTheTypeSystemPattern"/>'s bare-word alternatives contiguously — the same
    /// self-tripping this record's own scan target (<c>test/**</c>, which includes this very file) makes
    /// live for a pattern with no line-start anchor, the reason that pattern's own definition already
    /// fragments the same alternatives.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> ReflectionOverTheTypeSystemAllowlist { get; } =
    [
        ("test/Verifiable.Tests/TestInfrastructure/ConditionalTestMethodAttribute.cs", "using System." + "Reflection;"),
        ("test/Verifiable.Tests/TestInfrastructure/ConditionalTestMethodAttribute.cs", "skipAttributes.AddRange(type.GetCustom" + "Attributes<BaseSkipAttribute>(inherit: true));"),
        ("test/Verifiable.Tests/TestInfrastructure/PlatformTestAttributes.cs", "using System." + "Reflection;"),
        ("test/Verifiable.Tests/TestInfrastructure/PlatformTestAttributes.cs", "conditionType.GetMethod" + "(conditionMethodName, " + "Binding" + "Flags.Static | " + "Binding" + "Flags.Public)"),
        ("test/Verifiable.Tests/TestInfrastructure/FilesDataAttribute.cs", "using System." + "Reflection;"),
        ("test/Verifiable.Tests/OAuth/Oid4VpSchemeFormatMatrixTests.cs", "using System." + "Reflection;"),
    ];

    /// <summary>
    /// A test proves a spec case by direct assertion against the shipped API or by a source scan of the
    /// declaring file's own text; it never enumerates the runtime type system by reflection — a ledger cross-
    /// check between a test-local table and a class's declared members is bookkeeping, not a proof, and a
    /// structural invariant (an accessibility boundary, a naming convention, a required-member obligation) is
    /// provable from the source text alone. <see cref="ReflectionOverTheTypeSystemAllowlist"/> is the standing
    /// record of the four MSTest test-infrastructure files (six sites total) the framework's own contract
    /// forces this shape onto — it shrinks only if MSTest itself changes, and never grows.
    /// </summary>
    [TestMethod]
    public void SourceTreeProvesSpecCasesWithoutEnumeratingTheRuntimeTypeSystem()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertNoUnrecordedOrGrownSites(
            repositoryRoot,
            "src",
            ReflectionOverTheTypeSystemPattern,
            SourceHygieneViolationKind.ReflectionOverTheTypeSystem,
            new Dictionary<string, int>(),
            "prove the case directly or as a source scan, never by reflecting over the loaded type system");

        AssertNoUnrecordedOrGrownLineTextSites(
            repositoryRoot,
            "test",
            ReflectionOverTheTypeSystemPattern,
            SourceHygieneViolationKind.ReflectionOverTheTypeSystem,
            ReflectionOverTheTypeSystemAllowlist,
            "prove the case directly or as a source scan, never by reflecting over the loaded type system");
    }

    /// <summary>
    /// Matches the retired pre-v184 forms of thirteen TPM 2.0 Library Part 1 clause numbers superseded by
    /// the v185 renumbering, across two families: the Authorization Structures / Lockout family — chapter
    /// 16 in v185, retired as chapter 17 (<c>16.6.4.1</c> Overview, <c>16.6.4.2</c> authValue Size,
    /// <c>16.6.4.3</c> Authorization Size Convention, <c>16.7.12</c> the
    /// PolicySigned/PolicySecret/PolicyTicket clause, <c>16.8.1</c> the Dictionary Attack Protection
    /// Introduction, <c>16.8.3</c> Lockout Mode, <c>16.8.4</c> Recovering from Lockout Mode, <c>16.8.5</c>
    /// Authorization Failures Involving lockoutAuth, and <c>16.8.7</c> Justification for Lockout Due to
    /// Session Binding) — and the NV Index family, retired with a shifted leading digit (<c>34.2.6.x</c>
    /// as <c>35.2.6.x</c> or <c>37.2.6.x</c>, covering the NV Counter Index and NV PIN Index clauses among
    /// others, and <c>34.2.8</c>/<c>34.2.8.1</c> PIN Index Considerations as its retired counterpart with a
    /// leading <c>37</c> in place of <c>34</c>).
    /// A note, or a paste from an old draft, that reintroduces one of those old numbers fails the build
    /// naming <c>file:line</c> rather than silently drifting back into the tree. The Introduction clause's
    /// own retired form (bare digits <c>17</c>-<c>8</c>-<c>1</c>) is the only one of the thirteen that
    /// collides with an unrelated, genuinely-current v185 clause elsewhere in the numbering — Part 3's
    /// <c>TPM2_SequenceComplete()</c> General Description correctly and unrelatedly occupies the identical
    /// bare number in its own Part — so that one alternative fires only when the line attributes the number
    /// to Part 1, in any spelling this tree uses: a bare "Part 1" preceding the number on the same line
    /// whether or not a comma follows it (covering "TPM 2.0 Library Part 1, clause 17\.8\.1", "Part 1 clause
    /// 17\.8\.1", and "Part 1 §17\.8\.1" alike — escaped here the same way the pattern below escapes its own
    /// punctuation, so this very sentence does not trip the rule it documents), so long as no intervening
    /// "Part 3" attribution sits between the two — leaving Part 3's own correct citation of the same bare
    /// number untouched. Every other alternative bans its retired number outright, with no allowlist and no
    /// attribution check, because no v185 Part carries a clause of that same depth and number under any
    /// attribution. A new anchor spelled with "Section" or "§" for a number this pattern does not list is
    /// out of scope: only these specific retired numbers are banned, never the house form's own numbering
    /// shorthand. Built with escaped punctuation so this pattern's own definition does not read as a live
    /// occurrence of the shape it detects.
    /// </summary>
    private static Regex RetiredClauseNumberingPattern { get; } = new(
        @"\b3[57]\.2\.6\.\d\b" +
        "|" + @"\b37\.2\.8(?:\.\d)?\b" +
        "|" + @"\b17\.6\.4\.[1-3]\b" +
        "|" + @"\b17\.7\.12\b" +
        "|" + @"\b17\.8\.[34567]\b" +
        "|" + @"Part\s+1\b(?:(?!Part\s+3\b).)*?17\.8\.1\b",
        RegexOptions.Compiled);

    /// <summary>
    /// TPM 2.0 Library clause anchors cite the current v185 numbering; <see cref="RetiredClauseNumberingPattern"/>'s
    /// thirteen retired pre-v184 forms are banned OUTRIGHT, with no allowlist at all, rather than merely
    /// tracked — a paste from an old note or an unreviewed draft that reintroduces one of them fails the
    /// build immediately, naming the exact <c>file:line</c>, instead of surviving until the next
    /// citation sweep happens to be run by hand.
    /// </summary>
    [TestMethod]
    public void SourceCitesTheV185ClauseNumberingNeverARetiredPreV184Number()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();
        List<string> failures = [];

        foreach(string topLevelDirectory in new[] { "src", "test" })
        {
            IReadOnlyList<string> files = SourceHygieneScanner.EnumerateSourceFilesUnder(repositoryRoot, topLevelDirectory);

            foreach(string filePath in files)
            {
                string relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace(Path.DirectorySeparatorChar, '/');
                string[] lines = File.ReadAllLines(filePath);
                IReadOnlyList<SourceHygieneViolation> violations = SourceHygieneScanner.ScanAllLinesForPattern(
                    relativePath, lines, RetiredClauseNumberingPattern, SourceHygieneViolationKind.RetiredClauseNumbering);

                failures.AddRange(violations.Select(static v => v.ToString()));
            }
        }

        Assert.IsEmpty(failures, string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Matches a bundled TPM 2.0 reference-implementation source or header file name — an identifier
    /// followed by a dot and a bare "c" or "h" extension, which also covers the function-prototype header
    /// form (whose name ends in an underscore, "fp", dot, "h" — already covered by the general header
    /// alternative, since that suffix is just part of the identifier before the extension) — the shape a
    /// comment cites the reference tree by, whether or not a reference function accompanies it. Written
    /// with the extension separated from its dot below so this definition is not itself a live occurrence
    /// of the shape it detects.
    /// </summary>
    private static Regex ReferenceSourceFileNamePattern { get; } = new(
        @"\b[A-Za-z_][A-Za-z0-9_]*\.(?:c|h)\b", RegexOptions.Compiled);

    /// <summary>
    /// Matches a reference C function identifier: either a call-shaped <c>Xxx(</c> token, or one of the
    /// reference tree's own recognizable stems (<c>TPM2_</c>, <c>Crypt</c>, <c>Nv</c>, <c>Session</c>,
    /// <c>Command</c>, <c>Entity</c>, <c>Policy</c>, <c>Object</c>, <c>Parse</c>) immediately followed by
    /// <c>()</c>, a possessive <c>'s</c>, or a spaced dash, since a doc comment sometimes names a reference
    /// function without a call parenthesis (e.g. <c>ParseHandleBuffer's</c>). A bare multi-hump PascalCase
    /// word with neither shape is NEVER accepted — that laxity is what let a bare file citation through
    /// this gate before. Checked only against a line with every <see cref="ReferenceSourceFileNamePattern"/>
    /// match masked out first, so a file name's own hump-shaped stem (e.g. the "UndefineSpace" run inside
    /// the NV-prefixed source file name this very rule was written against) is never mistaken for a
    /// companion function reference.
    /// </summary>
    private static Regex ReferenceFunctionNamePattern { get; } = new(
        @"\b[A-Z][A-Za-z0-9_]*\s*\(|\b(?:TPM2_\w+|Crypt\w+|Nv\w+|Session\w+|Command\w+|Entity\w+|Policy\w+|Object\w+|Parse\w+)(?:\(\)|'s|\s-)",
        RegexOptions.Compiled);

    /// <summary>
    /// The standing record of every line where <see cref="ReferenceSourceFileNamePattern"/> fires under the
    /// rule <see cref="SourceNamesTheReferenceFunctionNeverTheBareReferenceFileAlone"/> enforces. Empty, and
    /// it must stay empty: a src comment names the reference function it mirrors, or states the rule in
    /// the code's own words with a spec anchor instead of any file name; test text names neither a
    /// reference file nor a private simulator member.
    /// </summary>
    private static IReadOnlyList<(string FilePath, string LineText)> BareReferenceSourceFileAllowlist { get; } = [];

    /// <summary>
    /// Scans every <c>//</c>/<c>///</c> comment line under <paramref name="topLevelDirectory"/> for a
    /// <see cref="ReferenceSourceFileNamePattern"/> hit: in <c>test</c>, every hit is reported outright
    /// (test text never names a reference file at all); in any other directory (<c>src</c>), a hit is
    /// reported only when no <see cref="ReferenceFunctionNamePattern"/> appears on that SAME LINE, once
    /// every file-name match on the line is masked out first — THE RULE names a function beside its file,
    /// not somewhere else in the surrounding comment block, so a citation wrapped onto a different line
    /// from the function that answers it is still a bare-file hit here.
    /// </summary>
    private static List<(string FilePath, int LineNumber, string LineText)> FindBareReferenceSourceFileHits(
        string repositoryRoot, string topLevelDirectory)
    {
        List<(string FilePath, int LineNumber, string LineText)> hits = [];
        IReadOnlyList<string> files = SourceHygieneScanner.EnumerateSourceFilesUnder(repositoryRoot, topLevelDirectory);

        foreach(string filePath in files)
        {
            string relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace(Path.DirectorySeparatorChar, '/');
            string[] lines = File.ReadAllLines(filePath);

            for(int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
            {
                string line = lines[lineIndex];
                if(!line.TrimStart().StartsWith("//", StringComparison.Ordinal))
                {
                    continue;
                }

                MatchCollection fileMatches = ReferenceSourceFileNamePattern.Matches(line);
                if(fileMatches.Count == 0)
                {
                    continue;
                }

                if(topLevelDirectory == "test")
                {
                    hits.Add((relativePath, lineIndex + 1, line.Trim()));

                    continue;
                }

                char[] masked = line.ToCharArray();
                foreach(Match fileMatch in fileMatches)
                {
                    for(int position = fileMatch.Index; position < fileMatch.Index + fileMatch.Length; position++)
                    {
                        masked[position] = ' ';
                    }
                }

                if(!ReferenceFunctionNamePattern.IsMatch(new string(masked)))
                {
                    hits.Add((relativePath, lineIndex + 1, line.Trim()));
                }
            }
        }

        return hits;
    }

    /// <summary>
    /// A <c>src/**</c> comment may name the reference C FUNCTION it mirrors; it may never name only the
    /// bundled reference source/header FILE with no function alongside it — a bare file citation gives a
    /// reader nothing to go read, and the rule it stands in for belongs in the code's own words anchored to
    /// a Part 3 table instead. Test text names neither a reference file nor a private simulator member.
    /// <see cref="BareReferenceSourceFileAllowlist"/> is the standing record of every site still doing
    /// either — empty, and it only ever shrinks.
    /// </summary>
    [TestMethod]
    public void SourceNamesTheReferenceFunctionNeverTheBareReferenceFileAlone()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        List<(string FilePath, int LineNumber, string LineText)> hits = [];
        hits.AddRange(FindBareReferenceSourceFileHits(repositoryRoot, "src"));
        hits.AddRange(FindBareReferenceSourceFileHits(repositoryRoot, "test"));

        List<string> failures = [];
        AssertLineTextHitsMatchAllowlistExactly(
            hits,
            BareReferenceSourceFileAllowlist,
            "name the reference function the comment mirrors (src), or state the rule in the code's own words instead of any reference file name (src and test alike)",
            failures);

        Assert.IsEmpty(failures, string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Scans every <c>.cs</c> file under <paramref name="topLevelDirectory"/> for <paramref name="pattern"/>
    /// on code lines only, then checks the result against <paramref name="allowlist"/> three ways: a file
    /// not on the list carrying at least one site fails naming <c>file:line</c>; an allowlisted file
    /// carrying more sites than its allowance fails naming the count and the lines; and an allowlisted file
    /// now carrying none fails with an instruction to remove the stale entry, since the allowlist only ever
    /// shrinks. <paramref name="ruleDescription"/> names how to comply and is folded into every failure
    /// line.
    /// </summary>
    private static void AssertNoUnrecordedOrGrownSites(
        string repositoryRoot,
        string topLevelDirectory,
        Regex pattern,
        SourceHygieneViolationKind kind,
        IReadOnlyDictionary<string, int> allowlist,
        string ruleDescription)
    {
        IReadOnlyList<string> files = SourceHygieneScanner.EnumerateSourceFilesUnder(repositoryRoot, topLevelDirectory);
        Dictionary<string, IReadOnlyList<SourceHygieneViolation>> violationsByFile = [];

        foreach(string filePath in files)
        {
            string relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace(Path.DirectorySeparatorChar, '/');
            string[] lines = File.ReadAllLines(filePath);
            IReadOnlyList<SourceHygieneViolation> violations = SourceHygieneScanner.ScanCodeLinesForPattern(relativePath, lines, pattern, kind);

            if(violations.Count > 0)
            {
                violationsByFile[relativePath] = violations;
            }
        }

        List<string> failures = [];

        foreach((string relativePath, IReadOnlyList<SourceHygieneViolation> violations) in violationsByFile)
        {
            if(!allowlist.TryGetValue(relativePath, out int allowedCount))
            {
                failures.Add(
                    $"{relativePath}: {violations.Count} site(s) not on the allowlist ({ruleDescription}) at line(s) " +
                    string.Join(", ", violations.Select(static v => v.LineNumber)) + ".");

                continue;
            }

            if(violations.Count > allowedCount)
            {
                failures.Add(
                    $"{relativePath}: {violations.Count} site(s) exceeds the allowed {allowedCount} ({ruleDescription}) at line(s) " +
                    string.Join(", ", violations.Select(static v => v.LineNumber)) + ".");
            }
        }

        foreach(string relativePath in allowlist.Keys)
        {
            if(!violationsByFile.ContainsKey(relativePath))
            {
                failures.Add(
                    $"{relativePath}: allowlisted for {allowlist[relativePath]} site(s) but now carries none - " +
                    "the list only shrinks, remove this entry.");
            }
        }

        Assert.IsEmpty(failures, string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Scans every <c>.cs</c> file under <paramref name="topLevelDirectory"/> for <paramref name="pattern"/>
    /// on code lines only, then hands the resulting (file, line, trimmed text) hits to
    /// <see cref="AssertLineTextHitsMatchAllowlistExactly"/> against <paramref name="allowlist"/>.
    /// <paramref name="ruleDescription"/> names how to comply and is folded into every unrecorded hit's
    /// failure line.
    /// </summary>
    private static void AssertNoUnrecordedOrGrownLineTextSites(
        string repositoryRoot,
        string topLevelDirectory,
        Regex pattern,
        SourceHygieneViolationKind kind,
        IReadOnlyList<(string FilePath, string LineText)> allowlist,
        string ruleDescription)
    {
        IReadOnlyList<string> files = SourceHygieneScanner.EnumerateSourceFilesUnder(repositoryRoot, topLevelDirectory);
        List<(string FilePath, int LineNumber, string LineText)> hits = [];

        foreach(string filePath in files)
        {
            string relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace(Path.DirectorySeparatorChar, '/');
            string[] lines = File.ReadAllLines(filePath);
            IReadOnlyList<SourceHygieneViolation> violations = SourceHygieneScanner.ScanCodeLinesForPattern(relativePath, lines, pattern, kind);

            hits.AddRange(violations.Select(violation => (relativePath, violation.LineNumber, violation.LineText.Trim())));
        }

        List<string> failures = [];
        AssertLineTextHitsMatchAllowlistExactly(hits, allowlist, ruleDescription, failures);

        Assert.IsEmpty(failures, string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// Compares <paramref name="hits"/> against <paramref name="allowlist"/> as an exact MULTISET keyed by
    /// (file, trimmed line text): every allowlist is this same shape, with a repeated (file, text) pair
    /// listed once per occurrence rather than carrying an explicit count field, so this one comparison
    /// serves every (file, line-text) allowlist in this class. Each hit consumes one still-unconsumed
    /// occurrence of its matching allowlist entry; a hit with none left to consume is unrecorded and its
    /// failure names the file, the line, the text, and both the recorded and now-matched counts, so a
    /// newly-occurring site can never pass by netting against one already recorded for a different line in
    /// the same file, nor by riding on a byte-identical line recorded elsewhere. An allowlist entry left
    /// with any occurrence unconsumed after every hit is processed fails as stale, naming the same file,
    /// text, and counts, with an instruction to remove it — the allowlist only ever shrinks.
    /// </summary>
    /// <param name="hits">Every scanned hit, as (file, one-based line number, trimmed line text).</param>
    /// <param name="allowlist">The standing record, as (file, trimmed line text), one entry per occurrence.</param>
    /// <param name="ruleDescription">How to comply, folded into an unrecorded hit's failure line.</param>
    /// <param name="failures">Receives one message per unrecorded hit and per stale allowlist entry.</param>
    private static void AssertLineTextHitsMatchAllowlistExactly(
        IReadOnlyList<(string FilePath, int LineNumber, string LineText)> hits,
        IReadOnlyList<(string FilePath, string LineText)> allowlist,
        string ruleDescription,
        List<string> failures)
    {
        Dictionary<(string FilePath, string LineText), int> allowedCounts = allowlist
            .GroupBy(static entry => entry)
            .ToDictionary(static group => group.Key, static group => group.Count());
        Dictionary<(string FilePath, string LineText), int> matchedCounts = [];

        foreach((string FilePath, int LineNumber, string LineText) hit in hits)
        {
            (string FilePath, string LineText) key = (hit.FilePath, hit.LineText);
            int allowed = allowedCounts.GetValueOrDefault(key);
            int matchedSoFar = matchedCounts.GetValueOrDefault(key);

            if(matchedSoFar >= allowed)
            {
                failures.Add(
                    $"{hit.FilePath}:{hit.LineNumber}: site not on the allowlist ({ruleDescription}): {hit.LineText} " +
                    $"(recorded {allowed} time(s), now matched {matchedSoFar + 1}).");
            }
            else
            {
                matchedCounts[key] = matchedSoFar + 1;
            }
        }

        foreach((string FilePath, string LineText) key in allowedCounts.Keys)
        {
            int allowed = allowedCounts[key];
            int matched = matchedCounts.GetValueOrDefault(key);

            if(matched < allowed)
            {
                failures.Add(
                    $"{key.FilePath}: allowlisted line (\"{key.LineText}\") recorded {allowed} time(s) but matches only " +
                    $"{matched} current hit(s) - the list only shrinks, remove the stale entries.");
            }
        }
    }

}

/// <summary>One offending line: which file, which line, and which pattern class it tripped.</summary>
internal sealed record SourceHygieneViolation(string FilePath, int LineNumber, SourceHygieneViolationKind Kind, string LineText)
{
    public override string ToString()
    {
        return $"{FilePath}:{LineNumber}: [{Kind}] {LineText.Trim()}";
    }
}

/// <summary>The pattern classes the source-hygiene gates check for.</summary>
internal enum SourceHygieneViolationKind
{
    /// <summary>A plain <c>//</c> comment carrying a run of four or more dash/equals/star/underscore characters.</summary>
    BannerDivider,

    /// <summary>A word or phrase belonging to a build coordination document — a repair-scope tag, a design-revision note, a review takeaway, a process handoff note, a verbatim-copy marker, or a repair's before/after adjective pair — never to shipped source.</summary>
    PlanningVocabulary,

    /// <summary>The bare <c>T</c>/<c>P</c>/<c>C</c>-dash-<c>L</c>-digit shorthand, or a section-symbol clause number followed by a rendering's own line range, used in place of a real specification anchor.</summary>
    SpecLineShorthand,

    /// <summary>A codename-prefixed identifier, id-family shorthand, stage/wave phrasing, review/session label, or by-name citation of an internal tempdocs artifact.</summary>
    InternalProvenancePointer,

    /// <summary>A <c>src/**</c> line renting from <see cref="BaseMemoryPool.Shared"/>, the process-wide default pool, instead of the caller's own pool.</summary>
    PoolHardcodedDefault,

    /// <summary>A <c>test/**</c> line that starts or reads a wall-clock <see cref="System.Diagnostics.Stopwatch"/> instead of counting the operation under test.</summary>
    WallClockStopwatchStart,

    /// <summary>A <c>test/**</c> assertion made against a <c>.Elapsed</c> wall-clock reading rather than a counted quantity.</summary>
    ElapsedTimeAssertion,

    /// <summary>A <c>src/**</c> line whose <see cref="TimeProvider"/> resolves to <see cref="TimeProvider.System"/>, the real system clock, instead of a caller-supplied clock.</summary>
    SystemClockDefault,

    /// <summary>A <c>src/**</c> line reaching for the platform CSPRNG (<see cref="RandomNumberGenerator"/>) directly, or an optional <see cref="FillEntropyDelegate"/> parameter defaulted to <see langword="null"/> or <see langword="default"/>, instead of a caller-supplied entropy source.</summary>
    SystemEntropyDefault,

    /// <summary>A TPM 2.0 Library clause anchor spelled in its retired pre-v184 numbering rather than the current v185 clause number.</summary>
    RetiredClauseNumbering,

    /// <summary>A <c>readonly</c> FIELD declaration in <c>src/**</c> or <c>test/**</c> where a get-only property (or, for a compile-time-literal value type nothing addresses, a <c>const</c>) would serve — the language forces a true field only for a validating <c>init</c> accessor's backing store, a by-ref/by-address use, or a similar structural reason named on the site.</summary>
    NakedReadonlyField,

    /// <summary>A <c>test/**</c> or <c>src/**</c> line reaching into the runtime type system by reflection — a member lookup, a type enumeration, or an attribute read — where a spec case takes a direct assertion and a structural invariant takes a source scan instead.</summary>
    ReflectionOverTheTypeSystem,

    /// <summary>A private get-only or init-only property declaration in <c>src/**</c> or <c>test/**</c> whose own name starts with a lowercase letter or an underscore instead of PascalCase.</summary>
    LowercasePrivatePropertyName,

    /// <summary>A comment naming a bundled TPM 2.0 reference-implementation source/header file with no reference function alongside it in <c>src/**</c>, or naming one at all in <c>test/**</c>.</summary>
    BareReferenceSourceFile,
}

/// <summary>
/// Scans C# source text for banner-divider comments, planning-process vocabulary, the spec-line
/// shorthand for citing roadmap clauses directly in source, and internal coordination-process pointers
/// (codename-prefixed identifiers, id-family shorthand, stage/wave phrasings, review/session labels, and
/// by-name citations of internal tempdocs artifacts). All four pattern classes exist to keep
/// coordination-process artifacts (temporary build documents, review notes, clause-numbering shorthand) out
/// of shipped source; none of them target the project's own established engineering vocabulary — see the
/// per-class remarks for what is and is not in scope.
/// </summary>
internal static class SourceHygieneScanner
{
    private static string[] ScannedTopLevelDirectories { get; } = ["src", "test"];

    private static string[] ExcludedDirectorySegments { get; } = ["obj", "bin"];

    /// <summary>
    /// Walks up from <see cref="AppContext.BaseDirectory"/> until a directory containing <c>Verifiable.slnx</c>
    /// is found — the one repository-root lookup every source-hygiene and source-scan test in this assembly
    /// shares, so each proves itself on a clean clone from the test binary's own output directory with no
    /// environment variable or hardcoded path involved.
    /// </summary>
    /// <exception cref="InvalidOperationException">No ancestor of <see cref="AppContext.BaseDirectory"/> contains <c>Verifiable.slnx</c>.</exception>
    public static string FindRepositoryRoot()
    {
        DirectoryInfo? candidate = new(AppContext.BaseDirectory);
        while(candidate is not null)
        {
            if(File.Exists(Path.Join(candidate.FullName, "Verifiable.slnx")))
            {
                return candidate.FullName;
            }

            candidate = candidate.Parent;
        }

        throw new InvalidOperationException(
            $"Could not locate Verifiable.slnx by walking up from '{AppContext.BaseDirectory}'.");
    }

    /// <summary>
    /// A banner-divider comment: a plain (non-doc) <c>//</c> comment carrying four or more consecutive
    /// characters drawn from <c>-</c>, <c>=</c>, <c>*</c>, <c>_</c> — mixed runs included, so a decorated
    /// <c>// -=-=</c> divider is caught the same as a single-character one.
    /// </summary>
    /// <remarks>
    /// Anchored on plain <c>//</c> (whitespace or the punctuation run must follow immediately) so it never
    /// matches a documentation comment's own <c>///</c> prefix — the codebase quotes PEM headers such as
    /// <c>-----BEGIN PUBLIC KEY-----</c> inside <c>&lt;summary&gt;</c> text, which starts with three
    /// slashes, not two. A de-dashed section label (<c>// helpers</c>) remains permitted.
    /// </remarks>
    private static Regex BannerDividerPattern { get; } = new(@"^\s*//[ \t]*[-=*_]{4,}", RegexOptions.Compiled);

    /// <summary>
    /// The spec-line shorthand banned from source: a bare <c>T</c>/<c>P</c>/<c>C</c> tag, a dash, the
    /// letter <c>L</c>, and a digit, used inline to cite roadmap clauses by number instead of a real
    /// specification anchor; ALSO a section-symbol clause number followed by an internal rendering's
    /// own line-number citation — a section anchor must name the section only, never a rendering's
    /// line range. Built from character fragments (including the sample below, in
    /// <see cref="ScannerReportsEmbeddedSamplesWithFileAndLineShape"/>) so this file's own pattern
    /// definition and its firing sample never read as the shorthand they describe.
    /// </summary>
    private static Regex SpecLineShorthandPattern { get; } = new(
        "\\b[" + "T" + "P" + "C" + "]" + "-" + "L" + "[0-9]"
        + "|" + "§" + "\\d[\\d.]*\\s+L\\d",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Planning-process words that belong in coordination documents, never in shipped source: a fix
    /// specification tag, a design-revision note, a review takeaway, a process handoff note, the literal
    /// marker for text copied in verbatim from another document, a hyphenated adjective pair describing a
    /// repair's before-state and after-state, and the project's own citation phrases
    /// naming the coordinated block of changes that produced a piece of code. The generic "contract" (this
    /// project's standard word for an API/behavioral guarantee: "the dispose contract", "the delegate's own
    /// contract" — used well over a thousand times) is deliberately the ONLY word left unenforced here: it
    /// is saturated with long-standing, reviewed, legitimate usage across the mature codebase, and no
    /// substring rule can separate that from an actual leftover without flagging (or requiring a rewrite
    /// of) that existing, accepted style. <see cref="InternalProvenancePointerPattern"/> narrows this word
    /// down to its own leftover shape ("contract" immediately followed by a lettered requirement id) rather
    /// than banning the bare word. Built from split fragments below so this file does not flag itself.
    /// </summary>
    /// <remarks>
    /// Also bans the hyphenated adjective pair describing a repair's before-state and after-state (the word
    /// "pre" or "post" immediately followed by a hyphen and "fix"), collision-checked against the full
    /// current tree: zero legitimate hits, since the unhyphenated compound-noun form ("prefix"/"postfix",
    /// ordinary computer-science terms) is a distinct word shape the word-boundary anchor does not touch.
    /// </remarks>
    private static Regex PlanningVocabularyPattern { get; } = new(
        @"\bfix[- ]?spec\b" +
        "|" + @"\bamend[- ]?ments?\b" +
        "|" + @"\bles[- ]?son\b" +
        "|" + @"\bhand" + "over\\b" +
        "|" + @"\bcarried" + "-in\\b" +
        "|" + @"\bthis\s+wave\b" +
        "|" + @"\bthis\s+arc\b" +
        "|" + @"\bpre" + "-fix\\b" +
        "|" + @"\bpost" + "-fix\\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Internal coordination-process pointer shapes that must never ship in source: codename-prefixed
    /// identifiers (the codename letters immediately followed by lowercase letters, or by a dash and a
    /// digit), defect/fix-slot tags, stage/ruling/trap artifact references, review/session labels,
    /// by-name citations of tempdocs artifacts, lettered internal requirement ids, the further short
    /// letter-prefixed id-family shorthand (a small set of two-to-five-letter prefixes, each optionally
    /// hyphenated, immediately followed by a digit) a coordinated build cycle leaves behind, and
    /// stage/wave prose describing source as belonging to a numbered stage or a not-yet-arrived wave.
    /// Case-insensitive, so a capitalized or all-lowercase variant of any shape below is caught the same
    /// as its canonical casing. Built from split fragments below so this file does not flag itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Anchored to a <c>//</c> comment (plain or doc) only for the shapes whose bare form doubles as
    /// ordinary test-fixture data or ordinary domain prose elsewhere in the tree: the defect tag (a short
    /// alphanumeric run collides with base64/JWT fixture bytes purely by chance, an inherent collision no
    /// tighter shape removes), the numbered-stage citation, the review takeaway, the review-flag citation,
    /// and the review-row citation — the last three collide closely enough with ordinary bit-flag,
    /// table-row, and pitfall-description engineering prose that only the inside-a-comment
    /// coordination-citation form is banned; an engineering comment can still legitimately discuss an
    /// ordinarily-numbered flag or table row, so anchoring narrows the surface without claiming to
    /// eliminate the risk. The remaining alternations carry no such legitimate reuse anywhere in the tree
    /// and are checked on the full line.
    /// </para>
    /// <para>
    /// The codename token is narrowed to the observed codename suffixes themselves (each a short
    /// consonant-cluster or format-name fragment, plus a bare trailing digit) rather than any lowercase
    /// run: an earlier broader shape — any lowercase letters immediately following the common word — is
    /// deliberately not used, because that broad form collides with ordinary English plurals and compounds
    /// built on the same word (a plural form, a compound-noun form) that carry no coordination-process
    /// meaning at all. None of the narrowed suffixes forms an ordinary English word or compound when glued
    /// to the common prefix, so the alternation stays unanchored (checked on the full line, not only inside
    /// comments) without risking that collision. Every production identifier that carries the
    /// codename glues it to a preceding identifier segment rather than starting with it, so no word
    /// boundary ever precedes the codename there. Should a legitimate suffix appear later, extend the
    /// alternation list here rather than reverting to the broad form.
    /// </para>
    /// <para>
    /// <c>this stage</c> is deliberately left ungated even though the stage-citation shapes above are
    /// otherwise banned: for example, <see cref="Verifiable.Core.Model.Mdoc.MdocIssuance"/>'s remarks and
    /// <see cref="Verifiable.Tpm.Automata.TpmVerifyCommandHmacAction"/>'s <c>Current</c> parameter doc both
    /// use that exact phrase as ordinary domain prose (an mdoc format stage, a TPM verification-automaton
    /// stage), not a coordination-process reference, and no substring rule separates the two usages.
    /// </para>
    /// <para>
    /// The review-agent citation is narrowed to a preceding-word-plus-citation shape rather than the bare
    /// word: an unanchored bare form of just that citation word collides with this file's own
    /// fragment-assembled sample construction — the standalone single-word literal
    /// <see cref="ScannerReportsEmbeddedSamplesWithFileAndLineShape"/> builds its dash-form sample line
    /// from — so gating the bare word would make this class flag itself.
    /// </para>
    /// <para>
    /// The XS-family stage/observation id is gated as a bare letter-pair-plus-digits shape: a full-tree
    /// collision check (including spec-anchor prose) found no legitimate hit, so the bare form is banned
    /// outright rather than enumerating each observed numbered-suffix shape individually; the
    /// pre-existing narrower dash-lettered shape below remains for the specific artifact-reference form
    /// it was written for.
    /// </para>
    /// <para>
    /// Bare <c>R&lt;n&gt;</c>/<c>D&lt;n&gt;</c> forms (no <c>contract</c> prefix, no hyphen) are
    /// deliberately not banned here: unlike the <c>contract R</c>/hyphenated-id shapes below, a lone
    /// letter-digit token collides too broadly with genuine specification numbering to gate safely. The
    /// HYPHENATED bare form (<c>R-&lt;n&gt;</c>, no prefix) is banned, case-restricted (<c>(?-i:…)</c>) because a
    /// lower-case <c>r-&lt;n&gt;</c> occurs as ordinary fixture data in the tree (a PREMIS rights-statement
    /// identifier): a full-tree collision check found no legitimate upper-case hit — no specification, algorithm,
    /// or curve name in the tree takes that shape — and every occurrence it did find outside this file's own
    /// samples was a leaked requirement id in a doc comment.
    /// </para>
    /// <para>
    /// Also banned outright, each collision-checked against the full current tree with zero legitimate
    /// hits: a spaced citation combining the wave word with a following digit; an attributed-ruling
    /// citation naming either the owner or the coordinator as source, in a proximity form (the owner or
    /// coordinator named within a short run of words of the word this remark's own class summary calls
    /// out, rather than only immediately beside it, closing a word-boundary gap that would otherwise let a
    /// digit-suffixed variant of the CTAP fixture-codename identifier through unmatched) as well as a
    /// numbered form; a numbered-block test-plan citation; a leg-numbered preflight citation, in two further
    /// word orders; a tempdocs directory-path reference; the bare identifier token a renamed
    /// test-infrastructure type's dropped codename would otherwise leave behind; a comment-anchored numbered
    /// decision citation (plain and contract-prefixed); a comment-anchored numbered legacy-phase/chunk
    /// citation pair; an audit-drift citation; a broadened by-name tempdocs-artifact filename shape (six
    /// extensions) alongside the bare form of the one remaining artifact word that carries no
    /// ordinary-English usage anywhere in the tree, and its hyphenated spelling; a two-group numbered
    /// register-row id; a comment-anchored numbered review-finding citation; and a comment-anchored
    /// coordination-noun form of the wave word (an optional <c>pre-</c>/<c>post-</c> prefix followed by
    /// <c>wave</c> and <c>report</c>/<c>contract</c>/<c>note</c>), distinct from the bare-word and citation
    /// shapes above. The numbered decision citation, the legacy-phase/chunk citation, and the review-finding
    /// citation are comment-anchored because their bare shapes are common enough elsewhere (ordinary
    /// numbered-phase algorithm prose, ordinary numbered-finding-adjacent prose) that only the
    /// inside-a-comment coordination-citation form is safe to ban; the remaining shapes above carry no such
    /// legitimate reuse and are checked on the full line. A bare word-boundary gate for an internal citation
    /// word describing scheduled work (as opposed to the standard library's own awaitable primitive of the
    /// same name, used throughout this codebase's concurrency code as ordinary domain prose) is deliberately
    /// omitted: no real instance of that citation shape exists in the current tree to justify it, and every
    /// narrower phrasing tried still collides with genuine primitive-usage prose describing that primitive's
    /// own result or dispatch.
    /// </para>
    /// <para>
    /// Two further shapes are banned: a bare word-boundary form naming the seam-catalog word immediately
    /// followed by the finding word, and a comment-anchored form of the finding word followed by a single
    /// capital letter, the latter with its capital-letter class exempted from the pattern's overall
    /// case-insensitivity (<c>(?-i:[A-Z])</c>) so it cannot match a lower-case word in that position —
    /// collision-checked against the full current tree, including a doc comment describing a file system
    /// finding a name, which the case restriction leaves unmatched. Zero legitimate hits for either shape.
    /// </para>
    /// <para>
    /// Naming source as belonging to a numbered or lettered portion of a coordinated build directly in
    /// prose, in place of stating what the code IS and IS NOT in spec terms, is banned across every spelling
    /// this tree used: a class-heading citation of that portion by number; a small set of prepositions or
    /// verbs placing a described behavior inside that portion rather than in spec terms, and the portion's
    /// own possessive forms; a comment-anchored word pair marking a limitation as already reviewed and left
    /// as-is (in either sense — agreed to, or merely written down); a comment-anchored citation of an
    /// out-of-band verification step; a two-part id combining this project's own two-digit stage numbering
    /// with a lettered or numbered ruling, and a comment-anchored citation of that stage's own ruling by
    /// name; a comment-anchored bare mention of a single-digit stage number, in three further spellings (the
    /// word "the" immediately before it, a slash-separated pair, or a comma immediately before it) that
    /// widen the same ban to a stage numbered with one digit rather than two; and a lettered id
    /// parenthetical, comment-anchored to a documentation-comment line only (<c>///</c>, never a plain
    /// <c>//</c>) since the identical letter-digit shape also occurs, harmlessly, inside two plain comments
    /// elsewhere in the tree that are not documentation paragraphs at all — an attacker-capability label an
    /// OAuth security specification defines, and a KERI next-key commitment index. Every phrase-literal
    /// alternative below is comment-anchored rather than split into fragments, since no line of this
    /// definition itself begins with a comment marker — the same self-tripping protection the fragments
    /// above achieve, by a different means; the numeric alternatives need neither, since their digit counts
    /// are regex quantifiers, not literal digits. Collision-checked against the full current tree: the
    /// numbered-portion noun's own real meaning — a labeled byte range within a buffer — survives untouched
    /// in <see cref="Verifiable.Tpm.Infrastructure.TpmSlice"/>, whose every own-noun usage pairs the noun
    /// with a verb ("is", "extracts") none of these alternatives reach; and the response-code family sharing
    /// the single-digit stage number's own shape (<c>TPM_RC_REFERENCE_S0</c> through
    /// <c>TPM_RC_REFERENCE_S6</c>, TPM 2.0 Library Part 2, clause 6.6.2) is always joined to its
    /// <c>TPM_RC_REFERENCE_</c> prefix by an underscore, so no word boundary ever precedes its own digit and
    /// the three single-digit alternatives never reach it.
    /// </para>
    /// </remarks>
    private static Regex InternalProvenancePointerPattern { get; } = new(
        @"\b" + "wave" + @"(cb|ep|pin|cm|bio|lb|nv|ext|close|xades|jades|pades|[0-9])[a-z0-9]*\b" +
        "|" + @"\b" + "wave" + @"-[0-9a-z]+\b" +
        "|" + @"\bwave\s\d" +
        "|" + @"^\s*//.*\bFX-?[A-Z0-9]+\b" +
        "|" + @"\bXS\d+-[AR]\d+\b" +
        "|" + @"\bXS\d+\b" +
        "|" + @"\bruling" + @"s?\s+XS\b" +
        "|" + @"\bruling\s*\(?\d" +
        "|" + @"\b(owner|coordinator)('s)?\b[^.\n]{0,40}\b" + "ruling" + @"\b" +
        "|" + @"\btest\s+plan\s+block\b" +
        "|" + @"\bpreflight\s+leg\b" +
        "|" + @"\bleg\s+\d\s+preflight\b" +
        "|" + @"\bpreflight\s+(report|survey|note)\b" +
        "|" + @"\btempdocs[/\\]" +
        "|" + @"\bCtapWave[0-9a-z]*\b" +
        "|" + @"\bKNOWN\s#\d+\b" +
        "|" + @"\bsession-\d+\b" +
        "|" + @"\bscout-[a-z]+\b" +
        "|" + @"\b[a-z]+\s+scout\b" +
        "|" + @"\w+-(contract|fix" + "spec" + "|build" + "log|ledger|survey|handoff)" + @"\.md" +
        "|" + @"\bbuild" + "-?" + "log" + @"\b" +
        "|" + @"^\s*//.*\bdecision\s+\d\b" +
        "|" + @"^\s*//.*\bcontract\s+decision\s+\d" +
        "|" + @"^\s*//.*\bPhase\s*9[a-z]\b" +
        "|" + @"^\s*//.*\bPhase9[a-z]" +
        "|" + @"^\s*//.*\bchunk\s+\d+\b" +
        "|" + @"\baudit\s+drift\b" +
        "|" + @"\bDV\d+-\d+\b" +
        "|" + @"^\s*//.*\bfindings?\s+#\d\b" +
        "|" + @"\bcontract R-?\d" +
        "|" + @"(?-i:\bR-\d+\b)" +
        "|" + @"\bVBC-\d" +
        "|" + @"\bRJ-\d" +
        "|" + @"\bJD\d+\b" +
        "|" + @"\bJ-S\d\b" +
        "|" + @"\bRW\d[a-z]?\b" +
        "|" + @"\bRW\d-D\d\b" +
        "|" + @"\bP-S\d\b" +
        "|" + @"\bSEC-\d\b" +
        "|" + @"\bMAJOR-\d\b" +
        "|" + @"\bMINOR-\d\b" +
        "|" + @"\bDoD\s\d" +
        "|" + @"^\s*//.*\bflag\s\d" +
        "|" + @"\bthe\s+stage's\b" +
        "|" + @"\ba\s+(later|future)\s+wave\b" +
        "|" + @"\bthe\s+wave's\b" +
        "|" + @"^\s*//.*\bstage-\d\b" +
        "|" + @"\bleg-\d\b" +
        "|" + @"^\s*//.*\bTORN\srows?\s\d" +
        "|" + @"^\s*//.*\btrap\s\d" +
        "|" + @"^\s*//.*\b(pre-|post-)?wave\s+(report|contract|note)\b" +
        "|" + @"\bseams\s+[Ff]inding\b" +
        "|" + @"^\s*//.*\b[Ff]inding\s+(?-i:[A-Z])\b" +
        "|" + @"\bSlice \d" +
        "|" + @"\bSlice [A-Z]\d" +
        "|" + @"\b(in|modelled|modeled|beyond|for|by) this" + " slice\\b" +
        "|" + @"\bthis slice (does|uses|changes|models|leaves|never)\b" +
        "|" + @"\bthis" + " " + @"slice\b" +
        "|" + @"^\s*//.*\bthis slice's\b" +
        "|" + @"^\s*//.*\bslice's scope\b" +
        "|" + @"^\s*//.*\baccepted residual\b" +
        "|" + @"^\s*//.*\bdocumented residual\b" +
        "|" + @"\(A\d, accepted" +
        "|" + @"^\s*///.*\(A\d[,:\)]" +
        "|" + @"^\s*//.*\bpost-verify adjudication\b" +
        "|" + @"\bS\d{2} \((D|R\d+)\)" +
        "|" + @"^\s*//.*\bthe S\d{2} ruling\b" +
        "|" + @"^\s*//.*\d{4}-\d{2}-\d{2} (ruling|adjudication|decision)\b" +
        "|" + @"^\s*//.*\bthe S\d\b" +
        "|" + @"^\s*//.*\bS\d/S\d\b" +
        "|" + @"^\s*//.*,\s*S\d\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static IReadOnlyList<string> EnumerateSourceFiles(string repositoryRoot)
    {
        List<string> files = [];

        foreach(string topLevelDirectory in ScannedTopLevelDirectories)
        {
            files.AddRange(EnumerateSourceFilesUnder(repositoryRoot, topLevelDirectory));
        }

        return files;
    }

    /// <summary>
    /// Enumerates every <c>.cs</c> file under a single top-level directory (<c>src</c> or <c>test</c>) of
    /// <paramref name="repositoryRoot"/>, skipping <c>bin</c>/<c>obj</c> the same way <see cref="EnumerateSourceFiles"/>
    /// does. Lets a gate scan only production sources or only test sources instead of both.
    /// </summary>
    public static IReadOnlyList<string> EnumerateSourceFilesUnder(string repositoryRoot, string topLevelDirectory)
    {
        List<string> files = [];
        string directoryPath = Path.Join(repositoryRoot, topLevelDirectory);

        if(!Directory.Exists(directoryPath))
        {
            return files;
        }

        foreach(string filePath in Directory.EnumerateFiles(directoryPath, "*.cs", SearchOption.AllDirectories))
        {
            string relativePath = Path.GetRelativePath(repositoryRoot, filePath);
            string[] segments = relativePath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

            if(segments.Any(segment => ExcludedDirectorySegments.Contains(segment)))
            {
                continue;
            }

            files.Add(filePath);
        }

        return files;
    }

    public static IReadOnlyList<SourceHygieneViolation> ScanFiles(IReadOnlyList<string> filePaths, string repositoryRoot)
    {
        List<SourceHygieneViolation> violations = [];

        foreach(string filePath in filePaths)
        {
            string relativePath = Path.GetRelativePath(repositoryRoot, filePath).Replace(Path.DirectorySeparatorChar, '/');
            string[] lines = File.ReadAllLines(filePath);

            violations.AddRange(ScanLines(relativePath, lines));
        }

        return violations;
    }

    /// <summary>
    /// Scans <paramref name="lines"/> per-line against all four pattern classes, then makes one additional
    /// pass over each pair of adjacent comment lines with the pair's text joined, to catch a banned shape
    /// whose characteristic token was split across a doc-comment wrap (e.g. a citation ending a line with
    /// <c>ruling</c> and resuming the next with a bare digit). A pair is joined only when both lines are
    /// comment lines (<c>//</c> or <c>///</c>, leading whitespace ignored); the continuation line's comment
    /// prefix is stripped before joining so the reconstructed text reads as the original unwrapped sentence
    /// would, and any match already found on either line individually is not re-reported through the join.
    /// </summary>
    /// <remarks>
    /// This closes evasion across exactly one line break. A token split across three or more physical
    /// lines (each fragment on its own line) is not detected: only consecutive pairs are joined, never
    /// triples, so a three-way split never reconstructs the banned shape in any single pass. That residual
    /// gap is accepted rather than chased with three-line (or n-line) joining, which would grow the false-
    /// positive surface faster than the evasion shape it would catch is likely to recur.
    /// </remarks>
    public static IReadOnlyList<SourceHygieneViolation> ScanLines(string filePath, IReadOnlyList<string> lines)
    {
        List<SourceHygieneViolation> violations = [];
        bool[] bannerMatchesByLine = new bool[lines.Count];
        bool[] specShorthandMatchesByLine = new bool[lines.Count];
        bool[] planningVocabularyMatchesByLine = new bool[lines.Count];
        bool[] provenancePointerMatchesByLine = new bool[lines.Count];

        for(int lineIndex = 0; lineIndex < lines.Count; lineIndex++)
        {
            string line = lines[lineIndex];
            int lineNumber = lineIndex + 1;

            bannerMatchesByLine[lineIndex] = BannerDividerPattern.IsMatch(line);
            if(bannerMatchesByLine[lineIndex])
            {
                violations.Add(new SourceHygieneViolation(filePath, lineNumber, SourceHygieneViolationKind.BannerDivider, line));
            }

            specShorthandMatchesByLine[lineIndex] = SpecLineShorthandPattern.IsMatch(line);
            if(specShorthandMatchesByLine[lineIndex])
            {
                violations.Add(new SourceHygieneViolation(filePath, lineNumber, SourceHygieneViolationKind.SpecLineShorthand, line));
            }

            planningVocabularyMatchesByLine[lineIndex] = PlanningVocabularyPattern.IsMatch(line);
            if(planningVocabularyMatchesByLine[lineIndex])
            {
                violations.Add(new SourceHygieneViolation(filePath, lineNumber, SourceHygieneViolationKind.PlanningVocabulary, line));
            }

            provenancePointerMatchesByLine[lineIndex] = InternalProvenancePointerPattern.IsMatch(line);
            if(provenancePointerMatchesByLine[lineIndex])
            {
                violations.Add(new SourceHygieneViolation(filePath, lineNumber, SourceHygieneViolationKind.InternalProvenancePointer, line));
            }
        }

        for(int lineIndex = 0; lineIndex < lines.Count - 1; lineIndex++)
        {
            string firstLine = lines[lineIndex];
            string secondLine = lines[lineIndex + 1];

            if(!IsCommentLine(firstLine) || !IsCommentLine(secondLine))
            {
                continue;
            }

            string joinedLine = firstLine + " " + StripCommentContinuationPrefix(secondLine);
            int lineNumber = lineIndex + 1;

            AddJoinedLineViolationIfNotAlreadyFound(
                violations, filePath, lineNumber, joinedLine, BannerDividerPattern,
                SourceHygieneViolationKind.BannerDivider, bannerMatchesByLine[lineIndex], bannerMatchesByLine[lineIndex + 1]);

            AddJoinedLineViolationIfNotAlreadyFound(
                violations, filePath, lineNumber, joinedLine, SpecLineShorthandPattern,
                SourceHygieneViolationKind.SpecLineShorthand, specShorthandMatchesByLine[lineIndex], specShorthandMatchesByLine[lineIndex + 1]);

            AddJoinedLineViolationIfNotAlreadyFound(
                violations, filePath, lineNumber, joinedLine, PlanningVocabularyPattern,
                SourceHygieneViolationKind.PlanningVocabulary, planningVocabularyMatchesByLine[lineIndex], planningVocabularyMatchesByLine[lineIndex + 1]);

            AddJoinedLineViolationIfNotAlreadyFound(
                violations, filePath, lineNumber, joinedLine, InternalProvenancePointerPattern,
                SourceHygieneViolationKind.InternalProvenancePointer, provenancePointerMatchesByLine[lineIndex], provenancePointerMatchesByLine[lineIndex + 1]);
        }

        return violations;
    }

    private static void AddJoinedLineViolationIfNotAlreadyFound(
        List<SourceHygieneViolation> violations,
        string filePath,
        int lineNumber,
        string joinedLine,
        Regex pattern,
        SourceHygieneViolationKind kind,
        bool matchedOnFirstLineAlone,
        bool matchedOnSecondLineAlone)
    {
        if(matchedOnFirstLineAlone || matchedOnSecondLineAlone)
        {
            return;
        }

        if(pattern.IsMatch(joinedLine))
        {
            violations.Add(new SourceHygieneViolation(filePath, lineNumber, kind, joinedLine));
        }
    }

    private static bool IsCommentLine(string line)
    {
        return line.TrimStart().StartsWith("//", StringComparison.Ordinal);
    }

    /// <summary>
    /// Scans <paramref name="lines"/> for <paramref name="pattern"/>, reporting one <see cref="SourceHygieneViolation"/>
    /// of <paramref name="kind"/> per matching line. A comment line (<c>//</c> or <c>///</c>, leading
    /// whitespace ignored) is skipped via <see cref="IsCommentLine"/> so a reference to the banned shape in
    /// its own documentation — a <c>&lt;see cref&gt;</c> naming the very API a rule forbids as a hidden
    /// default, for example — is never counted as a live call site. A second pass then joins each CODE line
    /// whose trimmed text ends in <c>(</c> or <c>,</c> with its successor (mirroring the wrapped-call
    /// formatting this codebase's multi-line <c>Assert</c> calls use) and re-runs <paramref name="pattern"/>
    /// on the joined text, so a match split across the wrap — an <c>Assert.IsLessThan(</c> call whose
    /// <c>.Elapsed</c> argument sits on the next line, for example — is not missed; a joined hit already
    /// found on either line alone is not re-reported, via the same de-duplication
    /// <see cref="AddJoinedLineViolationIfNotAlreadyFound"/> applies to the comment-line join in
    /// <see cref="ScanLines"/>.
    /// </summary>
    public static IReadOnlyList<SourceHygieneViolation> ScanCodeLinesForPattern(
        string filePath, IReadOnlyList<string> lines, Regex pattern, SourceHygieneViolationKind kind)
    {
        List<SourceHygieneViolation> violations = [];
        bool[] matchesByLine = new bool[lines.Count];

        for(int lineIndex = 0; lineIndex < lines.Count; lineIndex++)
        {
            string line = lines[lineIndex];
            if(IsCommentLine(line))
            {
                continue;
            }

            matchesByLine[lineIndex] = pattern.IsMatch(line);
            if(matchesByLine[lineIndex])
            {
                violations.Add(new SourceHygieneViolation(filePath, lineIndex + 1, kind, line));
            }
        }

        for(int lineIndex = 0; lineIndex < lines.Count - 1; lineIndex++)
        {
            string firstLine = lines[lineIndex];
            string secondLine = lines[lineIndex + 1];

            if(IsCommentLine(firstLine) || IsCommentLine(secondLine) || !EndsWithOpenContinuation(firstLine))
            {
                continue;
            }

            string joinedLine = firstLine + " " + secondLine.TrimStart();
            int lineNumber = lineIndex + 1;

            AddJoinedLineViolationIfNotAlreadyFound(
                violations, filePath, lineNumber, joinedLine, pattern, kind, matchesByLine[lineIndex], matchesByLine[lineIndex + 1]);
        }

        return violations;
    }

    /// <summary>
    /// Scans EVERY line of <paramref name="lines"/> for <paramref name="pattern"/>, comment lines included,
    /// reporting one <see cref="SourceHygieneViolation"/> of <paramref name="kind"/> per matching line. Unlike
    /// <see cref="ScanCodeLinesForPattern"/>, a comment line is a live site here rather than an exempt
    /// reference: a specification clause anchor legitimately lives inside a <c>///</c> or <c>//</c> comment,
    /// so a rule banning a specific anchor SHAPE (as opposed to a hidden-default API also legitimately named
    /// in a doc comment's prose) must see comments too.
    /// </summary>
    public static IReadOnlyList<SourceHygieneViolation> ScanAllLinesForPattern(
        string filePath, IReadOnlyList<string> lines, Regex pattern, SourceHygieneViolationKind kind)
    {
        List<SourceHygieneViolation> violations = [];

        for(int lineIndex = 0; lineIndex < lines.Count; lineIndex++)
        {
            string line = lines[lineIndex];
            if(pattern.IsMatch(line))
            {
                violations.Add(new SourceHygieneViolation(filePath, lineIndex + 1, kind, line));
            }
        }

        return violations;
    }

    /// <summary>
    /// A wrapped-call continuation cue: the line's trimmed text ends in <c>(</c> or <c>,</c>, the shape this
    /// codebase's own multi-line calls (an open argument list, or an argument list continuing onto the next
    /// line) leave at the wrap point.
    /// </summary>
    private static bool EndsWithOpenContinuation(string line)
    {
        string trimmed = line.TrimEnd();

        return trimmed.Length > 0 && (trimmed[^1] == '(' || trimmed[^1] == ',');
    }

    private static string StripCommentContinuationPrefix(string line)
    {
        string trimmed = line.TrimStart();
        trimmed = trimmed.StartsWith("///", StringComparison.Ordinal) ? trimmed[3..] : trimmed[2..];

        return trimmed.TrimStart();
    }
}
