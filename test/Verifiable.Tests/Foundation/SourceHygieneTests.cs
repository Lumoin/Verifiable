using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Verifiable.Tests.Foundation;

/// <summary>
/// Walks every <c>.cs</c> file under <c>src/</c> and <c>test/</c> from a located repository root and fails
/// listing <c>file:line</c> for banner-divider comments, planning-process vocabulary, the spec-line
/// shorthand, and internal coordination-process pointers (codename-prefixed identifiers, id-family
/// shorthand, stage/wave phrasings, review/session labels, and by-name citations of internal tempdocs
/// artifacts) described by <see cref="SourceHygieneScanner"/>. Runs on a clean clone: the root is located by walking up from
/// <see cref="AppContext.BaseDirectory"/> to the directory containing <c>Verifiable.slnx</c>, no environment
/// variable or hardcoded path involved.
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
        string repositoryRoot = FindRepositoryRoot();
        IReadOnlyList<string> sourceFiles = SourceHygieneScanner.EnumerateSourceFiles(repositoryRoot);
        IReadOnlyList<SourceHygieneViolation> violations = SourceHygieneScanner.ScanFiles(sourceFiles, repositoryRoot);

        Assert.IsEmpty(violations, FormatViolations(violations));
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
        ];

        IReadOnlyList<SourceHygieneViolation> violations = SourceHygieneScanner.ScanLines("Sample.cs", sampleLines);

        Assert.HasCount(77, violations);
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

    private static string FormatViolations(IReadOnlyList<SourceHygieneViolation> violations)
    {
        return string.Join(Environment.NewLine, violations.Select(static v => v.ToString()));
    }

    /// <summary>
    /// Walks up from <see cref="AppContext.BaseDirectory"/> until a directory containing <c>Verifiable.slnx</c>
    /// is found. Works from the test binary's output directory on a clean clone with no other input.
    /// </summary>
    private static string FindRepositoryRoot()
    {
        DirectoryInfo? candidate = new(AppContext.BaseDirectory);
        while(candidate is not null)
        {
            if(File.Exists(Path.Combine(candidate.FullName, "Verifiable.slnx")))
            {
                return candidate.FullName;
            }

            candidate = candidate.Parent;
        }

        throw new InvalidOperationException(
            $"Could not locate Verifiable.slnx by walking up from '{AppContext.BaseDirectory}'.");
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

/// <summary>The four pattern classes the source-hygiene gate checks for.</summary>
internal enum SourceHygieneViolationKind
{
    BannerDivider,
    PlanningVocabulary,
    SpecLineShorthand,
    InternalProvenancePointer,
}

/// <summary>
/// Scans C# source text for banner-divider comments, planning-process vocabulary, the spec-line
/// shorthand used to cite roadmap clauses directly in source, and internal coordination-process pointers
/// (codename-prefixed identifiers, id-family shorthand, stage/wave phrasings, review/session labels, and
/// by-name citations of internal tempdocs artifacts). All four pattern classes exist to keep
/// coordination-process artifacts (temporary build documents, review notes, clause-numbering shorthand) out
/// of shipped source; none of them target the project's own established engineering vocabulary — see the
/// per-class remarks for what is and is not in scope.
/// </summary>
internal static class SourceHygieneScanner
{
    private static readonly string[] ScannedTopLevelDirectories = ["src", "test"];

    private static readonly string[] ExcludedDirectorySegments = ["obj", "bin"];

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
    private static readonly Regex BannerDividerPattern = new(@"^\s*//[ \t]*[-=*_]{4,}", RegexOptions.Compiled);

    /// <summary>
    /// The spec-line shorthand banned from source: a bare <c>T</c>/<c>P</c>/<c>C</c> tag, a dash, the
    /// letter <c>L</c>, and a digit, used inline to cite roadmap clauses by number instead of a real
    /// specification anchor; ALSO a section-symbol clause number followed by an internal rendering's
    /// own line-number citation — a section anchor must name the section only, never a rendering's
    /// line range. Built from character fragments (including the sample below, in
    /// <see cref="ScannerReportsEmbeddedSamplesWithFileAndLineShape"/>) so this file's own pattern
    /// definition and its firing sample never read as the shorthand they describe.
    /// </summary>
    private static readonly Regex SpecLineShorthandPattern = new(
        "\\b[" + "T" + "P" + "C" + "]" + "-" + "L" + "[0-9]"
        + "|" + "§" + "\\d[\\d.]*\\s+L\\d",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Planning-process words that belong in coordination documents, never in shipped source: a fix
    /// specification tag, a design-revision note, a review takeaway, a process handoff note, the literal
    /// marker for text copied in verbatim from another document, and the project's own citation phrases
    /// naming the coordinated block of changes that produced a piece of code. The generic "contract" (this
    /// project's standard word for an API/behavioral guarantee: "the dispose contract", "the delegate's own
    /// contract" — used well over a thousand times) is deliberately the ONLY word left unenforced here: it
    /// is saturated with long-standing, reviewed, legitimate usage across the mature codebase, and no
    /// substring rule can separate that from an actual leftover without flagging (or requiring a rewrite
    /// of) that existing, accepted style. <see cref="InternalProvenancePointerPattern"/> narrows this word
    /// down to its own leftover shape ("contract" immediately followed by a lettered requirement id) rather
    /// than banning the bare word. Built from split fragments below so this file does not flag itself.
    /// </summary>
    private static readonly Regex PlanningVocabularyPattern = new(
        @"\bfix[- ]?spec\b" +
        "|" + @"\bamend[- ]?ments?\b" +
        "|" + @"\bles[- ]?son\b" +
        "|" + @"\bhand" + "over\\b" +
        "|" + @"\bcarried" + "-in\\b" +
        "|" + @"\bthis\s+wave\b" +
        "|" + @"\bthis\s+arc\b",
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
    /// comments) while no longer risking that collision. Every production identifier that carries the
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
    /// The round-4 additions — a spaced citation combining the wave word with a following digit, an
    /// attributed-ruling citation naming
    /// either the owner or the coordinator as source, a numbered-block test-plan citation, a leg-numbered
    /// preflight citation, a tempdocs directory-path reference, and the bare identifier token left over
    /// once every renamed test-infrastructure type had dropped the codename it used to carry — were each
    /// collision-checked against the full current tree before being added: zero legitimate hits for any of
    /// the six literal shapes and the identifier check, so none needed comment-anchoring or further
    /// narrowing. The tree's own remaining true positives these additions turned up (plain-prose
    /// citations combining the wave word with a following digit in doc comments, one numbered-block
    /// test-plan citation) were reworded in
    /// the same pass rather than left for the gate to report and a later pass to clean.
    /// </para>
    /// <para>
    /// The round-5 additions replace the two exact-adjacency attributed-ruling alternations with a
    /// proximity form (the owner or coordinator named within a short run of words of the word this
    /// remark's own class summary calls out, rather than immediately beside it), fix a word-boundary gap
    /// that let a digit-suffixed variant of the CTAP fixture-codename identifier through unmatched, and add
    /// a numbered attributed-ruling shape, a comment-anchored numbered decision citation (plain and
    /// contract-prefixed), a comment-anchored numbered legacy-phase/chunk citation pair, an audit-drift
    /// citation, a broadened by-name tempdocs-artifact filename shape (the existing two extensions plus
    /// four more) alongside the bare form of the one remaining artifact word that carries no ordinary-
    /// English usage anywhere in the tree, a two-group numbered register-row id, a comment-anchored
    /// numbered review-finding citation, and two further preflight-citation word orders. Each was
    /// collision-checked against the full current tree before being added: the numbered decision citation,
    /// the legacy-phase/chunk citation, and the review-finding citation are comment-anchored because their
    /// bare shapes are common enough elsewhere (ordinary numbered-phase algorithm prose, ordinary
    /// numbered-finding-adjacent prose) that only the inside-a-comment coordination-citation form is safe
    /// to ban; the remaining additions carry no such legitimate reuse and are checked on the full line. A
    /// bare word-boundary gate for an internal citation word describing scheduled work (as opposed to the
    /// standard library's own awaitable primitive of the same name, used throughout this codebase's
    /// concurrency code as ordinary domain prose) was considered and rejected: no real instance of that
    /// citation shape exists in the current tree to justify it, and every narrower phrasing tried still
    /// collided with genuine primitive-usage prose describing that primitive's own result or dispatch.
    /// </para>
    /// <para>
    /// The round-6 addition widens the by-name artifact shape to also catch the hyphenated spelling of
    /// the artifact word already banned in its bare form, and adds a comment-anchored coordination-noun
    /// form of the wave word (an optional <c>pre-</c>/<c>post-</c> prefix followed by
    /// <c>wave</c> and <c>report</c>/<c>contract</c>/<c>note</c>) distinct from the bare-word and
    /// citation shapes above. Both were collision-checked against the full current tree before being
    /// added: zero legitimate hits for either shape, so neither needed further narrowing.
    /// </para>
    /// <para>
    /// The round-7 addition removes the review-finding citations this remark's own history referred to
    /// by their letter suffix and bans the two shapes those citations used: a bare word-boundary form
    /// naming the seam-catalog word immediately followed by the finding word, and a comment-anchored
    /// form of the finding word followed by a single capital letter, the latter with its capital-letter
    /// class exempted from the pattern's overall case-insensitivity (<c>(?-i:[A-Z])</c>) so it cannot
    /// match a lower-case word in that position — collision-checked against the full current tree,
    /// including a doc comment describing a file system finding a name, which the case restriction
    /// leaves unmatched. Zero legitimate hits for either shape, so neither needed further narrowing.
    /// </para>
    /// </remarks>
    private static readonly Regex InternalProvenancePointerPattern = new(
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
        "|" + @"^\s*//.*\b[Ff]inding\s+(?-i:[A-Z])\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static IReadOnlyList<string> EnumerateSourceFiles(string repositoryRoot)
    {
        List<string> files = [];

        foreach(string topLevelDirectory in ScannedTopLevelDirectories)
        {
            string directoryPath = Path.Combine(repositoryRoot, topLevelDirectory);
            if(!Directory.Exists(directoryPath))
            {
                continue;
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

    private static string StripCommentContinuationPrefix(string line)
    {
        string trimmed = line.TrimStart();
        trimmed = trimmed.StartsWith("///", StringComparison.Ordinal) ? trimmed[3..] : trimmed[2..];

        return trimmed.TrimStart();
    }
}
