using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// The requirements matrix for the information-package specifications this wave builds against: every
/// requirement identifier of
/// <see href="https://earkcsip.dilcis.eu/">E-ARK Common Specification for Information Packages (CSIP)
/// v2.2.0</see> (its folder catalogue <c>CSIPSTR1</c>…<c>CSIPSTR16</c> and its METS profile catalogue
/// <c>CSIP1</c>…<c>CSIP119</c>), every requirement of
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata (CITS-PREMIS) v1.0.1</see> (both of its
/// identifier schemes — the tables' <c>PM1</c>…<c>PM125</c> and the narrative's fourteen <c>PREMIS-*</c>
/// mnemonics), and the three package-type extensions:
/// <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see>,
/// <see href="https://earksip.dilcis.eu/">E-ARK SIP v2.2.0</see> and
/// <see href="https://earkdip.dilcis.eu/">E-ARK DIP v2.2.0</see>.
/// Mirrors the rows-as-spec-cells shape of <c>PreservationRequirementsMatrixTests</c> (ETSI TS 119 511 and
/// TS 119 512), <c>AsicRequirementsMatrixTests</c> (ETSI EN 319 162-1/-2), <c>CAdESRequirementsMatrixTests</c>
/// (ETSI EN 319 122-1) and <c>SignatureValidationRequirementsMatrixTests</c> (ETSI EN 319 102-1).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="RequirementMatrixTest"/> fails a row that has no coverage disposition — no silent gaps — and,
/// for the dispositions that name a test, resolves the cited evidence through reflection over the compiled
/// test assembly: a row citing a class or method that does not exist, or that is not itself a
/// <c>[TestMethod]</c>, fails. A renamed or deleted evidence method is therefore caught here rather than
/// rotting into a stale citation.
/// </para>
/// <para>
/// <strong>The row identifiers are the specifications' own.</strong> A folder requirement is
/// <c>CSIPSTR9</c>, a METS profile requirement <c>CSIP114</c>, a preservation-metadata table row
/// <c>PM33</c>, a preservation-metadata narrative row <c>PREMIS-CHECKSUMS</c>, an archival-package row
/// <c>AIPM5</c> or <c>AIP17</c>. Obligations a source document states with no identifier of its own carry a
/// lower-case clause slug under their document's prefix (<c>csip-</c>, <c>premis-</c>, <c>aip-</c>,
/// <c>sip-</c>, <c>dip-</c>), which keeps them distinguishable from the upper-case catalogues by an ordinal
/// comparison. Keeping the specifications' own strings is what lets a consuming system key a
/// requirements-to-code graph on them.
/// </para>
/// <para>
/// <strong>Three registries are the oracle, in both directions.</strong>
/// <see cref="EArkClaimIds"/>, <see cref="PremisClaimIds"/> and <see cref="AipClaimIds"/> were transcribed
/// from the same normative texts by earlier stages of this wave, before this matrix existed; every identifier
/// they allocate must be a row here and every catalogued row must be allocated there. That makes the count a
/// cross-check rather than a number written into prose.
/// </para>
/// <para>
/// <strong>Submission and dissemination packages are recognition rows.</strong> The wave contract rules
/// E-ARK SIP and E-ARK DIP out of this wave — neither carries any preservation-evidence, signature or trust
/// content of its own — while the archival package is in narrowly: its preservation layer
/// (<c>AIPM5</c>…<c>AIPM7</c>, <c>AIP12</c>, <c>AIP13</c>, <c>AIP15</c>…<c>AIP18</c> and the untagged
/// parent-chain obligation) plus the METS shell that carries it. Every out-of-wave requirement still gets a
/// row stating the contract's reason, so a consuming graph can tell "deliberately not covered" from
/// "forgotten".
/// </para>
/// <para>
/// <strong>Two defects of the source bodies are rows rather than silence.</strong> The preservation-metadata
/// tables give <c>PM53</c> and <c>PM66</c> the keyword <c>COULD</c>, which the requirement-keyword vocabulary
/// those tables otherwise use does not define; and the archival package's prose identifier space is missing
/// eleven of its twenty-eight numbers. Both are recorded as documented interpretations at their own rows,
/// with the test that drives the interpretation cited beside them.
/// </para>
/// <para>
/// <strong>Term consistency against the archival reference model.</strong> Clause 1.4 item 4 of the reference
/// model this wave reads alongside these documents obliges a specification claiming conformance to it to use
/// its terms in the same manner. The three findings are rows of their own rather than prose.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkRequirementsMatrixTests
{
    /// <summary>Whether a requirement row is driven by a concrete test, binds the operating repository rather than a library, is explicitly out of this wave's scope, or is implemented at the building-block level but unreachable through the shipped composition because of an already-flagged defect.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped surface.</summary>
        Tested = 1,

        /// <summary>The requirement is explicitly out of this wave's scope, per the arc contract, the charter, a stage's own recorded flag, or the source document's own scope exclusion.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it, but the shipped default composition cannot reach it because of an already-flagged, unfixed defect or gap elsewhere in the pipeline.</summary>
        KnownDefect = 3,

        /// <summary>The obligation binds the repository operating an archive — its identifier governance, its storage system, its retention decisions, its tool conformance — and not a class library. The evidence names the primitive the library ships toward it, or states that it ships none.</summary>
        ServiceOperational = 4
    }


    /// <summary>One row of the matrix: a requirement identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The specification's own requirement identifier where it has one, otherwise a lower-case clause slug under its document's prefix.</param>
    /// <param name="Requirement">A short digest of the normative statement, opening with the requirement keyword and the cardinality its own catalogue gives it, close enough to the source's wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/> and <see cref="RequirementCoverageStatus.KnownDefect"/>, and for a <see cref="RequirementCoverageStatus.ServiceOperational"/> row that has an enabling primitive, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection. For <see cref="RequirementCoverageStatus.OutOfScope"/>, the stated reason. For a service-operational row with no primitive, a statement opening with <see cref="NoEnablingPrimitive"/>.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


    /// <summary>The opening words a service-operational row's evidence uses when this library ships nothing that helps discharge the obligation.</summary>
    private const string NoEnablingPrimitive = "No enabling primitive";

    /// <summary>The opening words every out-of-wave recognition row's evidence uses, so the contract's own reason is the first thing read.</summary>
    private const string OutOfWave = "OUT OF WAVE (wave contract, scope section)";

    /// <summary>The reason every submission-package recognition row states.</summary>
    private const string SubmissionDeferred = OutOfWave + " — the submission specification's whole normative content is producer-identity and submission-logistics bookkeeping, with no preservation-evidence, signature or trust content anywhere in it; deferred as a recognition row.";

    /// <summary>The reason every dissemination-package recognition row states.</summary>
    private const string DisseminationDeferred = OutOfWave + " — a dissemination package is by the specification's own definition a downstream rendering of an already-preserved archival package and adds no evidentiary content of its own; deferred as a recognition row.";


    /// <summary>The requirements matrix, one row per <c>object[]</c>.</summary>
    /// <returns>Every row.</returns>
    public static IEnumerable<object[]> Requirements()
    {
        foreach((string clauseId, string requirement, RequirementCoverageStatus status, string evidence) in RowData)
        {
            yield return [new RequirementMatrixRow(clauseId, requirement, status, evidence)];
        }
    }


    /// <summary>
    /// No row of the matrix may be left without a coverage disposition, and a row whose disposition names a
    /// test must resolve that name to a real, existing <c>[TestMethod]</c> in the compiled test assembly.
    /// </summary>
    /// <param name="row">The row under test.</param>
    [TestMethod]
    [DynamicData(nameof(Requirements))]
    public void RequirementMatrixTest(RequirementMatrixRow row)
    {
        Assert.AreNotEqual(RequirementCoverageStatus.Untested, row.Status, $"{row.ClauseId}: '{row.Requirement}' has no coverage disposition.");
        Assert.IsFalse(string.IsNullOrWhiteSpace(row.Evidence), $"{row.ClauseId}: '{row.Requirement}' needs a named test or a stated reason.");

        if(row.Status is RequirementCoverageStatus.Tested or RequirementCoverageStatus.KnownDefect)
        {
            AssertEvidenceNamesAShippedTestMethod(row);
        }

        if(row.Status is RequirementCoverageStatus.ServiceOperational && !row.Evidence.StartsWith(NoEnablingPrimitive, StringComparison.Ordinal))
        {
            AssertEvidenceNamesAShippedTestMethod(row);
        }
    }


    /// <summary>
    /// Every requirement identifier of the matrix is stated once. A duplicated identifier would let one row
    /// silently replace another's disposition in a reader's eye while both still pass, which is the failure
    /// mode a hand-maintained table of this size has.
    /// </summary>
    [TestMethod]
    public void EveryClauseIdentifierIsStatedOnce()
    {
        List<string> duplicated = [.. RowData
            .GroupBy(row => row.ClauseId, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)];

        Assert.IsEmpty(duplicated, $"These requirement identifiers appear more than once: {string.Join(", ", duplicated)}.");
    }


    /// <summary>
    /// Every row belongs to one of the five groups the matrix covers — the Common Specification, the
    /// preservation-metadata specification, the archival package, the submission and dissemination packages,
    /// or this library's own conventions over them — and each group is non-empty. A row belonging to none
    /// would sit in the matrix attached to nothing.
    /// </summary>
    [TestMethod]
    public void EveryRowNamesOneOfTheSourcesTheMatrixCovers()
    {
        List<string> unattributed = [.. RowData
            .Where(row => !IsCommonSpecificationRow(row.ClauseId)
                && !IsPreservationMetadataRow(row.ClauseId)
                && !IsArchivalPackageRow(row.ClauseId)
                && !IsSubmissionOrDisseminationRow(row.ClauseId)
                && !IsHouseConventionRow(row.ClauseId))
            .Select(row => row.ClauseId)];

        Assert.IsEmpty(unattributed, $"These rows name none of the matrix's sources: {string.Join(", ", unattributed)}.");
        Assert.IsNotEmpty(RowData.Where(row => IsCommonSpecificationRow(row.ClauseId)).ToList());
        Assert.IsNotEmpty(RowData.Where(row => IsPreservationMetadataRow(row.ClauseId)).ToList());
        Assert.IsNotEmpty(RowData.Where(row => IsArchivalPackageRow(row.ClauseId)).ToList());
        Assert.IsNotEmpty(RowData.Where(row => IsSubmissionOrDisseminationRow(row.ClauseId)).ToList());
        Assert.IsNotEmpty(RowData.Where(row => IsHouseConventionRow(row.ClauseId)).ToList());
    }


    /// <summary>
    /// The matrix and the shipped Common Specification claim-identifier registry state the same requirement
    /// inventory, in both directions: every identifier <see cref="EArkClaimIds"/> allocates — the folder
    /// catalogue, the METS profile catalogue and this library's own conventions over them — is a row here, and
    /// every such row is allocated there.
    /// </summary>
    /// <remarks>
    /// The registry is an independent transcription of the same catalogue, made by an earlier stage from the
    /// same normative text, so this is a cross-check rather than a restatement. It is also what settles the
    /// count: 116 METS profile requirements (three of the 119 numbers are retired or never assigned), sixteen
    /// folder requirements and eight house conventions.
    /// </remarks>
    [TestMethod]
    public void TheMatrixAndTheCommonSpecificationRegistryStateTheSameRequirementInventory()
    {
        AssertRegistryAndMatrixAgree(typeof(EArkClaimIds), 140);
    }


    /// <summary>
    /// The matrix and the shipped preservation-metadata claim-identifier registry state the same requirement
    /// inventory, in both directions, over BOTH of that specification's identifier schemes: the 125 table rows
    /// and the fourteen narrative mnemonics.
    /// </summary>
    [TestMethod]
    public void TheMatrixAndThePreservationMetadataRegistryStateTheSameRequirementInventory()
    {
        AssertRegistryAndMatrixAgree(typeof(PremisClaimIds), 139);
    }


    /// <summary>
    /// The matrix and the shipped archival-package claim-identifier registry state the same requirement
    /// inventory, in both directions, over all three of that specification's identifier spaces: the
    /// seventeen prose requirements it does assign, the seven METS profile requirements, and the four
    /// obligations its prose states with no identifier of its own.
    /// </summary>
    [TestMethod]
    public void TheMatrixAndTheArchivalPackageRegistryStateTheSameRequirementInventory()
    {
        AssertRegistryAndMatrixAgree(typeof(AipClaimIds), 28);
    }


    /// <summary>
    /// The three METS profile numbers the Common Specification retired or never assigned are recorded as one
    /// row saying so, and none of them appears as a requirement row. A matrix that simply skipped them would
    /// read as an incomplete transcription rather than as a faithful one.
    /// </summary>
    [TestMethod]
    public void TheRetiredMetsProfileNumbersAreRecordedRatherThanSilentlyMissing()
    {
        HashSet<string> rows = [.. RowData.Select(row => row.ClauseId)];

        Assert.DoesNotContain("CSIP86", rows);
        Assert.DoesNotContain("CSIP87", rows);
        Assert.DoesNotContain("CSIP115", rows);

        RequirementMatrixRow retired = RowFor("csip-retired-numbers");
        Assert.AreEqual(RequirementCoverageStatus.OutOfScope, retired.Status);
        Assert.Contains("CSIP86", retired.Requirement, StringComparison.Ordinal);
        Assert.Contains("CSIP87", retired.Requirement, StringComparison.Ordinal);
        Assert.Contains("CSIP115", retired.Requirement, StringComparison.Ordinal);
    }


    /// <summary>
    /// The eleven numbers the archival package's prose counts to but never assigns are recorded as one row
    /// naming all of them, and none of them appears as a requirement row.
    /// </summary>
    [TestMethod]
    public void TheUnassignedArchivalProseNumbersAreRecordedRatherThanSilentlyMissing()
    {
        HashSet<string> rows = [.. RowData.Select(row => row.ClauseId)];
        foreach(int unassigned in UnassignedArchivalProseNumbers)
        {
            Assert.DoesNotContain($"AIP{unassigned}", rows, $"AIP{unassigned} is a number the specification never assigns.");
        }

        RequirementMatrixRow gap = RowFor("aip-prose-identifier-gaps");
        Assert.AreEqual(RequirementCoverageStatus.OutOfScope, gap.Status);
        Assert.Contains("eleven", gap.Requirement, StringComparison.Ordinal);
        Assert.Contains("AIP4", gap.Requirement, StringComparison.Ordinal);
    }


    /// <summary>
    /// The two rows whose keyword the preservation-metadata tables state as <c>COULD</c> — a word the
    /// requirement-keyword vocabulary those tables otherwise use does not define — carry that word verbatim
    /// and cite the test that drives the interpretation this library applies to it.
    /// </summary>
    [TestMethod]
    public void TheTwoUndefinedKeywordRowsCarryTheirDocumentedInterpretation()
    {
        foreach(string identifier in UndefinedKeywordRowIdentifiers)
        {
            RequirementMatrixRow row = RowFor(identifier);
            Assert.AreEqual(RequirementCoverageStatus.Tested, row.Status);
            Assert.Contains("COULD", row.Requirement, StringComparison.Ordinal);
            Assert.Contains("TheTwoUndefinedKeywordRowsReachTheirOutcomeAsAStatedInterpretation", row.Evidence, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// The archival package's preservation layer — the part the wave contract rules in — is driven by tests
    /// rather than recognised: the provenance references its metadata hangs from, the events and agents that
    /// record what was done to the package, and the parent-chain obligation the prose states with no
    /// identifier of its own.
    /// </summary>
    [TestMethod]
    public void TheArchivalPreservationLayerIsTestedRatherThanRecognised()
    {
        foreach(string identifier in ArchivalPreservationLayerIdentifiers)
        {
            RequirementMatrixRow row = RowFor(identifier);
            Assert.AreEqual(RequirementCoverageStatus.Tested, row.Status, $"{identifier} is in this wave's archival scope and must be driven by a test.");
        }
    }


    /// <summary>
    /// Every requirement of the two package types the wave contract defers is present as a recognition row,
    /// out of scope, with the contract's own reason stated first — so a consuming graph can tell a
    /// deliberately deferred requirement from a forgotten one.
    /// </summary>
    [TestMethod]
    public void TheDeferredPackageTypesAreRecognisedRatherThanOmitted()
    {
        List<RequirementMatrixRow> deferred = [.. RowData
            .Where(row => IsSubmissionOrDisseminationRow(row.ClauseId))
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];

        Assert.IsGreaterThan(38, deferred.Count, "The submission catalogue alone states thirty-five requirements and the dissemination catalogue four.");
        foreach(RequirementMatrixRow row in deferred)
        {
            Assert.AreEqual(RequirementCoverageStatus.OutOfScope, row.Status, $"{row.ClauseId} belongs to a deferred package type.");
            Assert.StartsWith(OutOfWave, row.Evidence, StringComparison.Ordinal);
        }

        HashSet<string> identifiers = [.. deferred.Select(row => row.ClauseId)];
        for(int i = 1; i <= 35; ++i)
        {
            Assert.Contains($"SIP{i}", identifiers, $"SIP{i} has no recognition row.");
        }

        for(int i = 1; i <= 4; ++i)
        {
            Assert.Contains($"DIP{i}", identifiers, $"DIP{i} has no recognition row.");
        }
    }


    /// <summary>
    /// The service-operational tag is used in both of the two ways it admits — a row naming the primitive the
    /// library ships toward the obligation, and a row stating that the library ships none — so neither branch
    /// of <see cref="RequirementMatrixTest"/> can quietly stop being exercised.
    /// </summary>
    [TestMethod]
    public void TheServiceOperationalRowsEitherNameAPrimitiveOrStateThereIsNone()
    {
        List<RequirementMatrixRow> operational = [.. RowData
            .Where(row => row.Status == RequirementCoverageStatus.ServiceOperational)
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];

        List<RequirementMatrixRow> withoutAPrimitive = [.. operational.Where(row => row.Evidence.StartsWith(NoEnablingPrimitive, StringComparison.Ordinal))];
        List<RequirementMatrixRow> withAPrimitive = [.. operational.Except(withoutAPrimitive)];

        Assert.IsNotEmpty(withoutAPrimitive, "No service-operational row states that the library ships nothing toward it.");
        Assert.IsNotEmpty(withAPrimitive, "No service-operational row names an enabling primitive.");

        foreach(RequirementMatrixRow row in withAPrimitive)
        {
            AssertEvidenceNamesAShippedTestMethod(row);
        }
    }


    /// <summary>
    /// Every row of the two numbered catalogues opens with the requirement keyword its own source table gives
    /// it, so a reader — or a consuming graph — never has to guess how hard a requirement is. The two
    /// preservation-metadata rows whose table cell carries a cardinality and no keyword at all open with the
    /// marker naming that fact rather than with a keyword this library chose for them.
    /// </summary>
    [TestMethod]
    public void EveryCatalogueRowStatesTheKeywordItsSourceTableGivesIt()
    {
        List<string> unkeyworded = [.. RowData
            .Where(row => IsMetsProfileIdentifier(row.ClauseId) || IsFolderIdentifier(row.ClauseId) || IsPreservationTableIdentifier(row.ClauseId))
            .Where(row => !RequirementKeywords.Any(keyword => row.Requirement.StartsWith(keyword, StringComparison.Ordinal)))
            .Select(row => row.ClauseId)];

        Assert.IsEmpty(unkeyworded, $"These catalogue rows do not open with their source table's keyword: {string.Join(", ", unkeyworded)}.");
    }


    /// <summary>
    /// The Common Specification's Part I states twenty-one principles, each with a requirement keyword of its
    /// own, and the matrix carries a row for every one of them.
    /// </summary>
    /// <remarks>
    /// The preflight leg's own heading for this clause counts nineteen while its table enumerates twenty-one
    /// — the same navigation-aid-versus-enumeration discrepancy an earlier stage found in the preservation
    /// legs. The enumeration is the source of truth, and this test pins it so a later edit cannot thin the
    /// principle rows back toward the smaller figure.
    /// </remarks>
    [TestMethod]
    public void ThePrincipleRowsAreTheOnesThePartOneClauseEnumerates()
    {
        List<string> principles = [.. RowData
            .Select(row => row.ClauseId)
            .Where(clauseId => clauseId.StartsWith("csip-principle-", StringComparison.Ordinal))];

        Assert.HasCount(21, principles, "Part I enumerates twenty-one principles, whatever the preflight leg's heading counts.");
    }


    /// <summary>
    /// The archival-reference-model term-consistency findings are rows rather than prose, each stating what
    /// the document says and what the reference model defines.
    /// </summary>
    [TestMethod]
    public void TheArchivalVocabularyFindingsAreRecordedAsRows()
    {
        foreach(string identifier in TermConsistencyRowIdentifiers)
        {
            RequirementMatrixRow row = RowFor(identifier);
            Assert.AreEqual(RequirementCoverageStatus.OutOfScope, row.Status, $"{identifier} records a reading of a source document, which no test of this library can drive.");
            Assert.Contains("clause 1.4", row.Evidence, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// Asserts that one claim-identifier registry and this matrix state the same requirement inventory in both
    /// directions, and that the registry allocates the number of identifiers the source catalogues carry.
    /// </summary>
    /// <param name="registry">The registry class whose public static <see cref="ClaimId"/> getters are read.</param>
    /// <param name="expectedCount">The number of identifiers the registry is expected to allocate.</param>
    private static void AssertRegistryAndMatrixAgree(Type registry, int expectedCount)
    {
        HashSet<string> allocated = [.. DescriptionsOf(registry)];
        HashSet<string> rows = [.. RowData.Select(row => row.ClauseId)];

        Assert.HasCount(expectedCount, allocated, $"{registry.Name} allocates the identifiers its source catalogues enumerate.");

        List<string> missingFromTheMatrix = [.. allocated.Except(rows, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        Assert.IsEmpty(missingFromTheMatrix, $"These allocated requirements have no row: {string.Join(", ", missingFromTheMatrix)}.");

        List<string> missingFromTheRegistry = [.. rows
            .Where(clauseId => BelongsToRegistry(registry, clauseId))
            .Except(allocated, StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        Assert.IsEmpty(missingFromTheRegistry, $"These rows name a requirement {registry.Name} does not allocate: {string.Join(", ", missingFromTheRegistry)}.");
    }


    /// <summary>
    /// Resolves the <c>ClassName.MethodName</c> token a row's evidence leads with against the compiled test
    /// assembly and asserts that it names a real <c>[TestMethod]</c>.
    /// </summary>
    /// <param name="row">The row whose evidence is being resolved.</param>
    private static void AssertEvidenceNamesAShippedTestMethod(RequirementMatrixRow row)
    {
        string token = row.Evidence.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries)[0];
        int separatorIndex = token.LastIndexOf('.');
        Assert.IsGreaterThan(0, separatorIndex, $"{row.ClauseId}: evidence '{row.Evidence}' must lead with a Class.Method pair.");

        string className = token[..separatorIndex];
        string methodName = token[(separatorIndex + 1)..];
        Type? evidenceType = typeof(EArkRequirementsMatrixTests).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        Assert.IsNotNull(evidenceType, $"{row.ClauseId}: evidence class '{className}' does not exist in the test assembly.");

        MethodInfo? evidenceMethod = evidenceType!.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
        Assert.IsNotNull(evidenceMethod, $"{row.ClauseId}: evidence method '{className}.{methodName}' does not exist.");
        Assert.IsNotEmpty(evidenceMethod!.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false),
            $"{row.ClauseId}: evidence '{className}.{methodName}' is not a [TestMethod] — the matrix must cite a real test.");
    }


    /// <summary>Finds the one row carrying a requirement identifier, failing when the matrix does not state it.</summary>
    /// <param name="clauseId">The requirement identifier to find.</param>
    /// <returns>The row.</returns>
    private static RequirementMatrixRow RowFor(string clauseId)
    {
        (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence) found =
            RowData.SingleOrDefault(row => string.Equals(row.ClauseId, clauseId, StringComparison.Ordinal));

        Assert.IsNotNull(found.ClauseId, $"The matrix states no row {clauseId}.");
        return new RequirementMatrixRow(found.ClauseId, found.Requirement, found.Status, found.Evidence);
    }


    /// <summary>Determines whether a row belongs to the Common Specification: its two catalogues, its un-identified clauses, or the reference-model finding recorded against it.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when the row comes from that document.</returns>
    private static bool IsCommonSpecificationRow(string clauseId) =>
        IsFolderIdentifier(clauseId) || IsMetsProfileIdentifier(clauseId) || clauseId.StartsWith("csip-", StringComparison.Ordinal);


    /// <summary>Determines whether a row belongs to the preservation-metadata specification, under either of its two identifier schemes or its un-identified clauses.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when the row comes from that document.</returns>
    private static bool IsPreservationMetadataRow(string clauseId) =>
        IsPreservationTableIdentifier(clauseId)
        || clauseId.StartsWith("PREMIS-", StringComparison.Ordinal)
        || clauseId.StartsWith("premis-", StringComparison.Ordinal);


    /// <summary>Determines whether a row belongs to the archival-package specification, under any of its three identifier spaces or its un-identified clauses.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when the row comes from that document.</returns>
    private static bool IsArchivalPackageRow(string clauseId) =>
        clauseId.StartsWith("AIP", StringComparison.Ordinal) || clauseId.StartsWith("aip-", StringComparison.Ordinal);


    /// <summary>Determines whether a row belongs to one of the two package types the wave contract defers.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when the row comes from the submission or the dissemination specification.</returns>
    private static bool IsSubmissionOrDisseminationRow(string clauseId) =>
        clauseId.StartsWith("SIP", StringComparison.Ordinal)
        || clauseId.StartsWith("sip-", StringComparison.Ordinal)
        || clauseId.StartsWith("DIP", StringComparison.Ordinal)
        || clauseId.StartsWith("dip-", StringComparison.Ordinal);


    /// <summary>Determines whether a row states one of this library's own conventions over the source documents rather than a requirement of one of them.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when the row is a house convention.</returns>
    private static bool IsHouseConventionRow(string clauseId) =>
        clauseId.StartsWith("EArk", StringComparison.Ordinal);


    /// <summary>Determines whether an identifier is one of the Common Specification's folder catalogue.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when it is a <c>CSIPSTRn</c>.</returns>
    private static bool IsFolderIdentifier(string clauseId) =>
        clauseId.StartsWith("CSIPSTR", StringComparison.Ordinal);


    /// <summary>Determines whether an identifier is one of the Common Specification's METS profile catalogue.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when it is a <c>CSIPn</c> rather than a <c>CSIPSTRn</c>.</returns>
    private static bool IsMetsProfileIdentifier(string clauseId) =>
        clauseId.StartsWith("CSIP", StringComparison.Ordinal)
        && !IsFolderIdentifier(clauseId)
        && char.IsAsciiDigit(clauseId["CSIP".Length]);


    /// <summary>Determines whether an identifier is one of the preservation-metadata tables.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when it is a <c>PMn</c>.</returns>
    private static bool IsPreservationTableIdentifier(string clauseId) =>
        clauseId.StartsWith("PM", StringComparison.Ordinal) && char.IsAsciiDigit(clauseId["PM".Length]);


    /// <summary>Determines whether a row identifier is one the given registry could plausibly allocate, so that a one-directional gap is reported against the registry that owns the identifier space.</summary>
    /// <param name="registry">The registry being cross-checked.</param>
    /// <param name="clauseId">The row identifier.</param>
    /// <returns><see langword="true"/> when the identifier belongs to that registry's own space.</returns>
    private static bool BelongsToRegistry(Type registry, string clauseId) =>
        registry == typeof(EArkClaimIds) ? IsFolderIdentifier(clauseId) || IsMetsProfileIdentifier(clauseId) || IsHouseConventionRow(clauseId)
        : registry == typeof(PremisClaimIds) ? IsPreservationTableIdentifier(clauseId) || clauseId.StartsWith("PREMIS-", StringComparison.Ordinal)
        : registry == typeof(AipClaimIds) && clauseId.StartsWith("AIP", StringComparison.Ordinal);


    /// <summary>Reads the descriptions of every claim identifier a registry class allocates.</summary>
    /// <param name="registry">The registry class to read.</param>
    /// <returns>The descriptions, which are the source specifications' own identifier strings.</returns>
    private static List<string> DescriptionsOf(Type registry)
    {
        List<string> descriptions = [];
        foreach(PropertyInfo property in registry.GetProperties(BindingFlags.Public | BindingFlags.Static))
        {
            if(property.PropertyType == typeof(ClaimId))
            {
                var claimId = (ClaimId)property.GetValue(null)!;
                descriptions.Add(claimId.ToString());
            }
        }

        return descriptions;
    }


    /// <summary>The requirement keywords a catalogue row's digest may open with, including the marker for the two rows whose table cell states a cardinality and no keyword.</summary>
    private static string[] RequirementKeywords { get; } = ["MUST", "SHOULD", "MAY", "COULD", "CARDINALITY-ONLY"];


    /// <summary>The eleven numbers the archival package's prose counts to but never assigns.</summary>
    private static int[] UnassignedArchivalProseNumbers { get; } = [4, 5, 6, 9, 10, 14, 19, 23, 24, 25, 26];


    /// <summary>The two preservation-metadata rows whose stated keyword is not one the requirement-keyword vocabulary defines.</summary>
    private static string[] UndefinedKeywordRowIdentifiers { get; } = ["PM53", "PM66"];


    /// <summary>The archival-package requirements the wave contract rules in — the preservation layer and the METS shell that carries it.</summary>
    private static string[] ArchivalPreservationLayerIdentifiers { get; } =
    [
        "AIPM5", "AIPM6", "AIPM7",
        "AIP12", "AIP13", "AIP15", "AIP16", "AIP17", "AIP18",
        "AIP-PARENT-CHAIN-LISTED"
    ];


    /// <summary>The rows recording the archival-reference-model term-consistency findings.</summary>
    private static string[] TermConsistencyRowIdentifiers { get; } =
    [
        "csip-oais-1.4-4-package", "aip-oais-1.4-4-version", "premis-oais-1.4-1-pdi"
    ];


    /// <summary>The test driving the METS profile's root-element rows.</summary>
    private const string MetsRootEvidence = "EArkMetadataRuleTests.TheRootElementRowsReadTheAttributesTheyConstrain";

    /// <summary>The test driving a conformant manifest through every METS profile row at once.</summary>
    private const string MetsConformantEvidence = "EArkMetadataRuleTests.AConformantManifestFailsNoMetsProfileRequirement";

    /// <summary>The test driving the package-header rows.</summary>
    private const string MetsHeaderEvidence = "EArkMetadataRuleTests.AManifestWithoutTheCreatorStampFailsTheFiveRowsThatFixIt";

    /// <summary>The test driving the descriptive-metadata rows.</summary>
    private const string DescriptiveMetadataEvidence = "EArkMetadataRuleTests.AManifestWithoutDescriptiveMetadataDeviatesOnceRatherThanFailingThirteenTimes";

    /// <summary>The test driving the file-section rows.</summary>
    private const string FileSectionEvidence = "EArkMetadataRuleTests.AFileSectionMissingOneMandatoryGroupFailsThatGroupsRowAlone";

    /// <summary>
    /// The test driving both disjuncts of the file group's content-information-type condition, which the
    /// conformant fixture cannot exercise because it states the package-level value as mixed.
    /// </summary>
    private const string ContentInformationTypeDisjunctionEvidence =
        "EArkMetadataRuleTests.TheContentInformationTypeRowBindsOnARepresentationGroupOfAPackageThatIsNotMixed";

    /// <summary>The test driving the structural-map rows.</summary>
    private const string StructuralMapEvidence = "EArkMetadataRuleTests.WithoutTheMandatedStructuralMapTheFindingIsReportedOnceRatherThanThirtyThreeTimes";

    /// <summary>The test driving the representation-pointer rows of the structural map.</summary>
    private const string RepresentationPointerEvidence = "EArkMetadataRuleTests.ARepresentationDivisionWithoutItsPointerFailsThePointerRows";

    /// <summary>The test driving the digital-provenance reference rows.</summary>
    private const string ProvenanceReferenceEvidence = "EArkArchivalAndFixityRuleTests.AConformantProvenanceReferenceSatisfiesTheThreeArchivalRows";

    /// <summary>The test driving a stated checksum against a recomputation over the package's own octets.</summary>
    private const string FixityRecomputationEvidence = "EArkArchivalAndFixityRuleTests.AStatedChecksumThatDoesNotMatchTheOctetsFailsTheRecomputation";

    /// <summary>The test driving the whole preservation-metadata catalogue over a conformant document.</summary>
    private const string PreservationMetadataEvidence = "EArkMetadataRuleTests.AConformantPreservationMetadataDocumentFailsNothing";

    /// <summary>The test proving the manifest binding requires every particle the profile makes mandatory.</summary>
    private const string MetsShapeEvidence = "MetsXmlBindingTests.EveryParticleTheProfileMakesMandatoryIsRequiredByTheParseToo";

    /// <summary>The test proving the preservation-metadata binding requires every particle the catalogue makes mandatory.</summary>
    private const string PreservationShapeEvidence = "PremisXmlBindingTests.EveryParticleTheCatalogueMakesMandatoryIsRequiredByTheParseToo";

    /// <summary>The test driving a conformant package through every folder row at once.</summary>
    private const string FolderStructureEvidence = "EArkStructuralRuleTests.AConformantPackageSatisfiesEveryFolderRequirement";


    /// <summary>
    /// Every folder requirement of
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0
    /// clause 4.1</see>, <c>CSIPSTR1</c>…<c>CSIPSTR16</c>, in the catalogue's own order.
    /// </summary>
    /// <remarks>
    /// Every one of these rules except <c>CSIPSTR1</c> and <c>CSIPSTR4</c> is a SHOULD or a MAY, so the
    /// minimal conformant package is a root folder holding nothing but its manifest — which is why the
    /// evidence for most rows is a package that declines the recommendation rather than one that breaks a
    /// rule.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] CsipFolderRows { get; } =
    [
        ("CSIPSTR1", "MUST — any information package is included within a single physical root folder, and an archived package unpacks to exactly one.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.AnArchivedPackageUnderItsOwnIdentifierSatisfiesTheRootFolderRows (the archived form; EArkPackageSnapshotTests.AnArchiveWithoutOneRootFolderSaysSoAndKeepsItsNames is the reader stating the fact rather than repairing it)"),
        ("CSIPSTR2", "SHOULD — the root folder is named with the package's own identifier.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.AnArchivedPackageUnderSomeOtherNameDeviatesFromTheNamingRecommendation (and EArkStructuralRuleTests.APackageIdentifierThatIsAUniformResourceNameCannotNameAnArchiveRootFolder, the finding that a uniform-resource-name identifier cannot satisfy this recommendation and the entry-name rules at once)"),
        ("CSIPSTR3", "MAY — the package may be archived or compressed for storage and transfer; the format is decided by the interested parties.",
            RequirementCoverageStatus.ServiceOperational, "EArkPackageSnapshotTests.AReferencePackageReadFromAFolderAndFromAnArchiveIsTheSameSnapshot (both arrival forms read to the same package; which archive format a submission agreement fixes is the parties' own decision)"),
        ("CSIPSTR4", "MUST — the root folder holds a file named METS.xml identifying the package and pointing at its representations.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.APackageWithoutItsRootManifestFailsTheOnlyFolderMustItCan (and EArkPackageClassificationTests.AFileWhoseNameIsNotExactlyTheManifestsIsNotTheManifest for the ordinal name reading a case-folding reader would get wrong)"),
        ("CSIPSTR5", "SHOULD — the root folder holds a metadata folder for whole-package metadata.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence + " (and EArkStructuralRuleTests.TheMinimalPackageFailsNothing, the package that declines it)"),
        ("CSIPSTR6", "SHOULD — preservation metadata, where available, is placed in metadata/preservation; a conditional recommendation, so a package holding no preservation metadata never triggered it.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence + " (and EArkStructuralRuleTests.TheMetadataFolderRowsBindOnlyWhenTheMetadataExists, the three answers the condition admits)"),
        ("CSIPSTR7", "SHOULD — descriptive metadata, where available, is placed in metadata/descriptive; a conditional recommendation, so a package holding no descriptive metadata never triggered it.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence + " (and EArkStructuralRuleTests.TheMetadataFolderRowsBindOnlyWhenTheMetadataExists, the three answers the condition admits)"),
        ("CSIPSTR8", "MAY — other metadata may be placed in further sub-folders of metadata.",
            RequirementCoverageStatus.Tested, "EArkPackageClassificationTests.AMetadataSubFolderTheSpecificationDoesNotNameIsStillMetadata (the permission exercised) beside " + FolderStructureEvidence),
        ("CSIPSTR9", "SHOULD — the package folder holds a representations folder.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence),
        ("CSIPSTR10", "SHOULD — representations holds one sub-folder per representation, uniquely named within the package.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.AFileDirectlyUnderTheRepresentationsFolderDeviatesFromTheOneSubFolderRule"),
        ("CSIPSTR11", "SHOULD — each representation folder holds a data sub-folder, which may hold the representation's data.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.ASecondRepresentationMissingItsRecommendedFoldersIsReportedByItself"),
        ("CSIPSTR12", "SHOULD — each representation folder holds its own METS.xml, which the companion text calls the recommended best practice to always follow.",
            RequirementCoverageStatus.Tested, "EArkCorpusValidationTests.TheReferenceFullerPackageSatisfiesTheRecommendationsTheMinimalOneDeclines (the reference material's own fuller package declines this row, which is a fact about the material rather than about the rule)"),
        ("CSIPSTR13", "SHOULD — each representation folder holds its own metadata sub-folder.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.ASecondRepresentationMissingItsRecommendedFoldersIsReportedByItself"),
        ("CSIPSTR14", "MAY — the package may be extended with additional sub-folders.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.AFolderTheCatalogueNamesNoPositionForExercisesTheExtensionPermission"),
        ("CSIPSTR15", "SHOULD — schema documents are placed in a schemas sub-folder, at package level, representation level or both.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence),
        ("CSIPSTR16", "SHOULD — supplementary documentation is placed in a documentation sub-folder, at package level, representation level or both.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence),
    ];


    /// <summary>
    /// Every requirement of the Common Specification's machine-readable METS profile catalogue,
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>
    /// <c>CSIP1</c>…<c>CSIP119</c>, grouped by the structural element the profile itself groups them under.
    /// </summary>
    /// <remarks>
    /// The digest of each row carries the profile's own requirement level, its cardinality and its METS path,
    /// which together are what a validator has to read; the profile's longer prose description is not
    /// reproduced. Three of the 119 numbers carry no requirement — two were deprecated and one was never
    /// allocated — and are recorded at their own row rather than as gaps.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] CsipMetsProfileRows { get; } =
    [
        ("CSIP1", "MUST 1..1 mets/@OBJID — Package Identifier: the package's own identifier, which the base schema leaves optional and this profile hardens.",
            RequirementCoverageStatus.Tested, MetsRootEvidence),
        ("CSIP2", "MUST 1..1 mets/@TYPE — Content Category, from the profile's own vocabulary.",
            RequirementCoverageStatus.Tested, MetsRootEvidence),
        ("CSIP3", "SHOULD 0..1 mets[@TYPE='OTHER']/@csip:OTHERTYPE — Other Content Category, spelled out when the category is OTHER; the row's own sentence words the consequent as a MUST and the catalogue rates the row SHOULD, and the rated level is what the claim is issued at.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.AnUnspelledOtherContentCategoryDepartsFromItsOwnRow"),
        ("CSIP4", "SHOULD 0..1 mets/@csip:CONTENTINFORMATIONTYPE — Content Information Type Specification, mandatory for a representation-level manifest.",
            RequirementCoverageStatus.Tested, MetsRootEvidence),
        ("CSIP5", "MAY 0..1 mets[@csip:CONTENTINFORMATIONTYPE='OTHER']/@csip:OTHERCONTENTINFORMATIONTYPE — Other Content Information Type Specification; rated MAY, so an unstated value is a permission left untaken rather than a violation.",
            RequirementCoverageStatus.Tested, MetsRootEvidence + " beside EArkMetadataRuleTests.AnUnspelledOtherContentInformationTypeStatesAPermissionItDidNotTake"),
        ("CSIP6", "MUST 1..1 mets/@PROFILE — the METS profile this manifest claims conformance to.",
            RequirementCoverageStatus.Tested, MetsRootEvidence),

        ("CSIP117", "MUST 1..1 mets/metsHdr — Package header.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP7", "MUST 1..1 mets/metsHdr/@CREATEDATE — Package creation datetime, a schema datetime carrying a time as well as a date.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence + " (and MetsXmlBindingTests.AnInstantStatingNoZoneIsReadAsThoughItStatedZulu for the datetime reading)"),
        ("CSIP8", "SHOULD 0..1 mets/metsHdr/@LASTMODDATE — Package last modification datetime.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP9", "MUST 1..1 mets/metsHdr/@csip:OAISPACKAGETYPE — the package type, from the profile's own vocabulary.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP10", "MUST 1..n mets/metsHdr/agent — Agent: the package carries at least one.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP11", "MUST 1..1 mets/metsHdr/agent[@ROLE='CREATOR'] — Agent role, a fixed value.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP12", "MUST 1..1 mets/metsHdr/agent[@TYPE='OTHER'] — Agent type, a fixed value.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP13", "MUST 1..1 mets/metsHdr/agent[@OTHERTYPE='SOFTWARE'] — Agent other type, a fixed value.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP14", "MUST 1..1 mets/metsHdr/agent/name — the creating tool's name.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP15", "MUST 1..1 mets/metsHdr/agent/note — the creating tool's additional information.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),
        ("CSIP16", "MUST 1..1 mets/metsHdr/agent/note[@csip:NOTETYPE='SOFTWARE VERSION'] — the note's classification, a fixed value.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence),

        ("CSIP17", "SHOULD 0..n mets/dmdSec — Descriptive metadata section.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP18", "MUST 1..1 mets/dmdSec/@ID — Descriptive metadata identifier, itself bound by the name production of clause 5.1.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.ABareUniversallyUniqueIdentifierIsNotALegalSectionIdentifier"),
        ("CSIP19", "MUST 1..1 mets/dmdSec/@CREATED — Descriptive metadata creation datetime.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP20", "SHOULD 0..1 mets/dmdSec/@STATUS — Status of the descriptive metadata.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP21", "SHOULD 0..1 mets/dmdSec/mdRef — Reference to the descriptive metadata document.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP22", "MUST 1..1 mets/dmdSec/mdRef[@LOCTYPE='URL'] — Type of locator, a fixed value.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP23", "MUST 1..1 mets/dmdSec/mdRef[@xlink:type='simple'] — Type of link, a fixed value.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP24", "MUST 1..1 mets/dmdSec/mdRef/@xlink:href — Resource location of the referenced document.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence + " (and EArkArchivalAndFixityRuleTests.AReferenceToAFileThePackageDoesNotHoldFailsTheReferenceRule for the resolution of the location)"),
        ("CSIP25", "MUST 1..1 mets/dmdSec/mdRef/@MDTYPE — Type of metadata.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP26", "MUST 1..1 mets/dmdSec/mdRef/@MIMETYPE — the referenced file's media type.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP27", "MUST 1..1 mets/dmdSec/mdRef/@SIZE — the referenced file's size.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP28", "MUST 1..1 mets/dmdSec/mdRef/@CREATED — the referenced file's creation datetime.",
            RequirementCoverageStatus.Tested, DescriptiveMetadataEvidence),
        ("CSIP29", "MUST 1..1 mets/dmdSec/mdRef/@CHECKSUM — the referenced file's checksum.",
            RequirementCoverageStatus.Tested, FixityRecomputationEvidence + " (the checksum is recomputed through the registered digest seam rather than read)"),
        ("CSIP30", "MUST 1..1 mets/dmdSec/mdRef/@CHECKSUMTYPE — the checksum's algorithm, from the base schema's own eleven-value vocabulary.",
            RequirementCoverageStatus.Tested, "EArkFixityTests.EveryAlgorithmTheEnumerationAdmitsIsClassified (the whole vocabulary classified, including the values this library cannot recompute)"),

        ("CSIP31", "SHOULD 0..1 mets/amdSec — Administrative metadata section.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP32", "SHOULD 0..n mets/amdSec/digiprovMD — Digital provenance metadata, the section a preservation-metadata document moors to.",
            RequirementCoverageStatus.Tested, "EArkCorpusValidationTests.TheReferencePackageWithPreservationMetadataMoorsItToItsManifest"),
        ("CSIP33", "MUST 1..1 mets/amdSec/digiprovMD/@ID — Digital provenance metadata identifier.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP34", "SHOULD 0..1 mets/amdSec/digiprovMD/@STATUS — Status of the digital provenance metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP35", "SHOULD 0..1 mets/amdSec/digiprovMD/mdRef — Reference to the digital provenance metadata document.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AManifestWithoutProvenanceMetadataFailsTheMandatoryPointerRow"),
        ("CSIP36", "MUST 1..1 mets/amdSec/digiprovMD/mdRef[@LOCTYPE='URL'] — Type of locator, a fixed value.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP37", "MUST 1..1 mets/amdSec/digiprovMD/mdRef[@xlink:type='simple'] — Type of link, a fixed value.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP38", "MUST 1..1 mets/amdSec/digiprovMD/mdRef/@xlink:href — Resource location of the provenance document.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP39", "MUST 1..1 mets/amdSec/digiprovMD/mdRef/@MDTYPE — Type of metadata, which the preservation-metadata specification fixes for its own documents.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AProvenanceReferenceOfAnotherVocabularyDeviatesWithoutFailing"),
        ("CSIP40", "MUST 1..1 mets/amdSec/digiprovMD/mdRef/@MIMETYPE — the referenced file's media type.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP41", "MUST 1..1 mets/amdSec/digiprovMD/mdRef/@SIZE — the referenced file's size.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP42", "MUST 1..1 mets/amdSec/digiprovMD/mdRef/@CREATED — the referenced file's creation datetime.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence),
        ("CSIP43", "MUST 1..1 mets/amdSec/digiprovMD/mdRef/@CHECKSUM — the referenced file's checksum.",
            RequirementCoverageStatus.Tested, FixityRecomputationEvidence),
        ("CSIP44", "MUST 1..1 mets/amdSec/digiprovMD/mdRef/@CHECKSUMTYPE — the checksum's algorithm.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AWeakFixityAlgorithmIsFlaggedByDefaultAndFailsOnlyWhenTheCallerRaisesTheFloor"),
        ("CSIP45", "MAY 0..n mets/amdSec/rightsMD — Rights metadata section.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP46", "MUST 1..1 mets/amdSec/rightsMD/@ID — Rights metadata identifier.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP47", "SHOULD 0..1 mets/amdSec/rightsMD/@STATUS — Status of the rights metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP48", "SHOULD 0..1 mets/amdSec/rightsMD/mdRef — Reference to the rights metadata document.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP49", "MUST 1..1 mets/amdSec/rightsMD/mdRef[@LOCTYPE='URL'] — Type of locator, a fixed value.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP50", "MUST 1..1 mets/amdSec/rightsMD/mdRef[@xlink:type='simple'] — Type of link, a fixed value.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP51", "MUST 1..1 mets/amdSec/rightsMD/mdRef/@xlink:href — Resource location of the rights document.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP52", "MUST 1..1 mets/amdSec/rightsMD/mdRef/@MDTYPE — Type of metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP53", "MUST 1..1 mets/amdSec/rightsMD/mdRef/@MIMETYPE — the referenced file's media type.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP54", "MUST 1..1 mets/amdSec/rightsMD/mdRef/@SIZE — the referenced file's size.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP55", "MUST 1..1 mets/amdSec/rightsMD/mdRef/@CREATED — the referenced file's creation datetime.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP56", "MUST 1..1 mets/amdSec/rightsMD/mdRef/@CHECKSUM — the referenced file's checksum.",
            RequirementCoverageStatus.Tested, FixityRecomputationEvidence),
        ("CSIP57", "MUST 1..1 mets/amdSec/rightsMD/mdRef/@CHECKSUMTYPE — the checksum's algorithm.",
            RequirementCoverageStatus.Tested, "EArkFixityTests.AFixityStatedUnderASupportedAlgorithmReachesTheRecomputableCase"),

        ("CSIP58", "SHOULD 0..1 mets/fileSec — File section: the package's own fixity manifest.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP59", "MUST 1..1 mets/fileSec/@ID — File section identifier.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP60", "MUST 1..n mets/fileSec/fileGrp[@USE='Documentation'] — the documentation file group.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP113", "MUST 1..n mets/fileSec/fileGrp[@USE='Schemas'] — the schema file group.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP114", "MUST 1..n mets/fileSec/fileGrp[@USE starting with 'Representations'] — the representations file group, whose use value the profile matches by prefix rather than by equality.",
            RequirementCoverageStatus.Tested, "EArkMetadataVocabularyTests.TheFileGroupAndDivisionLabelVocabularyReadsThePerRepresentationForm"),
        ("CSIP61", "MAY 0..1 mets/fileSec/fileGrp/@ADMID — the file group's reference to administrative metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP62", "SHOULD 0..1 mets/@csip:CONTENTINFORMATIONTYPE='MIXED' | mets/fileSec/fileGrp[@USE starting with 'Representations']/@csip:CONTENTINFORMATIONTYPE — the file group's Content Information Type Specification, bound by either disjunct of the catalogue's condition.",
            RequirementCoverageStatus.Tested, ContentInformationTypeDisjunctionEvidence),
        ("CSIP63", "MAY 0..1 mets/fileSec/fileGrp[@csip:CONTENTINFORMATIONTYPE='OTHER']/@csip:OTHERCONTENTINFORMATIONTYPE — the spelled-out other type; rated MAY, which is also the ground the corpus sweep disposes this row's non-conformant packages on.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence + " beside EArkMetadataRuleTests.AFileGroupsUnspelledOtherContentInformationTypeStatesAPermissionItDidNotTake"),
        ("CSIP64", "MUST 1..1 mets/fileSec/fileGrp/@USE — the description of the file group's use.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP65", "MUST 1..1 mets/fileSec/fileGrp/@ID — File group identifier.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP66", "MUST 1..n mets/fileSec/fileGrp/file — the file entries of a group.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP67", "MUST 1..1 mets/fileSec/fileGrp/file/@ID — File identifier.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP68", "MUST 1..1 mets/fileSec/fileGrp/file/@MIMETYPE — the file's media type.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP69", "MUST 1..1 mets/fileSec/fileGrp/file/@SIZE — the file's size.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP70", "MUST 1..1 mets/fileSec/fileGrp/file/@CREATED — the file's creation datetime.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP71", "MUST 1..1 mets/fileSec/fileGrp/file/@CHECKSUM — the file's checksum.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AStatedChecksumThatMatchesTheOctetsPassesTheRecomputation (and EArkCorpusValidationTests.TheReferencePackagesStatedFixityAgreesWithARecomputationOverItsOwnOctets over the reference material)"),
        ("CSIP72", "MUST 1..1 mets/fileSec/fileGrp/file/@CHECKSUMTYPE — the checksum's algorithm.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnUnrecomputableFixityIsUndecidedByDefaultAndFailsUnderTheStricterPolicy"),
        ("CSIP73", "MAY 0..1 mets/fileSec/fileGrp/file/@OWNERID — the file's original identification.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP74", "MAY 0..1 mets/fileSec/fileGrp/file/@ADMID — the file's reference to administrative metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP75", "MAY 0..1 mets/fileSec/fileGrp/file/@DMDID — the file's reference to descriptive metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP76", "MUST 1..1 mets/fileSec/fileGrp/file/FLocat — the file's locator element.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP77", "MUST 1..1 mets/fileSec/fileGrp/file/FLocat[@LOCTYPE='URL'] — Type of locator, a fixed value.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP78", "MUST 1..1 mets/fileSec/fileGrp/file/FLocat[@xlink:type='simple'] — Type of link, a fixed value.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("CSIP79", "MUST 1..1 mets/fileSec/fileGrp/file/FLocat/@xlink:href — Resource location of the file.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AReferenceToAFileThePackageDoesNotHoldFailsTheReferenceRule"),

        ("CSIP80", "MUST 1..n mets/structMap — the structural description of the package.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP81", "MUST 1..1 mets/structMap[@TYPE='PHYSICAL'] — the type of structural description, a fixed value.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP82", "MUST 1..1 mets/structMap[@LABEL='CSIP'] — the label marking the profile-mandated map, which the companion text says is to be treated as a unique identifier.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP83", "MUST 1..1 mets/structMap[@LABEL='CSIP']/@ID — the structural map's identifier.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP84", "MUST 1..1 mets/structMap/div — the single root division.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP85", "MUST 1..1 mets/structMap/div/@ID — the root division's identifier.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP88", "MUST 1..1 mets/structMap/div/div[@LABEL='Metadata'] — the metadata division.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP89", "MUST 1..1 mets/structMap/div/div[@LABEL='Metadata']/@ID — the metadata division's identifier.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP90", "MUST 1..1 mets/structMap/div/div[@LABEL='Metadata'] — the metadata division's label, from the profile's own vocabulary.",
            RequirementCoverageStatus.Tested, "EArkMetadataVocabularyTests.EveryControlledVocabularyRecognisesItsOwnMembersAndNothingElse"),
        ("CSIP91", "SHOULD 0..1 mets/structMap/div/div[@LABEL='Metadata']/@ADMID — the metadata division's reference to administrative metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP92", "SHOULD 0..1 mets/structMap/div/div[@LABEL='Metadata']/@DMDID — the metadata division's reference to descriptive metadata.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP93", "SHOULD 0..1 mets/structMap/div/div[@LABEL='Documentation'] — the documentation division.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP94", "MUST 1..1 mets/structMap/div/div[@LABEL='Documentation']/@ID — the documentation division's identifier.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP95", "MUST 1..1 mets/structMap/div/div[@LABEL='Documentation'] — the documentation division's label.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP96", "SHOULD 0..n mets/structMap/div/div[@LABEL='Documentation']/fptr — the documentation division's file pointers.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP116", "MUST 1..1 mets/structMap/div/div[@LABEL='Documentation']/fptr/@FILEID — the documentation pointer's file-group reference.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP97", "SHOULD 0..1 mets/structMap/div/div[@LABEL='Schemas'] — the schema division.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP98", "MUST 1..1 mets/structMap/div/div[@LABEL='Schemas']/@ID — the schema division's identifier.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP99", "MUST 1..1 mets/structMap/div/div[@LABEL='Schemas'] — the schema division's label.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP100", "SHOULD 0..n mets/structMap/div/div[@LABEL='Schemas']/fptr — the schema division's file pointers.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP118", "MUST 1..1 mets/structMap/div/div[@LABEL='Schemas']/fptr/@FILEID — the schema pointer's file-group reference.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP101", "SHOULD 0..1 mets/structMap/div/div[@LABEL='Representations'] — the content division.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP102", "MUST 1..1 mets/structMap/div/div[@LABEL='Representations']/@ID — the content division's identifier.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP103", "MUST 1..1 mets/structMap/div/div[@LABEL='Representations'] — the content division's label.",
            RequirementCoverageStatus.Tested, StructuralMapEvidence),
        ("CSIP104", "SHOULD 0..n mets/structMap/div/div[@LABEL='Representations']/fptr — the content division's file pointers.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP119", "MUST 1..1 mets/structMap/div/div[@LABEL='Representations']/fptr/@FILEID — the content pointer's file-group reference.",
            RequirementCoverageStatus.Tested, MetsConformantEvidence),
        ("CSIP105", "SHOULD 0..n mets/structMap/div/div — one division per representation.",
            RequirementCoverageStatus.Tested, "EArkCorpusValidationTests.TheReferenceMinimalPackageSatisfiesTheRequirementsAMinimalPackageCan (the reference material's own minimal package declines this recommendation, which leaves the four pointer rows below it without a subject)"),
        ("CSIP106", "MUST 1..1 mets/structMap/div/div/@ID — the representation division's identifier.",
            RequirementCoverageStatus.Tested, RepresentationPointerEvidence),
        ("CSIP107", "MUST 1..1 mets/structMap/div/div/@LABEL — the representation division's label, the representations folder name followed by the representation's own.",
            RequirementCoverageStatus.Tested, "EArkMetadataVocabularyTests.TheFileGroupAndDivisionLabelVocabularyReadsThePerRepresentationForm"),
        ("CSIP108", "MUST 1..1 mets/structMap/div/div/mptr/@xlink:title — the representation pointer's title.",
            RequirementCoverageStatus.Tested, RepresentationPointerEvidence),
        ("CSIP109", "MUST 1..1 mets/structMap/div/div/mptr — the pointer at the representation's own manifest.",
            RequirementCoverageStatus.Tested, RepresentationPointerEvidence),
        ("CSIP110", "MUST 1..1 mets/structMap/div/div/mptr/@xlink:href — the representation manifest's location.",
            RequirementCoverageStatus.Tested, RepresentationPointerEvidence),
        ("CSIP111", "MUST 1..1 mets/structMap/div/div/mptr[@xlink:type='simple'] — Type of link, a fixed value.",
            RequirementCoverageStatus.Tested, RepresentationPointerEvidence),
        ("CSIP112", "MUST 1..1 mets/structMap/div/div/mptr[@LOCTYPE='URL'] — Type of locator, a fixed value.",
            RequirementCoverageStatus.Tested, RepresentationPointerEvidence),
    ];


    /// <summary>
    /// The obligations the Common Specification states with no requirement identifier of its own: the
    /// design principles of its Part I, the cross-cutting identifier, datetime and reference rules of
    /// clause 5.1, the per-element narrative sentences its own catalogue does not capture, the numbers the
    /// catalogue retired, and the two METS sections it declines to constrain.
    /// </summary>
    /// <remarks>
    /// This is the class of obligation a citation-by-identifier audit of the document would miss entirely, and
    /// the reason the matrix carries it: roughly a tenth of the specification's normative volume has no
    /// identifier at all.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] CsipClauseRows { get; } =
    [
        ("csip-principle-1.1", "MUST / MUST NOT — any type of data and metadata can be included; no type-specific restriction is imposed.",
            RequirementCoverageStatus.OutOfScope, "Design intent about what the package format must permit rather than a shape a package can be checked against; discharged by the schema-agnostic descriptive-metadata section and the generic file group the catalogue already states."),
        ("csip-principle-1.2", "MUST NOT — the package does not restrict the means, methods or tools of exchange.",
            RequirementCoverageStatus.OutOfScope, "Design intent; the specification imposes no transport, and the archive-format freedom it does state is CSIPSTR3."),
        ("csip-principle-1.3", "MUST NOT / MUST — the format does not define a package's intellectual scope and allows any submission-to-archival-to-dissemination cardinality.",
            RequirementCoverageStatus.OutOfScope, "An operator's and a business domain's decision, not a shape."),
        ("csip-principle-1.4", "SHOULD — the package is scalable.",
            RequirementCoverageStatus.ServiceOperational, "EArkPackageSnapshotTests.EachStatedBoundRefusesThePackageThatExceedsIt (the library states and enforces the bounds a caller sets; how large a package a repository accepts is its own decision)"),
        ("csip-principle-1.5", "MUST — the package is machine-readable.",
            RequirementCoverageStatus.Tested, "MetsXmlBindingTests.ADocumentRoundTripsThroughTheModel (a manifest read to a model and written back, which is what machine-readability means operationally)"),
        ("csip-principle-1.6", "SHOULD — the package is human-readable.",
            RequirementCoverageStatus.OutOfScope, "Folder-naming and semantic guidance rather than a testable shape."),
        ("csip-principle-1.7", "MUST NOT — the package does not prescribe a specific preservation method.",
            RequirementCoverageStatus.OutOfScope, "Design intent; this wave's own evidence-placement convention is offered rather than imposed, which is the same posture."),
        ("csip-principle-2.1", "MUST — the package type is clearly indicated.",
            RequirementCoverageStatus.Tested, MetsHeaderEvidence + " (the package-type attribute is CSIP9, read on the header)"),
        ("csip-principle-2.2", "MUST — the package clearly identifies its Content Information Types.",
            RequirementCoverageStatus.Tested, MetsRootEvidence + " (the root-level attribute is CSIP4, the per-group one CSIP62)"),
        ("csip-principle-2.3", "MUST / MUST NOT — the package carries a repository-unique and persistent identifier; the mechanism is not constrained.",
            RequirementCoverageStatus.ServiceOperational, MetsRootEvidence + " (the slot is CSIP1 and the library reads it; whether the value is unique in a repository is that repository's own governance)"),
        ("csip-principle-2.4", "SHOULD / MUST NOT — the identifier is globally unique and persistent; the mechanism is not constrained.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: whether an identifier is globally unique and stays resolvable is a property of the scheme a repository chose and of its continued operation, which no single package states."),
        ("csip-principle-2.5", "MUST — all components of a package carry a unique and persistent identifier.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.ABareUniversallyUniqueIdentifierIsNotALegalSectionIdentifier (every section identifier is judged against the name production the specification points at)"),
        ("csip-principle-3.1", "MUST — data and metadata are logically separated.",
            RequirementCoverageStatus.OutOfScope, "Design intent discharged by the descriptive, administrative and file sections the catalogue already separates."),
        ("csip-principle-3.2", "SHOULD — data and metadata are physically separated.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence + " (the separation is the metadata, representations and data folders of CSIPSTR5, CSIPSTR9 and CSIPSTR11)"),
        ("csip-principle-3.3", "SHOULD — metadata types are separable from one another.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence + " (the separation is the preservation and descriptive sub-folders of CSIPSTR6 and CSIPSTR7)"),
        ("csip-principle-3.4", "MUST — the structure allows multiple representations.",
            RequirementCoverageStatus.Tested, "EArkPackageClassificationTests.EachRepresentationIsItsOwnLevelWithTheSameShape"),
        ("csip-principle-3.5", "MUST — the structure defines extension points.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.AFolderTheCatalogueNamesNoPositionForExercisesTheExtensionPermission (the extension point is CSIPSTR14)"),
        ("csip-principle-3.6", "SHOULD — the common conceptual structure is followed whatever the implementation.",
            RequirementCoverageStatus.OutOfScope, "Design intent about implementations of the specification rather than about a package."),
        ("csip-principle-4.1", "MUST — metadata conforms to a standard or is at least well formed.",
            RequirementCoverageStatus.OutOfScope, "The specification declines to constrain a referenced descriptive-metadata document's own schema; which standard a repository picks is its choice, and this library validates the manifest and the preservation metadata rather than the domain metadata."),
        ("csip-principle-4.2", "MUST — metadata allows unambiguous use, and the chosen standard is reviewed and refined for ambiguity.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: reviewing a metadata standard for ambiguity is a repository's selection process."),
        ("csip-principle-4.3", "MUST NOT — the package does not restrict the addition of supplementary metadata.",
            RequirementCoverageStatus.OutOfScope, "Design intent; the extension permissions the catalogue states are CSIPSTR8 and CSIPSTR14."),

        ("csip-5.1-ncname", "MUST — every XML identifier conforms to the name production the specification points at: it begins with a letter or an underscore and carries no other characters than letters, digits, hyphens, underscores and full stops.",
            RequirementCoverageStatus.Tested, "EArkMetadataVocabularyTests.TheIdentifierRecognitionImplementsTheProductionsClause51PointsAt (including the universally-unique-identifier trap the clause calls out) beside EArkMetadataRuleTests.ABareUniversallyUniqueIdentifierIsNotALegalSectionIdentifier"),
        ("csip-5.1-datetime", "MUST — the creation and last-modification attributes are schema datetimes and carry a time as well as a date.",
            RequirementCoverageStatus.Tested, "MetsXmlBindingTests.AValueThatIsNotOfItsDeclaredTypeIsRefusedAsMalformedRatherThanMissing (a value that is not of its declared type is a defect rather than an absence) beside MetsXmlBindingTests.AnInstantStatingNoZoneIsReadAsThoughItStatedZulu"),
        ("csip-5.1-references", "MUST — all references within a package adhere to the requirements this specification states.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AReferenceToAFileThePackageDoesNotHoldFailsTheReferenceRule"),
        ("csip-5.1-package-references", "MUST — a reference to another package uses that package's own identifier rather than a location.",
            RequirementCoverageStatus.OutOfScope, "A reference to another package resolves against a repository's holdings rather than against the one package a validator is given; the manifest binding carries the pointer verbatim (proven by MetsXmlBindingTests.ThePackageToPackagePointerCarriesWhateverTheDocumentStated) and no rule of this wave judges its target. Recorded as a gap at this stage's buildlog flag rather than claimed."),
        ("csip-5.1-reference-format", "MUST — references are formed as uniform resource identifiers or expressed as a relative path to the data files.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AReferenceToAFileThePackageDoesNotHoldFailsTheReferenceRule (the relative-path form resolved against the package's own entries)"),
        ("csip-considerations-metadata-folder", "MUST (lower case) — all descriptive metadata is placed into the package's metadata folder.",
            RequirementCoverageStatus.OutOfScope, "Deciding which files of a package ARE descriptive metadata means following every descriptive-metadata reference and classifying its target; the folder half is CSIPSTR5 and CSIPSTR7 and is checked. The content half is recorded as a gap at this stage's buildlog flag rather than claimed."),
        ("csip-considerations-not-embedded", "SHOULD NOT (lower case) — descriptive metadata is not embedded directly in the manifest but referenced from it.",
            RequirementCoverageStatus.Tested, MetsShapeEvidence + " (the shipped manifest model carries the reference form alone and has no slot for embedded metadata, so a manifest this library writes cannot embed any)"),

        ("csip-filesec-checksums-blanket", "MUST (lower case) — location and checksum values are provided for all file entries, unconditionally.",
            RequirementCoverageStatus.Tested, FixityRecomputationEvidence),
        ("csip-filesec-no-nesting", "SHOULD NOT — file groups are not nested within other file groups.",
            RequirementCoverageStatus.Tested, "MetsXmlBindingTests.ADocumentRoundTripsThroughTheModel (the shipped model carries a flat list of file groups with no slot for a nested group, so a manifest this library writes cannot nest them)"),
        ("csip-filesec-three-groups", "MUST (lower case) — package-level and representation-level manifests both carry at least the three named file groups.",
            RequirementCoverageStatus.Tested, FileSectionEvidence),
        ("csip-filesec-representation-containment", "SHOULD NOT (lower case) — a representation-level manifest does not reference files outside its own representation.",
            RequirementCoverageStatus.OutOfScope, "A containment check over a representation manifest's references; the reference-resolution rule this wave ships resolves a reference against the package's entries but does not judge which level a target belongs to. Recorded as a gap at this stage's buildlog flag rather than claimed."),
        ("csip-filesec-representation-group", "SHOULD — the package-level manifest carries a file group per representation holding a single reference to that representation's own manifest.",
            RequirementCoverageStatus.Tested, "EArkMetadataVocabularyTests.TheFileGroupAndDivisionLabelVocabularyReadsThePerRepresentationForm (the per-representation group's use value) beside " + RepresentationPointerEvidence),
        ("csip-amdsec-preservation-completeness", "SHOULD — the administrative section references all relevant metadata held in the preservation-metadata folder.",
            RequirementCoverageStatus.OutOfScope, "A folder-to-section completeness cross-check: every preservation-metadata file on disk needs a provenance reference of its own. The pointer half is AIPM5 and is checked; the completeness half is recorded as a gap at this stage's buildlog flag rather than claimed."),
        ("csip-amdsec-level-containment", "SHOULD — a package-level manifest references package-level preservation metadata only, and a representation-level manifest representation-level preservation metadata only.",
            RequirementCoverageStatus.OutOfScope, "The same containment class as the file-section rule above, over provenance references; recorded as a gap at this stage's buildlog flag rather than claimed."),
        ("csip-structmap-div-label-folder", "MUST (lower case) — every division carries a label identical to the folder name it stands for.",
            RequirementCoverageStatus.Tested, "EArkMetadataVocabularyTests.TheFileGroupAndDivisionLabelVocabularyReadsThePerRepresentationForm (the general rule beyond the four named divisions is the representation division's label, CSIP107)"),
        ("csip-mets-root-namespaces", "MUST (lower case) — the manifest's root element declares all the namespaces and schema locations the package uses.",
            RequirementCoverageStatus.Tested, "MetsXmlBindingTests.ADocumentWrittenToBreakTheParseIsRefusedWithTheStatusThatNamesIt (a document in no namespace, or in the wrong one, is refused rather than read) beside EArkMetadataVocabularyTests.TheNamespacesAndProfileIdentifiersAreCarriedAsStated"),
        ("csip-tool-validates-preservation-metadata", "MUST (lower case) — a tool claiming to validate conformant packages also validates the preservation metadata once it exists within the package.",
            RequirementCoverageStatus.ServiceOperational, PreservationMetadataEvidence + " (this library validates the preservation-metadata catalogue beside the manifest, which is the capability the claim asks of a tool; making the claim is the tool vendor's own act)"),

        ("csip-retired-numbers", "Not requirements — CSIP86 and CSIP87 were deprecated (the top-level division label having to equal the package identifier, and the per-category division rule superseded by the current division catalogue), and CSIP115 was never allocated at all.",
            RequirementCoverageStatus.OutOfScope, "Three numbers of the catalogue carry no requirement. They are recorded here so a reader can tell a faithful transcription from an incomplete one, and EArkClaimIdAllocationTests.TheThreeRetiredMetsProfileNumbersStayUnallocated asserts their codes stay free in the registry."),
        ("csip-structlink", "MAY — the structural-link section is not defined or used by this specification; further own uses may occur.",
            RequirementCoverageStatus.OutOfScope, "The specification's own scope exclusion, stated at the requirement itself."),
        ("csip-behaviorsec", "MAY — the behaviour section is not defined or used by this specification; further own uses may occur.",
            RequirementCoverageStatus.OutOfScope, "The specification's own scope exclusion, stated at the requirement itself."),
        ("csip-technical-requirements", "Not requirements — the profile's technical-requirements block states, for content files, behaviour files and metadata files alike, that requirements are not stated in this specification.",
            RequirementCoverageStatus.OutOfScope, "The specification's own scope exclusion; the block carries three placeholder entries and no obligation."),

        ("csip-oais-1.4-4-package", "Term consistency: the specification adopts the reference model's Information Package term and its three package types, and states the package type in the manifest header through its own extension attribute, while defining Information Package structurally as a root folder holding a manifest.",
            RequirementCoverageStatus.OutOfScope, "FINDING, row-level, no defect: the specification quotes the reference model's own definitions of the three package types verbatim and adds a structural realisation of them, which is what clause 1.4 item 4 asks of a document claiming conformance — the term keeps its meaning and gains a shape. Recorded because the same clause 1.4 reading finds a real departure in the archival package's version vocabulary (row aip-oais-1.4-4-version) and a gap in the preservation-metadata layer (row premis-oais-1.4-1-pdi), and a reader needs the negative case beside them."),
    ];


    /// <summary>
    /// This library's own conventions over the Common Specification, allocated in the same registry as the
    /// specification's requirements because a consuming graph has to be able to name them: the bounds a
    /// package is read under, the fixity recomputation and algorithm-strength report the specifications ask
    /// nobody for, reference resolution, the identifier production, and the three rows of the wave's
    /// evidence-placement convention.
    /// </summary>
    /// <remarks>
    /// The evidence rows exist because neither source document has any notion of a signature, a time
    /// assertion or an evidence record; where such an artifact sits in a package, and how the package records
    /// what it attests, is this wave's own design and is documented as one.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] HouseConventionRows { get; } =
    [
        ("EArkPackageWithinStatedLimits", "House convention — the package stays inside the bounds the caller stated: entry count, total octets, name length and depth, one shared record whichever way the package arrived.",
            RequirementCoverageStatus.Tested, "EArkValidationProfileTests.APackageBeyondAStatedBoundFailsTheIntegrityRule (and EArkPackageSnapshotTests.TheSharedBoundsGovernTheArchiveLayerToo, the same bounds governing the archive path)"),
        ("EArkPackageFixityRecomputed", "House convention — every fixity value a package states is recomputed over the package's own octets through the registered digest seam rather than read and believed.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AStatedChecksumThatMatchesTheOctetsPassesTheRecomputation"),
        ("EArkPackageFixityAlgorithmStrength", "House convention — the strength of the algorithm a fixity value was computed under is reported; a weak but specification-legal algorithm is flagged rather than failed, and the caller may raise the floor.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AWeakFixityAlgorithmIsFlaggedByDefaultAndFailsOnlyWhenTheCallerRaisesTheFloor"),
        ("EArkPackageReferencesResolve", "House convention — every reference a manifest states resolves to an entry the package holds, compared ordinally.",
            RequirementCoverageStatus.Tested, "EArkCorpusValidationTests.TheReferenceMinimalPackageNamesASchemaFileItHoldsUnderAnotherCase (the reference material's own minimal package carries a reference that only a case-folding reader would call resolved)"),
        ("EArkPackageIdentifiersAreNCNames", "House convention — every identifier a manifest states is a legal name under the production clause 5.1 points at.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnIdentifierThatIsNotALegalNameFailsTheIdentifierRule"),
        ("EArkPackageEvidencePlacement", "House convention — an evidential artifact sits where this library's placement convention puts one, is named by the manifest with a digest that recomputes, and is recorded by a preservation event and a relationship saying what it attests.",
            RequirementCoverageStatus.Tested, "EArkEvidencePlacementTests.APackageCarryingEachArtifactKindReachesTheConventionsClaims (and EArkEvidencePlacementTests.AnArtifactSittingWhereTheConventionDoesNotPutOneFailsThePlacementRule)"),
        ("EArkPackageEvidenceSelfDescription", "House convention — an evidential artifact describes the preservation service, policy and profile it was produced under, in one shape carried over three different extension points.",
            RequirementCoverageStatus.Tested, "EArkEvidenceSelfDescriptionTests.TheThreeCarriersHoldTheSameOctets (and EArkEvidencePlacementTests.AnUnprotectedSelfDescriptionLeavesTheProtectionRowUnmet)"),
        ("EArkPackageProvenanceAnchored", "House convention — the package's own digital-provenance content is inside what one of its evidential artifacts proves, which is what gives a plain-text provenance chain a cryptographic anchor.",
            RequirementCoverageStatus.Tested, "EArkEvidenceAnchoringTests.APackageWhoseProvenanceWasAnchoredVerifiesAsAnchored (and EArkEvidenceAnchoringTests.TamperingWithTheProvenanceBreaksTheEvidenceWhileEveryPlainTextRuleReachesTheSameConclusion, which is the whole reason the anchor exists)"),
    ];


    /// <summary>
    /// Every row of the preservation-metadata catalogue,
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>
    /// <c>PM1</c>…<c>PM125</c>, in the source tables' own order and grouped by the entity each table covers:
    /// the document root, the intellectual-entity and environment object, the representation object, the file
    /// object, the agent, the event and the rights statement.
    /// </summary>
    /// <remarks>
    /// The digest of each row opens with the cardinality and the keyword the source table's own two-line cell
    /// carries. Two rows carry the keyword <c>COULD</c>, which the requirement-keyword vocabulary the rest of
    /// the tables use does not define, and two carry a cardinality with no keyword at all; all four are
    /// documented interpretations with a test of their own rather than a silent normalisation.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] PreservationMetadataTableRows { get; } =
    [
        ("PM1", "MUST 1..1 premis/@version — the version of the preservation-metadata vocabulary is given in the root element.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.ADocumentOfTheWrongVocabularyVersionFailsTheVersionRow"),

        ("PM2", "MUST 1..1 object/@xsi:type='intellectualEntity' — the object category, from the Object Category vocabulary.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.AnObjectCategoryTheVocabularyDoesNotNameFailsTheThreeRowsThatAskForOne"),
        ("PM3", "MUST 1..1 object/objectIdentifier — the object is given an identification.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM4", "MUST 1..1 objectIdentifier/objectIdentifierType — the identification follows a stated scheme, or the local type when it was created locally.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM5", "MUST 1..1 objectIdentifier/objectIdentifierValue — the identification value under the declared type.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM6", "MUST 1..n object/environmentFunction — the grouping element for an environment function.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheEnvironmentRowsBindOnlyAnEntityThatDescribesAnEnvironment"),
        ("PM7", "MUST 1..1 environmentFunction/environmentFunctionType — the function type, from the Environment Function Type vocabulary.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheEnvironmentRowsBindOnlyAnEntityThatDescribesAnEnvironment"),
        ("PM8", "MUST 1..1 environmentFunction/environmentFunctionLevel — the rendering-order sequence number.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheEnvironmentRowsBindOnlyAnEntityThatDescribesAnEnvironment"),
        ("PM9", "MUST 1..1 object/environmentDesignation — a description of the environment.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.AnEntityDescribingHalfAnEnvironmentFailsTheRowAskingForTheOtherHalf"),
        ("PM10", "MUST 1..1 environmentDesignation/environmentName — the name of the described software.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.AnEntityDescribingHalfAnEnvironmentFailsTheRowAskingForTheOtherHalf"),
        ("PM11", "SHOULD 0..1 environmentDesignation/environmentVersion — the software version, where it can be given.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheEnvironmentRowsBindOnlyAnEntityThatDescribesAnEnvironment"),
        ("PM12", "SHOULD 0..1 environmentDesignation/environmentOrigin — where the software came from, where it can be given.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheEnvironmentRowsBindOnlyAnEntityThatDescribesAnEnvironment"),
        ("PM13", "MAY 0..1 environmentDesignation/environmentDesignationNote — free-text information about the software.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheEnvironmentRowsBindOnlyAnEntityThatDescribesAnEnvironment"),

        ("PM14", "MUST 1..1 object/@xsi:type='representation' — the object category.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.AnObjectCategoryTheVocabularyDoesNotNameFailsTheThreeRowsThatAskForOne"),
        ("PM15", "MUST 1..1 object/objectIdentifier — the representation is given an identification.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM16", "MUST 1..1 objectIdentifier/objectIdentifierType — the identification's type.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM17", "MUST 1..1 objectIdentifier/objectIdentifierValue — the identification's value.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM18", "SHOULD 0..n object/significantProperties — the representation may carry significant properties.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM19", "MUST 1..1 significantProperties/significantPropertiesType — the property's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM20", "MUST 1..1 significantProperties/significantPropertiesValue — the property's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM21", "MUST 1..n object/relationship — the relationship connecting the representation to its rendering software.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM22", "MUST 1..1 relationship/relationshipType — the relationship type, from the Relationship Type vocabulary.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM23", "MUST 1..1 relationship/relationshipSubType — the relationship subtype, from the Relationship Subtype vocabulary.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM24", "MUST 1..1 relationship/relatedObjectIdentifier — the identifier of the rendering-software object.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM25", "MUST 1..1 relatedObjectIdentifier/relatedObjectIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM26", "MUST 1..1 relatedObjectIdentifier/relatedObjectIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM27", "SHOULD 0..1 relationship/relatedEnvironmentPurpose — the purpose of the related environment.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),

        ("PM28", "MUST 1..1 object/@xsi:type='file' — the object category.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.AnObjectCategoryTheVocabularyDoesNotNameFailsTheThreeRowsThatAskForOne"),
        ("PM29", "MUST 1..n object/objectIdentifier — the file is given an identification.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM30", "MUST 1..1 objectIdentifier/objectIdentifierType — the identification's type.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM31", "MUST 1..1 objectIdentifier/objectIdentifierValue — the identification's value.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM32", "MUST 1..n object/objectCharacteristics — the characteristics important for preservation.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM33", "SHOULD 0..n objectCharacteristics/fixity — the digital object's checksum may be stored.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence + " (and PremisXmlBindingTests.AFixityThisLibraryCannotRecomputeIsCarriedThroughTheParse, two fixities over one file where only one is recomputable)"),
        ("PM34", "MUST 1..1 fixity/messageDigestAlgorithm — the algorithm, from the Cryptographic Hash Functions vocabulary.",
            RequirementCoverageStatus.Tested, "EArkFixityTests.NamingAnAlgorithmAsAChecksumTypeReachesTheSameSetAsNamingItAsAnObjectIdentifier (the two vocabularies of the two documents read to one classification)"),
        ("PM35", "MUST 1..1 fixity/messageDigest — the calculated checksum.",
            RequirementCoverageStatus.Tested, "EArkFixityTests.AValueThatIsNotTheDigestOfItsAlgorithmNeverReachesADigestCarrier"),
        ("PM36", "MAY 0..1 fixity/messageDigestOriginator — the name of the software that calculated the checksum.",
            RequirementCoverageStatus.KnownDefect, PreservationMetadataEvidence + " (the rule reports this row as having no subject because the shipped model carries no originator element; asserted there by name, and recorded as a stage-4 flag rather than left silent)"),
        ("PM37", "SHOULD 0..1 objectCharacteristics/format — the file format, through a designation, a registry entry or both.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM38", "SHOULD 0..1 format/formatDesignation — the grouping element for the format's name and version.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM39", "MUST 1..1 formatDesignation/formatName — the format's name.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM40", "SHOULD 0..1 formatDesignation/formatVersion — the format's version.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM41", "SHOULD 0..1 format/formatRegistry — the link to a format registry.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM42", "MUST 1..1 formatRegistry/formatRegistryName — the registry's name.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM43", "MUST 1..1 formatRegistry/formatRegistryKey — the registry key of the format.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM44", "MAY 0..1 formatRegistry/formatRegistryRole — the registry entry's role.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM45", "MAY 0..n objectCharacteristics/creatingApplication — information about the application that created the file.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM46", "MUST 1..1 creatingApplication/creatingApplicationName — that application's name.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM47", "MAY 0..1 creatingApplication/creatingApplicationVersion — that application's version.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM48", "MAY 0..1 creatingApplication/dateCreatedByApplication — the date the file object was created.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM49", "MAY 0..n creatingApplication/creatingApplicationExtension — further markup about the creating application.",
            RequirementCoverageStatus.KnownDefect, PreservationMetadataEvidence + " (the rule reports this row as having no subject because the shipped model carries no arbitrary-extension element; asserted there by name, and recorded as a stage-4 flag)"),
        ("PM50", "MAY 0..1 objectCharacteristics/objectCharacteristicsExtension — embedded characterisation output.",
            RequirementCoverageStatus.KnownDefect, PreservationMetadataEvidence + " (the rule reports this row as having no subject because the shipped model carries no characterisation-extension element; asserted there by name, and recorded as a stage-4 flag)"),
        ("PM51", "SHOULD 0..1 object/originalName — the name the object carried before preservation renamed it.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM52", "MAY 0..n object/storage — the object's storage location.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM53", "COULD 0..1 storage/contentLocation — the location of the digital content, for easy access. The keyword is not one the requirement-keyword vocabulary defines.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheTwoUndefinedKeywordRowsReachTheirOutcomeAsAStatedInterpretation (read as the permissive keyword under a documented and switchable interpretation, never silently normalised)"),
        ("PM54", "MUST 1..1 contentLocation/contentLocationType — the location's type, from the Content Location Type vocabulary.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM55", "MUST 1..1 contentLocation/contentLocationValue — the location's name or identifier.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM56", "MAY 0..1 storage/storageMedium — the storage medium, from the Storage Medium vocabulary.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM57", "SHOULD 0..n object/relationship — the relationships connecting the file to other objects and events.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM58", "MUST 1..1 relationship/relationshipType — the relationship's type.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM59", "MUST 1..1 relationship/relationshipSubType — the relationship's subtype.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM60", "MUST 1..n relationship/relatedObjectIdentifier — the identifier of the related object.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM61", "MUST 1..1 relatedObjectIdentifier/relatedObjectIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM62", "MUST 1..1 relatedObjectIdentifier/relatedObjectIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM63", "SHOULD 0..n relationship/relatedEventIdentifier — the identifier of the related event; the release notes record this row's keyword being softened from the mandatory one in v1.0.1.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM64", "MUST 1..1 relatedEventIdentifier/relatedObjectIdentifierType — the related event identifier's type. The table names the element with the related-OBJECT prefix while its sibling row names the value element with the related-EVENT one.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheRelatedEventIdentifierRowCarriesItsTranscriptionResolution (a transcription defect of the requirement table, settled against the vocabulary's own schema by PremisXmlBindingTests.TheVocabularysOwnSchemaSettlesTheRelatedEventIdentifierDiscrepancy rather than by a house reading)"),
        ("PM65", "MUST 1..1 relatedEventIdentifier/relatedEventIdentifierValue — the related event identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM66", "COULD 0..n object/linkingRightsStatementIdentifier — the object may relate to rights statements. The keyword is not one the requirement-keyword vocabulary defines.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheTwoUndefinedKeywordRowsReachTheirOutcomeAsAStatedInterpretation (read as the permissive keyword under a documented and switchable interpretation, never silently normalised)"),
        ("PM67", "MUST 1..1 linkingRightsStatementIdentifier/linkingRightsStatementIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM68", "MUST 1..1 linkingRightsStatementIdentifier/linkingRightsStatementIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),

        ("PM69", "SHOULD 0..n agent — an agent connected with an event on a digital object.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM70", "MUST 1..n agent/agentIdentifier — the agent is given an identification.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM71", "MUST 1..1 agentIdentifier/agentIdentifierType — the identification's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM72", "MUST 1..1 agentIdentifier/agentIdentifierValue — the identification's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM73", "MUST 1..1 agent/agentName — a human-understandable name for the agent.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM74", "MUST 1..1 agent/agentType — the agent's type, from the Agent Type vocabulary.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM75", "SHOULD 0..1 agent/agentVersion — the software version, where the agent is software.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM76", "MAY 0..1 agent/agentNote — free-text description of the agent.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM77", "SHOULD 0..n agent/linkingRightsStatementIdentifier — the rights the agent was granted.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM78", "MUST 1..1 linkingRightsStatementIdentifier/linkingRightsStatementIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM79", "MUST 1..1 linkingRightsStatementIdentifier/linkingRightsStatementIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),

        ("PM80", "CARDINALITY-ONLY 0..n event — each event on a digital object is recorded. The source table's cell carries the cardinality and no keyword at all.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheTwoRowsWithNoKeywordAreReadAtTheLevelTheirCardinalityGives (read at the level the cardinality gives, as a stated interpretation)"),
        ("PM81", "MUST 1..n event/eventIdentifier — the event is given an identification.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM82", "MUST 1..1 eventIdentifier/eventIdentifierType — the identification's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM83", "MUST 1..1 eventIdentifier/eventIdentifierValue — the identification's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM84", "MUST 1..1 event/eventType — the event's type, from the Event Type vocabulary.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM85", "MUST 1..1 event/eventDateTime — when the event occurred.",
            RequirementCoverageStatus.Tested, "PremisXmlBindingTests.AValueFromAnOpenVocabularyIsCarriedAsStated (including an event instant stated as an interval, which no single instant could hold)"),
        ("PM86", "MUST 1..1 eventOutcomeInformation/eventOutcome — the event's outcome, from the Event Outcome vocabulary.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM87", "SHOULD 0..n event/linkingAgentIdentifier — the agent that carried the event out.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventWithoutAPerformerFailsTheRowThatAsksForOne"),
        ("PM88", "MUST 1..1 linkingAgentIdentifier/linkingAgentIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM89", "MUST 1..1 linkingAgentIdentifier/linkingAgentIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingAnUndescribedAgentFailsTheCrossEntityRow"),
        ("PM90", "CARDINALITY-ONLY 0..n event/linkingObjectIdentifier — the object the event affected. The source table's cell carries the cardinality and no keyword at all.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheTwoRowsWithNoKeywordAreReadAtTheLevelTheirCardinalityGives (read at the level the cardinality gives, as a stated interpretation)"),
        ("PM91", "MUST 1..1 linkingObjectIdentifier/linkingObjectIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM92", "MUST 1..1 linkingObjectIdentifier/linkingObjectIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),

        ("PM93", "SHOULD 0..1 rights — all rights statements for the objects and the agents.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM94", "MUST 1..n rights/rightsStatement — each rights statement in its own element.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM95", "MUST 1..n rightsStatement/rightsStatementIdentifier — the statement is given an identification.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM96", "MUST 1..1 rightsStatementIdentifier/rightsStatementIdentifierType — the identification's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM97", "MUST 1..1 rightsStatementIdentifier/rightsStatementIdentifierValue — the identification's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM98", "MUST 1..1 rightsStatement/rightsBasis — the rights type, from the Rights Basis vocabulary.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheFourRightsBasesAreAlternativesRatherThanFourObligations"),
        ("PM99", "SHOULD 0..1 rightsStatement/copyrightInformation — present when the rights basis is copyright.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheFourRightsBasesAreAlternativesRatherThanFourObligations"),
        ("PM100", "MUST 1..1 copyrightInformation/copyrightStatus — the copyright status, from the Copyright Status vocabulary.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM101", "MUST 1..1 copyrightInformation/copyrightJurisdiction — the country whose copyright law applies.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM102", "MAY 0..1 copyrightInformation/copyrightDocumentationIdentifier — a link to supporting documentation.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM103", "MUST 1..1 copyrightDocumentationIdentifier/copyrightDocumentationIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM104", "MUST 1..1 copyrightDocumentationIdentifier/copyrightDocumentationIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM105", "SHOULD 0..1 rightsStatement/licenseInformation — present when the rights basis is a licence.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheFourRightsBasesAreAlternativesRatherThanFourObligations"),
        ("PM106", "MAY 0..1 licenseInformation/licenseDocumentationIdentifier — a link to supporting documentation.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM107", "MUST 1..1 licenseDocumentationIdentifier/licenseDocumentationIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM108", "MUST 1..1 licenseDocumentationIdentifier/licenseDocumentationIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM109", "SHOULD 0..1 rightsStatement/statuteInformation — present when the rights basis is a statute.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheFourRightsBasesAreAlternativesRatherThanFourObligations"),
        ("PM110", "MUST 1..1 statuteInformation/statuteJurisdiction — the country whose statute applies.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM111", "MUST 1..1 statuteInformation/statuteCitation — the statute's identifying designation.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM112", "MAY 0..1 statuteInformation/statuteDocumentationIdentifier — a link to supporting documentation.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM113", "MUST 1..1 statuteDocumentationIdentifier/statuteDocumentationIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM114", "MUST 1..1 statuteDocumentationIdentifier/statuteDocumentationIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM115", "SHOULD 0..1 rightsStatement/otherRightsInformation — present when the rights basis is another one.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheFourRightsBasesAreAlternativesRatherThanFourObligations"),
        ("PM116", "MAY 0..1 otherRightsInformation/otherRightsDocumentationIdentifier — a link to supporting documentation.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM117", "MUST 1..1 otherRightsDocumentationIdentifier/otherRightsDocumentationIdentifierType — that identifier's type.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM118", "MUST 1..1 otherRightsDocumentationIdentifier/otherRightsDocumentationIdentifierValue — that identifier's value.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM119", "MUST 1..1 otherRightsInformation/otherRightsBasis — the basis, from a locally maintained vocabulary.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM120", "SHOULD 0..1 rightsStatement/rightsGranted — information about the rights granted.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM121", "MUST 1..1 rightsGranted/act — the acts allowed, from the Event Type vocabulary.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM122", "SHOULD 0..1 rightsGranted/termOfGrant — the term the act is allowed for.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM123", "MUST 1..1 termOfGrant/startDate — the start of the grant period.",
            RequirementCoverageStatus.Tested, PreservationShapeEvidence),
        ("PM124", "MAY 0..1 termOfGrant/endDate — the end of the grant period.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
        ("PM125", "MAY 0..1 rightsGranted/rightsGrantedNote — a note about the rights granted.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence),
    ];


    /// <summary>
    /// The preservation-metadata specification's SECOND identifier scheme — the fourteen mnemonic
    /// requirements its clause-4 narrative states outside the numbered tables — and the obligations of its
    /// context, placement and root-element clauses that carry no identifier at all.
    /// </summary>
    /// <remarks>
    /// The mnemonics are not a summary of the tables: each states its own obligation, several of them at a
    /// different level from the table row covering the same element, and a matrix walking only the numbered
    /// tables would miss all fourteen.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] PreservationMetadataNarrativeRows { get; } =
    [
        ("PREMIS-ID-LOCAL", "SHOULD — an identifier of the local type is unique within the preservation-metadata document AND within the repository.",
            RequirementCoverageStatus.ServiceOperational, PreservationMetadataEvidence + " (the identity rows within one document are checked; uniqueness across a repository's holdings is that repository's own governance)"),
        ("PREMIS-ID-OTHER", "MAY — further identifier types are added beside the local one by repeating the identifier element.",
            RequirementCoverageStatus.Tested, "PremisXmlBindingTests.ADocumentRoundTripsThroughTheModel (repeated identifiers on one entity carried through the model and back)"),
        ("PREMIS-CHECKSUMS", "SHOULD — checksums are provided under the object characteristics, recommended as a 256-bit value of the second secure-hash family. This is the one place in either source document naming a preferred algorithm outright.",
            RequirementCoverageStatus.Tested, "EArkFixityTests.TheCreationSideFloorIsEnforcedWhereTheModelIsBuilt (the creation side of this library states nothing weaker, which is the secure default this recommendation asks for)"),
        ("PREMIS-FILE-FORMAT", "SHOULD — the format element is given through a format registry entry, a format designation, or both.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence + " (the table rows for the same element are PM37, PM38 and PM41)"),
        ("PREMIS-FILE-FORMAT-PUID", "SHOULD — the format registry uses a persistent unique identifier of the named external format registry.",
            RequirementCoverageStatus.ServiceOperational, PreservationMetadataEvidence + " (the registry name and key are carried as stated, PM42 and PM43; which registry a repository resolves them against is its own choice and no registry is bundled)"),
        ("PREMIS-CHARACTERISATION", "MAY — technical characterisation markup produced by a characterisation tool is embedded under the object-characteristics extension.",
            RequirementCoverageStatus.OutOfScope, "A third-party characterisation tool's own output format, which this library neither produces nor interprets; the shipped model carries no extension element for it, recorded at row PM50."),
        ("PREMIS-ORIGINAL-NAME", "MAY — the original name records a file's name before preservation renamed it.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence + " (the table row for the same element is PM51)"),
        ("PREMIS-STORAGE", "MAY — the storage element holds the digital object's physical or storage location, a resolvable identifier being recommended.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence + " (the table rows for the same element are PM52 to PM56)"),
        ("PREMIS-RELATIONSHIP", "SHOULD — the relationship element describes the digital object's relationships.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence + " (the table row for the same element is PM57)"),
        ("PREMIS-IP-INCLUDED", "MUST — where a package is part of another, the relationship subtype references the superordinate package.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AWellFormedPackagePointerSatisfiesTheParentChainRule (and EArkArchivalAndFixityRuleTests.APackagePointerNamingNoTargetFailsTheParentChainRule)"),
        ("PREMIS-RIGHTS", "MAY / MUST — rights statements linked from an object are described through the rights element.",
            RequirementCoverageStatus.Tested, "EArkMetadataRuleTests.TheFourRightsBasesAreAlternativesRatherThanFourObligations"),
        ("PREMIS-EVENT-ID", "SHOULD — the event identifier identifies preservation-action events.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingADescribedAgentSatisfiesTheCrossEntityRow (the event identity rows beside the archival rows that read them)"),
        ("PREMIS-EVENT-AGENT", "MUST / SHOULD — the agent causing an event is linked through the linking-agent identifier, and the event a resource was created by is recorded on the object itself.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingAnUndescribedAgentFailsTheCrossEntityRow"),
        ("PREMIS-AGENT", "MUST — agents referenced in events are described through the agent element.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventWithoutAPerformerFailsTheRowThatAsksForOne"),

        ("premis-2.2-tool-conformance", "MUST (lower case) — a tool claiming to validate conformant packages also validates the preservation metadata once it exists within the package.",
            RequirementCoverageStatus.ServiceOperational, PreservationMetadataEvidence + " (the same obligation the Common Specification states, recorded at row csip-tool-validates-preservation-metadata; making the claim is the tool vendor's act)"),
        ("premis-2.2-agent-recording", "MUST — information about the agents of preservation actions is recorded in the preservation metadata rather than in the manifest, whose own agents cover package-level events alone.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingADescribedAgentSatisfiesTheCrossEntityRow (an event's performer is resolved against the preservation-metadata agents, never against the manifest's creator stamp)"),
        ("premis-2.2.2-conformance-level", "Descriptive — the specification maps the object, event and agent entities at the vocabulary's own conformance level, while still using the rights entity throughout its tables.",
            RequirementCoverageStatus.OutOfScope, "A statement about the specification's own conformance claim to the vocabulary it profiles, not an obligation on a package."),
        ("premis-2.2.3-files-listed", "MUST (lower case) — all preservation-metadata files are listed in the appropriate manifest: package-level files from the package manifest and representation-level files from the representation manifests.",
            RequirementCoverageStatus.OutOfScope, "The completeness half of the same folder-to-section cross-check recorded at row csip-amdsec-preservation-completeness: the pointer is checked (AIPM5), the exhaustiveness over the files on disk is not. Recorded as a gap at this stage's buildlog flag rather than claimed."),
        ("premis-2.2.4-vocabularies", "Descriptive — the specification defines no vocabulary of its own and recommends an external registry family throughout.",
            RequirementCoverageStatus.OutOfScope, "An external registry referenced by identifier only; this library hard-codes no term beyond what a numbered row names, which is the posture the clause asks for."),
        ("premis-2.2.5-identifiers", "Descriptive / MUST — every entity uses the generic identifier container of a type and a value; the type vocabulary is implementation-specific and the local type is used throughout the specification's own examples.",
            RequirementCoverageStatus.Tested, PreservationMetadataEvidence + " (the identity rows of all four entities)"),
        ("premis-5.1-placement", "MUST (lower case) — the preservation metadata is placed in the administrative section of the information package.",
            RequirementCoverageStatus.Tested, "EArkCorpusValidationTests.TheReferencePackageWithPreservationMetadataMoorsItToItsManifest"),
        ("premis-5.1.1-table1", "MUST — the manifest binding of a preservation-metadata document: one administrative section, one digital-provenance section per document, and the metadata type naming this vocabulary.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AProvenanceReferenceOfAnotherVocabularyDeviatesWithoutFailing"),
        ("premis-5.2-placement", "MUST (lower case) — the documents giving the preservation metadata for the data objects are placed in the metadata section of the package, referenced rather than embedded.",
            RequirementCoverageStatus.Tested, FolderStructureEvidence + " (the folder half is CSIPSTR6; the referenced-not-embedded half is row csip-considerations-not-embedded)"),
        ("premis-4.1.7-references", "MUST — referencing between the parts of a package and to other representations is created following the Common Specification's own referencing rules.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AReferenceToAFileThePackageDoesNotHoldFailsTheReferenceRule (one reference-resolution rule serving both documents, which is what this cross-document obligation asks for)"),
        ("premis-4.5-level-policy", "Policy — whether preservation-metadata files exist at representation level or at package level only is a decision the specification leaves to the repository.",
            RequirementCoverageStatus.ServiceOperational, "EArkPackageClassificationTests.EachRepresentationIsItsOwnLevelWithTheSameShape (both levels are read the same way, so either policy is servable; which one a repository takes is its own decision)"),
        ("premis-6.1.1-root", "MUST — the root element declares its namespaces and schema location and states the vocabulary version; schema copies should be bundled in the package's own schemas folder.",
            RequirementCoverageStatus.Tested, "PremisXmlBindingTests.ADocumentWrittenToBreakTheParseIsRefusedWithTheStatusThatNamesIt (a document in the wrong namespace or with no root of this vocabulary is refused) beside EArkMetadataRuleTests.ADocumentOfTheWrongVocabularyVersionFailsTheVersionRow"),

        ("premis-oais-1.4-1-pdi", "Term consistency: the preservation-metadata specification carries the reference model's Fixity and Provenance content — checksums under the object characteristics, events and agents under the digital-provenance section — without ever naming Preservation Description Information, Content Information or Representation Information.",
            RequirementCoverageStatus.OutOfScope, "FINDING, row-level: clause 1.4 item 1 of the reference model asks a specification claiming conformance to map its own constructs onto the model's information objects. This specification does not claim conformance and does not make the mapping, so item 4's use-the-terms-the-same-way obligation is not engaged and there is no redefinition. Recorded because the mapping's absence is what makes the archival package's provenance chain a plain-text one — which is exactly the gap this wave's evidence-placement convention closes, at rows EArkPackageProvenanceAnchored and EArkPackageEvidencePlacement."),
    ];


    /// <summary>
    /// Every requirement of <see href="https://earkaip.dilcis.eu/">E-ARK AIP v2.2.0</see> across all three of
    /// its identifier spaces — the METS profile's <c>AIPM1</c>…<c>AIPM7</c>, the narrative's
    /// <c>AIP1</c>…<c>AIP28</c>, and the obligations its prose states with no identifier at all — plus the
    /// three defects and quotations a reader of that document has to be warned about.
    /// </summary>
    /// <remarks>
    /// The wave contract rules this package in narrowly: its preservation layer and the provenance pointer
    /// that carries it. The rows outside that subset are recognition rows with the contract's reason, not
    /// gaps: the divided-representation rules, the container-naming policy and the packaging-format rules are
    /// a complete authoring capability this wave deliberately does not build.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] ArchivalPackageRows { get; } =
    [
        ("AIPM1", "MUST — mets/@OBJID does not change during the life-cycle of the archival package.",
            RequirementCoverageStatus.ServiceOperational, MetsRootEvidence + " (the identifier slot is read from the one package a validator is given; whether it changed since an earlier generation needs the repository's own version history, which the profile itself acknowledges by giving this row no conformance test)"),
        ("AIPM2", "MUST — mets/@PROFILE states the archival package's own profile identifier.",
            RequirementCoverageStatus.OutOfScope, "The archival specialisation of CSIP6, which is checked generally; pinning the value to the archival profile is outside the narrow archival subset the wave contract rules in, and is recorded rather than claimed."),
        ("AIPM3", "MUST — the package-type attribute of the header states the archival package type.",
            RequirementCoverageStatus.OutOfScope, "The archival specialisation of CSIP9, which is checked generally; outside the narrow archival subset the wave contract rules in."),
        ("AIPM4", "SHOULD — the descriptive-metadata status uses the fixed vocabulary, and one section is the current one.",
            RequirementCoverageStatus.OutOfScope, "The archival specialisation of CSIP20, which is checked generally; which section is current is a repository's own statement about its holdings, and this row is outside the narrow archival subset the wave contract rules in."),
        ("AIPM5", "MUST — digital provenance metadata is referenced through the administrative section's provenance reference.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AManifestWithoutProvenanceMetadataFailsTheMandatoryPointerRow (and " + ProvenanceReferenceEvidence + " for the conformant case)"),
        ("AIPM6", "SHOULD — at least one such reference names the preservation-metadata vocabulary as its metadata type.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AProvenanceReferenceOfAnotherVocabularyDeviatesWithoutFailing"),
        ("AIPM7", "SHOULD — that reference states the preservation-metadata vocabulary's major version.",
            RequirementCoverageStatus.Tested, ProvenanceReferenceEvidence + " (the conditional row, reported as not triggered when the vocabulary row above it is unmet)"),

        ("AIP1", "MUST — a representation divided into parts uses the same component name in every container.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — a cross-container rule that only holds when every part is present, which is a repository's assembly step rather than one package's shape. The divided-structure requirements are outside the narrow archival subset the contract rules in."),
        ("AIP2", "MUST — the sub-paths of items are unique across the different containers.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — the same cross-container class as AIP1."),
        ("AIP3", "MUST — a divided package's structural map carries a manifest pointer and a matching file pointer per representation.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — the divided-structure shape; the undivided package's own pointer rows are CSIP109 to CSIP112 and are checked."),
        ("AIP7", "COULD — format information is given through a format registry, a format designation, or both. The keyword is not one the requirement-keyword vocabulary defines.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — a restatement of PREMIS-FILE-FORMAT at a keyword this specification never defines; the preservation-metadata rows for the same element (PM37, PM38, PM41) are checked."),
        ("AIP8", "COULD — the format registry uses a persistent unique identifier. The keyword is not one the requirement-keyword vocabulary defines.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — a restatement of PREMIS-FILE-FORMAT-PUID at an undefined keyword."),
        ("AIP11", "COULD — the storage element holds the object's physical location, ideally a resolvable identifier. The keyword is not one the requirement-keyword vocabulary defines.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — the retrieval mechanism a storage location serves is a repository concern; the element itself is PM52 to PM56 and is checked."),
        ("AIP12", "SHOULD — the relationship element describes the digital object's relationships.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingADescribedAgentSatisfiesTheCrossEntityRow"),
        ("AIP13", "MUST — a package that is part of another names the superordinate package through the relationship subtype.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingADescribedAgentSatisfiesTheCrossEntityRow (the document half; whether the named package is the right one is a repository's holding and is documented at the rule as unreachable from one package)"),
        ("AIP15", "SHOULD — the event identifier identifies the preservation events.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingADescribedAgentSatisfiesTheCrossEntityRow"),
        ("AIP16", "MUST — a described event names the agent that caused it through the linking-agent identifier.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventWithoutAPerformerFailsTheRowThatAsksForOne"),
        ("AIP17", "SHOULD — the event a resource was created by is recorded through the related-event identification, which is what chains a migration back to the event that made its source.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingADescribedAgentSatisfiesTheCrossEntityRow"),
        ("AIP18", "MUST — agents referenced in events are described through the agent element.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AnEventNamingAnUndescribedAgentFailsTheCrossEntityRow"),
        ("AIP20", "SHOULD — the package identifier is used to derive the physical container's file name.",
            RequirementCoverageStatus.ServiceOperational, "EArkStructuralRuleTests.APackageIdentifierThatIsAUniformResourceNameCannotNameAnArchiveRootFolder (the finding that a uniform-resource-name identifier cannot be a portable name unchanged, which is what makes this derivation necessary; the derivation itself is not shipped and is a recorded stage-4 flag)"),
        ("AIP21", "SHOULD — a stated policy allows deriving a portable, cross-platform file-name part from the identifier and back.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: the policy is the repository's to state, and no derivation helper is shipped — the gap is a recorded stage-4 flag."),
        ("AIP22", "SHOULD — the container file name starts with a part stable across every version and generation of the same logical package.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: stability across generations is a commitment over time that no single package states."),
        ("AIP27", "MUST — the package content is contained in a single folder once unpacked.",
            RequirementCoverageStatus.Tested, "EArkStructuralRuleTests.AnArchivedPackageUnderItsOwnIdentifierSatisfiesTheRootFolderRows (the same post-unpack invariant CSIPSTR1 states, restated by this specification for the packaged case)"),
        ("AIP28", "SHOULD — where a tape-archive packaging format is used, the content is aggregated without compression.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — this library packages a package as an archive of the format the container layer already ships, and no tape-archive writer is built; the packaging-format rows are outside the narrow archival subset the contract rules in."),

        ("AIP-IDENTIFIER-ASSIGNED", "MUST (lower case) — each archival package's root manifest is assigned a persistent and unique identifier. Distinct from AIPM1, which is about that identifier not changing once it exists.",
            RequirementCoverageStatus.Tested, MetsRootEvidence + " (the identifier is CSIP1 and its presence is a mandatory row; persistence is the repository's, recorded at row AIP-RETRIEVABLE-BY-IDENTIFIER)"),
        ("AIP-PARENT-CHAIN-LISTED", "MUST (lower case) — a parent package referenced by child packages carries a structural map listing all of them.",
            RequirementCoverageStatus.Tested, "EArkArchivalAndFixityRuleTests.AWellFormedPackagePointerSatisfiesTheParentChainRule (and EArkArchivalAndFixityRuleTests.APackagePointerNamingNoTargetFailsTheParentChainRule; whether the list is COMPLETE needs the repository's holdings and is documented at the rule rather than claimed)"),
        ("AIP-RETRIEVABLE-BY-IDENTIFIER", "MUST (lower case) — the system can retrieve the corresponding package from the repository using that identifier.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: retrieval by identifier is a repository's storage system, not a serialization library."),
        ("AIP-SOLUTION-INCORPORATES-UNTRANSFORMED", "SHALL — a conformant archival solution immediately analyses and incorporates existing packages without applying data transformation.",
            RequirementCoverageStatus.ServiceOperational, "EArkPackageSnapshotTests.AReferencePackageReadFromAFolderAndFromAnArchiveIsTheSameSnapshot (a package is read as it stands, from either arrival form, with nothing rewritten; whether an archive system as a whole can incorporate it is that system's claim)"),

        ("aip-prose-identifier-gaps", "Not requirements — the narrative identifier space is missing eleven of its twenty-eight numbers: AIP4, AIP5, AIP6, AIP9, AIP10, AIP14, AIP19 and AIP23 to AIP26 are never assigned anywhere in the specification.",
            RequirementCoverageStatus.OutOfScope, "A defect of the source document rather than of this transcription, confirmed by searching the whole specification rather than by reading one converted table. Recorded so a reader can tell a faithful transcription from an incomplete one, and EArkClaimIdAllocationTests.TheElevenUnassignedArchivalProseNumbersStayUnallocated asserts their codes stay free in the registry."),
        ("aip-bagit-quotation", "Not requirements — four mandatory-keyword sentences about serialising a package appear inside this specification's packaging section as a verbatim quotation from a WITHDRAWN section of a different, external specification, reproduced as background only.",
            RequirementCoverageStatus.OutOfScope, "External specification content quoted for context, and from a section its own publisher withdrew. Recorded because a reader searching this document for mandatory keywords would otherwise attribute four requirements to it that it does not state."),
        ("aip-ocfl-recommendation", "Informative — a layered object storage format is recommended as an optional extension for holding successive versions of one logical package.",
            RequirementCoverageStatus.OutOfScope, OutOfWave + " — framed as an optional extension by the specification itself; multi-version package STORAGE is a later wave's subject, and this wave validates and anchors one generation."),

        ("aip-oais-1.4-4-version", "Term consistency: the specification quotes the reference model's definition of an archival package VERSION verbatim and then adds a GENERATION of its own — a version being a logical form of the package and a generation its manifestation as one or several physical containers — a distinction the reference model does not draw.",
            RequirementCoverageStatus.OutOfScope, "FINDING, row-level: clause 1.4 item 4 obliges a document claiming conformance to the reference model to use its terms in the same manner, and this document does claim it by quoting the model's own definition. Adding a term the model does not have is not a redefinition of one it does have, so this is an extension rather than a departure — but the two words are one letter apart in usage and the specification's own examples move between them freely. Recorded so a later wave implementing multi-version storage does not read version and generation as synonyms. It also carries the finding the same clause makes about this chain: the parent-child references are plain manifest pointers with no cryptographic linkage, which the specification itself calls a risk without proposing a mitigation — the mitigation is this wave's row EArkPackageProvenanceAnchored."),
    ];


    /// <summary>
    /// Every requirement of the two package types the wave contract defers —
    /// <see href="https://earksip.dilcis.eu/">E-ARK SIP v2.2.0</see> and
    /// <see href="https://earkdip.dilcis.eu/">E-ARK DIP v2.2.0</see> — as recognition rows.
    /// </summary>
    /// <remarks>
    /// A recognition row is not a gap: it states the requirement, its level and the contract's reason for
    /// deferring it, so a consuming requirements-to-code graph carries "deliberately not covered" as data
    /// rather than inferring it from an absence. Both catalogues are pure manifest-attribute and vocabulary
    /// rules layered on the Common Specification, which the matrix covers in full above.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] SubmissionAndDisseminationRows { get; } =
    [
        ("SIP1", "MAY — mets/@LABEL, a free-text description of the package.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP2", "MUST — mets/@PROFILE states the submission package's own profile identifier.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP3", "MAY — metsHdr/@RECORDSTATUS, from the package-status vocabulary.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP4", "MUST — the header's package-type attribute states the submission package type.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP5", "MAY — metsHdr/altRecordID typed as the submission agreement: the pointer at the governing agreement.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred + " The agreement is an opaque pointer even to the specification itself, which mandates no format for it."),
        ("SIP6", "MAY — metsHdr/altRecordID typed as a previous submission agreement, repeatable.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP7", "MAY — metsHdr/altRecordID typed as the archival reference code.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP8", "MAY — metsHdr/altRecordID typed as a previous reference code, repeatable.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP9", "MAY — the archival creator agent element.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP10", "MUST (when SIP9 is present) — that agent's role attribute.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP11", "MUST (when SIP9 is present) — that agent's type attribute, an organisation or an individual.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP12", "MUST (when SIP9 is present) — that agent's name.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP13", "MAY (when SIP9 is present) — that agent's note.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP14", "MUST (when SIP13 is present) — that note's classification as an identification code.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP15", "MUST — the submitting agent element, mandatory unlike the archival creator's.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP16", "MUST (when SIP15 is present) — the submitting agent's role attribute.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP17", "MUST (when SIP15 is present) — the submitting agent's type attribute.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP18", "MUST (when SIP15 is present) — the submitting agent's name.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP19", "MAY (when SIP15 is present) — the submitting agent's note.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP20", "MUST (when SIP19 is present) — that note's classification as an identification code.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP21", "MAY — the contact-person agent element, repeatable.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP22", "MUST (when SIP21 is present) — the contact person's role attribute, fixed to the same value the archival creator uses.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred + " The shared role value is a trap for any lookup keyed on role alone: two semantically distinct agents carry it."),
        ("SIP23", "MUST (when SIP21 is present) — the contact person's type attribute, fixed to an individual.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP24", "MUST (when SIP21 is present) — the contact person's name.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP25", "MAY (when SIP21 is present) — the contact person's note, repeatable.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP26", "MAY — the preservation agent element.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP27", "MUST (when SIP26 is present) — the preservation agent's role attribute, a fixed value.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP28", "MUST (when SIP26 is present) — the preservation agent's type attribute, fixed to an organisation.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP29", "MUST (when SIP26 is present) — the preservation agent's name.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP30", "MAY (when SIP26 is present) — the preservation agent's note.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP31", "MUST (when SIP30 is present) — that note's classification as an identification code.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP32", "MAY — a file's format name, in this specification's own extension attribute.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP33", "MAY — a file's format version, in this specification's own extension attribute.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP34", "MAY — a file's format registry, in this specification's own extension attribute.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("SIP35", "MAY — a file's format registry key, in this specification's own extension attribute.", RequirementCoverageStatus.OutOfScope, SubmissionDeferred),
        ("sip-delegation-stubs", "SHOULD / MAY — five requirements delegating the descriptive, administrative and structural sections and the two unused manifest sections wholly to the Common Specification, with no local content of their own.",
            RequirementCoverageStatus.OutOfScope, SubmissionDeferred + " Each resolves to a Common Specification row the matrix already carries."),
        ("sip-representations-folders", "MUST (untagged) — representations are placed within distinct folders under the representations folder.",
            RequirementCoverageStatus.OutOfScope, SubmissionDeferred + " The same shape as CSIPSTR10, which is checked; recorded because this sentence carries no requirement identifier of its own."),
        ("sip-filesec-completeness", "MUST (lower case, untagged) — the location and checksum of every file composing the package is listed in the file section, including the files of the data, schemas and documentation folders.",
            RequirementCoverageStatus.OutOfScope, SubmissionDeferred + " A completeness obligation of the same class as row csip-amdsec-preservation-completeness."),
        ("sip-zero-representations", "Permitted — a submission package may carry zero representations, being a metadata-only update to an already-ingested package.",
            RequirementCoverageStatus.OutOfScope, SubmissionDeferred + " Recorded because it is the exact mirror of the dissemination package's own prohibition (row dip-must-have-data): one shared representations-must-exist rule across the package types would reject valid metadata-update submissions."),
        ("sip-submission-agreement", "Recommendation — the submission agreement's own semantic elements are listed as a checklist which the specification explicitly does not require and does not forbid other forms of.",
            RequirementCoverageStatus.OutOfScope, SubmissionDeferred + " There is no schema to validate against and no evidentiary content to anchor; the specification disclaims any format mandate itself."),

        ("DIP1", "MUST — mets/@OBJID, whose own prose says the identifier is expected to differ from the submission and archival packages rather than that it must.",
            RequirementCoverageStatus.OutOfScope, DisseminationDeferred + " The requirement level attribute and the prose disagree in hardness, which a generator reading only the attribute would over-state."),
        ("DIP2", "MUST — mets/@PROFILE states the dissemination package's own profile identifier.", RequirementCoverageStatus.OutOfScope, DisseminationDeferred),
        ("DIP3", "MUST — the header's package-type attribute states the dissemination package type.", RequirementCoverageStatus.OutOfScope, DisseminationDeferred),
        ("DIP4", "SHOULD — the descriptive-metadata status is the current one.", RequirementCoverageStatus.OutOfScope, DisseminationDeferred),
        ("dip-delegation-stubs", "SHOULD / MAY — five requirements delegating the administrative, file and structural sections and the two unused manifest sections wholly to the Common Specification.",
            RequirementCoverageStatus.OutOfScope, DisseminationDeferred + " Each resolves to a Common Specification row the matrix already carries."),
        ("dip-must-have-data", "MUST (lower case, untagged) — there must be data to disseminate: unlike a submission package, a dissemination package may not be representation-free.",
            RequirementCoverageStatus.OutOfScope, DisseminationDeferred + " Recorded as the mirror of row sip-zero-representations."),
        ("dip-cits-authoring", "SHOULD ×3 / COULD — a Content Information Type specification carries a section on dissemination requirements, describes how access rights are read and edited, and describes how access software is registered.",
            RequirementCoverageStatus.OutOfScope, DisseminationDeferred + " These bind whoever AUTHORS a content-information-type specification, which is neither the package producer nor this library."),
        ("dip-access-rights", "Informative — three preservation-metadata patterns for describing access software and access restrictions are illustrated and explicitly framed as possible ways rather than recommendations.",
            RequirementCoverageStatus.OutOfScope, DisseminationDeferred + " The specification states no obligation here at all."),
    ];


    /// <summary>
    /// Every row of the matrix, in source order: the Common Specification's folder catalogue, its METS
    /// profile catalogue and the obligations it states without identifiers; this library's own conventions
    /// over them; the preservation-metadata tables and narrative; the archival package; and the two package
    /// types the wave contract defers.
    /// </summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        .. CsipFolderRows,
        .. CsipMetsProfileRows,
        .. CsipClauseRows,
        .. HouseConventionRows,
        .. PreservationMetadataTableRows,
        .. PreservationMetadataNarrativeRows,
        .. ArchivalPackageRows,
        .. SubmissionAndDisseminationRows
    ];
}
