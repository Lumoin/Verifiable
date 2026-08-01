using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// The requirements matrix for the two preservation specifications this wave builds against: every
/// requirement identifier of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
/// ETSI TS 119 511 V1.2.1</see> (the policy and security requirements for a preservation service, whose
/// clause 3.4 fixes an <c>OVR-</c>/<c>PRP-</c> identifier grammar the document applies throughout clauses 5
/// to 9 and Annex A) and every normative statement of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> (the preservation protocol: eight operations, nine shared components, the
/// container extensions, the hash-only submission payload, and Annexes A, F, G, H and I).
/// Mirrors the rows-as-spec-cells shape of <c>AsicRequirementsMatrixTests</c> (ETSI EN 319 162-1/-2),
/// <c>CAdESRequirementsMatrixTests</c> (ETSI EN 319 122-1) and <c>SignatureValidationRequirementsMatrixTests</c>
/// (ETSI EN 319 102-1).
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
/// <strong>The row identifiers are the specifications' own.</strong> A TS 119 511 requirement is named by the
/// identifier its clause 3.4 grammar gives it (<c>OVR-6.4-04</c>, <c>PRP-8.1-05</c>); the clauses that state
/// obligations or model elements with no identifier of their own are named by their clause number under the
/// prefix <c>511-</c>. TS 119 512 fixes no identifier grammar, so its rows are named by clause and statement
/// number under the prefix <c>512-</c>. Keeping the specifications' own strings is what lets a consuming
/// system key a requirements-to-code graph on them.
/// </para>
/// <para>
/// <strong>The clause-4 model rows are present although clause 4 carries no identifier at all.</strong>
/// TS 119 511 clause 4 defines the three storage models, the four preservation goals, the applicable
/// documentation taxonomy, the expected evidence duration and the preservation period — the scaffold every
/// later tag (<c>[WST]</c>, <c>[PDS]</c>, …) depends on for meaning. A matrix walking only the
/// <c>OVR-</c>/<c>PRP-</c> grammar would silently omit the definitions its own tags refer to.
/// The same holds for the three failure strategies clause 4.2 lists as bare prose and <c>OVR-6.2-06</c>
/// obliges a service to choose between.
/// </para>
/// <para>
/// <strong>Service-operational rows name their enabling primitive.</strong> The larger part of TS 119 511
/// binds an operating trust service provider — documentation, audit, access control, vendor selection — which
/// no library can discharge. Such a row is <see cref="RequirementCoverageStatus.ServiceOperational"/> and its
/// evidence either leads with the test driving the primitive this library ships toward the obligation, or
/// begins with the words <c>No enabling primitive</c> when the library ships nothing that helps. Nothing in
/// between is admitted, so the tag can never become a place to hide an untested capability.
/// </para>
/// <para>
/// <strong>Term consistency against the archival reference model.</strong> Clause 1.4 item 4 of the reference
/// model this wave reads alongside these two documents obliges a specification claiming conformance to it to
/// use its terms in the same manner. Both documents were checked against that reading key while the rows were
/// written; the three findings are rows of their own (<c>511-oais-1.4-4-poc</c>, <c>511-oais-1.4-1</c> and
/// <c>512-oais-1.4-4-xaip</c>) rather than prose, so a later reader meets them where the requirement is.
/// </para>
/// </remarks>
[TestClass]
internal sealed class PreservationRequirementsMatrixTests
{
    /// <summary>Whether a requirement row is driven by a concrete test, binds the operating service rather than a library, is explicitly out of this wave's scope, or is implemented at the building-block level but unreachable through the shipped composition because of an already-flagged defect.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped surface.</summary>
        Tested = 1,

        /// <summary>The requirement is explicitly out of this wave's scope, per the arc contract, the charter, a stage's own recorded flag, or the source document's own scope exclusion.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it, but the shipped default composition cannot reach it because of an already-flagged, unfixed defect elsewhere in the pipeline.</summary>
        KnownDefect = 3,

        /// <summary>The obligation binds the trust service provider operating a preservation service — its documentation, its audit trail, its access control, its vendor selection — and not a class library. The evidence names the primitive the library ships toward it, or states that it ships none.</summary>
        ServiceOperational = 4
    }


    /// <summary>One row of the matrix: a requirement identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The specification's own requirement identifier where it has one, otherwise its clause number under the <c>511-</c>/<c>512-</c> prefix naming the document it comes from.</param>
    /// <param name="Requirement">A short digest of the normative statement, carrying the storage-model and goal tags the specification prints beside it, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/> and <see cref="RequirementCoverageStatus.KnownDefect"/>, and for a <see cref="RequirementCoverageStatus.ServiceOperational"/> row that has an enabling primitive, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection. For <see cref="RequirementCoverageStatus.OutOfScope"/>, the stated reason. For a service-operational row with no primitive, a statement opening with <see cref="NoEnablingPrimitive"/>.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


    /// <summary>The opening words a service-operational row's evidence uses when this library ships nothing that helps discharge the obligation.</summary>
    private const string NoEnablingPrimitive = "No enabling primitive";

    /// <summary>The prefix a row of ETSI TS 119 511 carries when the clause it comes from states no requirement identifier of its own.</summary>
    private const string PreservationServiceClausePrefix = "511-";

    /// <summary>The prefix every row of ETSI TS 119 512 carries, that document stating no requirement-identifier grammar at all.</summary>
    private const string PreservationProtocolPrefix = "512-";


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
    /// Every row names one of the two specifications, by carrying either an identifier of the requirement
    /// grammar the preservation-service specification fixes or one of the two clause prefixes. A row naming
    /// neither would sit in the matrix belonging to nothing.
    /// </summary>
    [TestMethod]
    public void EveryRowNamesOneOfTheTwoSpecifications()
    {
        List<string> unattributed = [.. RowData
            .Where(row => !IsPreservationServiceRow(row.ClauseId) && !IsPreservationProtocolRow(row.ClauseId))
            .Select(row => row.ClauseId)];

        Assert.IsEmpty(unattributed, $"These rows name neither specification: {string.Join(", ", unattributed)}.");
        Assert.IsNotEmpty(RowData.Where(row => IsPreservationServiceRow(row.ClauseId)).ToList());
        Assert.IsNotEmpty(RowData.Where(row => IsPreservationProtocolRow(row.ClauseId)).ToList());
    }


    /// <summary>
    /// The matrix and the shipped claim-identifier registry state the same requirement inventory, in both
    /// directions: every <c>OVR-</c>/<c>PRP-</c> identifier <see cref="PreservationClaimIds"/> allocates is a
    /// row here, and every such row is allocated there.
    /// </summary>
    /// <remarks>
    /// The registry is an independent transcription of the same clauses, made by an earlier stage from the
    /// same normative text, so this is a cross-check rather than a restatement. It is also what settles the
    /// count: the preflight leg's own navigation table prints a summary of roughly 117 identifiers and says
    /// outright that the per-clause enumeration is the source of truth — enumerating the clauses gives 122,
    /// and the registry independently allocates 122.
    /// </remarks>
    [TestMethod]
    public void TheMatrixAndTheClaimIdentifierRegistryStateTheSameRequirementInventory()
    {
        HashSet<string> allocated = [.. RequirementIdentifiersOfTheRegistry()];
        HashSet<string> rows = [.. RowData.Select(row => row.ClauseId).Where(IsGrammaredRequirementIdentifier)];

        Assert.HasCount(122, allocated, "The registry allocates the identifiers the clauses of the preservation-service specification enumerate.");

        List<string> missingFromTheMatrix = [.. allocated.Except(rows, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        Assert.IsEmpty(missingFromTheMatrix, $"These allocated requirements have no row: {string.Join(", ", missingFromTheMatrix)}.");

        List<string> missingFromTheRegistry = [.. rows.Except(allocated, StringComparer.Ordinal).Order(StringComparer.Ordinal)];
        Assert.IsEmpty(missingFromTheRegistry, $"These rows name a requirement the registry does not allocate: {string.Join(", ", missingFromTheRegistry)}.");
    }


    /// <summary>
    /// Every protocol operation and every result code the registry allocates is named by a row of the
    /// protocol section, so the operation catalogue and the result-code vocabulary are covered by clause
    /// rather than only by the vocabulary tests that assert their spellings.
    /// </summary>
    [TestMethod]
    public void EveryProtocolOperationAndResultCodeIsNamedByARowOfTheProtocolSection()
    {
        List<RequirementMatrixRow> protocolRows = [.. RowData
            .Where(row => IsPreservationProtocolRow(row.ClauseId))
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];

        foreach(string operation in DescriptionsOf(PreservationClaimIds.IsProtocolOperation))
        {
            Assert.IsNotEmpty(
                protocolRows.Where(row => row.Requirement.Contains(operation, StringComparison.Ordinal)).ToList(),
                $"No row of the protocol section names the operation {operation}.");
        }

        foreach(string resultCode in DescriptionsOf(PreservationClaimIds.IsProtocolResult))
        {
            string suffix = resultCode[(resultCode.LastIndexOf('/') + 1)..];
            Assert.IsNotEmpty(
                protocolRows.Where(row => row.Requirement.Contains(suffix, StringComparison.Ordinal)).ToList(),
                $"No row of the protocol section names the result code {suffix}.");
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
    /// The rows the preservation model rests on are present although clause 4 of the preservation-service
    /// specification states no requirement identifier anywhere: the three storage models, the four goals, the
    /// documentation taxonomy, the expected evidence duration, the preservation period, the hash-only
    /// submission mode, and the three failure strategies <c>OVR-6.2-06</c> obliges a service to choose from.
    /// </summary>
    [TestMethod]
    public void TheClauseFourModelRowsAndTheStrategyRowsArePresent()
    {
        HashSet<string> rows = [.. RowData.Select(row => row.ClauseId)];

        foreach(string required in ClauseFourModelRowIdentifiers)
        {
            Assert.Contains(required, rows, $"The clause-4 model row {required} is missing, and every tag the later requirements carry refers to it.");
        }
    }


    /// <summary>
    /// The row the wave still carries an owner flag for cites it where the requirement is: the
    /// qualified-service requirement whose input procedure belongs to a companion specification this repository
    /// has never implemented. The other formerly-flagged row — the time-stamp-token profile — is
    /// <see cref="RequirementCoverageStatus.Tested"/> since the managed-RSA widening closed the last surviving
    /// flag, and its evidence records that closure.
    /// </summary>
    /// <remarks>
    /// The first row also has to carry the clause-number collision, because the companion specification's
    /// central procedure and the trusted-list specification this arc DID implement are both numbered clause
    /// 4.4 — a reader skimming for a clause-4.4 qualification determination in the shipped code would wrongly
    /// conclude the requirement is already satisfied.
    /// </remarks>
    [TestMethod]
    public void TheBankedGapAndTheClosedFlagAreCitedAtTheirOwnRows()
    {
        RequirementMatrixRow suitability = RowFor("OVR-A-02A");
        Assert.AreEqual(RequirementCoverageStatus.OutOfScope, suitability.Status);
        Assert.Contains("119 172-4", suitability.Evidence, StringComparison.Ordinal);
        Assert.Contains("119 615", suitability.Evidence, StringComparison.Ordinal);
        Assert.Contains("clause 4.4", suitability.Evidence, StringComparison.Ordinal);

        RequirementMatrixRow tokenProfile = RowFor("OVR-9.2-02");
        Assert.AreEqual(RequirementCoverageStatus.Tested, tokenProfile.Status);
        Assert.Contains("319 422", tokenProfile.Evidence, StringComparison.Ordinal);
        Assert.Contains("owner flag", tokenProfile.Evidence, StringComparison.Ordinal);
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
    /// The protocol section covers at least the ninety-five statements the operation and shared-component
    /// clauses enumerate, which is the figure the preflight index gives for that document.
    /// </summary>
    /// <remarks>
    /// The leg promises a count table in a section it does not contain, so the figure is re-derived here from
    /// the clauses themselves: clause 5.3 (the base types and the eight operations) and clause 5.4 (the nine
    /// shared components) are what the index counted. The matrix carries more than the figure, because the
    /// container extensions of clause 5.5, the hash-only payload of clause 5.6, the format and scheme
    /// requirements of clauses 6 and 7, and Annexes A, F, G, H and I are normative too and are enumerated by
    /// the same leg.
    /// </remarks>
    [TestMethod]
    public void TheProtocolSectionCoversTheOperationAndComponentClausesInFull()
    {
        List<string> clauseFiveRows = [.. RowData
            .Select(row => row.ClauseId)
            .Where(clauseId => clauseId.StartsWith("512-5.3.", StringComparison.Ordinal) || clauseId.StartsWith("512-5.4.", StringComparison.Ordinal))];

        Assert.IsGreaterThan(94, clauseFiveRows.Count, "Clauses 5.3 and 5.4 carry the ninety-five statements the preflight index counts for this document.");
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
        Type? evidenceType = typeof(PreservationRequirementsMatrixTests).Assembly.GetTypes()
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


    /// <summary>Determines whether a requirement identifier belongs to the preservation-service specification.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when it carries the requirement grammar or the clause prefix of that document.</returns>
    private static bool IsPreservationServiceRow(string clauseId) =>
        IsGrammaredRequirementIdentifier(clauseId) || clauseId.StartsWith(PreservationServiceClausePrefix, StringComparison.Ordinal);


    /// <summary>Determines whether a requirement identifier belongs to the preservation-protocol specification.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when it carries that document's clause prefix.</returns>
    private static bool IsPreservationProtocolRow(string clauseId) =>
        clauseId.StartsWith(PreservationProtocolPrefix, StringComparison.Ordinal);


    /// <summary>Determines whether a requirement identifier is one the preservation-service specification's clause-3.4 grammar states.</summary>
    /// <param name="clauseId">The identifier to classify.</param>
    /// <returns><see langword="true"/> when it opens with one of the two element-of-service letters.</returns>
    private static bool IsGrammaredRequirementIdentifier(string clauseId) =>
        clauseId.StartsWith("OVR-", StringComparison.Ordinal) || clauseId.StartsWith("PRP-", StringComparison.Ordinal);


    /// <summary>Reads the requirement identifiers the shipped claim-identifier registry allocates for the preservation-service specification.</summary>
    /// <returns>Every allocated identifier, as the registry describes it.</returns>
    private static List<string> RequirementIdentifiersOfTheRegistry() =>
        DescriptionsOf(PreservationClaimIds.IsPreservationServiceRequirement);


    /// <summary>Reads the descriptions of every claim identifier the registry allocates in one band.</summary>
    /// <param name="band">The band membership test.</param>
    /// <returns>The descriptions, which are the source specifications' own identifier strings.</returns>
    private static List<string> DescriptionsOf(Func<ClaimId, bool> band)
    {
        List<string> descriptions = [];
        foreach(PropertyInfo property in typeof(PreservationClaimIds).GetProperties(BindingFlags.Public | BindingFlags.Static))
        {
            if(property.PropertyType == typeof(ClaimId))
            {
                var claimId = (ClaimId)property.GetValue(null)!;
                if(band(claimId))
                {
                    descriptions.Add(claimId.ToString());
                }
            }
        }

        return descriptions;
    }


    /// <summary>The clause-4 model rows and the strategy rows that must be present whatever else the matrix carries.</summary>
    private static string[] ClauseFourModelRowIdentifiers { get; } =
    [
        "511-4.1.2", "511-4.1.3", "511-4.1.4", "511-4.1-external", "511-4.1-monitoring",
        "511-4.2-pgd", "511-4.2-pds", "511-4.2-pds-pgd", "511-4.2-aug",
        "511-4.2-strategy-fail", "511-4.2-strategy-partial", "511-4.2-strategy-retry",
        "511-4.2-hash-only",
        "511-4.3.1", "511-4.3.2", "511-4.3.2-identifiers", "511-4.3.3", "511-4.3.4", "511-4.3.5",
        "511-4.4-factors", "511-4.4-conditions", "511-4.5"
    ];


    /// <summary>The rows recording the archival-reference-model term-consistency findings.</summary>
    private static string[] TermConsistencyRowIdentifiers { get; } =
    [
        "511-oais-1.4-1", "511-oais-1.4-4-poc", "512-oais-1.4-4-xaip"
    ];


    /// <summary>
    /// Every row of ETSI TS 119 511 V1.2.1, in the document's own order: the clause-4 model the later tags
    /// refer to, then clause 5 (risk assessment), clause 6 (policies and practices), clause 7 (management and
    /// operation), clause 8 (the two protocols), clause 9 (the preservation process), Annex A (the qualified
    /// service), and the informative annexes whose content is load-bearing for the audit trail.
    /// </summary>
    /// <remarks>
    /// The tags in square brackets are the document's own applicability tags: <c>[WST]</c>/<c>[WTS]</c>/
    /// <c>[WOS]</c> name the storage model a requirement binds under, <c>[PGD]</c>/<c>[PDS]</c>/
    /// <c>[PDS+PGD]</c>/<c>[AUG]</c> the preservation goal, and <c>[CONDITIONAL]</c> a requirement whose own
    /// antecedent has to hold first. Annex A NOTE 1 makes the goal tags decide which requirements bind a
    /// qualified service, so dropping them from the row text would lose the applicability the matrix is read
    /// for.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] PreservationServiceRows { get; } =
    [
        ("511-4.1.2", "[WST] With Storage: the service stores the submitted data objects, the preservation objects derived from them and their evidences for a defined preservation period, delivers evidences on request, and supports update and deletion.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheGoalsAndStorageModelsRecogniseTheirOwnMembersOnly (the model is carried as the value WithStorage, and PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated is the half that gates retrieval and deletion on it)"),
        ("511-4.1.3", "[WTS] With Temporary Storage: the service stores the submitted data objects or their hash values only until the evidence is produced, then deletes them; evidences are produced asynchronously and retrievable during a preservation evidence retention period.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.ATemporaryStorageProfileOwesTheRetentionPeriodAndIsOnlyRecommendedTheDuration (the retention period is the item this model alone owes)"),
        ("511-4.1.4", "[WOS] Without Storage: the service stores neither the data, nor a hash of it, nor the evidences; the evidence is produced synchronously and returned in the response, and only action traces are kept.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheGoalsAndStorageModelsRecogniseTheirOwnMembersOnly (the model is carried as the value WithoutStorage, and the synchronous echo it implies is the response shape of row 512-5.3.3.2.1-2)"),
        ("511-4.1-external", "All three storage models can contact external trust service providers — certificate status authorities, time-stamping authorities, signature creation services and validation services — to retrieve the information an evidence needs.",
            RequirementCoverageStatus.ServiceOperational, "TimestampAcquisitionTests.AcquireAsyncRunsTheFullRequestTransportVerifyRoundTrip (the time-stamping-authority client; OcspRevocationCheckerTests.ReportsGoodWhenTheResponderConfirmsGoodStatus is the certificate-status half. Which authorities a deployment contacts is its own topology)"),
        ("511-4.1-monitoring", "All three storage models monitor the cryptographic algorithms used for the evidences and augment them, or change the set of applicable algorithms, when needed.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnAlgorithmPastItsTrustedUntilInstantMakesAugmentationDue (the clause-4 preview of OVR-7.14 and OVR-7.15)"),

        ("511-4.2-pgd", "[PGD] Preservation of General Data: the goal is to produce evidence that data, signed or not, have not been altered and existed at a certain time. No validity-status tracking and no validation-data collection obligation.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheGoalsAndStorageModelsRecogniseTheirOwnMembersOnly (the goal is carried as its own uniform resource identifier; PreservationHashOnlySubmissionTests.AnAcceptedSubmissionCarriesTwoGoalTreatmentsAtOnce shows the treatment it names)"),
        ("511-4.2-pds", "[PDS] Preservation of Digital Signatures: the ability to validate a signature and to maintain its validity status is extended by collecting, verifying and protecting all needed validation data using digital signature techniques.",
            RequirementCoverageStatus.Tested, "EvidenceRecordSignatureValidationTests.AnEvidenceRecordProvesAnExpiredCertificateSignatureAndCarriesItToTotalPassed (the goal reached end to end through the shipped validation engine)"),
        ("511-4.2-pds-pgd", "[PDS+PGD] Both goals at once: the signature's validity is preserved and a separate proof of existence is produced for the signed data.",
            RequirementCoverageStatus.Tested, "AsicCapstoneFirewalledFlowTests.FirewalledCapstoneReachesTotalPassedFromContainerBytesAloneWithProofsFromTheRecordAndTheArchiveChain (one container proving both the signature and the data objects beside it)"),
        ("511-4.2-aug", "[AUG] Augmentation: the service accepts one or more externally produced preservation evidences and augments them. NOTE 5 distinguishes this from ordinary OVR-7.15 housekeeping over internally stored evidence.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ATimestampRenewalAppendsToTheChainItRenews (both renewal procedures accept an existing sequence whatever produced it, which is what the goal asks for)"),
        ("511-4.2-strategy-fail", "[PDS] Strategy one of the three OVR-6.2-06 obliges a service to choose between when validation data cannot be fully collected: fail the preservation request.",
            RequirementCoverageStatus.ServiceOperational, "SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm (the library reports the unmet condition the strategy branches on; which branch a service takes is its policy)"),
        ("511-4.2-strategy-partial", "[PDS] Strategy two: preserve what validation data could be collected and record that the set is partial.",
            RequirementCoverageStatus.ServiceOperational, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem (the placement surface takes whatever material the caller collected, complete or not)"),
        ("511-4.2-strategy-retry", "[PDS] Strategy three: retry the collection later.",
            RequirementCoverageStatus.ServiceOperational, "CAdESSignatureAugmentationTests.MaterialAddedAfterTheArchiveTimestampLeavesItValid (material collected later can still be placed into a signature already protected, which is what makes the retry strategy reachable)"),
        ("511-4.2-hash-only", "A preservation submitter may submit only a hash of the signed document rather than the document itself; the service is then responsible only for the preservation of the submitted hashes and has no way of checking what they correspond to.",
            RequirementCoverageStatus.Tested, "PreservationHashOnlySubmissionTests.AnAcceptedSubmissionCarriesTwoGoalTreatmentsAtOnce"),

        ("511-4.3.1", "The preservation service practice statement states HOW the service meets its policies.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a practice statement is a document a provider writes and publishes."),
        ("511-4.3.2", "The preservation service policy states WHAT the service undertakes, and a provider's documentation carries an object identifier saying whether it claims the unqualified or the Annex-A-qualified branch.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.TheDocumentationObjectIdentifiersAreTheTwoTheClauseStates"),
        ("511-4.3.2-identifiers", "The two object identifiers clause 4.3.2 states for a provider's documentation: the main policy branch and the qualified branch beside it.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.TheDocumentationObjectIdentifiersAreTheTwoTheClauseStates"),
        ("511-4.3.3", "A preservation scheme is the generic, specification-level recipe; a preservation profile is the concrete, implementation-level instance referencing a scheme.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne (the scheme identifiers) and PreservationProfileConformanceTests.AProfileStatingEveryItemIsConformant (the profile that instantiates one)"),
        ("511-4.3.4", "The preservation evidence policy states how evidence is created and validated, and is referenced by the profile.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.AProfileStatingEveryItemIsConformant (the reference is one of the profile's own items)"),
        ("511-4.3.5", "[PDS][PDS+PGD] The signature validation policy states how validation data is obtained, and is referenced by the profile when the client does not supply that data.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.APolicyWhoseConditionNoProfileCarriesIsUndecidedRatherThanConformant (the conditional second policy reference, undecidable from a profile alone and never read as conformance)"),

        ("511-4.4-factors", "[WTS][WOS] The expected evidence duration rests on six factors: private-key validity, certificate validity, the revocation-request window, the revocation-information availability window, the hash-collision-resistance window and the public-key-attack-resistance window.",
            RequirementCoverageStatus.ServiceOperational, "PreservationAugmentationDecisionTests.AnEvidenceWhoseAlgorithmsAreReliablePastTheLeadIsSound (the two cryptographic windows are read off the constraints table; publishing a duration figure is the provider's own act)"),
        ("511-4.4-conditions", "A preservation evidence stays valid as long as no certificate within it was revoked for key compromise, no public key within it is subject to cryptographic attack, and no hash function within it is subject to collision attack.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnAlgorithmPastItsTrustedUntilInstantMakesAugmentationDue (the two cryptographic conditions) beside OcspRevocationCheckerTests.ReportsRevokedWhenTheResponderConfirmsRevokedStatus (the revocation condition)"),
        ("511-4.5", "[WST] The preservation period is the window a with-storage service keeps the preservation objects and their evidences for.",
            RequirementCoverageStatus.ServiceOperational, "PreservationAsicExtensionTests.ThePreservationPeriodRoundTripsAsACalendarDate (the companion standard's container extension carries the period; deciding and honouring it is the provider's)"),

        ("OVR-5-01", "The requirements of ETSI EN 319 401 clause 5 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to a trust-service-provider policy standard whose text this repository does not hold; its risk-assessment process is an organizational activity with no library surface."),

        ("OVR-6.1-01", "The requirements of ETSI EN 319 401 clause 6.1 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to a trust-service-provider policy standard whose text this repository does not hold."),
        ("OVR-6.1-02", "The provider should list, reference and briefly describe the supported preservation service policies in its practice statement.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: what a practice statement lists is a document's content."),
        ("OVR-6.1-03", "The provider shall list the supported preservation profiles in its practice statement.",
            RequirementCoverageStatus.ServiceOperational, "PreservationProfileConformanceTests.AProfileStatingEveryItemIsConformant (the profile a statement lists is the shipped descriptor; listing it is the provider's act)"),
        ("OVR-6.1-04", "The provider shall state how the preservation goals are achieved.",
            RequirementCoverageStatus.ServiceOperational, "PreservationProfileConformanceTests.EveryObligationTakenAwayMakesTheProfileNonConformant (a profile owes its goals, which is the machine-readable half of the statement)"),
        ("OVR-6.1-05", "The provider shall define how the availability of the submitted data objects and of the evidences is achieved.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: availability is a property of a deployment, not of a format."),
        ("OVR-6.1-06", "The provider shall identify the obligations of external organizations, including the applicable policies and practices.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an obligation on another organization is a contractual statement."),
        ("OVR-6.1-07", "[WST] The provider shall state the details of the export-import package request process.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: the request process is a documented procedure. The package's own content shape is OVR-7.16-01."),
        ("OVR-6.1-08", "[WST] The provider shall specify the methods by which export-import packages are produced.",
            RequirementCoverageStatus.ServiceOperational, "PreservationContainerProfileTests.AContainerTheProfileCreatedSatisfiesTheProfile (a production method a provider can specify; which one it specifies is its own choice)"),
        ("OVR-6.1-09", "[WST] The provider shall specify what happens to the data at the end of the preservation period.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an end-of-period disposition is a data-lifecycle policy."),

        ("OVR-6.2-01", "The requirements of ETSI EN 319 401 clause 6.2 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to a trust-service-provider policy standard whose text this repository does not hold."),
        ("OVR-6.2-02", "The provider shall list all supported preservation service policies in its terms and conditions.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: terms and conditions are a published document."),
        ("OVR-6.2-03", "The provider shall state where information about the supported profiles can be found.",
            RequirementCoverageStatus.ServiceOperational, "PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated (the discovery operation RetrieveInfo is where a client finds them; naming the place is the provider's)"),
        ("OVR-6.2-04", "[CONDITIONAL] When the submitter may take a role in the preservation process, for instance by supplying validation data, the provider shall describe the conditions and the split of responsibilities.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a split of responsibilities is a contractual statement."),
        ("OVR-6.2-05", "[WST] The provider shall state how an export-import package can be requested.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a request channel is a documented procedure."),
        ("OVR-6.2-06", "[PDS] The provider shall state its strategy when it is unable to collect or verify all the validation data: fail, preserve what could be collected, or retry the collection later.",
            RequirementCoverageStatus.ServiceOperational, "SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm (the mechanism behind each of the three strategies is shipped and is itemised at rows 511-4.2-strategy-fail, -partial and -retry; the choice and its publication are the provider's)"),
        ("OVR-6.2-07", "[CONDITIONAL] When hash values for a hash-tree renewal may be submitted by the client, the provider shall state in its terms and conditions that it is not liable for their correspondence to the original hash tree.",
            RequirementCoverageStatus.ServiceOperational, "PreservationDigestListTests.DataObjectsThatDisagreeWithTheSubmittedDigestValuesAreRefused (the library checks the correspondence wherever the caller supplies the objects, which is exactly the case the disclaimer is written for; the disclaimer itself is legal text)"),
        ("OVR-6.2-08", "[CONDITIONAL] When only hashes of the objects may be submitted, the provider shall state that the preservation covers only the submitted hashes and that the validity of the existence proof depends on the hash algorithm's strength.",
            RequirementCoverageStatus.ServiceOperational, "PreservationHashOnlySubmissionTests.AnAcceptedSubmissionCarriesTwoGoalTreatmentsAtOnce (the submitted hash is treated as general data, which is what the statement discloses)"),

        ("OVR-6.3-01", "The requirements of ETSI EN 319 401 clause 6.3 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to a trust-service-provider policy standard whose text this repository does not hold."),

        ("OVR-6.4-01", "A preservation service shall support at least one preservation profile.",
            RequirementCoverageStatus.ServiceOperational, "PreservationProfileConformanceTests.AProfileStatingEveryItemIsConformant (the profile a service supports; how many it deploys is its own configuration)"),
        ("OVR-6.4-02", "A preservation service may support more than one preservation profile.",
            RequirementCoverageStatus.ServiceOperational, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing (a discovery response carries as many profiles as a service publishes)"),
        ("OVR-6.4-03", "A preservation profile shall be uniquely identified.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.EveryItemCarriesTheDocumentsOwnRequirementIdentifier (the identifier is one of the sixteen items; whether it is unique ACROSS the profiles one service publishes is a fact about a service and rides on the row as a detail rather than being claimed)"),
        ("OVR-6.4-04", "A preservation profile shall contain the content items a) to j): its identifier, its supported operations with their formats, its applicable technical policy set, its validity period, its storage model, its goals, its evidence formats, optionally a specification reference, a human-readable description, and optionally a scheme identifier.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.AProfileStatingEveryItemIsConformant (the whole item map) and PreservationProfileConformanceTests.EveryObligationTakenAwayMakesTheProfileNonConformant (each obligation taken away in turn)"),
        ("OVR-6.4-05", "[WTS] The preservation profile shall contain the preservation evidence retention period.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.ATemporaryStorageProfileOwesTheRetentionPeriodAndIsOnlyRecommendedTheDuration (the companion standard's own Table 21 maps this identifier to the expected evidence duration instead, which is the other way round from this clause; the library follows this clause's text and both stages that read it independently reached the same reading)"),
        ("OVR-6.4-06", "[WTS][WOS] The preservation profile should contain the expected evidence duration.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.OnlyTheItemsTheDocumentSoftensAreSoftened (a recommendation, not an obligation; the companion standard's Table 21 maps this identifier to the retention period instead, which is the interchange recorded at the row above)"),
        ("OVR-6.4-07", "[WTS][WOS] The expected evidence duration shall be based on the estimated suitability of the cryptographic algorithms.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnEvidenceWhoseAlgorithmsAreReliablePastTheLeadIsSound (the estimate is read off the constraints table's per-algorithm trusted-until instants)"),
        ("OVR-6.4-08", "[WTS][WOS] That estimate should be based on ETSI TS 119 312.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnEvidenceWhoseAlgorithmsHaveNoAssertedExpiryIsSoundWithNoDeadline (the constraints table is caller-supplied and shaped for exactly that publication, and a table asserting no expiry schedules nothing rather than defaulting to sound)"),
        ("OVR-6.4-09", "The supported preservation profiles shall be available online.",
            RequirementCoverageStatus.ServiceOperational, "PreservationSeamTests.AStandInServiceAnswersThroughTheOperationSeams (the discovery operation's seam; hosting it is the provider's)"),
        ("OVR-6.4-10", "A preservation service shall publish all the profiles it supports or has supported.",
            RequirementCoverageStatus.ServiceOperational, "PreservationVocabularyTests.TheStatusVocabularyCarriesTheProseOnlyThirdValueAndKeepsBothReadingsApart (the status filter is what lets a client ask for the inactive profiles too; publishing them is the provider's)"),
        ("OVR-6.4-11", "[WST] The same preservation profile shall apply for the whole preservation period.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an invariant over a service's own history, which no single message can carry."),
        ("OVR-6.4-12", "[WTS] The same preservation profile shall apply for the whole preservation evidence retention period.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: the same invariant over the retention window."),
        ("OVR-6.4-13", "A preservation profile should not change over time, and its dynamic aspects should live outside it.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a versioning discipline over published documents."),
        ("OVR-6.4-14", "The evidence and validation policies a profile references may change over time, but all versions shall stay publicly available and it shall be clear which version applied when.",
            RequirementCoverageStatus.ServiceOperational, "PreservationProfileConformanceTests.AnEvidenceNamingAnotherProfileDisagreesWithIt (an evidence carrying its own policy and profile identifiers is what makes which-version-applied answerable from the artifact; publishing every version is the provider's)"),

        ("OVR-6.5-01", "The preservation evidence policy may be in human-readable form.",
            RequirementCoverageStatus.OutOfScope, "A permission about the form of a document; it constrains nothing this library produces."),
        ("OVR-6.5-02", "[CONDITIONAL] If the policy exists in several formats or languages, the provider shall state which takes precedence.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a precedence rule between documents."),
        ("OVR-6.5-03", "The preservation evidence policy shall describe how the evidence is created, including which cryptographic algorithms are used.",
            RequirementCoverageStatus.ServiceOperational, "PreservationAugmentationDecisionTests.AUseNoRowMentionsNeverReachesASoundDecision (the algorithms in use are the decision function's own input; describing them in a policy document is the provider's)"),
        ("OVR-6.5-04", "The algorithms should be chosen per ETSI TS 119 312.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnAlgorithmTheTableDoesNotListLeavesTheDecisionUndecidable (an algorithm outside the table can never read as sound, which is what makes the table the choosing authority)"),
        ("OVR-6.5-05", "The policy shall describe which trust service providers — signature creation, time-stamping and certificate status — may be used.",
            RequirementCoverageStatus.ServiceOperational, "TimestampAcquisitionTests.AcquireAsyncRunsTheFullRequestTransportVerifyRoundTrip (the authority a service contacts is caller-supplied at the seam; naming the admitted ones is the provider's)"),
        ("OVR-6.5-06", "The policy shall describe how the evidence can be validated, naming the trust anchors that validate the digital signatures within it and those that validate the time-stamps within it.",
            RequirementCoverageStatus.ServiceOperational, "TrustedListQualificationTests.QualifiedCertificateDeterminationMatchesEverySpecificationTableCell (the trust-anchor material a policy names is modelled and evaluated; authoring the policy is the provider's)"),
        ("OVR-6.5-07", "[WST][WTS] The policy shall state how the evidence is augmented.",
            RequirementCoverageStatus.ServiceOperational, "EvidenceRecordRenewalTests.AHashTreeRenewalStartsANewChainUnderTheNewAlgorithm (the augmentation the policy describes; describing it is the provider's)"),
        ("OVR-6.5-08", "The policy shall describe the evidence format.",
            RequirementCoverageStatus.ServiceOperational, "PreservationVocabularyTests.TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase (every candidate format has a registered identifier a policy can name)"),
        ("OVR-6.5-09", "The policy shall state whether and how the evidence carries explicit information about a) the applicable preservation service, b) the preservation evidence policy, and c) the preservation profile.",
            RequirementCoverageStatus.Tested, "PreservationEvidenceAttributeTests.TheStandardisedAttributesAndTheHouseSelfDescriptionSayTheSameThreeThings (the three items in the companion standard's own attributes and in this library's convention, read through one code path) and EArkEvidenceSelfDescriptionTests.TheThreeCarriersHoldTheSameOctets"),

        ("OVR-6.6-01", "The signature validation policy may be in human-readable form.",
            RequirementCoverageStatus.OutOfScope, "A permission about the form of a document; it constrains nothing this library produces."),
        ("OVR-6.6-02", "[CONDITIONAL] If the policy exists in several formats or languages, the provider shall state which takes precedence.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a precedence rule between documents."),
        ("OVR-6.6-03", "[CONDITIONAL] If a signature validation policy is present, it shall state the validation-material selection strategy, including the trust anchors and the validation model.",
            RequirementCoverageStatus.ServiceOperational, "SignatureValidationLongTermBlockTests.PastCertificateValidationPassesAtTheControlTimeAssignedByARevokedIntermediate (the validation model the policy selects is a knob of the shipped engine; the policy document itself has no machine-readable form in this version of the specification)"),

        ("OVR-6.7-01", "The provider shall make a subscriber agreement available that includes acceptance of the terms and conditions.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a subscriber agreement is a contract."),
        ("OVR-6.7-02", "[CONDITIONAL] If a notification protocol exists, the agreement shall state whether and how the subscriber is notified.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: the notification protocol is out of scope by clause 8.2's own words."),
        ("OVR-6.7-03", "[CONDITIONAL] The agreement shall be updated whenever a notification channel is added or removed.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a contract-maintenance obligation."),
        ("OVR-6.7-04", "[WTS][WST] The agreement shall state who may access the preservation objects.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an access-control policy; the protocol's own refusal is the noPermission result code of row 512-5.3.4.2-errors."),
        ("OVR-6.7-05", "[WTS][WST] The agreement shall state who may request the action traces of a preservation object.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an access-control policy over the trace-retrieval operation."),

        ("OVR-7.1-01", "The requirements of ETSI EN 319 401 clause 7.1 (internal organization) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.2-01", "The requirements of ETSI EN 319 401 clause 7.2 (human resources) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.3-01", "The requirements of ETSI EN 319 401 clause 7.3 (asset management) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.4-01", "The requirements of ETSI EN 319 401 clause 7.4 (access control) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.6-01", "The requirements of ETSI EN 319 401 clause 7.6 (physical and environmental security) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.7-01", "The requirements of ETSI EN 319 401 clause 7.7 (operation security) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.9-01", "The requirements of ETSI EN 319 401 clause 7.9 (incident management) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.11-01", "The requirements of ETSI EN 319 401 clause 7.11 (business continuity) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.13-01", "The requirements of ETSI EN 319 401 clause 7.13 (compliance) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.17-01", "The requirements of ETSI EN 319 401 clause 7.14 (supply chain) shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),

        ("OVR-7.5-01", "The requirements of ETSI EN 319 401 clause 7.5 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.5-02", "The provider shall ensure the preservation time-stamps come from a state-of-the-art time-stamping authority, which should conform to ETSI EN 319 421.",
            RequirementCoverageStatus.ServiceOperational, "TimestampAcquisitionTests.VerifiesAGrantedResponseCarryingAMatchingToken (the request-and-verify mechanism; selecting the authority is the provider's)"),
        ("OVR-7.5-03", "The provider should only use time-stamps that can be verified through a certificate revocation list or an online status response carrying a reason code on revocation.",
            RequirementCoverageStatus.ServiceOperational, "RevocationSourceFactsExtractorTests.ExtractsEveryUriAndSkipsNonUriFormsFromAMintedCertificate (the revocation sources a token's certificate names are read and followed; choosing an authority that publishes them is the provider's)"),
        ("OVR-7.5-04", "[CONDITIONAL] When the provider signs part of an evidence, its signing certificate should be issued by a certification authority conformant to ETSI EN 319 411-1 or -2.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a certificate-procurement criterion."),
        ("OVR-7.5-05", "[CONDITIONAL] The provider's signing key shall be held in a secure cryptographic device meeting either a common-criteria assurance level or a cryptographic-module security level.",
            RequirementCoverageStatus.OutOfScope, "A hardware-assurance property of a deployment environment; no software library can satisfy or verify it."),
        ("OVR-7.5-06", "[CONDITIONAL] That device should meet the common-criteria alternative specifically.",
            RequirementCoverageStatus.OutOfScope, "A hardware-assurance property of a deployment environment."),
        ("OVR-7.5-07", "[CONDITIONAL] Backup copies of the signing key shall be protected for integrity and confidentiality by the secure device before leaving it.",
            RequirementCoverageStatus.OutOfScope, "A hardware-module procedure; no library surface."),

        ("OVR-7.8-01", "The requirements of ETSI EN 319 401 clause 7.8 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.8-02", "[WST] Storage access that changes content shall be routable only through the preservation service.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a deployment topology."),

        ("OVR-7.10-01", "The requirements of ETSI EN 319 401 clause 7.10 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.10-02", "The preservation service shall implement event logs so that later proofs can be produced.",
            RequirementCoverageStatus.ServiceOperational, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the trace response's Trace is the protocol's own reading of such a log; keeping the log is the provider's)"),

        ("OVR-7.12-01", "The requirements of ETSI EN 319 401 clause 7.12 shall apply.",
            RequirementCoverageStatus.OutOfScope, "Pure delegation to an organizational standard whose text this repository does not hold."),
        ("OVR-7.12-02", "[WST] The termination plan shall cover what happens to the stored preservation objects at termination.",
            RequirementCoverageStatus.ServiceOperational, "PreservationContainerProfileTests.AContainerTheProfileCreatedSatisfiesTheProfile (a container a terminating service can hand over; the plan itself is a document)"),

        ("OVR-7.14-01", "For every active profile the provider shall monitor the strength of every cryptographic algorithm used with it, and shall update the preservation evidence policy or create a new profile for newly submitted objects when an algorithm or parameter is thought to weaken or a relevant certificate approaches expiry.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnAlgorithmExpiringInsideTheStatedLeadMakesAugmentationDue (the detection trigger; the certificate half is deliberately outside this function and is a fact about a chain the shipped chain machinery answers, which is recorded at the class)"),
        ("OVR-7.14-02", "[WST][CONDITIONAL] When an algorithm or parameter used in an existing preservation evidence weakens, or a relevant certificate approaches expiry, that evidence shall be augmented under a new policy version during the preservation period.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnAlgorithmPastItsTrustedUntilInstantMakesAugmentationDue (the same detection scoped per evidence; the augmentation act itself is OVR-7.15-03)"),
        ("OVR-7.14-03", "ETSI TS 119 312 should be considered for the evaluations of OVR-7.14-01 and OVR-7.14-02.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.MovingATrustedUntilInstantLaterNeverMakesADecisionMoreUrgent (the property that makes the table the sole authority over the decision's urgency)"),

        ("OVR-7.15-01", "[WST] During the preservation period the service shall ensure the evidence can still achieve its preservation goal.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.AnEvidenceWhoseAlgorithmsAreReliablePastTheLeadIsSound (the ongoing-validity assertion computed at an instant)"),
        ("OVR-7.15-02", "[WTS] During the preservation evidence retention period the service shall ensure the same.",
            RequirementCoverageStatus.Tested, "PreservationAugmentationDecisionTests.TheSameQuestionAlwaysAnswersTheSameDecision (the same computation over a different window, deterministic over its inputs)"),
        ("OVR-7.15-03", "[WST][WTS] The service shall augment the evidences before they can no longer achieve the goal. NOTE 2 names incorporating time-stamps and validation data for a signature; NOTE 3 names time-stamp renewal and hash-tree renewal for an evidence record.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.EveryPriorChainStillVerifiesAfterEachRenewal (both renewal procedures NOTE 3 names) beside CAdESSignatureAugmentationTests.IncludesTheValidationMaterialBeforeGeneratingTheArchiveTimestamp (NOTE 2's route) and PreservationAugmentationDecisionTests.AnAlgorithmExpiringInsideTheStatedLeadMakesAugmentationDue (the before-it-expires timing, whose lead is required rather than defaulted)"),

        ("OVR-7.16-01", "[WST] The provider shall allow the client, or another authorized preservation service, to request export-import packages containing the preserved data, the evidences and all the information needed to validate the evidences.",
            RequirementCoverageStatus.Tested, "PreservationContainerProfileTests.AContainerTheProfileCreatedSatisfiesTheProfile (a container carrying the data objects and the evidence record over them; the validation material it may carry beside them is CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem)"),
        ("OVR-7.16-02", "[WST] The provider should use a standardized export-import package format.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase (the registered container formats a provider can choose between)"),
        ("OVR-7.16-03", "[WST] Packages shall only be delivered to an authorized legal or natural person.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an authorization decision, not a container property."),
        ("OVR-7.16-04", "[WST] The provider shall keep records of every released package: the date of the event and the selection criteria used.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an audit-logging obligation."),

        ("PRP-8.1-01", "The channel between the client and the provider shall be secured: the provider shall offer client authentication and shall ensure the confidentiality of the data.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: transport security is supplied by the caller's transport, which this library deliberately does not take a dependency on."),
        ("PRP-8.1-02", "The preservation protocol of ETSI TS 119 512 should be used.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType (that protocol's whole message vocabulary is the second section of this matrix)"),
        ("PRP-8.1-03", "The protocols shall be protected against unauthorized usage.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: an authorization decision; the protocol's own refusal is the noPermission result code."),
        ("PRP-8.1-04", "A preservation service shall allow retrieving information about the currently and previously supported profiles, for example through RetrieveInfo.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists (the discovery message pair) and PreservationVocabularyTests.TheStatusVocabularyCarriesTheProseOnlyThirdValueAndKeepsBothReadingsApart (the filter that reaches the previously supported ones)"),
        ("PRP-8.1-05", "A preservation service shall allow submitting one or more submitted data objects under a named profile, returning either a preservation object identifier or, synchronously, an evidence.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the submission request obliges the profile and the response's identifier is conditionally mandatory, which no type can state)"),
        ("PRP-8.1-06", "A preservation service may allow retrieving the traces of all the operations performed for a preservation object identifier, for example through RetrieveTrace.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the trace response obliges the trace itself)"),
        ("PRP-8.1-07", "A preservation service may allow searching for preservation objects, returning a set of identifiers, for example through Search.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the search request obliges nothing and the response carries the identifiers)"),
        ("PRP-8.1-08", "A preservation service may allow submitting a preservation evidence and the sequence of preservation objects it protects for validation, returning a validation report, for example through ValidateEvidence.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the validation request obliges the evidence, which the prose makes mandatory although the reproduced schema does not)"),
        ("PRP-8.1-09", "[CONDITIONAL] If searching is supported, it may include a filter facility.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.AProfileOwesTheCardinalitiesItsOwnClauseStates (the query language a filter is written in is announced by the profile's own operation catalogue; the filter itself is an opaque string)"),
        ("PRP-8.1-10", "[WST] A with-storage service shall allow retrieving the evidences and the preservation objects, for example through RetrievePO.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated (the retrieval operation and its storage-model gate)"),
        ("PRP-8.1-11", "[WST] A with-storage service shall allow deleting stored preservation objects, and deleting the evidence shall delete the corresponding submitted data object with it.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheDeletionModesSubjectsAndVersionSentinelRecogniseTheirOwnMembersOnly (the two deletion modes, one of which is the cascade this requirement states)"),
        ("PRP-8.1-12", "[WST] A stored preservation object may only be deleted before the end of the preservation period when the request carries a justification, and every justification shall be logged with the request.",
            RequirementCoverageStatus.ServiceOperational, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists (the deletion request carries the requestor name and the reason the justification rides in; logging it is the provider's)"),
        ("PRP-8.1-13", "[WST] A with-storage service should allow requesting a set of preservation object identifiers usable in the submission and trace operations.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType (the search response's identifiers are the same string type the other operations address objects by)"),
        ("PRP-8.1-14", "[WST] A with-storage service may allow submitting a new version of a preservation object container, which may state only the difference to the existing one.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ADeltaIsAPreservationObjectUnderAnotherElementName (the update message and its deltas; the delta preservation object CONTAINER — a container describing only the difference — is out of this wave per the contract's Out list and has no shipped format)"),
        ("PRP-8.1-15", "[WTS] A with-temporary-storage service shall allow retrieving the asynchronously produced evidences.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated (the retrieval operation is admitted under this storage model too, which is what the gate states)"),

        ("OVR-8.2-01", "A preservation service may define a notification protocol to message its subscribers. The NOTE states that how this is done is out of the scope of the document.",
            RequirementCoverageStatus.OutOfScope, "The specification disclaims defining it, and the companion protocol standard's own definitions clause repeats that the notification interface is not addressed."),
        ("OVR-8.2-02", "[CONDITIONAL] When a notification protocol exists and a referenced evidence policy becomes considered insecure, the service shall notify the subscribers using that profile.",
            RequirementCoverageStatus.ServiceOperational, "PreservationAugmentationDecisionTests.AnAlgorithmPastItsTrustedUntilInstantMakesAugmentationDue (the becomes-insecure detection that would trigger the notification; the notification channel is out of scope by clause 8.2)"),
        ("OVR-8.2-03", "[CONDITIONAL] When a notification protocol exists and referenced elements affecting a profile change, the provider shall notify the subscribers using that profile.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: the notification channel is out of scope by clause 8.2's own NOTE."),

        ("OVR-9.1-01", "[WOS][WTS] A service without storage or with temporary storage should not store the data after the evidence has been created.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a retention decision about a service's own storage."),
        ("OVR-9.1-02", "[WOS][WTS][CONDITIONAL] If such a service does store the data after the evidence has been created, it should state why in its terms and conditions.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: a disclosure obligation."),
        ("OVR-9.1-03", "[WTS] A with-temporary-storage service shall not store an evidence longer than its practice statement states.",
            RequirementCoverageStatus.ServiceOperational, "PreservationProfileConformanceTests.ATemporaryStorageProfileOwesTheRetentionPeriodAndIsOnlyRecommendedTheDuration (the period the profile publishes is the bound; honouring it is the provider's)"),

        ("OVR-9.2-01", "[CONDITIONAL] If the service uses a time-stamp token, it shall conform to IETF RFC 3161 as updated by IETF RFC 5816.",
            RequirementCoverageStatus.Tested, "TimestampRequestsTests.BuildsAWellFormedRequestTheIndependentReaderDecodesFieldByField (the request) and TimestampAcquisitionTests.VerifiesAGrantedResponseCarryingAMatchingToken (the token, verified field by field by an independent reader)"),
        ("OVR-9.2-02", "[CONDITIONAL] If used, time-stamp tokens should conform to the ETSI EN 319 422 time-stamping protocol and token profile.",
            RequirementCoverageStatus.Tested, "Timestamp319422RequirementsMatrixTests.RequirementMatrixTest (every ETSI EN 319 422 V1.1.1 normative statement and the incorporated IETF RFC 3161 and IETF RFC 5816 client deltas is a row of that matrix, each client row driven by a named test the gate resolves through reflection; TheMatrixEnumeratesTheWholeProfile pins the enumeration complete. The flag that kept this row OutOfScope — the managed backend refusing a SHA-512-signing or at-least-3000-bit TSU following ETSI TS 119 312 — is closed by the managed-RSA widening, proven at that matrix's rows 4.2.3-sigalg and 4.2.4-keylength, which closes owner flag 1 of the wave contract)"),
        ("OVR-9.2-03", "[CONDITIONAL] If the service uses an evidence record, it shall conform to IETF RFC 4998 or IETF RFC 6283.",
            RequirementCoverageStatus.Tested, "ReferenceArtifactEvidenceRecordTests.ARenewedRecordLinksItsChainsThePositionalWay (the first format, proven against third-party artifacts) and ReferenceArtifactXmlEvidenceRecordTests.ARecordOfTheCorpusProvesADataObjectOfTheCorpus (the second, validation-side; its creation side stays an owner flag from the previous wave)"),
        ("OVR-9.2-04", "[CONDITIONAL] If the preservation evidence policy cannot be identified from the context, it should be included directly in the preservation evidence.",
            RequirementCoverageStatus.Tested, "EArkEvidencePlacementTests.APackageCarryingEachArtifactKindReachesTheConventionsClaims (the row is issued from the package the evidence sits in) and PreservationEvidenceAttributeTests.ASignedDataObjectCarriesTheAttributesAsUnsignedAttributes (the standardised carrier)"),
        ("OVR-9.2-05", "[CONDITIONAL] If the evidence policy is embedded in the evidence, it should be cryptographically protected.",
            RequirementCoverageStatus.Tested, "EArkEvidenceSelfDescriptionTests.AHashTreeRenewalIsWhatProtectsAnEvidenceRecordsSelfDescription (the answer is computed from the artifact rather than taken from the caller) and EArkEvidencePlacementTests.AnUnprotectedSelfDescriptionLeavesTheProtectionRowUnmet"),

        ("OVR-9.3-01", "[PDS][PDS+PGD][CONDITIONAL] If the validation data is not submitted by the client, the service shall make its best effort to collect and verify it per the signature validation policy.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem (the collect-and-embed path; the best-effort qualifier and the policy selection are the provider's configuration)"),
        ("OVR-9.3-02", "[PDS][PDS+PGD][CONDITIONAL] If the validation data is submitted, the service should verify it against the policy and collect its own when what was submitted is inappropriate.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.AvoidsDuplicatingMaterialTheSignatureAlreadyCarries (supplied material is read before anything is collected) and CAdESSignatureAugmentationTests.RefusesADeltaCrlWithoutTheCompleteSetAndAcceptsItWithOne (inappropriate supplied material is refused rather than embedded)"),
        ("OVR-9.3-03", "[PDS] The service shall at minimum provide a proof of existence of the signature and of the validation data needed to validate it, using digital signature techniques.",
            RequirementCoverageStatus.Tested, "EvidenceRecordSignatureValidationTests.TheReportAttributesTheProofOfExistenceToTheEvidenceRecord (the proof reaching the validation report through the shipped engine)"),
        ("OVR-9.3-04", "[PDS+PGD] The service shall additionally provide a proof of existence of the signed data itself.",
            RequirementCoverageStatus.Tested, "AsicCapstoneFirewalledFlowTests.FirewalledCapstoneReachesTotalPassedFromContainerBytesAloneWithProofsFromTheRecordAndTheArchiveChain (the data objects are proved by the record beside the signature, from the container bytes alone)"),
        ("OVR-9.3-05", "[PDS][PDS+PGD][CONDITIONAL] For a detached signature the service may allow the submitter to provide only a hash of the signed data.",
            RequirementCoverageStatus.Tested, "PreservationHashOnlySubmissionTests.AProfilesAcceptedHashFunctionsAreItsSubmissionOperationsHashInputFormats (the submission shape and the profile that admits it)"),
        ("OVR-9.3-06", "[PDS][PDS+PGD][CONDITIONAL] If hash-only submission is allowed, the provider shall state in the profile which hash-function identifiers are accepted.",
            RequirementCoverageStatus.Tested, "PreservationHashOnlySubmissionTests.AnInputFormatThatNamesNoComputableHashFunctionIsNotAnAcceptedOne (the accepted functions read off the submission operation's input formats, which is the documented interpretation of a requirement naming no element of its own)"),
        ("OVR-9.3-07", "[PDS][PDS+PGD][CONDITIONAL] The service shall treat a submitted hash value, with its hash-function identifier, as general data linked to the signature, because it cannot verify that the hash corresponds to the signed data.",
            RequirementCoverageStatus.Tested, "PreservationHashOnlySubmissionTests.AnAcceptedSubmissionCarriesTwoGoalTreatmentsAtOnce (one submission, two goal treatments: the detached signature stays under the signature goal and each submitted hash is demoted to the general-data one)"),
        ("OVR-9.3-08", "[PDS][PDS+PGD][CONDITIONAL] The service shall verify that a hash-only submission's hash-function identifier is on the profile's accepted list and that each hash value's length matches the stated identifier.",
            RequirementCoverageStatus.Tested, "PreservationHashOnlySubmissionTests.AHashFunctionTheProfileDoesNotListIsRefused (the first check) and PreservationHashOnlySubmissionTests.AHashValueOfTheWrongLengthIsRefused (the second, with the offending index named)"),

        ("OVR-A-01", "[PDS][PDS+PGD] All the untagged, [PDS]- and [PDS+PGD]-tagged requirements of clauses 5 to 9 shall apply to a qualified preservation service.",
            RequirementCoverageStatus.OutOfScope, "A meta-rule selecting which of the requirements above bind rather than a capability of its own. NOTE 1's exclusion of the [PGD]- and [AUG]-tagged rows is why the goal tags are carried in every row of this section."),
        ("OVR-A-02", "[PDS][PDS+PGD] The service shall preserve all the information needed to check the qualification status of the signature or seal that would not otherwise remain publicly available until the end of the preservation period.",
            RequirementCoverageStatus.Tested, "TrustedListQualificationTests.EvaluationBeforeCurrentStatusSelectsHistoryInstance (the determination is computed from preserved inputs at a stated instant, which is what preserving the information needed to check it makes possible) beside CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem (the preservation of those inputs)"),
        ("OVR-A-02A", "[PDS][PDS+PGD] The service shall ensure that, at any time during the preservation period, the preserved information fed as input to clause 4.4 of ETSI TS 119 172-4 yields an output clearly determining whether the signature or seal was, at preservation time, technically suitable to implement an EU-qualified signature or seal.",
            RequirementCoverageStatus.OutOfScope, "The cited procedure is clause 4.4 of ETSI TS 119 172-4, whose text is not cached anywhere in this repository and which no wave of this arc has implemented. THE COLLISION TRAP: the shipped trusted-list qualification implements clause 4.4 of ETSI TS 119 615 — a different document that happens to number its central procedure the same — and answers a different question (is this CERTIFICATE EU-qualified) from the one this requirement asks (was this SIGNATURE, at time T, technically suitable to be one). A reader matching on the clause number alone would wrongly conclude the requirement is covered. Banked as the recurring TS 119 172-family gap first recorded by the validation arc; the contract's Out list keeps it there."),
        ("OVR-A-03", "[PDS][PDS+PGD] The time-stamps within the evidence should come from a qualified time-stamping authority.",
            RequirementCoverageStatus.ServiceOperational, "TrustedListQualificationTests.TimeStampDeterminationPassesWhenBothInstantsAgree (whether an authority is qualified is determinable from the trusted list; selecting one is the provider's)"),
        ("OVR-A-04", "The service shall have one service digital identifier, per ETSI TS 119 612 clause 5.5.3, uniquely identifying it within a member state trusted list.",
            RequirementCoverageStatus.ServiceOperational, "TrustedListQualificationTests.TokenIssuerQualificationFollowsServiceStatus (a service's own trusted-list entry and its digital identity are modelled the same way every other party's are; being listed is the provider's own registration act)"),

        ("511-B-article-34", "Annex B maps Regulation (EU) 910/2014 Article 34.1 — extending the trustworthiness of a qualified signature beyond the technological validity period — onto clauses 7.14, 7.15, 9.2, 9.3 and OVR-A-02 of this document.",
            RequirementCoverageStatus.OutOfScope, "An informative mapping table rather than an obligation. It is recorded because it is independent confirmation that the clauses this matrix marks as the library-capability core are the legally load-bearing ones."),
        ("511-C.3", "Annex C.3 distinguishes a digital archival service, which demonstrates a proof of existence by audit alone, from a preservation service, which demonstrates it by audit AND digital signature techniques.",
            RequirementCoverageStatus.OutOfScope, "Informative prose drawing the boundary between this document and the archival-packaging specifications this wave also implements; it states no obligation. The technical output of this document is what an archival package would embed to gain the second of the two factors."),
        ("511-D.1", "Annex D.1: the countermeasure to hash-collision risk is to re-hash and re-protect with a stronger algorithm before the original weakens.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.AHashTreeRenewalStartsANewChainUnderTheNewAlgorithm (the re-hash under a stronger algorithm) beside PreservationAugmentationDecisionTests.AnAlgorithmExpiringInsideTheStatedLeadMakesAugmentationDue (the before-it-weakens timing)"),
        ("511-D.2", "Annex D.2: the countermeasure to signature-algorithm and key-length risk is a time assertion proving the signature existed before the attack became feasible, itself periodically re-applied over the data, its time-stamps and the corresponding validation data.",
            RequirementCoverageStatus.Tested, "EvidenceRecordRenewalTests.ATimestampRenewalBindsTheWholeTimeStampElementOfTheStructureBeforeIt (the periodic re-application over everything the structure already carried)"),
        ("511-D.3", "Annex D.3: the countermeasure to signing-key-revocation risk is to capture and protect the revocation information by a proof of existence alongside the signature.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.AddsAnArchiveTimestampTheIndependentOracleAndTheCoverageComputationBothAgreeWith (the signature and its revocation material jointly time-stamped) beside OcspRevocationCheckerTests.TheRetainingCheckKeepsTheVerifiedResponseTheStatusWasDecidedFrom (the capture of the response the status was decided from)"),

        ("511-oais-1.4-1", "Term consistency: the archival reference model's clause 1.4 item 1 asks a conforming archive to be able to map its information onto Content Information, the five Preservation Description Information categories, Packaging Information and Descriptive Information. This document uses none of that vocabulary.",
            RequirementCoverageStatus.OutOfScope, "A grep of the cached text finds zero occurrences of Designated Community, Fixity, Provenance, Content Information and Representation Information. FINDING, non-defect: the document does not claim conformance to the reference model — it cites it only as an informative reference and as one of the audit criteria an archival service can be measured against — so clause 1.4 item 4's binding rule is not engaged and there is no redefinition. What follows is that this document discharges none of the mapping obligation; the archival-packaging specifications of the sibling matrix section are where that mapping lives."),
        ("511-oais-1.4-4-poc", "Term consistency: clause 3.1's EXAMPLE 2 states that an OAIS Submission Information Package is a Preservation Object Container. The reference model defines a Submission Information Package as an Information Package delivered by a producer for use in constructing or updating archival packages, carrying Content Information and Preservation Description Information.",
            RequirementCoverageStatus.OutOfScope, "FINDING, row-level, informative: an EXAMPLE subsumes a reference-model workflow ROLE under this document's own STRUCTURAL term. A preservation object container has no slot for preservation description information or for descriptive information, so the example is a partial mapping rather than an identity. It is not a redefinition — the example claims only that such a package can serve as a container — and the same sentence appears verbatim in the companion protocol standard, where it is recorded again. Checked against clause 1.4 of the reference model as the matrix was written."),
    ];


    /// <summary>
    /// Every normative statement of ETSI TS 119 512 V1.2.1, in the document's own order: the base request and
    /// response types, the eight operations of clause 5.3, the nine shared components of clause 5.4, the
    /// container extensions of clause 5.5, the hash-only payload of clause 5.6, the format and scheme
    /// requirements of clauses 6 and 7, the two binding rule sets, and Annexes A, B, C, D, E, F, G, H and I.
    /// </summary>
    /// <remarks>
    /// The document fixes no requirement-identifier grammar, so a row is named by its clause and, where the
    /// clause states several obligations, by the statement number the preflight leg gives it. The clause-5.3
    /// and clause-5.4 rows are the ninety-five statements the preflight index counts for this document; every
    /// row after them is normative surface the same leg enumerates outside those two clauses.
    /// </remarks>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] PreservationProtocolRows { get; } =
    [
        ("512-5.2-1", "The preservation service shall support the RetrieveInfo operation. It is the one universally mandatory operation across all four schemes of Annex F.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated"),

        ("512-5.3.1.1.1-1", "The optional OptionalInputs element, if present, shall contain a sub-component defined by the external base specification.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.TheRequestBaseComponentStatesTheNamesTheOperationTablesRestate (the element is carried verbatim as octets, because the base specification's own text is not held by this repository and nothing is invented for it)"),
        ("512-5.3.1.1.1-2a", "The optional RequestID element, if present, shall contain one instance of a string.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.TheRequestBaseComponentStatesTheNamesTheOperationTablesRestate"),
        ("512-5.3.1.1.1-2b", "When a RequestID is present in a request, the preservation service shall return it in the response.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.AStandInServiceAnswersThroughTheOperationSeams (the stand-in service echoes the request identifier, which is the obligation this statement puts on a service)"),
        ("512-5.3.1.1.2-1", "The XML type RequestType shall implement the requirements defined in the Request component.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.TheHierarchyIsEightRequestsAndEightResponsesAndEveryResponseCarriesAResult (the model keeps the base type's real inheritance, which is the XML syntax's own structure)"),
        ("512-5.3.1.2.1-1", "The Response component's optional OptionalOutputs element, if present, shall contain a sub-component defined by the external base specification.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.TheResponseBaseComponentStatesTwoPairsAndOneNameWithoutAMember"),
        ("512-5.3.1.2.1-2", "The Result element shall be present in every response, carrying the major and minor status codes of the external base specification.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.TheHierarchyIsEightRequestsAndEightResponsesAndEveryResponseCarriesAResult"),
        ("512-5.3.1.2.1-3", "The Response component's optional RequestID element carries back the identifier the request stated.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.AStandInServiceAnswersThroughTheOperationSeams"),
        ("512-5.3.1-json-base", "The Request and Response components are base types only and are never JSON instances; every concrete operation's JSON object restates the base members directly rather than referencing a shared base schema.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.TheBaseNamesAreRestatedExactlyWhereTheTablesRestateThem (the eleven tables that restate the base names and the four that do not)"),

        ("512-5.3.2.1.1-1", "The RetrieveInfo request shall extend the Request component and shall inherit its sub-components.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType"),
        ("512-5.3.2.1.1-2", "The optional Profile element may be present and shall, if present, contain a uniform resource identifier naming the profile information is retrieved for.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists"),
        ("512-5.3.2.1.1-3a", "The optional Status element may be present and shall, if present, satisfy the requirements of the Status component.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists"),
        ("512-5.3.2.1.1-3b", "If the Status element is omitted, only active preservation profiles are returned.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheThreeStatedDefaultsAreTheOnesTheirClausesGive (the default is stated in the vocabulary and read by whoever acts on the message, so an omitted element stays distinguishable from one stating the default)"),
        ("512-5.3.2.2.1-1", "The RetrieveInfo response carries zero or more Profile elements, each satisfying the requirements of the Profile component.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing"),
        ("512-5.3.2.2-errors", "The result codes RetrieveInfo admits: noPermission, internalError, parameterError and notSupported.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.EachOperationAdmitsExactlyTheCodesItsOwnClauseEnumerates"),

        ("512-5.3.3.1.1-1", "The PreservePO request shall extend the Request component and shall inherit its sub-components.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType"),
        ("512-5.3.3.1.1-2", "The Profile element shall contain one instance of a uniform resource identifier naming the operational profile used for the preservation. Unlike the discovery operation's filter of the same element name, it is mandatory here.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the submission request is the one request obliging a profile identifier)"),
        ("512-5.3.3.1.1-3", "The request carries zero or more instances of the PO element, each satisfying the requirements of the PO component.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing"),
        ("512-5.3.3.1-note", "Invoking PreservePO with zero PO elements is how a with-storage service issues a bare preservation object identifier for a container not yet populated, to be filled later through the update operation. It is a real submission mode rather than a degenerate request.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the submission request obliges only the profile, so the zero-payload mode round-trips rather than being refused by the type)"),
        ("512-5.3.3.2.1-1", "The optional POID element, if present, shall contain a string, and shall be returned after a successful call when the service provides permanent or temporary storage or supports the RetrieveTrace operation.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the identifier is conditionally mandatory on two independent conditions, which no type can state, so it stays optional on the record and the condition is the caller's to check)"),
        ("512-5.3.3.2.1-2", "The response carries zero or more PO elements; under the without-storage model a successful call returns one PO for each provided PO, with the evidence produced synchronously and enveloped in it.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing (the cardinality) beside PreservationVocabularyTests.TheGoalsAndStorageModelsRecogniseTheirOwnMembersOnly (the storage model the one-for-one rule is conditioned on)"),
        ("512-5.3.3.2-errors", "The result codes PreservePO admits: noPermission, internalError, parameterError, transferError, noSpaceError, notSupported, unknownPOFormat, POFormatError and externalServiceUnavailable, plus the warning lowSpace.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationSpecificCodesAreStatedWhereTheirClausesStateThem (this operation is the first to carry a warning beside its errors, and PreservationVocabularyTests.EveryErrorCodeRoundTripsThroughItsOutcomeAndNothingElseReadsAsSuccess asserts a warning never reads as success)"),

        ("512-5.3.4.1.1-gate", "[WST][WTS] The RetrievePO operation may only be provided in preservation schemes with storage or with temporary storage.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated"),
        ("512-5.3.4.1.1-1", "The POID element shall contain one instance of a string addressing preservation objects deposited previously through PreservePO.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory"),
        ("512-5.3.4.1.1-2a", "Zero or more VersionID elements may be present, each containing a string; the element applies only where the preservation object format supports versioning.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.ThreeElementNamesMapToTwoDifferentMemberNamesEach (this element is one of the three the document spells two ways, versionId here and verId on the evidence component)"),
        ("512-5.3.4.1.1-2b", "A missing VersionID returns the latest version, and a VersionID equal to the string all returns every version.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheDeletionModesSubjectsAndVersionSentinelRecogniseTheirOwnMembersOnly (the sentinel is a magic string inside a repeatable string element rather than an enumeration of its own)"),
        ("512-5.3.4.1.1-3", "The optional SubjectOfRetrieval element, if present, shall contain the corresponding sub-component; if it is missing, POwithEmbeddedEvidence is the default.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheThreeStatedDefaultsAreTheOnesTheirClausesGive"),
        ("512-5.3.4.1.1-4", "The optional POFormat element, if present, shall contain a uniform resource identifier that shall be among the output formats the applicable profile's RetrievePO operation announces; if it is missing, that operation's default output format is used.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.OnlyAnOperationAcceptingSubmittedContentOwesAnInputFormat (the profile's operation catalogue is what the identifier is checked against) beside PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists"),
        ("512-5.3.4.1.1-5", "The optional EvidenceFormat element, if present, names the evidence format; if it is missing, the applicable profile's default evidence format is used.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.ThreeElementNamesMapToTwoDifferentMemberNamesEach (this element is the third the document spells two ways)"),
        ("512-5.3.4.2.1-1", "The returned PO elements shall contain the sequence of preservation objects, the evidence, or both, as the request specified.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheDeletionModesSubjectsAndVersionSentinelRecogniseTheirOwnMembersOnly (the four subjects of retrieval that decide what comes back)"),
        ("512-5.3.4.2.1-2", "One or more instances of the PO element, each satisfying the requirements of the PO component.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing"),
        ("512-5.3.4.2.1-3", "If the request is only partly successful, the preservation service should provide further details in the result message component.",
            RequirementCoverageStatus.ServiceOperational, "PreservationVocabularyTests.TheResultCodesAreSeventeenAndPartitionIntoErrorsAndWarnings (the partly-successful warning is carried; how richly a service explains itself beside it is its own choice)"),
        ("512-5.3.4.2-errors", "The result codes RetrievePO admits: noPermission, internalError, parameterError, notSupported, unknownPOFormat, unknownEvidenceFormat, unknownPOID and unknownVersionID, plus the warning requestOnlyPartlySuccessful.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.EachOperationAdmitsExactlyTheCodesItsOwnClauseEnumerates"),

        ("512-5.3.5.1.1-gate", "[WST] The DeletePO request shall only be supported in the case of a preservation scheme with storage.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated"),
        ("512-5.3.5.1.1-1", "The POID element shall contain one instance of a string and shall be used for addressing preservation objects deposited previously.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory"),
        ("512-5.3.5.1.1-2", "The optional Mode element, if present, shall contain the deletion-mode sub-component; if it is omitted, SubDOsAndEvidence shall be used.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheThreeStatedDefaultsAreTheOnesTheirClausesGive"),
        ("512-5.3.5.1.1-3", "The optional ClaimedRequestorName element, if present, shall contain a string.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists (the member name is one of the pairs no derivation reproduces)"),
        ("512-5.3.5.1.1-4", "The optional Reason element, if present, shall contain a string.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists"),
        ("512-5.3.5.2-1", "The DeletePO response shall extend the Response component and shall inherit its sub-components; it is the one response with no payload of its own, success being signalled by the result alone.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.TheDeletionResponseIsTheOnlyMessageWithNoPayloadOfItsOwn"),
        ("512-5.3.5.2-errors", "The result codes DeletePO admits: noPermission, internalError, parameterError, notSupported, unknownPOID and unknownMode.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.EachOperationAdmitsExactlyTheCodesItsOwnClauseEnumerates"),

        ("512-5.3.6.1.1-1", "The UpdatePOC request shall extend the Request component and shall inherit its sub-components.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType"),
        ("512-5.3.6.1-strategies", "Two update strategies exist: a simple one where several deltas are treated as plain additions, and a sophisticated one where a single delta is a full difference specification. A given container format may support either or both.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ADeltaIsAPreservationObjectUnderAnotherElementName (both strategies are the same repeatable element, which is what makes one or several deltas expressible without a second type)"),
        ("512-5.3.6.1.1-2", "The POID element shall contain one instance of a string, and shall address the preservation object container to be updated.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory"),
        ("512-5.3.6.1.1-3", "The DeltaPOC element shall be present one or more times and satisfy the requirements of the PO component; it has no distinct type of its own.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ADeltaIsAPreservationObjectUnderAnotherElementName beside PreservationSeamTests.AnUpdateStatingNoDeltaIsRefused (the one-or-more bound, which no type can carry)"),
        ("512-5.3.6.1-disambiguation", "Which of the two update cases applies is decided by whether a single sophisticated delta or several plain ones were submitted.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ADeltaIsAPreservationObjectUnderAnotherElementName (the count and the format identifier a delta carries are what the disambiguation reads; the rule itself is descriptive prose rather than a modal statement)"),
        ("512-5.3.6.2.1-1a", "The optional VersionID element of the update response, if present, shall contain a string.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists"),
        ("512-5.3.6.2.1-1b", "A sequential versioning scheme should be used, assigning identifiers such as v1, v2 and v3. It is a recommendation, so a caller must not assume the identifier parses as a number.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.ThreeElementNamesMapToTwoDifferentMemberNamesEach (the identifier is carried as an opaque string, never parsed, which is what the recommendation being a recommendation requires)"),
        ("512-5.3.6.2-errors", "The result codes UpdatePOC admits: noPermission, internalError, parameterError, transferError, notSupported, noSpaceError, unknownPOID, unknownDeltaPOCType and DeltaPOCInternalProblem, plus the warning lowSpace.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationSpecificCodesAreStatedWhereTheirClausesStateThem"),

        ("512-5.3.7.1.1-1", "The RetrieveTrace request shall extend the Request component and shall inherit its sub-components.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType"),
        ("512-5.3.7.1.1-2", "The POID element shall contain one instance of a string, which shall identify the submitted data objects an audit trail is requested for.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory"),
        ("512-5.3.7.2.1-1", "The trace response shall be returned to an invocation of the operation and shall contain the trace of operations corresponding to the provided identifier.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the trace is the only payload member of any response the type itself obliges)"),
        ("512-5.3.7.2.1-2", "The Trace element shall contain one instance of the sub-component and shall satisfy the requirements of the Trace component.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),
        ("512-5.3.7.2-errors", "The result codes RetrieveTrace admits: noPermission, internalError, parameterError, notSupported and unknownPOID.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.EachOperationAdmitsExactlyTheCodesItsOwnClauseEnumerates"),

        ("512-5.3.8.1.1-1", "The ValidateEvidence request shall extend the Request component and shall inherit its sub-components.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType"),
        ("512-5.3.8.1.1-2", "The Evidence element shall satisfy the requirements of the Evidence component. The semantics prose makes it mandatory while the reproduced schema fragment marks it optional.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the prose decides, because the fragments are copied for information while the semantics clause is the normative body — one rule resolving every such disagreement rather than a case-by-case reading)"),
        ("512-5.3.8.1.1-3", "Zero or more instances of the optional PO element, each satisfying the requirements of the PO component: the objects the evidence protects, validated alongside it.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing"),
        ("512-5.3.8.2.1-1", "The optional ValidationReport element, if present, shall satisfy the requirements of the PO component — the report is carried as a preservation-object-shaped payload rather than as a bespoke type.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheValidationReportRoundTripsAsAPreservationObject (the same reading of the same element where the container extensions carry it)"),
        ("512-5.3.8.2.1-2", "The optional ProofOfExistence element, if present, shall contain a date and time value corresponding to a moment the preservation object is known to have existed.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EveryOperationMessageStatesTheNamesItsOwnTableLists (the element and its member name; the instant itself is carried as a time value rather than as either binding's encoding of one)"),
        ("512-5.3.8.2-naming", "The clause names both its XML type and its JSON schema key after an operation called ValidatePOC, not after ValidateEvidence as the clause title and every other clause do, and the reproduced JSON fragment carries a further property no semantics prose explains.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType (the message is named after the operation the document defines, and the residue of the earlier name is documented at the type rather than reproduced into the model)"),
        ("512-5.3.8.2-errors", "The result codes ValidateEvidence admits: noPermission, internalError, parameterError and notSupported.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.EachOperationAdmitsExactlyTheCodesItsOwnClauseEnumerates"),

        ("512-5.3.9.1.1-1", "The Search request shall extend the Request component and shall inherit its sub-components.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryMessageKindIsRealisedByExactlyOneMessageType"),
        ("512-5.3.9.1.1-2", "The optional Filter element, if present, shall contain one instance of a string structured according to the query language the profile's own operation catalogue describes. The semantics prose calls it optional while the reproduced schema fragment marks it mandatory.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EachMessageObligesTheMembersItsOwnClauseMakesMandatory (the prose decides, by the same one rule; the query language itself is unspecified by this document and the filter is therefore an opaque string)"),
        ("512-5.3.9.2.1-1", "Zero or more instances of the optional POID element, each containing a string; the returned list matches the provided filter.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing"),
        ("512-5.3.9.2-errors", "The result codes Search admits: noPermission, internalError, parameterError and notSupported. The clause introduces them under a heading naming the trace response instead of its own.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.EachOperationAdmitsExactlyTheCodesItsOwnClauseEnumerates (the list is read as this operation's own, the misattributed heading being copy-paste residue)"),

        ("512-5.4.2.1-1", "The value element shall contain one instance of a string limited to OnlySubDOs or SubDOsAndEvidence.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheDeletionModesSubjectsAndVersionSentinelRecogniseTheirOwnMembersOnly (the table maps this element to a member name although the JSON type the same clause reproduces is a bare string enumeration with no properties, which is transcribed rather than normalised)"),

        ("512-5.4.3.1-1", "The Time element is mandatory and carries the instant of the event.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),
        ("512-5.4.3.1-2a", "The Subject element is mandatory and carries a string.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),
        ("512-5.4.3.1-2b", "The subject should identify the client when the event was client-triggered and should indicate the service when it was service-triggered.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: which party a service writes into its own audit trail is its decision; the element carrying it is asserted at the row above."),
        ("512-5.4.3.1-3", "The Operation element is mandatory and names the operation that triggered the event.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheOperationNamesAreTheEightTheDocumentDefinesAndTwoOfThemAreGated (the eight names an event may carry)"),
        ("512-5.4.3.1-4", "The optional Object element carries a string addressing the object the event concerned.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),
        ("512-5.4.3.1-5", "The optional Detail element carries free text.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),

        ("512-5.4.4.1-1", "The Evidence component shall extend the PO component, inheriting the mandatory sub-component carrying the value and the FormatId sub-component, which is mandatory in this case.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.TheEvidenceComponentMakesTheFormatIdentifierMandatoryAndTheObjectComponentDoesNot (the one member the wire's inheritance tightens, restated on the subtype rather than left to a nullable base property)"),
        ("512-5.4.4.1-2", "One instance of either base-64-encoded binary data or XML data, carrying the value of the preservation evidence.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.TheSerialisationSeamsCarryTheirContextsAndRefusalsAsStatuses (a JSON encoding of a markup payload is refused rather than re-encoded as the other alternative, because the JSON schema omits that alternative and nothing authorises the substitution)"),
        ("512-5.4.4.1-3", "The FormatId element shall contain one instance of a uniform resource identifier identifying the format of the preservation evidence.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase"),
        ("512-5.4.4.1-4", "The optional POID element, if present, shall contain one instance of a string identifying the preservation object the evidence belongs to.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),
        ("512-5.4.4.1-5", "The optional VersionID element, if present, shall contain one instance of a string identifying the version of the preservation object.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.ThreeElementNamesMapToTwoDifferentMemberNamesEach (this element's member name here is not the one the retrieval tables give it, which is the sharpest proof that the member names are not derivable)"),

        ("512-5.4.5.1-1", "One instance of a sub-component carrying the value of the preservation object: either base-64-encoded binary data or XML data.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.APayloadWithNoStatedContentFormIsRefused"),
        ("512-5.4.5.1-2", "The optional FormatId element, if present, shall contain a uniform resource identifier; it shall be present when the object is an evidence, a specific submission data object or an additional output format needing treatment beyond base-64 decoding.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.APayloadStatingNeitherAFormatNorAMediaTypeIsRefused"),
        ("512-5.4.5.1-3", "The optional MimeType element, if present, shall contain one instance of a string indicating the media type; it shall be present when the FormatId element is omitted.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.APayloadStatingNeitherAFormatNorAMediaTypeIsRefused (the at-least-one rule between two independently optional elements, which no type can carry)"),
        ("512-5.4.5.1-3b", "The media type should carry a value registered in the media-type registry.",
            RequirementCoverageStatus.ServiceOperational, $"{NoEnablingPrimitive}: registry membership is a property of the value a caller states; the element carrying it is asserted at the row above."),
        ("512-5.4.5.1-4", "The optional PronomId element, if present, shall contain one instance of a string carrying a persistent unique format identifier, and should be used when additional classification information is required.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),
        ("512-5.4.5.1-5", "The optional ID element, if present, shall contain one instance of a unique identifier.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),
        ("512-5.4.5.1-6", "The optional RelatedObjects element, if present, shall contain unique identifier references. The prose says one instance while the schema type is a plural reference list.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ARepeatableElementDefaultsToNoneRatherThanToNothing (the plural reading is taken, because the singular one would silently drop references on a round trip through a multi-target container)"),

        ("512-5.4.6.1-1", "The storage model is a closed enumeration of WithStorage, WithTemporaryStorage and WithoutStorage. It is the discriminator the operation availability gates read.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheGoalsAndStorageModelsRecogniseTheirOwnMembersOnly"),

        ("512-5.4.7.1-1", "The ProfileIdentifier element is a mandatory, unique uniform resource identifier.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.EveryObligationTakenAwayMakesTheProfileNonConformant"),
        ("512-5.4.7.1-2", "The Operation element is present one or more times, one per supported operation, each stating its input formats, its supported optional inputs and its output formats.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.OnlyAnOperationAcceptingSubmittedContentOwesAnInputFormat"),
        ("512-5.4.7.1-3", "The Policy element is present once or twice: always one of the preservation-evidence type, and a second of the signature-validation type when the goal is the preservation of digital signatures and the validation data is not provided by the client.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.AProfileOwesTheCardinalitiesItsOwnClauseStates beside PreservationProfileConformanceTests.APolicyWhoseConditionNoProfileCarriesIsUndecidedRatherThanConformant (the second condition is a submission-time fact no profile carries, so the row is undecidable rather than conformant)"),
        ("512-5.4.7.1-4", "The ProfileValidityPeriod element is mandatory, with a mandatory start and an optional end.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.AProfileThatEndsBeforeItBeginsStatesAnUnusablePeriod"),
        ("512-5.4.7.1-5", "The PreservationStorageModel element is mandatory.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.AValueTheVocabularyDoesNotNameIsUnusable (an unusable value is told apart from an absent one)"),
        ("512-5.4.7.1-6", "The PreservationGoal element is present one or more times, each a uniform resource identifier.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.EveryObligationTakenAwayMakesTheProfileNonConformant"),
        ("512-5.4.7.1-7", "The EvidenceFormat element is present one or more times.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.APermissionIsNotADepartureAndAnUnregisteredValueIsReportedNotRefused (a format outside the registered ones is reported beside its row rather than refused)"),
        ("512-5.4.7.1-8", "The Specification element may be present zero or more times, each a uniform resource identifier pointing at a publicly available specification.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.APermissionIsNotADepartureAndAnUnregisteredValueIsReportedNotRefused"),
        ("512-5.4.7.1-9", "The Description element may be present zero or more times, each an internationalized string.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.AValueTheVocabularyDoesNotNameIsUnusable (a blank description is unusable rather than absent)"),
        ("512-5.4.7.1-10", "The SchemeIdentifier element may be present once, naming the scheme the profile instantiates.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne"),
        ("512-5.4.7.1-11", "The ExpectedEvidenceDuration element may be present once, carrying a duration.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.ATemporaryStorageProfileOwesTheRetentionPeriodAndIsOnlyRecommendedTheDuration"),
        ("512-5.4.7.1-12", "The PreservationEvidenceRetentionPeriod element shall be present in the case of preservation with temporary storage; each scheme of Annex F closes the condition by stating it shall or shall not be present.",
            RequirementCoverageStatus.Tested, "PreservationProfileConformanceTests.ATemporaryStorageProfileOwesTheRetentionPeriodAndIsOnlyRecommendedTheDuration"),
        ("512-5.4.7.1-13", "The Extension element may be present zero or more times, carrying the metadata extension shape of the external base specification.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.DisposingAMessageReturnsEveryCarrierItOwns (a discovery response reaches the extensions of every profile it carries, which is what proves they are modelled and owned rather than dropped)"),
        ("512-5.4.7-table21", "Table 21 maps every Profile sub-element to its JSON member name and to the requirement identifier of the companion policy specification's clause 6.4.",
            RequirementCoverageStatus.KnownDefect, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists (the member names are transcribed letter for letter from this table). THE DEFECT IS THE SOURCE TABLE'S: its last two correspondences appear interchanged — it maps the expected evidence duration to OVR-6.4-05 and the retention period to OVR-6.4-06, while the companion specification's clause 6.4 states those two requirements the other way round. The library follows the companion specification's own texts, and two stages reading it independently reached that reading; the interchange is transcribed verbatim in the doc comments beside the members."),

        ("512-5.4.8.1-1", "The Status component is a closed enumeration; the reproduced schema lists active and inactive while the semantics prose gives a third value, all, meaning both are returned.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheStatusVocabularyCarriesTheProseOnlyThirdValueAndKeepsBothReadingsApart (three values for the discovery filter, two for a profile's own status, kept apart so an implementer following the schema alone cannot refuse a specification-valid request)"),
        ("512-5.4.9.1-1", "The SubjectOfRetrieval component is a closed enumeration of PO, Evidence, POwithEmbeddedEvidence and POwithDetachedEvidence.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheDeletionModesSubjectsAndVersionSentinelRecogniseTheirOwnMembersOnly"),
        ("512-5.4.10.1-1", "The Trace component carries zero or more instances of the Event element.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.EverySharedComponentStatesTheNamesItsOwnTableLists"),

        ("512-5.5.2.1", "The ContainerID extension carries a mandatory POID and an optional VersionID, and should not be critical.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheContainerIdentifierRoundTripsThroughTheExtensionModel beside PreservationAsicExtensionTests.EachPayloadCarriesTheCriticalityItsOwnClauseRecommends"),
        ("512-5.5.2.1.1-1", "The POID element shall be present and shall indicate the preservation object identifier of the preservation object container.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheContainerIdentifierRoundTripsThroughTheExtensionModel"),
        ("512-5.5.2.1.1-2", "The optional VersionID element may be present.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheContainerIdentifierRoundTripsThroughTheExtensionModel"),
        ("512-5.5.2.2", "The PreservationPeriod extension is a single element of date type, and should not be critical.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.ThePreservationPeriodRoundTripsAsACalendarDate"),
        ("512-5.5.2.2.1-1", "The PreservationPeriod extension consists of a single element, which shall indicate the preservation period of the preservation object container.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.ThePreservationPeriodRoundTripsAsACalendarDate"),
        ("512-5.5.2.3", "The PreservationSubmitter extension is a single string element, and should not be critical.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheSingleValuePayloadsRoundTripVerbatim"),
        ("512-5.5.2.3.1-1", "The PreservationSubmitter extension consists of a single element, which shall identify the client in its role as preservation submitter.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheSingleValuePayloadsRoundTripVerbatim"),
        ("512-5.5.2.4", "The IsUpdatedVersionOf extension is a single element of identifier type, and should not be critical.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheSingleValuePayloadsRoundTripVerbatim"),
        ("512-5.5.2.4.1-1", "The IsUpdatedVersionOf extension shall refer to the preservation object container the carrying one is an update of.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheSingleValuePayloadsRoundTripVerbatim"),
        ("512-5.5.2.5", "The CanonicalizationMethod extension references an element of an external schema, and should be critical, because preservation evidences will appear to become invalid if a required canonicalization method is missed.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.ACriticalCanonicalizationMethodFromAnUnknownNamespaceFailsClosed (the recommended policy recognises the six extensions this document declares and stops on the seventh until a caller states the namespace it met, which is exactly the consequence the criticality recommendation is written for) beside PreservationAsicExtensionTests.TheCanonicalizationMethodRoundTripsUnderTheStatedNamespace"),
        ("512-5.5.2.6", "The ValidationReport extension carries a preservation-object-shaped payload, and should not be critical.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheValidationReportRoundTripsAsAPreservationObject"),
        ("512-5.5.3.1", "The IsMetaDataOf extension sits on a data object reference rather than on the manifest, and should not be critical.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.ThePlacementOfEachPayloadIsTheOneItsClauseGivesIt"),
        ("512-5.5.3.1.1-1", "The IsMetaDataOf extension shall refer to the preservation object it is metadata information of.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheSingleValuePayloadsRoundTripVerbatim"),
        ("512-5.5-criticality", "Every criticality sub-clause is a recommendation rather than an obligation, so a departure from it is reported and never refused; what fails closed is an unrecognised critical extension.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.ADepartureFromTheRecommendedCriticalityIsCarriedAndReported beside PreservationContainerProfileTests.ACriticalExtensionThePolicyDoesNotRecogniseStopsTheProfile"),

        ("512-5.6.1.1-intro", "It is only admissible to submit a single PO component carrying a single DigestList component within one PreservePO call.",
            RequirementCoverageStatus.Tested, "PreservationDigestListTests.ADigestListOwnsWhatItCarries (the component and its ownership; the one-per-call bound is a rule on the submission request rather than on the component's own schema and is documented at the component)"),
        ("512-5.6.1.1-1", "The DigestMethod element shall contain one instance of a string specifying the digest algorithm as a uniform resource identifier carrying an object identifier per IETF RFC 3061.",
            RequirementCoverageStatus.Tested, "PreservationDigestListTests.EveryAlgorithmRoundTripsThroughItsObjectIdentifierName beside PreservationDigestListTests.OnlyAWellFormedNameOfAComputableAlgorithmResolves"),
        ("512-5.6.1.1-2", "The DigestValue element may occur one or more times and shall contain one instance of a base-64-encoded binary value computed with the specified digest method.",
            RequirementCoverageStatus.Tested, "PreservationDigestListTests.AnUnusableDigestMethodAndAMisSizedValueAreRefusedApart (a value whose length contradicts the stated method is refused)"),
        ("512-5.6.1.1-3", "The optional Evidence element shall, if present, contain a preservation evidence to be augmented by the service, and shall satisfy the requirements of the Evidence component.",
            RequirementCoverageStatus.Tested, "PreservationDigestListTests.ASubmissionCarryingAnEvidenceRecordIsRenewedAndTheRenewalVerifies beside PreservationDigestListTests.AnEvidenceThisLibraryDoesNotRenewIsRefusedByFormatAndByContent"),
        ("512-5.6.1.1-note", "Submitting a digest method, a list of digest values and an evidence record allows a hash-tree renewal of the provided record.",
            RequirementCoverageStatus.KnownDefect, "PreservationDigestListTests.ASubmissionCarryingAnEvidenceRecordIsRenewedAndTheRenewalVerifies (the renewal runs and is recomputed from the clause text by an independent oracle) — but the privacy-preserving half, where the submitter supplies ONLY the hashes, cannot be served: the shipped hash-tree renewal takes the data objects and hashes them itself, and the bridge answers a documented refusal rather than doing something else, as PreservationDigestListTests.AHashOnlySubmissionIsRefusedWithTheReasonRatherThanServedWrongly asserts. Widening the renewal group with a hash-stated alternative is an owner-flagged follow-up on a previous wave's surface."),

        ("512-6.1-1", "An admissible preservation object data format shall be documented in a permanent, readily available public specification, in enough detail for independent implementations to interoperate.",
            RequirementCoverageStatus.OutOfScope, "A governance requirement on a format's SPECIFICATION rather than on code."),
        ("512-6.1-2", "The format of a preservation object shall be identified by a uniform resource identifier.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase"),
        ("512-6.1-3", "For the sake of interoperability one should only use the preservation object data formats the annex defines. The clause cites the annex carrying the interface description rather than the one carrying the formats.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase (the registered set is the one the formats annex states, the cross-reference in the clause being a typing slip in the source)"),
        ("512-6.2-1", "A preservation object container shall allow storing one or more data objects.",
            RequirementCoverageStatus.Tested, "PreservationContainerProfileTests.AContainerTheProfileCreatedSatisfiesTheProfile (one data object reference per data object)"),
        ("512-6.2-2", "It may allow assigning further attributes to the contained data objects, distinguishing content data objects from metadata objects.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.ThePlacementOfEachPayloadIsTheOneItsClauseGivesIt (the metadata-of extension is the concrete instance of this permission)"),
        ("512-6.2-3", "It shall allow storing one or more preservation evidence objects protecting a well-defined set of data objects in a well-defined manner.",
            RequirementCoverageStatus.Tested, "PreservationContainerProfileTests.AContainerCarryingNoEvidenceRecordManifestIsRefused (the manifest naming what the evidence protects is what makes the set well defined)"),
        ("512-6.2-4", "It may contain an identifier allowing the container to be addressed within the scope of a preservation service.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheContainerIdentifierRoundTripsThroughTheExtensionModel"),
        ("512-6.2-5", "It may support a versioning mechanism.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheSingleValuePayloadsRoundTripVerbatim (the is-updated-version-of extension is the container-side half of the versioning the update operation drives)"),
        ("512-6.2-6", "It may support a privacy-friendly mode in which the original data objects are replaced by their hash values and optional locators.",
            RequirementCoverageStatus.KnownDefect, "PreservationDigestListTests.AHashOnlySubmissionIsRefusedWithTheReasonRatherThanServedWrongly (the mode is modelled and its refusal is documented, but the shipped hash-tree renewal has no hash-stated entry point, so the mode cannot be served end to end; the same owner-flagged widening as row 512-5.6.1.1-note)"),
        ("512-6.2-7", "It may support the inclusion of validation reports.",
            RequirementCoverageStatus.Tested, "PreservationAsicExtensionTests.TheValidationReportRoundTripsAsAPreservationObject"),
        ("512-7-scheme-requirements", "Clause 7's eight requirements bind a preservation scheme's own specification document: permanent documentation, identification by a uniform resource identifier, declaration of the storage model, of the goals and of the mandatory and optional operations, description of the evidence generation, validation and augmentation processes, and optional format recommendations.",
            RequirementCoverageStatus.OutOfScope, "These bind a scheme SPECIFICATION's completeness rather than a library. The four schemes of Annex F are this document's own demonstration against them, and their identifiers are carried by PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne."),

        ("512-binding-names", "Every JSON member name is an abbreviation of its XML element name given by a per-component table; no naming convention is stated and none reproduces the pairs.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.NoMechanicalDerivationReproducesTheMemberNames (three candidate derivations, each compared case-insensitively so the finding is about spelling rather than capitalisation, and each shown to disagree)"),
        ("512-binding-choice", "The XML choice between binary data and markup data collapses to binary data only in the JSON binding, which the reproduced schema fragments show by omitting the second alternative rather than by stating a rule.",
            RequirementCoverageStatus.Tested, "PreservationSeamTests.TheSerialisationSeamsCarryTheirContextsAndRefusalsAsStatuses (a JSON encoding of a markup payload answers a refusal rather than silently re-encoding it, which is the fail-closed reading of an omission nothing authorises)"),
        ("512-binding-inheritance", "The base-type inheritance of the XML binding is flattened in the JSON binding, every operation's object restating the base members directly.",
            RequirementCoverageStatus.Tested, "PreservationParameterNameTests.TheBaseNamesAreRestatedExactlyWhereTheTablesRestateThem"),
        ("512-binding-instants", "Instants bind differently per field rather than systematically: the XML binding types them as date-and-time values while the two JSON fragments showing a concrete type give an integer count of milliseconds.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.EveryPayloadCarriesTheTagItsKindStates (the model carries instants as time values and neither binding's encoding of one, so a binding may render either; the divergence is documented at the members)"),
        ("512-binding-transport", "The document asserts a binding to a message-envelope protocol and to a resource-oriented one, but the clause-5 prose gives neither the verb, path and status mapping of the second nor the operation and action mapping of the first; both live in external files the annexes point at.",
            RequirementCoverageStatus.OutOfScope, "Transport is caller-supplied delegate territory throughout this arc, and this library takes no dependency on an HTTP client. The message bodies are what the clause-5 rows above cover."),
        ("512-binding-external-types", "The Request, Response, Result, OptionalInputs, OptionalOutputs, Operation, Policy, Format, internationalized-string and metadata-extension base types are defined by reference to external base specifications rather than by this document.",
            RequirementCoverageStatus.OutOfScope, "Those texts are not cached in this repository, so nothing is invented for them: the sub-components this document's own prose names are modelled and everything else rides verbatim as octets or as text. An acknowledged gap rather than a modelled one, recorded as an owner flag by the stage that shipped the vocabulary."),

        ("512-A.1", "Annex A.1 registers the submission data object formats: the three signature formats, the extended container, the markup-based archival package, and the DigestList.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase beside PreservationDigestListTests.TheSubmissionFormatIdentifierIsTheOneItsClauseRegisters"),
        ("512-A.2", "Annex A.2 registers the preservation evidence formats: the time-stamp token, the two evidence record formats, and the three archive-time-stamp attributes of the signature families.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.TheFormatIdentifiersAreTheOnesAnnexARegistersAndTheContainerProfilesDifferByCase (the identifiers of the formats this library produces; the markup-signature and document-signature archive time-stamps belong to families outside this arc)"),
        ("512-A.3.1", "Annex A.3.1 profiles the extended container with an evidence record manifest as a preservation object container, and states six numbered requirements it shall satisfy.",
            RequirementCoverageStatus.Tested, "PreservationContainerProfileTests.AContainerTheProfileCreatedSatisfiesTheProfile beside PreservationContainerProfileTests.TheProfileIsIdentifiedByTheUrlItsClauseRegisters"),
        ("512-A.3.1-tightening", "Requirement 6 of that profile states that the optional MimeType element of the signature reference shall not be present, tightening the container specification's own optional rule.",
            RequirementCoverageStatus.Tested, "PreservationContainerProfileTests.CreationRefusesAMediaTypeOnTheSignatureReference (creation refuses the value rather than dropping it silently, which would produce a container the caller did not ask for) beside PreservationContainerProfileTests.AContainerStatingAMediaTypeOnItsSignatureReferenceIsReported"),
        ("512-A.3.2", "Annex A.3.2 registers a markup-based archival information package as the second preservation object container format.",
            RequirementCoverageStatus.OutOfScope, "It requires a markup archival-package object model this repository does not have, is defined by a national technical guideline whose text is not cached here, and the contract's Out list keeps it out of this wave. Recorded rather than silently skipped."),
        ("512-B", "Annex B is the interface description document, given as an external file reference.",
            RequirementCoverageStatus.OutOfScope, "An external file pointer carrying the transport binding this library deliberately does not take a dependency on."),
        ("512-C", "Annex C gives the locations of the markup schema documents for the two namespaces.",
            RequirementCoverageStatus.OutOfScope, "External file pointers; the element and member names this library carries are transcribed from the clause tables, which the same document states as normative."),
        ("512-D", "Annex D gives the locations of the JSON schema and interface-description documents.",
            RequirementCoverageStatus.OutOfScope, "External file pointers; the member names are transcribed from the clause tables."),
        ("512-E", "Annex E walks through container versioning with a worked example, giving the update operation's delta semantics.",
            RequirementCoverageStatus.Tested, "PreservationMessageTests.ADeltaIsAPreservationObjectUnderAnotherElementName (informative prose, whose only normative consequence is the shape of the delta the update request carries)"),

        ("512-F.1", "Scheme F.1: the signature and general-data goals with augmentation, with storage, using evidence records.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne"),
        ("512-F.2", "Scheme F.2: the general-data goal, with temporary storage, using evidence records.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne (the one scheme of the four whose two statements of its own identifier agree)"),
        ("512-F.3", "Scheme F.3: the signature goal with augmentation, with storage.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne"),
        ("512-F.4", "Scheme F.4: the signature goal with augmentation, without storage.",
            RequirementCoverageStatus.Tested, "PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne"),
        ("512-F-identifiers", "Three of the four schemes state two different identifiers for themselves: the identifier clause and the profile-requirements clause disagree for F.1, F.3 and F.4.",
            RequirementCoverageStatus.KnownDefect, "PreservationVocabularyTests.ThreeOfTheFourSchemesStateTwoIdentifiersAndTheLibraryWritesTheConsistentOne (THE DEFECT IS THE SOURCE DOCUMENT'S, and it is threefold rather than the single occurrence the preflight leg found: in all three disagreements the identifier clause's value agrees with the goals the scheme's own goals clause lists while the restatement contradicts them, which is the evidence for writing the first and recognising the second; both the rule and its evidence are under test)"),

        ("512-G", "Annex G gives an evidence-exchange data structure carrying full, non-reduced hash trees, for migrating or backing up a with-storage service's evidences.",
            RequirementCoverageStatus.OutOfScope, "Informative, and outside the contract's Scope list for this wave. It is the only stated route for moving full hash trees between providers, so it is recorded as a candidate rather than dropped; the reduced trees the shipped evidence records carry are unaffected."),

        ("512-H.1", "The three attributes are inserted into the preservation evidence itself: as an unsigned attribute of a signature before its archive time-stamp is applied, or as an attribute of an evidence record's archive time-stamp before the next chain covers it.",
            RequirementCoverageStatus.Tested, "PreservationEvidenceAttributeTests.ARenewalCarriesTheAttributesForwardAndProtectsThem (the chain carrying them is asserted carried forward octet for octet, which is what makes them protected) beside PreservationEvidenceAttributeTests.ASignedDataObjectCarriesTheAttributesAsUnsignedAttributes"),
        ("512-H.2", "The preservation-service-identifier attribute is a single string under its own object identifier.",
            RequirementCoverageStatus.Tested, "PreservationEvidenceAttributeTests.TheThreeAttributeTypesAreTheChildrenOfTheArcAnnexIDeclares"),
        ("512-H.3", "The preservation-evidence-policy attribute is a single string under its own object identifier.",
            RequirementCoverageStatus.Tested, "PreservationEvidenceAttributeTests.AnAttributeIsOneStringUnderTheTypeItsClauseNames"),
        ("512-H.4", "The preservation-profile attribute is a single string under its own object identifier.",
            RequirementCoverageStatus.Tested, "PreservationEvidenceAttributeTests.EachAttributeHasTheXmlElementItsClauseDeclares (each attribute's markup twin beside its object identifier)"),
        ("512-I", "Annex I is the consolidated module declaring the arc and the three attribute types, and takes precedence over the inline reproductions of Annex H on any discrepancy.",
            RequirementCoverageStatus.Tested, "PreservationEvidenceAttributeTests.ReadingRefusesOctetsThatAreNotOneStringWithinTheBound (the value type the module declares is what the reader enforces, refusing another string type and trailing octets) beside PreservationEvidenceAttributeTests.WritingRefusesWhatCannotBeReadBack"),
        ("512-H-versus-house", "The three attributes are the standardised spelling of the three items the companion policy specification's OVR-6.5-09 lists, and the same three this library's own self-description convention carries.",
            RequirementCoverageStatus.Tested, "PreservationEvidenceAttributeTests.TheStandardisedAttributesAndTheHouseSelfDescriptionSayTheSameThreeThings (a bridge in both directions, so a package may carry the specification's own attributes and still be read by the shipped placement rules). Which spelling a package this library writes should state is an owner decision recorded as a flag; nothing under the house convention was changed pending it."),

        ("512-oais-1.4-4-xaip", "Term consistency: the markup-based archival package of Annexes A.1.5 and A.3.2 is declared to be based on the archival reference model, and its clause headings spell it XML-based Archival Information Package — while the abbreviations table and the container EXAMPLE of clause 6.2 spell the same acronym XML-based Archive Information Package.",
            RequirementCoverageStatus.OutOfScope, "FINDING, row-level: the reference model's own term is Archival Information Package, and clause 1.4 item 4 obliges a document claiming conformance to it to use its terms in the same manner. Annex A.3.2 makes that claim explicitly by deriving the package from the reference model, so the two Archive spellings inside the same document are a departure from the term the model defines. Both spellings are in the cached text and neither is a conversion artefact. It changes nothing this library builds — the format is out of this wave — and is recorded so a later wave implementing it does not treat the two spellings as two things. The same document repeats the submission-package-is-a-container example recorded at row 511-oais-1.4-4-poc."),
    ];


    /// <summary>Every row of the matrix: the preservation-service specification first, the preservation protocol after it.</summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
        [.. PreservationServiceRows, .. PreservationProtocolRows];
}
