using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The requirements matrix for the signature applicability rules of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1</see>: every normative statement of clauses 4.1 through 4.5 and the Annex A
/// object identifier allocations, judged against the shipped composition in
/// <c>SignatureApplicabilityRules</c> — a pure composition over the ETSI EN 319 102-1 validation engine and
/// the ETSI TS 119 615 qualification procedures. Mirrors the rows-as-spec-cells shape of
/// <c>Timestamp319422RequirementsMatrixTests</c> (ETSI EN 319 422), <c>CAdESRequirementsMatrixTests</c>
/// (ETSI EN 319 122-1) and <c>PreservationRequirementsMatrixTests</c> (ETSI TS 119 511/512).
/// </summary>
/// <remarks>
/// <para>
/// Every requirement identifier of the specification is one <see cref="RequirementMatrixRow"/>, with the
/// composite requirements (REQ-4.2-03's lettered constraints, REQ-4.3-01's format list, REQ-4.5-01's
/// lettered report elements) split one row per distinct normative statement so no letter can hide behind a
/// sibling's disposition. <see cref="RequirementMatrixTest"/> fails a row without a disposition and
/// resolves every cited evidence method through reflection, so a renamed or deleted test fails here rather
/// than rotting into a stale citation.
/// </para>
/// <para>
/// <strong>Mind the clause-number collision.</strong> Clause 4.4 of this specification (the technical
/// applicability rules checking process) and clause 4.4 of ETSI TS 119 615 (the EU qualified certificate
/// determination) are different procedures answering different questions; the TARC rows here compose the
/// latter and never claim it as the former. The same trap is recorded at the consuming end in
/// <c>PreservationRequirementsMatrixTests</c> row OVR-A-02A.
/// </para>
/// <para>
/// <strong>The deferred formats are stated, not hidden.</strong> REQ-4.3-01 is recommendation-strength;
/// its XAdES and PAdES arms are <see cref="RequirementCoverageStatus.OutOfScope"/> because the EU
/// signatures arc charter schedules those formats deliberately last, while the CAdES and ASiC arms point at
/// the matrices that enumerate the shipped support row by row.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SignatureApplicabilityRulesRequirementsMatrixTests
{
    /// <summary>Whether a requirement row is driven by a concrete test over the shipped composition, or is out of a class library's reach because it binds a validation service, a host application or a format family the arc charter schedules later. </summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped surface.</summary>
        Tested = 1,

        /// <summary>The requirement binds a validation service or host application this library does not ship, is a VOID identifier the specification keeps, or names a format family the arc charter schedules deliberately later. The evidence states which.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's mechanism is implemented and unit-tested but the shipped composition cannot reach all of it because of an already-flagged, unfixed defect. The evidence names the proving test and the follow-up.</summary>
        KnownDefect = 3
    }


    /// <summary>One row of the matrix: a requirement identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The specification's own requirement identifier, with a lower-case letter suffix for the composite requirements' split statements.</param>
    /// <param name="Requirement">A short digest of the normative statement, carrying its RFC 2119 verb, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/> and <see cref="RequirementCoverageStatus.KnownDefect"/>, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection. For <see cref="RequirementCoverageStatus.OutOfScope"/>, the stated reason.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


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
    }


    /// <summary>
    /// Every requirement identifier of the matrix is stated once. A duplicated identifier would let one row
    /// silently replace another's disposition in a reader's eye while both still pass.
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
    /// The matrix carries the whole specification: the clause 4.1 rule-set definition, the twelve clause 4.2
    /// statements, the twelve clause 4.3 statements, the six clause 4.4.2 statements, the eleven clause 4.5
    /// statements and the two Annex A allocation groups. A matrix that quietly lost a row would drop a
    /// normative obligation without any test noticing.
    /// </summary>
    [TestMethod]
    public void TheMatrixEnumeratesTheWholeSpecification()
    {
        Assert.HasCount(44, RowData, "TS 119 172-4 V1.2.1 states forty-four rows across clauses 4.1-4.5 and Annex A at this matrix's statement granularity.");
    }


    /// <summary>
    /// The technical applicability (rules) checking process rows are all driven by tests over the shipped
    /// composition, and the one VOID identifier stays recorded as VOID rather than dropped.
    /// </summary>
    [TestMethod]
    public void TheTarcRowsAreTestedAndTheVoidIdentifierIsKept()
    {
        foreach(string clauseId in (string[])["REQ-4.4.2-01", "REQ-4.4.2-02", "REQ-4.4.2-04", "REQ-4.4.2-05", "REQ-4.4.2-06"])
        {
            Assert.AreEqual(RequirementCoverageStatus.Tested, RowFor(clauseId).Status, $"{clauseId} is a shipped, tested TARC composition step.");
        }

        RequirementMatrixRow voidRow = RowFor("REQ-4.4.2-03");
        Assert.AreEqual(RequirementCoverageStatus.OutOfScope, voidRow.Status, "The VOID identifier binds nothing.");
        Assert.Contains("VOID", voidRow.Evidence, StringComparison.Ordinal, "The row states the identifier is VOID per the clause 3.4 identifier-management rules.");
    }


    /// <summary>
    /// Every fixed-constraint statement of REQ-4.2-03 is driven by a test: the composition either states the
    /// value or proves the engine behavior the statement leans on.
    /// </summary>
    [TestMethod]
    public void EveryFixedConstraintRowIsTested()
    {
        List<RequirementMatrixRow> constraintRows = [.. RowData
            .Where(row => row.ClauseId.StartsWith("REQ-4.2-03-", StringComparison.Ordinal))
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];

        Assert.HasCount(10, constraintRows, "REQ-4.2-03 splits into its ten lettered statements.");
        foreach(RequirementMatrixRow row in constraintRows)
        {
            Assert.AreEqual(RequirementCoverageStatus.Tested, row.Status, $"{row.ClauseId} is a fixed constraint value or a verified engine behavior.");
        }
    }


    /// <summary>
    /// Every REQ-4.5-01 report element row is driven by the report composition tests, so the lettered field
    /// set stays complete.
    /// </summary>
    [TestMethod]
    public void EveryReportElementRowIsTested()
    {
        List<RequirementMatrixRow> reportRows = [.. RowData
            .Where(row => row.ClauseId.StartsWith("REQ-4.5-01-", StringComparison.Ordinal))
            .Select(row => new RequirementMatrixRow(row.ClauseId, row.Requirement, row.Status, row.Evidence))];

        Assert.HasCount(10, reportRows, "REQ-4.5-01 splits into its ten lettered elements a) through j).");
        foreach(RequirementMatrixRow row in reportRows)
        {
            Assert.AreEqual(RequirementCoverageStatus.Tested, row.Status, $"{row.ClauseId} is a shipped report element.");
        }
    }


    /// <summary>
    /// The deferred format arms of REQ-4.3-01 record the arc charter's sequencing decision rather than
    /// silently claiming or hiding XAdES and PAdES support.
    /// </summary>
    [TestMethod]
    public void TheDeferredFormatRowsRecordTheCharterDecision()
    {
        foreach(string clauseId in (string[])["REQ-4.3-01-a", "REQ-4.3-01-b", "REQ-4.3-01-e-xades", "REQ-4.3-01-e-pades"])
        {
            RequirementMatrixRow row = RowFor(clauseId);
            Assert.AreEqual(RequirementCoverageStatus.OutOfScope, row.Status, $"{clauseId} names a format family the charter schedules later.");
            Assert.Contains("charter", row.Evidence, StringComparison.Ordinal, $"{clauseId} states the charter decision.");
        }
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
        Type? evidenceType = typeof(SignatureApplicabilityRulesRequirementsMatrixTests).Assembly.GetTypes()
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


    /// <summary>The requirements matrix rows, in the specification's clause order followed by the Annex A allocations.</summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        ("4.1-rule-sets", "The document defines two sets of signature applicability rules and allocates an OID for each: id-etsi-sarc-realTimeReq and id-etsi-sarc-realTimeNotReq.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.RuleSetsCarryTheSpecificationsPolicyOidsAndFreshnessValues"),
        ("REQ-4.2-01", "The DA or SVA shall follow the EN 319 102-1 clause 5.1.2 validation process and shall support the validation process for Signatures providing Long Term Availability and Integrity of Validation Material.",
            RequirementCoverageStatus.Tested, "SignatureValidationProcessTests.LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed (the clause 5.6.3 process is shipped and selected per clause 5.1.2)"),
        ("REQ-4.2-02", "The document gives minimum QES requirements: a validation service may use additional inputs or requirements, and if used they shall be clearly indicated in the applicability rules checking report.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportIndicatesNoPseudonymForAnOrdinarySubject (the report's AdditionalRequirementsIndications member carries the indication, empty when none were used)"),
        ("REQ-4.2-03-a", "The SetOfTrustAnchors constraint shall be set to the Service digital identity information of the TS 119 615 clause 4.3 SI-Results, with the signing certificate, the CA/QC service type and the certificate's NotBeforeDate as inputs.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CreateValidationConstraintsEvaluatesTheServiceMatchAtNotBefore (the clause 4.3 run at notBefore decides the anchor set; the anchor octets are the matched identity's certificate per CreateValidationConstraintsComposesTheFixedConstraintValues)"),
        ("REQ-4.2-03-b", "Constraints of TS 119 172-1 table A.2 rows (m)1.2 to (m)1.10 shall not be used.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CreateValidationConstraintsComposesTheFixedConstraintValues (no certificate meta-data constraints, default shell validity model)"),
        ("REQ-4.2-03-c-i", "The RevocationCheckingConstraints shall be set to eitherCheck (table A.2 row (m)2.1).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockGapTests.FreshnessIsDecidedByThisUpdateNeverByProducedAt (the engine reads revocation status from either a CRL or an OCSP response with no per-source mode, and the composed constraints restrict neither source)"),
        ("REQ-4.2-03-c-ii", "The RevocationFreshnessConstraints shall be a maximum of 24h for the signing certificate under realTimeReq, and a maximum of 0 under realTimeNotReq.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.RuleSetsCarryTheSpecificationsPolicyOidsAndFreshnessValues (the engine consumes the stated value per SignatureValidationBuildingBlockTests.UsesTheConstraintValueForRevocationFreshnessWhenOneIsStated)"),
        ("REQ-4.2-03-c-iii", "Constraints of table A.2 rows (m)2.3 and (m)3 shall not be used.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CreateValidationConstraintsComposesTheFixedConstraintValues (no certificate is exempted from revocation checking and no extension-based exemption is stated)"),
        ("REQ-4.2-03-d", "No constraints shall be applied to end-entity certificates representing a trust anchor: clause 5.2.6.4 always returns PASSED for one (NOTE 6).",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.PassesWhenTheSigningCertificateIsATrustAnchorAndFailsAfterItsSunsetDate (the step 1 short-circuit; the composed constraints state no sunset date that could re-constrain it)"),
        ("REQ-4.2-03-e", "The cryptographic verification shall enable reporting the suites used and potential security issues, indicating clearly whether national rules or TS 119 312 expressed them.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (CryptographicSuitesReport carries the uses, the issues and the rules source; the issue assessments come from the dated constraint table per SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm)"),
        ("REQ-4.2-03-f", "An algorithm or suite the application cannot deal with shall not invalidate the signature but lead to an INDETERMINATE result with a warning naming the suite.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.ReportsCryptoConstraintsFailureNoProofOfExistenceForAnUnlistedAlgorithm (INDETERMINATE with the named assessment, never TOTAL-FAILED; the cryptographic verification block's fallback for a suite its binding cannot verify is likewise INDETERMINATE with a diagnostic)"),
        ("REQ-4.2-03-g", "Failure to comply with one of the REQ-4.3-01 signature formats shall not invalidate the signature but yield a warning indicating the failure and its reasons.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.SignedSigningCertificateBindingIsNotRequiredByDefaultAndACAdESSignatureSatisfiesIt (the non-invalidation half: a plain CMS signature carrying no baseline attributes still passes acceptance under the stated constraints alone — the engine applies no baseline-profile gate that could invalidate) with SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (the warning half: the report's FormatComplianceWarnings member carries each failure with its reasons)"),
        ("REQ-4.2-03-h", "The signature elements constraints shall enforce the presence of a signed reference or signed copy of the signing certificate.",
            RequirementCoverageStatus.Tested, "SignatureValidationBuildingBlockTests.RequiredSignedSigningCertificateBindingFailsASignatureCarryingNone (the composed constraints set RequireSignedSigningCertificateBinding, added for this requirement)"),
        ("REQ-4.3-01-a", "The SVA should support signature formats compliant with ETSI TS 103 171 (XAdES baseline profile).",
            RequirementCoverageStatus.OutOfScope, "Recommendation-strength; the EU signatures arc charter schedules XAdES deliberately last, so no XAdES surface ships yet."),
        ("REQ-4.3-01-b", "The SVA should support signature formats compliant with ETSI TS 103 172 (PAdES baseline profile).",
            RequirementCoverageStatus.OutOfScope, "Recommendation-strength; the EU signatures arc charter schedules PAdES deliberately last, so no PAdES surface ships yet."),
        ("REQ-4.3-01-c", "The SVA should support signature formats compliant with ETSI TS 103 173 (CAdES baseline profile).",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.RequirementMatrixTest (the shipped CAdES support is enumerated row by row against ETSI EN 319 122-1, which subsumes the TS 103 173 profile)"),
        ("REQ-4.3-01-d", "The SVA should support signature formats compliant with ETSI TS 103 174 (ASiC baseline profile).",
            RequirementCoverageStatus.Tested, "AsicRequirementsMatrixTests.RequirementMatrixTest (the shipped ASiC support is enumerated row by row against ETSI EN 319 162-1/-2)"),
        ("REQ-4.3-01-e-cades", "The SVA should support CAdES baseline signatures per ETSI EN 319 122-1.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.RequirementMatrixTest"),
        ("REQ-4.3-01-e-xades", "The SVA should support XAdES baseline signatures per ETSI EN 319 132-1.",
            RequirementCoverageStatus.OutOfScope, "Recommendation-strength; the EU signatures arc charter schedules XAdES deliberately last."),
        ("REQ-4.3-01-e-pades", "The SVA should support PAdES baseline signatures per ETSI EN 319 142-1.",
            RequirementCoverageStatus.OutOfScope, "Recommendation-strength; the EU signatures arc charter schedules PAdES deliberately last."),
        ("REQ-4.3-02", "Signature validation applications should be compliant with ETSI TS 119 101.",
            RequirementCoverageStatus.OutOfScope, "Recommendation-strength application-level policy and security requirements binding the signature validation application; the host application states its own TS 119 101 posture over this library."),
        ("REQ-4.3-03", "When provided as a service, the validation and applicability rules checking processes should comply with ETSI TS 119 441.",
            RequirementCoverageStatus.OutOfScope, "Binds a trust service provider offering validation as a service; this repository ships no service."),
        ("REQ-4.3-04", "Relying parties shall be provided with unambiguous information on any security relevant issue the validation and checking processes identified.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (the report model carries the security issues, the determinations and the conclusion's reasons in full, typed)"),
        ("REQ-4.3-05", "Relying parties shall be provided with procedures and facilities to validate signatures and obtain validation and checking results data.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CheckDeterminesSuitabilityForAQualifiedSignatureWithQscdAndTotalPassed (the shipped composition verbs and the report are the facility a host exposes to its relying parties)"),
        ("REQ-4.3-06", "Relying parties shall be provided with procedures and facilities to identify further actions when preservation of signed data and associated signatures is required.",
            RequirementCoverageStatus.OutOfScope, "A relying-party provisioning duty of the host service; the preservation capabilities themselves are enumerated separately against ETSI TS 119 511/512 in PreservationRequirementsMatrixTests."),
        ("REQ-4.4.2-01", "The TARC process shall perform TS 119 615 clause 4.4 with CERT set to the signing certificate and Date-time set to the best signature time of the REQ-4.2-01 process.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CheckDeterminesSuitabilityForAQualifiedSignatureWithQscdAndTotalPassed (the determination runs at the conclusion's best signature time; a conclusion without one is refused per CheckRefusesAConclusionWithoutBestSignatureTime)"),
        ("REQ-4.4.2-02", "When QC-Status includes PROCESS_PASSED and QC-Results includes QC_For_eSig or QC_For_eSeal the certificate is determined qualified; otherwise the process stops, the signature is determined technically indeterminate and all intermediate results are reflected in the report.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CheckStopsWithoutDeviceDeterminationWhenTheCertificateIsNotQualified (the stop, the neither-determination and the retained intermediates); the status conjunct read strictly in CheckStopsWhenTheCertificateDeterminationFailsEvenWithAQualifiedIndicationRetained (a PROCESS_FAILED determination retaining a qualified indication does not qualify)"),
        ("REQ-4.4.2-03", "Void.",
            RequirementCoverageStatus.OutOfScope, "VOID in V1.2.1; the identifier is kept per the clause 3.4 identifier-management rules, so this matrix keeps its row."),
        ("REQ-4.4.2-04", "The TARC process shall perform TS 119 615 clause 4.5 with the same CERT and Date-time.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CheckDeterminesSuitabilityForAQualifiedSignatureWithQscdAndTotalPassed (the shipped clause 4.5 procedure re-runs clause 4.4 internally, which NOTE 3 permits an implementation to shortcut but does not require)"),
        ("REQ-4.4.2-05", "When QSCD-Status includes PROCESS_PASSED and QSCD-Results includes QSCD_YES the signature is determined created by a qualified device; otherwise the process stops and the signature is determined technically indeterminate.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CheckWithoutQscdMapsToAdvancedSignatureWithQualifiedCertificate (the negative arm; the affirmative arm in CheckDeterminesSuitabilityForAQualifiedSignatureWithQscdAndTotalPassed)"),
        ("REQ-4.4.2-06", "With a determined qualified certificate, a determined qualified creation device and TOTAL-PASSED, the signature shall be determined technically suitable as an EU qualified electronic signature (respectively seal); otherwise as neither.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CheckWithoutTotalPassedYieldsNoSuitability (condition c); the affirmative arms in CheckDeterminesSuitabilityForAQualifiedSignatureWithQscdAndTotalPassed and CheckDeterminesSuitabilityForAQualifiedSeal)"),
        ("REQ-4.5-01-a", "The report shall include the stated scope text of the applicability rules checking.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (exact transcription equality)"),
        ("REQ-4.5-01-b", "The report shall include the complete signer data of the certificate's Subject field and, when present, its Subject Alternative Name extension.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (SignerSubject and SubjectAlternativeNames)"),
        ("REQ-4.5-01-c", "The use of any pseudonym at the best signature time shall be clearly indicated.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (derived from the subject's X.520 attribute types; the counter-case in BuildReportIndicatesNoPseudonymForAnOrdinarySubject)"),
        ("REQ-4.5-01-d", "The report shall state the timing information points with their evidential relevance and level of assurance — time-stamp policy, accuracy and EU qualification — and should express an absent TSA/QTST trust anchor.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (the ApplicabilityTimingInformation model states the d) i)-iii) points, the qualification member being the TS 119 615 clause 4.7 determination result)"),
        ("REQ-4.5-01-e", "The report shall present the data covered by the signature.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (SignedDataPresentations)"),
        ("REQ-4.5-01-f", "The report shall list the signature attributes and indicate which were signed and which were not.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (the format binding's attribute facts carry identifier, signed/unsigned scope and well-formedness)"),
        ("REQ-4.5-01-g", "The report shall state the overall status of the checking and the reasons that led to it.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (the checking outcome and the EN 319 102-1 conclusion travel whole, in the vocabulary NOTE 6 points at)"),
        ("REQ-4.5-01-h", "The report shall carry cryptographic suites information and clearly indicate which of the national rules or TS 119 312 failed.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (CryptographicSuitesReport with its required RulesSource)"),
        ("REQ-4.5-01-i", "The report shall state the freshness of the revocation status information used for the signing certificate against the best signature time.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (SigningCertificateRevocationFreshness)"),
        ("REQ-4.5-01-j", "The report may include the detailed outcome of each step of the checking, including the technical signature validation's.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier (the optional DetailedOutcome attaches the TS 119 102-2 report element)"),
        ("REQ-4.5-02", "The Annex A OIDs may be used to identify the signature's type and compliance with this document in the report.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.CheckDeterminesSuitabilityForAQualifiedSignatureWithQscdAndTotalPassed (euqesig; euqeseal in CheckDeterminesSuitabilityForAQualifiedSeal, adesigqc in CheckWithoutQscdMapsToAdvancedSignatureWithQualifiedCertificate, adesealqc in CheckWithoutQscdOnASealCertificateMapsToAdvancedSealWithQualifiedCertificate; the identifiers pinned by AnnexAObjectIdentifiersMatchTheSpecificationsArc)"),
        ("A-1-policies", "Annex A allocates id-etsi-sars, id-etsi-sars-SpCompliance and the two signature applicability rules identifiers under itu-t(0) identified-organization(4) etsi(0) idsigapprules(191724).",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.AnnexAObjectIdentifiersMatchTheSpecificationsArc"),
        ("A-2-sigtypes", "Annex A allocates id-etsi-sars-SigType and the seven digital signature type identifiers.",
            RequirementCoverageStatus.Tested, "SignatureApplicabilityRulesTests.AnnexAObjectIdentifiersMatchTheSpecificationsArc")
    ];
}
