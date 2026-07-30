using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The report-building flow: the world of clause A.3 example 1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> is validated with time through the shipped engine, and the clause 4 validation
/// report graph of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see> is built from the run and asserted element by element.
/// </summary>
/// <remarks>
/// <para>
/// The engine run is the same one <c>AnnexAValidationScenarioTests</c> asserts the conclusion of, so what is
/// under test here is only the projection: whether every element clause 4.3 makes mandatory or conditionally
/// mandatory for the validation report of a signature is populated from the run's own evidence, in the wire
/// vocabulary clause 4.3.4 fixes.
/// </para>
/// <para>
/// The constraint set states one check the policy disabled, because clause 5.1.4.1 of EN 319 102-1 requires the
/// Signature Validation Application to return those in its final report and clause 4.3.5.1 requires the report
/// to carry an individual validation constraint report element for each of them. Without it the report of a
/// <c>TOTAL-PASSED</c> run would carry an empty constraints report — see the flag in this stage's build-log
/// section about constraints that were applied and passed.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AnnexAValidationReportFlowTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The status indication, the validation time information, the signer information and the process
    /// information of clauses 4.3.4, 4.3.6, 4.3.9 and 4.3.11, each populated from what the run of clause 5.5
    /// concluded and each carrying the URI clause 4.3.4.2 and clause 4.3.11.1 fix for it.
    /// </summary>
    [TestMethod]
    public async Task Example1WithTimeReportCarriesTheMandatedStatusTimeSignerAndProcessElements()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        SignatureValidationInputs inputs = WithADisabledCheck(scenario);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, report.SignatureValidationReports, "Clause 4.2: one Signature-Validation-Report-Element per validated signature.");
        SignatureValidationReportElement element = report.SignatureValidationReports[0];

        Assert.AreEqual(SignatureValidationWellKnown.MainIndicationTotalPassed, element.Status.MainIndication,
            "Clause 4.3.4.2 fixes the URI for TOTAL-PASSED in the validation report of a signature.");
        Assert.IsEmpty(element.Status.SubIndications, "Clause 4.3.4.3: sub-indication elements explain a non-passing indication, of which there is none here.");
        AssociatedValidationReportDataElement associated = element.Status.AssociatedValidationReportData.Single();
        Assert.IsInstanceOfType<CertificateRevocationReportData>(associated.Source,
            "Step 11) of EN 319 102-1 clause 5.5.4 returns, alongside PASSED, the additional information the intermediate steps used — here the revocation the signature time-stamp let the process overcome; clause 4.3.4.2 carries it in an associated validation data element.");
        Assert.HasCount(3, associated.CertificateChain, "Clause 4.3.12.4 projects the chain that evidence names, certificate by certificate.");
        Assert.AreEqual(scenario.Chain[^1], associated.TrustAnchor, "Clause 4.3.12.4.1: the trust anchor is the last element of the chain.");
        Assert.IsNotNull(associated.RevocationStatusInformation, "Clause 4.3.12.6 is present whenever a certificate was found revoked.");
        Assert.AreEqual(scenario.Chain[0], associated.RevocationStatusInformation!.RevokedCertificate,
            "Clause 4.3.12.6.1 item 1): the certificate the revocation status information is about.");
        Assert.AreEqual(scenario.SigningCertificateRevoked, associated.RevocationStatusInformation!.RevocationTime,
            "Clause 4.3.12.6.1 item 2) is mandatory: the time of revocation, which the timeline places at t4.");

        Assert.IsNotNull(element.SignatureIdentifier, "Clause 4.3.3.1: this element is absent only for TOTAL-FAILED/FORMAT_FAILURE.");
        Assert.IsNotNull(element.SignatureIdentifier!.SignatureValue, "Clause 4.3.3.1 item 2): the signature value identifies the signature within its Signed Data Object.");
        Assert.IsFalse(element.SignatureIdentifier!.HashOnly, "The signature encapsulates its content, so nothing was validated from a hash alone.");
        Assert.IsFalse(element.SignatureIdentifier!.DocHashOnly, "The signer's document was available in full.");

        ValidationTimeInfo timeInfo = element.ValidationTimeInfo!;
        Assert.AreEqual(scenario.ValidationTime, timeInfo.ValidationTime, "Clause 4.3.6.1 item 1): the date and time the validation was performed.");
        Assert.AreEqual(scenario.SignatureTimestampCreated, timeInfo.BestSignatureTime.Instant,
            "Clause 4.3.6.1 item 2): the date and time for which a proof of existence of the signature has been identified, which clause 5.5.4 makes best-signature-time.");
        Assert.AreEqual(ProofOfExistenceOrigin.TimestampToken, timeInfo.BestSignatureTime.Origin,
            "Clause 4.3.6.1 admits information on the source of the proof; here a validated signature time-stamp token established it.");
        Assert.AreEqual(SignatureValidationReportWellKnown.ProofOfExistenceTypeValidation,
            ProofOfExistenceOriginMapping.ToWireValue(timeInfo.BestSignatureTime.Origin),
            "Clause 4.4.6.2's TypeOfProof vocabulary is what a serializer emits for that origin.");

        Assert.IsNotNull(element.SignerInformation, "Clause 4.3.9.1: mandatory once a signing certificate was identified.");
        Assert.AreEqual(scenario.Chain[0], element.SignerInformation!.SignerCertificate, "Clause 4.3.9 references the identified signing certificate.");
        Assert.IsNotEmpty(element.SignerInformation!.Signer!, "Clause 4.3.9.1 admits the human readable name of the signer, rendered from the certificate's subject.");

        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermValidationMaterial, element.SignatureValidationProcessInfo!.ProcessIdentifier,
            "Clause 4.3.11.1 names the validation process that was applied, which is the one of EN 319 102-1 clause 5.5.");
        Assert.AreEqual(SignatureValidationWellKnown.ValidationProcessLongTermValidationMaterial, element.SignatureValidationProcessInfo!.ProcessIdentifier.Value,
            "That process identity is the URI clause 4.3.11.1 fixes for it.");

        Assert.IsNotNull(element.SignersDocument, "Clause 4.3.7.1: the signer's document element, present because the signature encapsulates its content.");
        Assert.IsNotNull(element.SignersDocument!.Representation, "The content the signature covers is the representation reported.");
        Assert.IsNotEmpty(element.SignatureAttributes, "Clause 4.3.8: one element per attribute the format binding surfaced.");
        Assert.Contains(CAdESSignatureFacts.SigningCertificateV2AttributeOid, element.SignatureAttributes.Select(a => a.Identifier).ToArray(),
            "The signing-certificate-v2 signed attribute the signature carries is reported.");
        Assert.IsTrue(element.SignatureAttributes.All(a => a.IsWellFormed), "Every attribute of this signature parsed, so none is reported as present-but-malformed.");
    }


    /// <summary>
    /// The validation objects of clause 4.4: the validated certificate chain and the validation data the run
    /// consulted are each projected as an object with the type clause 4.4.4 fixes, and the content the signature
    /// covers is projected alongside them.
    /// </summary>
    [TestMethod]
    public async Task Example1WithTimeReportProjectsTheValidatedChainAndTheValidationDataAsValidationObjects()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        SignatureValidationInputs inputs = WithADisabledCheck(scenario);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<ValidationObject> objects = report.SignatureValidationObjects;
        Assert.IsNotEmpty(objects, "Clause 4.4: the objects used during validation.");
        Assert.IsTrue(objects.All(o => o.ObjectType != ValidationObjectKind.Unknown),
            "Every carrier the builder gathers is classified into the vocabulary clause 4.4.4 fixes.");

        List<PkiCertificateMemory> certificates = [.. objects.Where(o => o.ObjectType == ValidationObjectKind.Certificate).Select(o => (PkiCertificateMemory)o.Representation!)];
        Assert.HasCount(4, certificates,
            "The validated certificate chain Table 5 of EN 319 102-1 clause 5.1.3 mandates on TOTAL-PASSED is projected certificate by certificate, together with the one further certification authority certificate the Driving Application supplied as validation data and the run therefore reports as used.");
        for(int i = 0; i < scenario.Chain.Count; ++i)
        {
            Assert.Contains(scenario.Chain[i], certificates, "Every certificate of the chain the run validated is a validation object.");
        }

        Assert.IsNotEmpty(objects.Where(o => o.ObjectType == ValidationObjectKind.RevocationData).ToArray(),
            "The revocation status information the run consulted is validation data used, which clause 5.1.3 requires alongside the validation time.");
        Assert.HasCount(1, objects.Where(o => o.ObjectType == ValidationObjectKind.SignedDataObject).ToArray(),
            "The content the signature covers is projected once.");
        Assert.AreEqual(SignatureValidationReportWellKnown.ValidationObjectCertificate,
            ValidationObjectKindMapping.ToWireValue(ValidationObjectKind.Certificate),
            "Clause 4.4.4 fixes the URI a serializer emits for a certificate object.");

        foreach(ValidationObject validationObject in objects)
        {
            Assert.IsNull(validationObject.ProofOfExistence,
                "Clause 4.4.7's proof of existence is attached only by the validation process for Signatures providing Long Term Availability and Integrity of Validation Material, which this run is not.");
        }
    }


    /// <summary>
    /// The validation constraints evaluation report of clause 4.3.5: the checks the validation policy disabled
    /// are each reported as an individual validation constraint report element with the status clause 4.3.5.4
    /// fixes and, per its own rule, without a validation result.
    /// </summary>
    [TestMethod]
    public async Task Example1WithTimeReportListsTheChecksThePolicyDisabledAsIndividualConstraintReports()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);
        SignatureValidationInputs inputs = WithADisabledCheck(scenario);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "Stating a disabled check does not change the conclusion of clause A.3.3; the report is what changes.");
        Assert.Contains(ValidationConstraintIdentifier.RevocationFreshness, outcome.Conclusion.ChecksDisabledByPolicy,
            "Clause 5.1.4.1 of EN 319 102-1 requires the Signature Validation Application to return the checks the constraints stated were not required.");

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ValidationConstraintsEvaluationReport constraints = report.SignatureValidationReports[0].ValidationConstraintsEvaluationReport!;
        Assert.IsNotNull(constraints, "Clause 4.3.5.1: this element shall be present in the validation report of a signature.");
        Assert.IsNull(constraints.SignatureValidationPolicy,
            "Clause 4.3.5.1's formal policy element is present only when a formal signature validation policy specification drove the validation; this run was driven by caller-supplied constraints.");

        IndividualValidationConstraintReport disabled = constraints.ValidationConstraints.Single(
            c => c.ConstraintIdentifier.Equals(ValidationConstraintIdentifier.RevocationFreshness));
        Assert.AreEqual(ConstraintApplicationStatus.Disabled, disabled.Status,
            "Clause 4.3.5.4.1 item 2): whether the constraint was applied, disabled or overridden.");
        Assert.AreEqual(SignatureValidationReportWellKnown.ConstraintStatusDisabled,
            ConstraintApplicationStatusMapping.ToWireValue(disabled.Status),
            "Clause 4.3.5.4 fixes the URI a serializer emits for a disabled constraint.");
        Assert.IsNull(disabled.Result, "Clause 4.3.5.4.1: the validation result is present only for a constraint that was actually applied.");
        Assert.IsNull(disabled.OverriddenBy, "Nothing overrode this constraint; the policy disabled it outright.");
    }


    /// <summary>
    /// The POE Provisioning of clause 4.4.7: after the validation process for Signatures providing Long Term
    /// Availability and Integrity of Validation Material has run, the archive time-stamp token is itself a
    /// validation object, it carries the proof time it established, and it names the objects it provided that
    /// proof of existence for — which for the world of clause A.3.4 is what the earlier time-stamp and the
    /// certificates the signature carries owe their proofs at <c>t5</c> to.
    /// </summary>
    [TestMethod]
    public async Task Example2LongTermReportNamesWhatTheArchiveTimestampProvesTheExistenceOf()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, scenario.Inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<ValidationObject> objects = report.SignatureValidationObjects;
        List<ValidationObject> tokens = [.. objects.Where(o => o.ObjectType == ValidationObjectKind.TimestampToken)];
        ValidationObject archiveToken = tokens.Single(t => t.ProvidesProofOfExistenceFor.Count > 0);
        ProofOfExistenceProvisioning provisioning = archiveToken.ProvidesProofOfExistenceFor.Single();

        List<SensitiveMemory> covered = [.. provisioning.CoveredObjects];
        ValidationObject signingCertificate = objects.Single(
            o => o.ObjectType == ValidationObjectKind.Certificate && o.Representation.Equals(scenario.Chain[0]));

        Assert.HasCount(2, tokens,
            "Clause 4.4: the signature time-stamp of t3 and the archive time-stamp of t5 are both objects the validation used, so both are projected.");
        Assert.AreEqual(scenario.ArchiveTimestampCreated, provisioning.ProofTime,
            "Clause 4.4.7.1: the time value of the proof, which for an archive time-stamp is its own generation time.");
        Assert.Contains(signingCertificate.Representation, covered,
            "Clause 4.4.7 names the objects the validation object provides a proof of existence for; the signing certificate travels inside the signature the archive time-stamp protects.");
        Assert.Contains(tokens.Single(t => !ReferenceEquals(t, archiveToken)).Representation, covered,
            "An archive time-stamp protects the whole signature except itself, so the earlier signature time-stamp token is among the objects it proves existed.");
        Assert.AreEqual(scenario.ArchiveTimestampCreated, signingCertificate.ProofOfExistence!.Instant,
            "Clause 4.4.6: the same run attaches the earliest proof of the object's existence to the object itself, which is the proof the archive time-stamp established.");
        Assert.IsEmpty(signingCertificate.ProvidesProofOfExistenceFor,
            "Clause 4.4.7 is about what a time-stamp token or evidence record proves; a certificate establishes no proof of existence for anything.");
    }


    /// <summary>
    /// States one check the validation policy disables, so that the report of a passing run carries the
    /// individual validation constraint report elements clause 4.3.5.1 requires for disabled checks.
    /// </summary>
    /// <param name="scenario">The world whose inputs are narrowed.</param>
    /// <returns>The inputs with the disabled check stated.</returns>
    private static SignatureValidationInputs WithADisabledCheck(AnnexAValidationScenario scenario) => scenario.Inputs with
    {
        Constraints = scenario.Constraints with { ChecksDisabledByPolicy = [ValidationConstraintIdentifier.RevocationFreshness] }
    };
}
