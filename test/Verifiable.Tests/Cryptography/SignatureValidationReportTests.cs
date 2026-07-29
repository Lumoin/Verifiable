using System;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Validates <see cref="SignatureValidationReportBuilder"/>, which builds the clause 4 validation report graph of
/// ETSI TS 119 102-2 V1.4.1 from a completed ETSI EN 319 102-1 V1.4.1 signature validation run.
/// </summary>
/// <remarks>
/// Every scenario is <see cref="SignatureValidationProcessTests.SignatureScenario"/> — a real CAdES signature
/// with real time-stamps validated over a real three-level certificate chain through the shipped seams — so the
/// report is built from the same evidence the process tests already exercise, rather than from hand-built
/// conclusions a report test could get away with mis-shaping.
/// </remarks>
[TestClass]
internal sealed class SignatureValidationReportTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The clause 4 report of a real Basic Signature validation of a revoked signing certificate carries every
    /// element the clause makes mandatory and projects the conclusion's own Table 6 evidence onto the associated
    /// validation report data of clause 4.3.12 rather than restating it.
    /// </summary>
    [TestMethod]
    public async Task BasicValidationOfARevokedSigningCertificateOmitsNoElementAndProjectsTheRevocationEvidence()
    {
        using var scenario = await SignatureValidationProcessTests.SignatureScenario.CreateAsync(
            "report-revoked-signer.example.test", revokeSigningCertificate: true, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, scenario.Inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, report.SignatureValidationReports, "Clause 4.2: one Signature-Validation-Report-Element per validated signature.");
        SignatureValidationReportElement element = report.SignatureValidationReports[0];

        Assert.AreEqual(SignatureValidationWellKnown.MainIndicationIndeterminate, element.Status.MainIndication,
            "Clause 4.3.4.2's TOTAL-* URI set applies to the top-level status of a validation report of a signature.");
        Assert.Contains(
            SignatureValidationSubIndicationMapping.ToWireValue(SignatureValidationSubIndication.RevokedNoProofOfExistence),
            element.Status.SubIndications,
            "Clause A.3.2 names INDETERMINATE/REVOKED_NO_POE.");
        Assert.IsNotNull(element.SignatureIdentifier, "Clause 4.3.3.1: absent only for FORMAT_FAILURE, which this scenario does not reach.");

        AssociatedValidationReportDataElement revocation = element.Status.AssociatedValidationReportData.Single();
        Assert.IsInstanceOfType<CertificateRevocationReportData>(revocation.Source, "The conclusion's own Table 6 evidence is referenced, not duplicated.");
        Assert.IsNotEmpty(revocation.CertificateChain, "Clause 4.3.12.4 projects the chain Table 6 carries alongside the revocation.");
        Assert.AreEqual(scenario.Chain[^1], revocation.TrustAnchor, "Clause 4.3.12.4.1: the trust anchor is the last element of the chain.");
        Assert.IsNotNull(revocation.RevocationStatusInformation, "Clause 4.3.12.6 is present whenever a certificate was found revoked.");
        Assert.AreEqual(scenario.Chain[0], revocation.RevocationStatusInformation!.RevokedCertificate,
            "The signing certificate itself is revoked in this scenario, not the intermediate.");
        Assert.AreEqual(scenario.CertificationAuthorityRevocationTime, revocation.RevocationStatusInformation!.RevocationTime,
            "Clause 4.3.12.6.1 item 2) is mandatory: the time of revocation.");
    }


    /// <summary>
    /// A <c>TOTAL-PASSED</c> validation with time reports the signer's information and the validation objects of
    /// clause 4.4 that the run actually used.
    /// </summary>
    [TestMethod]
    public async Task ValidationWithTimeOfATotalPassedSignatureReportsTheSignerAndTheValidationObjects()
    {
        using var scenario = await SignatureValidationProcessTests.SignatureScenario.CreateAsync(
            "report-passed.example.test", revokeSigningCertificate: true, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, scenario.Inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationReportElement element = report.SignatureValidationReports[0];
        Assert.AreEqual(SignatureValidationWellKnown.MainIndicationTotalPassed, element.Status.MainIndication,
            "Clause A.3.3 turns this scenario TOTAL-PASSED.");
        Assert.IsNotNull(element.SignerInformation, "Clause 4.3.9.1: mandatory once a signing certificate was identified.");
        Assert.AreEqual(scenario.Chain[0], element.SignerInformation!.SignerCertificate,
            "Clause 4.3.9's referenced object is the identified signing certificate.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermValidationMaterial, element.SignatureValidationProcessInfo!.ProcessIdentifier,
            "Clause 4.3.11.1's URI names the process of clause 5.5 that actually ran.");
        Assert.IsNotEmpty(element.SignatureAttributes, "Clause 4.3.8: the CAdES signature carries signed attributes.");
        Assert.Contains(true, element.SignatureAttributes.Select(a => a.Signed).ToArray(), "At least one attribute is a signed attribute.");

        Assert.IsNotEmpty(report.SignatureValidationObjects, "Clause 4.4: the certificate chain and validation data used populate the object list.");
        Assert.Contains(ValidationObjectKind.Certificate, report.SignatureValidationObjects.Select(o => o.ObjectType).ToArray(),
            "The certificate chain contributes at least one certificate-kind object.");
        foreach(ValidationObject validationObject in report.SignatureValidationObjects)
        {
            Assert.AreNotEqual(ValidationObjectKind.Unknown, validationObject.ObjectType,
                "Every carrier this builder gathers is a certificate, CRL, OCSP response or time-stamp token this wave classifies.");
        }
    }


    /// <summary>
    /// The time information of the report states the best-signature-time step 6) of clause 5.6.3.4 determined,
    /// which for this world is the generation time of the real archive time-stamp the signature carries.
    /// </summary>
    [TestMethod]
    public async Task LongTermValidationAttachesTheRealArchiveTimestampProofToBestSignatureTime()
    {
        using var scenario = await SignatureValidationProcessTests.SignatureScenario.CreateAsync(
            "report-long-term.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, scenario.Inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ValidationTimeInfo timeInfo = report.SignatureValidationReports[0].ValidationTimeInfo!;
        Assert.AreEqual(scenario.CurrentTime, timeInfo.ValidationTime, "Clause 4.3.6.1 item 1): the date and time the validation was performed.");
        Assert.AreEqual(scenario.ArchiveTimestampTime, timeInfo.BestSignatureTime.Instant,
            "Step 6) of clause 5.6.3.4 determines best-signature-time from the accumulated proofs of existence, which the archive time-stamp establishes.");
        Assert.AreEqual(ProofOfExistenceOrigin.TimestampToken, timeInfo.BestSignatureTime.Origin,
            "The real accumulated proof of existence is reused rather than a synthetic one, so its origin is a validated time-stamp token.");
    }


    /// <summary>
    /// Without a Driving Application time indication for signature existence the report states the current time
    /// with the origin the clause defines for a time nothing proved, never a claimed origin it cannot support.
    /// </summary>
    [TestMethod]
    public async Task BasicValidationWithNoDrivingApplicationTimeIndicationReportsAnUnknownOriginAtTheCurrentTime()
    {
        using var scenario = await SignatureValidationProcessTests.SignatureScenario.CreateAsync(
            "report-basic-time.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, scenario.Inputs, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ValidationTimeInfo timeInfo = report.SignatureValidationReports[0].ValidationTimeInfo!;
        Assert.AreEqual(scenario.CurrentTime, timeInfo.BestSignatureTime.Instant,
            "The NOTE of clause 4.3.6.1: the current time for the validation process for Basic Signatures.");
        Assert.AreEqual(ProofOfExistenceOrigin.Unknown, timeInfo.BestSignatureTime.Origin,
            "Neither a signature time-stamp nor a Driving Application time indication established this instant, so no origin can honestly be stated.");
    }


    /// <summary>
    /// A Signed Data Object the binding cannot parse yields a report that omits the signature identification
    /// clause 4 conditions on a parsed signature and states the format failure instead.
    /// </summary>
    [TestMethod]
    public async Task AnUnparsableSignedDataObjectOmitsTheSignatureIdentifierAndReportsFormatFailure()
    {
        using var scenario = await SignatureValidationProcessTests.SignatureScenario.CreateAsync(
            "report-format-failure.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData notCms = CmsSignedData.FromBytes("not a signed data object"u8, BaseMemoryPool.Shared);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs with { SignedDataObject = notCms }, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, scenario.Inputs with { SignedDataObject = notCms }, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationReportElement element = report.SignatureValidationReports[0];
        Assert.AreEqual(SignatureValidationWellKnown.MainIndicationTotalFailed, element.Status.MainIndication,
            "Clause 5.1.2 step 6) of EN 319 102-1 promotes a FAILED format check to TOTAL-FAILED.");
        Assert.Contains(SignatureValidationSubIndicationMapping.ToWireValue(SignatureValidationSubIndication.FormatFailure), element.Status.SubIndications,
            "The sub-indication is FORMAT_FAILURE.");
        Assert.IsNull(element.SignatureIdentifier,
            "Clause 4.3.3.1: this element is absent exactly for TOTAL-FAILED/FORMAT_FAILURE.");
        Assert.IsEmpty(element.SignatureAttributes, "No attributes can be surfaced from a signature whose facts were never extracted.");
        Assert.IsNull(element.SignerInformation, "No signing certificate was identified from unparsable bytes.");
    }


    /// <summary>
    /// Clause 4.3.5.4: a check the constraints disabled is reported as an individual validation constraint report
    /// carrying the disabled status, so a reader can tell a check that passed from one that never ran.
    /// </summary>
    [TestMethod]
    public async Task ChecksDisabledByPolicyProjectOntoDisabledIndividualValidationConstraintReports()
    {
        using var scenario = await SignatureValidationProcessTests.SignatureScenario.CreateAsync(
            "report-disabled-constraint.example.test", revokeSigningCertificate: true, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationInputs inputsWithDisabledCheck = scenario.Inputs with
        {
            Constraints = scenario.Constraints with { ChecksDisabledByPolicy = [ValidationConstraintIdentifier.RevocationFreshness] }
        };

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputsWithDisabledCheck, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.Contains(ValidationConstraintIdentifier.RevocationFreshness, outcome.Conclusion.ChecksDisabledByPolicy,
            "Clause 5.1.4.1 requires the SVA to return, in its final report, the checks the constraints stated were not required.");

        ValidationReport report = await SignatureValidationReportBuilder.BuildAsync(
            outcome, inputsWithDisabledCheck, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ValidationConstraintsEvaluationReport constraintsReport = report.SignatureValidationReports[0].ValidationConstraintsEvaluationReport!;
        IndividualValidationConstraintReport disabled = constraintsReport.ValidationConstraints.Single(
            c => c.ConstraintIdentifier.Equals(ValidationConstraintIdentifier.RevocationFreshness));

        Assert.AreEqual(ConstraintApplicationStatus.Disabled, disabled.Status,
            "Clause 4.3.5.4.1 item 2): whether the constraint was applied, disabled, or overridden.");
        Assert.IsNull(disabled.Result,
            "Clause 4.3.5.4.1: the validation result is present only when the constraint was not disabled or overridden.");
    }
}
