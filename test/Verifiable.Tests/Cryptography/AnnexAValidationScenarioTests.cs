using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The worked validation examples of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 Annex A</see>, driven end to end through the shipped engine over the real minted
/// worlds of <see cref="AnnexAValidationScenario"/>: clause A.3.2 and A.3.3 for example 1 ("Revoked
/// certificate"), and clauses A.3.5, A.3.6 and A.3.7 for example 2 ("Revoked CA certificate").
/// </summary>
/// <remarks>
/// <para>
/// Each test asserts the <em>content</em> of the conclusion, not only its indication: the associated validation
/// report data of Table 6 that the reported sub-indication mandates (the certificate chain, the revoked
/// certificate within it, the time and the reason of revocation), the process identity of clause 5.1.3, the
/// validation time the status was determined for, and best-signature-time where the process determines one. An
/// example that reached the right enumeration value through the wrong evidence would fail here.
/// </para>
/// <para>
/// The worlds themselves are asserted to be internally consistent by <c>AnnexAValidationFixtureTests</c>; this
/// class assumes them and spends its assertions on the algorithm's conclusions.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AnnexAValidationScenarioTests
{
    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Clause A.3.2: the validation process for Basic Signatures of clause 5.3 cannot process the
    /// signature-time-stamp attribute, so a signing certificate revoked at <c>t4</c> leaves the status
    /// <c>INDETERMINATE</c>/<c>REVOKED_NO_POE</c>. The mandated report data of Table 6 — the chain used in the
    /// validation together with the time and the reason of revocation — is asserted item by item.
    /// </summary>
    [TestMethod]
    public async Task Example1BasicValidationReportsRevokedNoProofOfExistenceWithTheMandatedRevocationEvidence()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion.Indication,
            "Clause A.3.2 states the expected result INDETERMINATE.");
        Assert.HasCount(1, conclusion.SubIndications, "One sub-indication explains one reason.");
        Assert.AreEqual(SignatureValidationSubIndication.RevokedNoProofOfExistence, conclusion.SubIndications[0],
            "Clause A.3.2 states the expected sub-indication REVOKED_NO_POE.");

        CertificateRevocationReportData revocation = SingleReportData<CertificateRevocationReportData>(conclusion);
        Assert.HasCount(3, revocation.CertificateChain,
            "Table 6 mandates the certificate chain used in the validation process: the signing certificate, its certification authority and the trust anchor.");
        Assert.AreEqual(scenario.Chain[0], revocation.CertificateChain[0], "The chain starts at the signing certificate.");
        Assert.AreEqual(scenario.Chain[2], revocation.CertificateChain[2], "The chain ends at the trust anchor of the world.");
        Assert.AreEqual(scenario.Chain[0], revocation.RevokedCertificate,
            "In example 1 the revoked certificate is the signing certificate itself.");
        Assert.AreEqual(scenario.SigningCertificateRevoked, revocation.RevocationTime,
            "Table 6 mandates the time of revocation, which the timeline of clause A.3.1 places at t4.");
        Assert.AreEqual(X509ChainTestRingRevocation.KeyCompromiseReason, revocation.RevocationReason,
            "Table 6 mandates the reason of revocation when the revocation data states one.");

        Assert.AreEqual(scenario.ValidationTime, conclusion.ValidationTime,
            "Clause 5.1.3 requires the date and time the validation status was determined for, which NOTE 1 makes the current time for this process.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, conclusion.ProcessIdentifier,
            "Clause 5.1.3 requires the validation process that has been used, which is the one of clause 5.3.");
        Assert.AreEqual(SignatureValidationPolicyIdentifier.CallerSuppliedConstraints, conclusion.PolicyIdentifier,
            "Clause 5.1.3 requires an indication of the set of constraints validated against.");
        Assert.IsNull(conclusion.BestSignatureTime,
            "The validation process for Basic Signatures determines no best-signature-time; only clauses 5.5 and 5.6.3 do.");
        Assert.HasCount(3, conclusion.ValidatedCertificateChain,
            "Table 13 of clause 5.2.6.3 calls the chain reported alongside a revocation the validated certificate chain: certification path validation succeeded and only the revocation status made the outcome indeterminate.");
    }


    /// <summary>
    /// Clause A.3.3: the validation process of clause 5.5 processes the signature-time-stamp attribute, finds
    /// that the signing time lies before the revocation date, and turns the status
    /// <c>INDETERMINATE</c>/<c>REVOKED_NO_POE</c> into <c>TOTAL-PASSED</c> with best-signature-time at the
    /// generation time of the token.
    /// </summary>
    /// <remarks>
    /// Best-signature-time is asserted twice: once against the timeline instant the world places at <c>t3</c>,
    /// and once against the generation time read out of the token the signature actually carries, so the
    /// assertion does not rest on the fixture's own bookkeeping alone.
    /// </remarks>
    [TestMethod]
    public async Task Example1ValidationWithTimeReportsTotalPassedAtTheSignatureTimestampGenerationTime()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        DateTimeOffset tokenGenerationTime = await ReadSignatureTimestampGenerationTimeAsync(scenario).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, conclusion.Indication,
            "Clause A.3.3 states the expected result TOTAL-PASSED.");
        Assert.IsEmpty(conclusion.SubIndications, "Table 5 names no sub-indication for TOTAL-PASSED.");
        Assert.AreEqual(scenario.SignatureTimestampCreated, conclusion.BestSignatureTime,
            "Step 3)b) of clause 5.5.4 lowers best-signature-time to the generation time of the token that validated, which the timeline places at t3.");
        Assert.AreEqual(tokenGenerationTime, conclusion.BestSignatureTime,
            "Best-signature-time is the generation time the token itself states, not a value the fixture merely remembers.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermValidationMaterial, conclusion.ProcessIdentifier,
            "The process that ran is the one of clause 5.5.");
        Assert.HasCount(3, conclusion.ValidatedCertificateChain,
            "Table 5 mandates the validated certificate chain including the signing certificate on TOTAL-PASSED.");

        SignatureWithTimeValidationResult withTime = outcome.SignatureWithTimeValidation!;
        Assert.HasCount(1, withTime.AcceptedSignatureTimestamps,
            "Steps 3)a) and 3)b) keep the single signature time-stamp token, whose message imprint binds the signature value and whose own validation passed.");
        Assert.AreEqual(SignatureValidationSubIndication.RevokedNoProofOfExistence, withTime.BasicValidation.Conclusion.SubIndications[0],
            "Step 2) of clause 5.5.4 continues from exactly the INDETERMINATE/REVOKED_NO_POE of clause A.3.2.");
        Assert.AreEqual(scenario.SigningCertificateRevoked, withTime.BasicValidation.RevocationTime,
            "Step 4)a) compares best-signature-time with the revocation time step 2) returned.");
    }


    /// <summary>
    /// The same world of clause A.3.2 reached through the other revocation material RFC 6960 defines: an OCSP
    /// response about the signing certificate, whose <c>revocationTime</c> and <c>revocationReason</c> the
    /// shipped reader surfaces, produces the identical conclusion and the identical mandated report data.
    /// </summary>
    [TestMethod]
    public async Task Example1BasicValidationOverOnlineRevocationMaterialReportsTheSameRevocationEvidence()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificateWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationInputs inputs = scenario.Inputs with
        {
            RevocationStatusInformation = [scenario.SigningCertificateOcspStatus]
        };

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, outcome.Conclusion.Indication,
            "The revocation material changes, the conclusion of clause A.3.2 does not.");
        Assert.Contains(SignatureValidationSubIndication.RevokedNoProofOfExistence, outcome.Conclusion.SubIndications,
            "Clause A.3.2 names REVOKED_NO_POE regardless of which revocation material established the revocation.");

        CertificateRevocationReportData revocation = SingleReportData<CertificateRevocationReportData>(outcome.Conclusion);
        Assert.AreEqual(scenario.SigningCertificateRevoked, revocation.RevocationTime,
            "The revocation instant read out of the OCSP response is the one the timeline places at t4.");
        Assert.AreEqual(X509ChainTestRingRevocation.KeyCompromiseReason, revocation.RevocationReason,
            "The reason read out of the OCSP response is the one it states.");
        Assert.IsTrue(outcome.BasicValidation.DecisiveRevocationStatusInformation!.RevocationData.IsOcspResponse,
            "The instance of revocation status information the conclusion turns on is the OCSP response, not a certificate revocation list.");
    }


    /// <summary>
    /// Clause A.3.5: the validation process for Basic Signatures does not handle the attributes for long term
    /// availability, so the revocation of the certification authority at <c>t8</c> leaves the status
    /// <c>INDETERMINATE</c>/<c>REVOKED_CA_NO_POE</c>, with the chain that includes the revoked certification
    /// authority certificate as the mandated report data.
    /// </summary>
    [TestMethod]
    public async Task Example2BasicValidationReportsRevokedCertificationAuthorityNoProofOfExistence()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion.Indication,
            "Clause A.3.5 states the expected result INDETERMINATE.");
        Assert.HasCount(1, conclusion.SubIndications, "One sub-indication explains one reason.");
        Assert.AreEqual(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, conclusion.SubIndications[0],
            "Clause A.3.5 states the expected sub-indication REVOKED_CA_NO_POE.");

        CertificateRevocationReportData revocation = SingleReportData<CertificateRevocationReportData>(conclusion);
        Assert.AreEqual(scenario.Chain[1], revocation.RevokedCertificate,
            "Table 6 mandates the certificate chain which includes the revoked certification authority certificate; in example 2 that is the issuer of the signing certificate.");
        Assert.Contains(scenario.Chain[1], revocation.CertificateChain,
            "The revoked certificate is a member of the reported chain.");
        Assert.AreEqual(scenario.CertificationAuthorityRevoked, revocation.RevocationTime,
            "The timeline of clause A.3.4 places the revocation of the certification authority certificate at t8.");
        Assert.AreEqual(X509ChainTestRingRevocation.KeyCompromiseReason, revocation.RevocationReason,
            "The reason the root's own revocation list states reaches the report data.");
        Assert.IsEmpty(conclusion.ValidatedCertificateChain,
            "A chain whose certification authority is revoked is the last chain built, not a validated chain, so Table 5's TOTAL-PASSED output is absent.");
    }


    /// <summary>
    /// Clause A.3.6: the validation process of clause 5.5 does not handle the attributes for long term
    /// availability either — a signature time-stamp protects the signature value and the signing certificate but
    /// not against the revocation of an intermediary certification authority — so the status remains
    /// <c>INDETERMINATE</c>/<c>REVOKED_CA_NO_POE</c>.
    /// </summary>
    /// <remarks>
    /// The informative narrative of clause A.3.6 reasons from a version of clause 5.5.4 whose step 2) did not
    /// continue on <c>REVOKED_CA_NO_POE</c>. In V1.4.1 the process does continue, and the stated result is
    /// nevertheless reproduced exactly: the certificate of the authority that produced the signature time-stamp
    /// has expired at <c>t7</c>, so step 3)b) removes that token from the set, best-signature-time stays at the
    /// current time, and step 4)a)b returns the sub-indication step 2) reported.
    /// </remarks>
    [TestMethod]
    public async Task Example2ValidationWithTimeStillReportsRevokedCertificationAuthorityNoProofOfExistence()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.Indeterminate, conclusion.Indication,
            "Clause A.3.6 states the expected result INDETERMINATE.");
        Assert.Contains(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, conclusion.SubIndications,
            "Clause A.3.6 states the expected sub-indication REVOKED_CA_NO_POE.");
        Assert.AreEqual(scenario.ValidationTime, conclusion.BestSignatureTime,
            "Step 1) of clause 5.5.4 initializes best-signature-time to the current time and no token lowered it.");
        Assert.IsEmpty(outcome.SignatureWithTimeValidation!.AcceptedSignatureTimestamps,
            "Step 3)b) removes the signature time-stamp token: the certificate of its authority expired at t7, before the validation time.");
        Assert.HasCount(1, outcome.SignatureWithTimeValidation!.SignatureTimestampValidations,
            "Step 11) returns the validation result of the token that was tried, even though the token left the set.");
    }


    /// <summary>
    /// Clause A.3.7: the validation process of clause 5.6.3 turns the same world <c>TOTAL-PASSED</c>, because
    /// the archive time-stamp produced at <c>t5</c> — before any compromising event — proves the signature and
    /// the certificates it needs existed then, which is what the past validation building blocks of clause 5.6.2
    /// consume.
    /// </summary>
    [TestMethod]
    public async Task Example2LongTermValidationReportsTotalPassedOnTheArchiveTimestampProofs()
    {
        using AnnexAValidationScenario scenario = await AnnexAValidationScenario
            .CreateRevokedCertificationAuthorityWorldAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, scenario.ValidationTime, BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConclusion conclusion = outcome.Conclusion;
        Assert.AreEqual(SignatureValidationIndication.TotalPassed, conclusion.Indication,
            "Clause A.3.7 states the expected result TOTAL-PASSED.");
        Assert.IsEmpty(conclusion.SubIndications, "Table 5 names no sub-indication for TOTAL-PASSED.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermAvailability, conclusion.ProcessIdentifier,
            "The process that ran is the one of clause 5.6.3.");
        Assert.AreEqual(scenario.ArchiveTimestampCreated, conclusion.BestSignatureTime,
            "Step 6) of clause 5.6.3.4 determines best-signature-time from the accumulated proofs of existence, the earliest of which the archive time-stamp of t5 establishes.");

        LongTermValidationResult longTerm = outcome.LongTermValidation!;
        Assert.IsTrue(longTerm.HasLongTermAvailabilityAttributes,
            "Step 3) branches on the signature carrying attributes for long term availability and integrity of validation material, which the archive time-stamp attribute is.");
        Assert.AreEqual(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence,
            longTerm.SignatureWithTimeValidation.Conclusion.SubIndications[0],
            "Step 3) continues from exactly the INDETERMINATE/REVOKED_CA_NO_POE of clause A.3.6.");

        ValidationObjectIdentity signingCertificate = await ProofOfExistenceExtraction.CreateIdentityAsync(
            scenario.Chain[0].AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null,
            outcome.Resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ValidationObjectIdentity certificationAuthority = await ProofOfExistenceExtraction.CreateIdentityAsync(
            scenario.Chain[1].AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null,
            outcome.Resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(scenario.ArchiveTimestampCreated, longTerm.ProofsOfExistence.EarliestInstantFor(signingCertificate),
            "Table A.3.7-2 records a proof of existence at t5 for the signing certificate, which the archive time-stamp protects.");
        Assert.AreEqual(scenario.ArchiveTimestampCreated, longTerm.ProofsOfExistence.EarliestInstantFor(certificationAuthority),
            "Table A.3.7-2 records the same for the other certificates required to form a chain to a trust anchor, which travel inside the signature.");
    }


    /// <summary>
    /// Reads the generation time out of the signature time-stamp token the Signed Data Object of a world carries,
    /// through the shipped time-stamp surface.
    /// </summary>
    /// <param name="scenario">The world whose signature is read.</param>
    /// <returns>The generation time the token states.</returns>
    private async Task<DateTimeOffset> ReadSignatureTimestampGenerationTimeAsync(AnnexAValidationScenario scenario)
    {
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = scenario.SignedDataObject },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlyList<EmbeddedTimestamp> tokens = facts.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp);
        DateTimeOffset? generationTime = await TimestampValidation.ReadGenerationTimeAsync(
            tokens[0].Token, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return generationTime!.Value;
    }


    /// <summary>
    /// States the single associated validation report data item of a conclusion, asserting both that there is
    /// exactly one and that it is of the shape Table 6 mandates for the reported sub-indication.
    /// </summary>
    /// <typeparam name="T">The mandated report data shape.</typeparam>
    /// <param name="conclusion">The conclusion to read.</param>
    /// <returns>The item.</returns>
    private static T SingleReportData<T>(SignatureValidationConclusion conclusion) where T: SignatureValidationReportData
    {
        Assert.HasCount(1, conclusion.ReportData,
            "Table 6 mandates one associated validation report data item for the reported sub-indication.");
        Assert.IsInstanceOfType<T>(conclusion.ReportData[0],
            "The reported evidence has the shape Table 6 mandates for the reported sub-indication.");

        return (T)conclusion.ReportData[0];
    }
}
