using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using AlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Validates the signature validation processes of ETSI EN 319 102-1 V1.4.1 clause 5: the process for Basic
/// Signatures (clause 5.3), the time-stamp validation building block (clause 5.4), the process for Signatures
/// with Time and Signatures with Long-Term Validation Material (clause 5.5), the additional building blocks of
/// clause 5.6.2, the process for Signatures providing Long Term Availability and Integrity of Validation Material
/// (clause 5.6.3), and the process selection of clause 5.1.2.
/// </summary>
/// <remarks>
/// <para>
/// The named scenarios reproduce the worked examples of the specification's informative Annex A. Example 1
/// (clause A.3) is a signature whose signing certificate is revoked after a signature time-stamp was produced:
/// basic validation is <c>INDETERMINATE</c>/<c>REVOKED_NO_POE</c> (clause A.3.2) and validation with time is
/// <c>TOTAL-PASSED</c> (clause A.3.3). Example 2 (clause A.3.4) is a signature whose intermediate CA certificate
/// is revoked and whose signature time-stamp is no longer usable at validation time: basic validation and
/// validation with time both end at <c>INDETERMINATE</c>/<c>REVOKED_CA_NO_POE</c> (clauses A.3.5 and A.3.6),
/// and the long-term validation of clause A.3.7 turns that into <c>TOTAL-PASSED</c> because the archive
/// time-stamp proves the signature existed before the compromising event.
/// </para>
/// <para>
/// Every signature is a real CAdES signature produced by the framework's own CMS signer through
/// <see cref="CmsSignedDataTestFactory"/> and validated through the shipped CAdES binding; every certificate
/// chain is a real chain minted by <see cref="X509ChainTestRing"/>'s platform certificate requests and validated
/// through the shipped chain seams. Nothing here re-implements a check the library performs, and every digest an
/// assertion depends on is taken by the library through the registered digest seam.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SignatureValidationProcessTests
{
    /// <summary>The content every signature minted here covers.</summary>
    private static ReadOnlySpan<byte> Content => "the long-term content"u8;

    /// <summary>The RFC 3161 <c>id-ct-TSTInfo</c> encapsulated content type of a time-stamp token.</summary>
    private const string TimestampTokenContentTypeOid = "1.2.840.113549.1.9.16.1.4";

    /// <summary>The CAdES archive-time-stamp-v3 unsigned attribute of ETSI EN 319 122-1.</summary>
    private const string ArchiveTimestampV3Oid = "0.4.0.1733.2.4";

    /// <summary>The SHA-256 digest algorithm object identifier.</summary>
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    /// <summary>The ECDSA-with-SHA256 signature algorithm object identifier every minted certificate and signature uses.</summary>
    private const string EcdsaWithSha256Oid = "1.2.840.10045.4.3.2";

    /// <summary>The length in bytes of a SHA-256 digest.</summary>
    private const int Sha256Length = 32;


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// The validation process for Basic Signatures of clause 5.3 over a signature whose signing certificate is
    /// revoked at the current time: <c>INDETERMINATE</c>/<c>REVOKED_NO_POE</c> with the chain, the revocation
    /// date and the reason Table 6 mandates.
    /// </summary>
    [TestMethod]
    public async Task BasicValidationOfARevokedSigningCertificateIsIndeterminateRevokedNoProofOfExistence()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "revoked-signer.example.test", revokeSigningCertificate: true, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, outcome.Conclusion.Indication,
            "Clause A.3.2: the Basic Signature validation algorithm does not process the signature time-stamp attribute, so the status is indeterminate.");
        Assert.Contains(SignatureValidationSubIndication.RevokedNoProofOfExistence, outcome.Conclusion.SubIndications,
            "Clause A.3.2 names INDETERMINATE/REVOKED_NO_POE.");
        Assert.IsInstanceOfType<CertificateRevocationReportData>(outcome.Conclusion.ReportData[0],
            "Table 6 mandates the chain, the revocation time and, when available, the reason.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, outcome.Conclusion.ProcessIdentifier,
            "Clause 5.1.3 requires the validation process that was used to be reported.");
    }


    /// <summary>
    /// Step 4)a) of clause 5.5.4: a signature time-stamp proving the signature existed before the revocation date
    /// takes the same signature from <c>INDETERMINATE</c>/<c>REVOKED_NO_POE</c> to <c>TOTAL-PASSED</c>.
    /// </summary>
    [TestMethod]
    public async Task ValidationWithTimeTurnsARevokedSigningCertificateIntoTotalPassed()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "revoked-signer-with-time.example.test", revokeSigningCertificate: true, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "Clause A.3.3: the signature time-stamp places the signing before the revocation time, which takes the status from INDETERMINATE to TOTAL-PASSED.");
        Assert.AreEqual(scenario.SignatureTimestampTime, outcome.Conclusion.BestSignatureTime,
            "Step 3)b) of clause 5.5.4 sets best-signature-time to the generation time of the time-stamp token that validated.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermValidationMaterial, outcome.Conclusion.ProcessIdentifier,
            "The process reported has to be the one that ran.");
        Assert.IsNotEmpty(outcome.Conclusion.ValidatedCertificateChain,
            "Table 5 requires the validated certificate chain on TOTAL-PASSED.");
    }


    /// <summary>
    /// Step 4)d) of clause 5.2.6.4 through the process of clause 5.3: a revoked intermediate CA certificate is
    /// <c>INDETERMINATE</c>/<c>REVOKED_CA_NO_POE</c>, not a failure of the signature itself.
    /// </summary>
    [TestMethod]
    public async Task BasicValidationOfARevokedCertificationAuthorityIsIndeterminateRevokedCaNoProofOfExistence()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "revoked-ca.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, outcome.Conclusion.Indication,
            "Clause A.3.5: the algorithm for Basic Signatures does not handle the long-term validation attributes.");
        Assert.Contains(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, outcome.Conclusion.SubIndications,
            "Clause A.3.5 names INDETERMINATE/REVOKED_CA_NO_POE.");
    }


    /// <summary>
    /// Step 4)a)b of clause 5.5.4: a revocation date that is not posterior to best-signature-time leaves the
    /// process at <c>INDETERMINATE</c>/<c>REVOKED_CA_NO_POE</c>, which is what clause 5.6 then continues from.
    /// </summary>
    [TestMethod]
    public async Task ValidationWithTimeLeavesARevokedCertificationAuthorityIndeterminate()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "revoked-ca-with-time.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.SignaturesWithTime, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.Indeterminate, outcome.Conclusion.Indication,
            "Clause A.3.6: the signature time-stamp does not help when an intermediary CA is revoked.");
        Assert.Contains(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, outcome.Conclusion.SubIndications,
            "Clause A.3.6 names INDETERMINATE/REVOKED_CA_NO_POE.");
        Assert.AreEqual(scenario.CurrentTime, outcome.Conclusion.BestSignatureTime,
            "Step 3)b) of clause 5.5.4 removes a time-stamp token that does not validate, so best-signature-time stays at the value step 1) initialized it to.");
    }


    /// <summary>
    /// The process of clause 5.6.3 over the same signature: the proofs of existence the archive time-stamp
    /// establishes take the revoked-CA case from <c>INDETERMINATE</c> to <c>TOTAL-PASSED</c> through the past
    /// validation building blocks of clause 5.6.2.
    /// </summary>
    [TestMethod]
    public async Task LongTermValidationTurnsARevokedCertificationAuthorityIntoTotalPassed()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "long-term.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalPassed, outcome.Conclusion.Indication,
            "Clause A.3.7: INDETERMINATE turns into TOTAL-PASSED due to the archive time-stamp, which was produced before any compromising event.");
        Assert.AreEqual(scenario.ArchiveTimestampTime, outcome.Conclusion.BestSignatureTime,
            "Step 6) of clause 5.6.3.4 sets best-signature-time to the earliest time the accumulated proofs of existence prove the signature existed.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermAvailability, outcome.Conclusion.ProcessIdentifier,
            "The process reported has to be the one that ran.");
        Assert.IsNotNull(outcome.LongTermValidation, "The long-term process ran, so its own result must be surfaced.");
        Assert.IsTrue(outcome.LongTermValidation!.HasLongTermAvailabilityAttributes,
            "The signature carries an archive time-stamp, which is what step 3) of clause 5.6.3.4 branches on.");
    }


    /// <summary>
    /// The time-stamp validation building block of clause 5.4: step 3) returns the generation time of a token
    /// whose own Basic Signature validation passed, and a token whose authority reaches no trust anchor returns
    /// what that validation returned instead.
    /// </summary>
    [TestMethod]
    public async Task TimestampValidationReturnsTheGenerationTimeAndFailsClosedForAnUntrustedAuthority()
    {
        using var trusted = await SignatureScenario.CreateAsync(
            "timestamp-trusted.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);
        using var untrusted = await SignatureScenario.CreateAsync(
            "timestamp-untrusted.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);

        using var trustedResources = new SignatureValidationResources();
        using var untrustedResources = new SignatureValidationResources();

        TimestampValidationResult passed = await TimestampValidation.ValidateAsync(
            await trusted.SignatureTimestampTokenAsync(trustedResources, TestContext.CancellationToken).ConfigureAwait(false),
            trusted.Inputs, trusted.Seams, trusted.CurrentTime, trustedResources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        TimestampValidationResult failed = await TimestampValidation.ValidateAsync(
            await untrusted.SignatureTimestampTokenAsync(untrustedResources, TestContext.CancellationToken).ConfigureAwait(false),
            untrusted.Inputs, untrusted.Seams, untrusted.CurrentTime, untrustedResources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, passed.Conclusion.Indication,
            "Step 1) of clause 5.4.4 validates the token as a Basic Signature, which passes for a Time-Stamping Authority the policy trusts.");
        Assert.AreEqual(trusted.SignatureTimestampTime, passed.GenerationTime,
            "Step 3) requires the generation time present in the TSTInfo field to be returned.");
        Assert.IsNotNull(passed.MessageImprint, "Step 3) requires the message imprint to be returned.");
        Assert.AreEqual(AlgorithmIdentifier.Sha256, passed.MessageImprintAlgorithm,
            "The message imprint algorithm is what clause 5.6.2.3 gates proof-of-existence extraction on.");
        Assert.AreEqual(BuildingBlockIndication.Indeterminate, failed.Conclusion.Indication,
            "Step 2) returns the indication the validation process returned, and a token whose authority reaches no trust anchor establishes nothing.");
        Assert.IsNull(failed.GenerationTime, "A token that did not validate must report no generation time.");
    }


    /// <summary>
    /// Steps 2)a) and 2)b) of clause 5.6.2.2: control-time slides back to the revocation time of a certificate
    /// proven revoked, and a set of proofs of existence that proves nothing about the certificate and its
    /// revocation data at control-time is <c>INDETERMINATE</c>/<c>NO_POE</c>.
    /// </summary>
    [TestMethod]
    public async Task ValidationTimeSlidesToTheRevocationTimeAndReportsNoProofOfExistenceWithoutProofs()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "sliding.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);
        using var resources = new SignatureValidationResources();

        //The proofs are at the time of the archive time-stamp, which is before the revocation: step 2)a) of clause
        //5.6.2.2 selects revocation data only where the certificate and the data are proven to have existed at or
        //before control-time, and control-time has already slid back to the revocation instant by the time the
        //walk reaches the signing certificate.
        ProofOfExistenceSet proofs = await scenario.ProofsForChainAsync(resources, scenario.ArchiveTimestampTime, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationTimeSlidingResult slid = await ValidationTimeSliding.SlideAsync(
            scenario.Chain, proofs, scenario.RevocationStatusInformation, trustAnchorSunsetDate: null,
            scenario.CryptographicConstraints, scenario.X509Constraints, scenario.CurrentTime, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationTimeSlidingResult withoutProofs = await ValidationTimeSliding.SlideAsync(
            scenario.Chain, ProofOfExistenceSet.Empty, scenario.RevocationStatusInformation, trustAnchorSunsetDate: null,
            scenario.CryptographicConstraints, scenario.X509Constraints, scenario.CurrentTime, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, slid.Conclusion.Indication,
            "Step 2)e) of clause 5.6.2.2 returns PASSED once every certificate of the chain has been considered.");
        Assert.AreEqual(scenario.CertificationAuthorityRevocationTime, slid.ControlTime,
            "Step 2)b) slides control-time to the revocation time of the revoked certification authority under the shell model.");
        Assert.AreEqual(BuildingBlockIndication.Indeterminate, withoutProofs.Conclusion.Indication,
            "Step 2)a) requires a proof of existence for the certificate and its revocation data at or before control-time.");
        Assert.Contains(SignatureValidationSubIndication.NoProofOfExistence, withoutProofs.Conclusion.SubIndications,
            "Table 24 names INDETERMINATE/NO_POE as the block's only indeterminate outcome.");
        Assert.IsInstanceOfType<MissingProofOfExistenceReportData>(withoutProofs.Conclusion.ReportData[0],
            "Table 6 mandates at least the objects for which the proofs of existence are missing.");
    }


    /// <summary>
    /// Steps 1) and 5) of clause 5.6.2.3.4: an <c>archive-time-stamp-v3</c> whose message imprint the shipped
    /// CAdES binding recomputes from the Signed Data Object and the token's own <c>ats-hash-index-v3</c> proves
    /// every object it protects at its generation time under the <em>default</em> constraints — no declaration
    /// by the Driving Application is involved, because the coverage was verified rather than asserted.
    /// </summary>
    [TestMethod]
    public async Task ProofOfExistenceExtractionProvesEveryObjectAnArchiveTimestampProtects()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "poe-extraction.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);
        using var resources = new SignatureValidationResources();

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = scenario.SignedDataObject }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        IReadOnlyList<EmbeddedTimestamp> archiveTimestamps = facts.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp);

        ProofOfExistenceSet extracted = await ProofOfExistenceExtraction.ExtractAsync(
            facts, archiveTimestamps[0], scenario.ArchiveTimestampTime, ProofOfExistenceSet.Empty,
            scenario.CryptographicConstraints, SignatureElementsConstraints.None, scenario.Seams, resources,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ValidationObjectIdentity signatureValueIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            facts.SignatureValue!.AsReadOnlyMemory(), ValidationObjectKind.SignatureValue, reference: null, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ValidationObjectIdentity signingCertificateIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            facts.SigningCertificate!.AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, archiveTimestamps, "The signature carries exactly one archive time-stamp attribute.");
        Assert.IsTrue(extracted.ExistsAtOrBefore(signatureValueIdentity, scenario.ArchiveTimestampTime),
            "Step 5) of clause 5.6.2.3 adds a proof of existence at the generation time for every object the archive time-stamp protects, and the signature value is one of them.");
        Assert.IsTrue(extracted.ExistsAtOrBefore(signingCertificateIdentity, scenario.ArchiveTimestampTime),
            "The signing certificate the signature carries is protected by the archive time-stamp too.");
        Assert.AreEqual(scenario.ArchiveTimestampTime, extracted.EarliestInstantFor(signatureValueIdentity),
            "Every proof the extraction derives is at the generation time of the time-stamp, which clause 5.6.2.3 calls T1.");
    }


    /// <summary>
    /// The constraint itself: <see cref="SignatureElementsConstraints.AcceptsUnverifiableTimestampCoverage"/>
    /// defaults to <see langword="false"/> and decides only the case step 1) of clause 5.6.2.3.4 leaves open —
    /// a time-stamp whose covered octets the format binding states nothing about. An archive time-stamp of the
    /// deprecated v2 form (ETSI EN 319 122-1 clause A.2.4) carries no <c>ats-hash-index-v3</c>, so it is exactly
    /// that case, while the conformant v3 attribute on the same signature is decided by verification and not by
    /// the constraint at all.
    /// </summary>
    [TestMethod]
    public async Task AcceptingUnverifiableCoverageDecidesOnlyTheTimestampsTheBindingStatesNothingAbout()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "unverifiable-coverage.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);
        using var resources = new SignatureValidationResources();

        CmsSignedData withBothForms = await scenario.WithDeprecatedArchiveTimestampAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = withBothForms }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        EmbeddedTimestamp conformant = FindTimestamp(facts, CAdESSignatureFacts.ArchiveTimestampV3AttributeOid);
        EmbeddedTimestamp deprecated = FindTimestamp(facts, CAdESSignatureFacts.ArchiveTimestampV2AttributeOid);
        var accepting = new SignatureElementsConstraints { AcceptsUnverifiableTimestampCoverage = true };

        ProtectedObjectSet conformantByDefault = await ProofOfExistenceExtraction.DetermineProtectedObjectsAsync(
            facts, conformant, SignatureElementsConstraints.None, scenario.Seams, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ProtectedObjectSet deprecatedByDefault = await ProofOfExistenceExtraction.DetermineProtectedObjectsAsync(
            facts, deprecated, SignatureElementsConstraints.None, scenario.Seams, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ProtectedObjectSet deprecatedWhenAccepted = await ProofOfExistenceExtraction.DetermineProtectedObjectsAsync(
            facts, deprecated, accepting, scenario.Seams, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(SignatureElementsConstraints.None.AcceptsUnverifiableTimestampCoverage,
            "The documented default is false: a token whose message imprint nothing verified against those objects has not been shown to protect them.");
        Assert.IsNotEmpty(conformantByDefault.Objects,
            "The archive-time-stamp-v3 states its coverage through the binding, so the default admits what its imprint is verified to protect.");
        Assert.IsEmpty(deprecatedByDefault.Objects,
            "The deprecated v2 form carries no ats-hash-index-v3, so the binding states nothing and the default admits nothing from it.");
        Assert.IsNotEmpty(deprecatedWhenAccepted.Objects,
            "A Driving Application that declares it establishes the binding by other means gets the class-based admission of clause 5.6.3.1 for that same token.");
    }


    /// <summary>
    /// The <c>REVOKED_CA_NO_POE</c> branch of step 3) of clause 5.6.2.4.4: a proof of existence for the
    /// revocation data of the signer's certificate at or before the CA's revocation time, with best-signature-time
    /// inside the signing certificate's validity, takes the past signature validation to <c>PASSED</c>.
    /// </summary>
    [TestMethod]
    public async Task PastSignatureValidationTurnsRevokedCertificationAuthorityIntoPassed()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "past-signature.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: false, TestContext.CancellationToken).ConfigureAwait(false);
        using var resources = new SignatureValidationResources();

        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = scenario.SignedDataObject }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        ValidationObjectIdentity signatureValueIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            facts.SignatureValue!.AsReadOnlyMemory(), ValidationObjectKind.SignatureValue, reference: null, resources, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        ProofOfExistenceSet proofs = (await scenario.ProofsForChainAsync(resources, scenario.CurrentTime, TestContext.CancellationToken).ConfigureAwait(false))
            .Union(await scenario.ProofsForChainAsync(resources, scenario.ArchiveTimestampTime, TestContext.CancellationToken).ConfigureAwait(false))
            .With(new ProofOfExistence
            {
                ObjectIdentity = signatureValueIdentity,
                Instant = scenario.ArchiveTimestampTime,
                Scope = ProofOfExistenceScope.Object,
                Origin = ProofOfExistenceOrigin.TimestampToken
            });

        PastSignatureValidationResult past = await PastSignatureValidation.ValidateAsync(
            new PastSignatureValidationInputs
            {
                SignatureValueIdentity = signatureValueIdentity,
                CurrentTimeStatus = BuildingBlockConclusion.Indeterminate(
                    SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence, []),
                TargetCertificate = facts.SigningCertificate!,
                BestSignatureTime = scenario.ArchiveTimestampTime,
                ProofsOfExistence = proofs,
                CertificateValidationData = scenario.CertificateValidationData,
                RevocationStatusInformation = scenario.RevocationStatusInformation,
                CertificationAuthorityRevocationTime = scenario.CertificationAuthorityRevocationTime
            },
            scenario.Constraints,
            scenario.Seams,
            scenario.CurrentTime,
            resources,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Passed, past.Conclusion.Indication,
            "Clause A.3.7: with a proof of existence for the signature before the certification authority's revocation, the past signature validation returns PASSED.");
        Assert.AreEqual(scenario.CertificationAuthorityRevocationTime, past.ValidationTime,
            "Step 2) returns the control-time the validation time sliding process calculated, which is the revocation time of the revoked certification authority.");
    }


    /// <summary>
    /// Clause 5.1.2: the process the entry point runs is the one the Driving Application requested where it
    /// requested one, and otherwise the most capable process the supplied validation material supports.
    /// </summary>
    [TestMethod]
    public async Task ProcessSelectionHonoursTheRequestAndTheSupportedProcesses()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "selection.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);

        using SignatureValidationOutcome automatic = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.Automatic, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome basicOnly = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.Automatic, SignatureValidationCapabilities.BasicSignaturesOnly,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureValidationOutcome requested = await SignatureValidation.ValidateAsync(
            scenario.Inputs, scenario.Seams, SignatureValidationProcessSelection.BasicSignatures, SignatureValidationCapabilities.All,
            scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationProcessIdentifier.LongTermAvailability, automatic.Conclusion.ProcessIdentifier,
            "Steps 1)a) and 2) of clause 5.1.2 select the long-term process when the Signature Validation Application supports it.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, basicOnly.Conclusion.ProcessIdentifier,
            "Steps 2), 3) and 4) fall through to the validation process for Basic Signatures, which every Signature Validation Application supports.");
        Assert.AreEqual(SignatureValidationProcessIdentifier.Basic, requested.Conclusion.ProcessIdentifier,
            "Step 1)b) goes straight to step 4) when the Driving Application requires the validation process for Basic Signatures.");
    }


    /// <summary>
    /// A Signed Data Object that is not a processable signature ends the whole process at
    /// <c>TOTAL-FAILED</c>/<c>FORMAT_FAILURE</c>, which is the clause 5.2.2 outcome promoted by clause 5.1.3 —
    /// and never an exception out of the entry point.
    /// </summary>
    [TestMethod]
    public async Task ValidationOfAnUnparsableSignedDataObjectFailsWithFormatFailure()
    {
        using var scenario = await SignatureScenario.CreateAsync(
            "format-failure.example.test", revokeSigningCertificate: false, trustTheSignatureTimestampAuthority: true, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData notCms = CmsSignedData.FromBytes("not a signed data object"u8, BaseMemoryPool.Shared);

        using SignatureValidationOutcome outcome = await SignatureValidation.ValidateAsync(
            scenario.Inputs with { SignedDataObject = notCms }, scenario.Seams, SignatureValidationProcessSelection.LongTermAvailability,
            SignatureValidationCapabilities.All, scenario.CurrentTime, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureValidationIndication.TotalFailed, outcome.Conclusion.Indication,
            "Step 1) of clause 5.3.4 makes a non-conformant signature FAILED, which clause 5.1.2 step 6) reports as TOTAL-FAILED.");
        Assert.Contains(SignatureValidationSubIndication.FormatFailure, outcome.Conclusion.SubIndications,
            "The sub-indication is FORMAT_FAILURE.");
    }


    /// <summary>
    /// Finds the one time-stamp a signature carries in a named attribute.
    /// </summary>
    /// <param name="facts">The extracted facts.</param>
    /// <param name="attributeOid">The attribute the token was carried in.</param>
    /// <returns>The time-stamp.</returns>
    private static EmbeddedTimestamp FindTimestamp(SignatureFacts facts, string attributeOid)
    {
        for(int i = 0; i < facts.Timestamps.Count; ++i)
        {
            if(string.Equals(facts.Timestamps[i].Identifier, attributeOid, StringComparison.Ordinal))
            {
                return facts.Timestamps[i];
            }
        }

        throw new InvalidOperationException($"The signature carries no time-stamp in the attribute '{attributeOid}'.");
    }


    /// <summary>
    /// One complete validation scenario: a real CAdES signature with a signature time-stamp and an archive
    /// time-stamp, a real three-level certificate chain, and the revocation status information that makes the
    /// timeline of the specification's Annex A examples hold. Disposing it releases every carrier it minted.
    /// </summary>
    /// <remarks>
    /// Internal rather than private so <c>SignatureValidationReportTests</c> can drive the TS 119 102-2 report
    /// builder over the same rich, real material rather than duplicating this fixture.
    /// </remarks>
    internal sealed class SignatureScenario: IDisposable
    {
        /// <summary>The carriers this scenario minted, released in reverse order.</summary>
        private readonly List<IDisposable> owned = [];

        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>The current time every validation runs at.</summary>
        public DateTimeOffset CurrentTime { get; private set; }

        /// <summary>The generation time of the signature time-stamp.</summary>
        public DateTimeOffset SignatureTimestampTime { get; private set; }

        /// <summary>The generation time of the archive time-stamp.</summary>
        public DateTimeOffset ArchiveTimestampTime { get; private set; }

        /// <summary>The instant the certificate the scenario revokes was revoked.</summary>
        public DateTimeOffset CertificationAuthorityRevocationTime { get; private set; }

        /// <summary>The Signed Data Object under validation.</summary>
        public CmsSignedData SignedDataObject { get; private set; } = null!;

        /// <summary>The certificate chain, signing certificate first.</summary>
        public IReadOnlyList<PkiCertificateMemory> Chain { get; private set; } = [];

        /// <summary>The certificate validation data the Driving Application supplies.</summary>
        public IReadOnlyList<PkiCertificateMemory> CertificateValidationData { get; private set; } = [];

        /// <summary>The revocation status information the Driving Application's checkers established.</summary>
        public IReadOnlyList<RevocationStatusInformation> RevocationStatusInformation { get; private set; } = [];

        /// <summary>The X.509 validation constraints, naming the root as the trust anchor.</summary>
        public X509ValidationConstraints X509Constraints { get; private set; } = null!;

        /// <summary>The cryptographic constraints, asserting the algorithms the minted material uses reliable without expiry.</summary>
        public CryptographicConstraints CryptographicConstraints { get; private set; } = null!;

        /// <summary>The validation constraints the run applies.</summary>
        public SignatureValidationConstraints Constraints { get; private set; } = null!;

        /// <summary>The inputs one validation run takes.</summary>
        public SignatureValidationInputs Inputs { get; private set; } = null!;

        /// <summary>The seams one validation run composes.</summary>
        public SignatureValidationSeams Seams { get; private set; } = null!;


        /// <summary>
        /// Builds a scenario: a three-level chain, a CAdES signature with a signature time-stamp and an archive
        /// time-stamp, and revocation status information placing a revocation after the time-stamps.
        /// </summary>
        /// <param name="dnsName">The subject name of the leaf certificate.</param>
        /// <param name="revokeSigningCertificate">Whether the signing certificate is revoked (Annex A example 1) rather than the intermediate certification authority (example 2).</param>
        /// <param name="trustTheSignatureTimestampAuthority">Whether the signature time-stamp's authority is a trust anchor for time-stamps, which decides whether that time-stamp can lower best-signature-time.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The scenario, which the caller disposes.</returns>
        public static async ValueTask<SignatureScenario> CreateAsync(
            string dnsName,
            bool revokeSigningCertificate,
            bool trustTheSignatureTimestampAuthority,
            CancellationToken cancellationToken)
        {
            var scenario = new SignatureScenario();
            try
            {
                await scenario.BuildAsync(dnsName, revokeSigningCertificate, trustTheSignatureTimestampAuthority, cancellationToken).ConfigureAwait(false);

                return scenario;
            }
            catch
            {
                scenario.Dispose();

                throw;
            }
        }


        /// <summary>
        /// Extracts the signature time-stamp token of the scenario's signature.
        /// </summary>
        /// <param name="resources">The ledger the extracted facts are tracked in.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The token carrier, owned by the tracked facts.</returns>
        public async ValueTask<PkiCertificateMemory> SignatureTimestampTokenAsync(
            SignatureValidationResources resources,
            CancellationToken cancellationToken)
        {
            SignatureFacts facts = resources.Track(await CAdESSignatureFacts.ExtractAsync(
                new SignatureFactsExtractionContext { SignedDataObject = SignedDataObject }, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false));

            return facts.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp)[0].Token;
        }


        /// <summary>
        /// Builds proofs of existence at one instant for every certificate of the chain and every revocation data
        /// object the scenario supplies — the material clause 5.6.2.2 step 2)a) asks for.
        /// </summary>
        /// <param name="resources">The ledger the computed identities are tracked in.</param>
        /// <param name="instant">The instant the objects are proven to have existed at.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The proofs.</returns>
        public async ValueTask<ProofOfExistenceSet> ProofsForChainAsync(
            SignatureValidationResources resources,
            DateTimeOffset instant,
            CancellationToken cancellationToken)
        {
            List<ProofOfExistence> proofs = [];
            for(int i = 0; i < Chain.Count; ++i)
            {
                proofs.Add(new ProofOfExistence
                {
                    ObjectIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                        Chain[i].AsReadOnlyMemory(), ValidationObjectKind.Certificate, reference: null, resources, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
                    Instant = instant,
                    Scope = ProofOfExistenceScope.Object,
                    Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
                });
            }

            for(int i = 0; i < RevocationStatusInformation.Count; ++i)
            {
                proofs.Add(new ProofOfExistence
                {
                    ObjectIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                        RevocationStatusInformation[i].RevocationData.AsReadOnlyMemory(), ValidationObjectKind.RevocationData, reference: null, resources, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
                    Instant = instant,
                    Scope = ProofOfExistenceScope.Object,
                    Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
                });
            }

            return ProofOfExistenceSet.Create(proofs);
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            for(int i = owned.Count - 1; i >= 0; --i)
            {
                owned[i].Dispose();
            }

            owned.Clear();
        }


        /// <summary>
        /// Mints every artefact of the scenario and assembles the inputs and seams.
        /// </summary>
        /// <param name="dnsName">The subject name of the leaf certificate.</param>
        /// <param name="revokeSigningCertificate">Whether the signing certificate rather than the intermediate is revoked.</param>
        /// <param name="trustTheSignatureTimestampAuthority">Whether the signature time-stamp's authority is a trust anchor for time-stamps.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        private async ValueTask BuildAsync(
            string dnsName,
            bool revokeSigningCertificate,
            bool trustTheSignatureTimestampAuthority,
            CancellationToken cancellationToken)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            CurrentTime = timeProvider.GetUtcNow();
            SignatureTimestampTime = CurrentTime.AddHours(-12);
            ArchiveTimestampTime = CurrentTime.AddHours(-4);
            CertificationAuthorityRevocationTime = CurrentTime.AddHours(-2);

            X509ChainTestRingChain ring = Own(X509ChainTestRing.BuildThreeLevelChain(dnsName, timeProvider));
            using X509Certificate2 signerWithKey = ring.Leaf.Certificate.CopyWithPrivateKey(ring.Leaf.SigningKey);

            using ECDsa signatureAuthorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            X509Certificate2 signatureAuthority = Own(CmsSignedDataTestFactory.MintSelfSignedCertificate(
                signatureAuthorityKey, CurrentTime.AddDays(-1), CurrentTime.AddYears(1)));
            using ECDsa archiveAuthorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            X509Certificate2 archiveAuthority = Own(CmsSignedDataTestFactory.MintSelfSignedCertificate(
                archiveAuthorityKey, CurrentTime.AddDays(-1), CurrentTime.AddYears(1)));

            using CmsSignedData withSignatureTimestamp = CmsSignedDataTestFactory.SignAsCAdEST(
                Content, signerWithKey, CurrentTime.AddDays(-1), signatureAuthority, SignatureTimestampTime);
            SignedDataObject = Own(await AttachArchiveTimestampAsync(
                withSignatureTimestamp, archiveAuthority, ArchiveTimestampTime, cancellationToken).ConfigureAwait(false));

            Chain = OwnAll(MicrosoftX509Functions.ParseX5c(ring.X5cValues, BaseMemoryPool.Shared));
            IReadOnlyList<PkiCertificateMemory> anchors = OwnAll(MicrosoftX509Functions.ParseX5c(ring.RootX5c, BaseMemoryPool.Shared));
            IReadOnlyList<PkiCertificateMemory> timestampAnchors = OwnAll(MicrosoftX509Functions.ParseX5c(
                trustTheSignatureTimestampAuthority
                    ? [Convert.ToBase64String(signatureAuthority.RawData), Convert.ToBase64String(archiveAuthority.RawData)]
                    : [Convert.ToBase64String(archiveAuthority.RawData)],
                BaseMemoryPool.Shared));

            PkiCertificateMemory signingCertificateRevocationData = Own(MintRevocationData([0x01]));
            PkiCertificateMemory authorityRevocationData = Own(MintRevocationData([0x02]));

            CertificateValidationData = [Chain[1], Chain[2], signingCertificateRevocationData, authorityRevocationData];
            RevocationStatusInformation =
            [
                new RevocationStatusInformation
                {
                    RevocationData = signingCertificateRevocationData,
                    SubjectCertificate = Chain[0],
                    Status = revokeSigningCertificate ? CertificateRevocationStatus.Revoked : CertificateRevocationStatus.Good,
                    ThisUpdate = CurrentTime.AddHours(-6),
                    NextUpdate = CurrentTime.AddHours(18),
                    RevocationTime = revokeSigningCertificate ? CertificationAuthorityRevocationTime : null,
                    RevocationReason = revokeSigningCertificate ? 1 : null,
                    IssuerCertificate = Chain[1]
                },
                new RevocationStatusInformation
                {
                    RevocationData = authorityRevocationData,
                    SubjectCertificate = Chain[1],
                    Status = revokeSigningCertificate ? CertificateRevocationStatus.Good : CertificateRevocationStatus.Revoked,
                    ThisUpdate = CurrentTime.AddHours(-6),
                    NextUpdate = CurrentTime.AddHours(18),
                    RevocationTime = revokeSigningCertificate ? null : CertificationAuthorityRevocationTime,
                    RevocationReason = revokeSigningCertificate ? null : 1,
                    IssuerCertificate = Chain[2]
                }
            ];

            X509Constraints = BuildX509Constraints(anchors);
            CryptographicConstraints = BuildCryptographicConstraints();
            Constraints = new SignatureValidationConstraints
            {
                Identifier = SignatureValidationPolicyIdentifier.CallerSuppliedConstraints,
                X509 = X509Constraints,
                Cryptographic = CryptographicConstraints,

                //Nothing is declared about time-stamp coverage. This world's archive time-stamp carries the
                //ats-hash-index-v3 of ETSI EN 319 122-1 clause 5.5.2 and its message imprint is the clause 5.5.3
                //concatenation, both of which the shipped CAdES binding recomputes from the Signed Data Object's
                //own octets, so the coverage is verified rather than declared.
                SignatureElements = SignatureElementsConstraints.None
            };

            var completer = new CertificateChainCompleter([Chain[1], Chain[2]]);
            Seams = new SignatureValidationSeams
            {
                Format = CAdESSignatureFacts.Seam,
                CompleteCertificateChain = completer.CompleteAsync,
                ValidateCertificateChain = MicrosoftX509Functions.ValidateChainAsync
            };

            //The Driving Application asserts, from its own archive, that the revocation data existed when the
            //archive time-stamp was produced — the "set of POEs" input of Table 27 that NOTE 3 of clause 5.6.3.4
            //says is used without additional processing. Everything else is proven by the signature's own
            //time-stamps.
            SignatureValidationResources initialProofResources = Own(new SignatureValidationResources());
            List<ProofOfExistence> initialProofs = [];
            for(int i = 0; i < RevocationStatusInformation.Count; ++i)
            {
                initialProofs.Add(new ProofOfExistence
                {
                    ObjectIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                        RevocationStatusInformation[i].RevocationData.AsReadOnlyMemory(), ValidationObjectKind.RevocationData, reference: null,
                        initialProofResources, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false),
                    Instant = ArchiveTimestampTime,
                    Scope = ProofOfExistenceScope.Object,
                    Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
                });
            }

            Inputs = new SignatureValidationInputs
            {
                SignedDataObject = SignedDataObject,
                Constraints = Constraints,
                CertificateValidationData = CertificateValidationData,
                RevocationStatusInformation = RevocationStatusInformation,
                ProofsOfExistence = ProofOfExistenceSet.Create(initialProofs),
                TimestampConstraints = Constraints with
                {
                    X509 = BuildX509Constraints(timestampAnchors)
                }
            };
        }


        /// <summary>
        /// Builds X.509 validation constraints over a set of trust anchors.
        /// </summary>
        /// <param name="anchors">The trust anchors.</param>
        /// <returns>The constraints.</returns>
        private static X509ValidationConstraints BuildX509Constraints(IReadOnlyList<PkiCertificateMemory> anchors)
        {
            List<TrustAnchorConstraint> trustAnchors = [];
            for(int i = 0; i < anchors.Count; ++i)
            {
                trustAnchors.Add(new TrustAnchorConstraint(anchors[i], SunsetDate: null));
            }

            return new X509ValidationConstraints
            {
                TrustAnchors = trustAnchors,
                MaximumAcceptedRevocationFreshness = TimeSpan.FromDays(7)
            };
        }


        /// <summary>
        /// Builds a cryptographic constraints table asserting the algorithms every minted certificate, signature
        /// and time-stamp uses reliable without expiry, so a process test is decided by the step under test and
        /// not by an empty algorithm table.
        /// </summary>
        /// <returns>The table.</returns>
        private static CryptographicConstraints BuildCryptographicConstraints() => new()
        {
            Entries =
            [
                new AlgorithmReliabilityEntry(new AlgorithmIdentifier(EcdsaWithSha256Oid), MinimumKeySizeBits: 256, TrustedUntil: null),
                new AlgorithmReliabilityEntry(new AlgorithmIdentifier(Sha256Oid), MinimumKeySizeBits: null, TrustedUntil: null)
            ]
        };


        /// <summary>
        /// Attaches an archive time-stamp as an unsigned attribute of a CAdES signature, which is what makes the
        /// signature one "providing Long Term Availability and Integrity of Validation Material".
        /// </summary>
        /// <param name="signature">The signature to attach it to.</param>
        /// <param name="authority">The Time-Stamping Authority's certificate, which holds its own key.</param>
        /// <param name="generationTime">The generation time of the archive time-stamp.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The signature with the attribute attached, which the caller disposes.</returns>
        /// <remarks>
        /// The attribute is a conformant <c>archive-time-stamp-v3</c>: the index of ETSI EN 319 122-1 clause
        /// 5.5.2 is computed over the signature as it stands, the token's message imprint is the digest of the
        /// four-part concatenation of clause 5.5.3, and the index is grafted into the token's own
        /// <c>unsignedAttrs</c> as that clause requires — so the shipped CAdES binding can restate the coverage
        /// and the proof-of-existence extraction building block can verify it rather than take it on trust.
        /// </remarks>
        private static async ValueTask<CmsSignedData> AttachArchiveTimestampAsync(
            CmsSignedData signature,
            X509Certificate2 authority,
            DateTimeOffset generationTime,
            CancellationToken cancellationToken)
        {
            using AtsHashIndexV3 hashIndex = await ArchiveTimestampV3.ComputeHashIndexAsync(
                signature, signerIndex: 0, PkiDigestAlgorithm.Sha256, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);
            using SignedContentMemory imprintInput = await ArchiveTimestampV3.BuildMessageImprintInputAsync(
                new ArchiveTimestampImprintContext
                {
                    SignedData = signature,
                    HashIndex = hashIndex,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    SignerIndex = 0
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            using CmsSignedData token = await MintTimestampTokenAsync(
                imprintInput.AsReadOnlyMemory(), authority, generationTime, cancellationToken).ConfigureAwait(false);
            using CmsAttribute indexAttribute = CmsAttribute.Create(
                CAdESSignatureFacts.AtsHashIndexV3AttributeOid, hashIndex.AsReadOnlySpan(), BaseMemoryPool.Shared);
            using CmsSignedData grafted = CmsSignedDataAugmentation.AppendUnsignedAttributes(
                token, signerIndex: 0, [indexAttribute], BaseMemoryPool.Shared);
            using CmsAttribute archiveAttribute = CmsAttribute.Create(
                ArchiveTimestampV3Oid, grafted.AsReadOnlySpan(), BaseMemoryPool.Shared);

            return CmsSignedDataAugmentation.AppendUnsignedAttributes(signature, signerIndex: 0, [archiveAttribute], BaseMemoryPool.Shared);
        }


        /// <summary>
        /// Mints a time-stamp token over caller-supplied octets: a <c>TSTInfo</c> naming their SHA-256 digest as
        /// its message imprint, encapsulated in a CMS SignedData the authority signs.
        /// </summary>
        /// <param name="timestampedOctets">The octets the authority time-stamps.</param>
        /// <param name="authority">The Time-Stamping Authority's certificate, which holds its own key.</param>
        /// <param name="generationTime">The generation time the authority states.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The token, which the caller disposes.</returns>
        private static async ValueTask<CmsSignedData> MintTimestampTokenAsync(
            ReadOnlyMemory<byte> timestampedOctets,
            X509Certificate2 authority,
            DateTimeOffset generationTime,
            CancellationToken cancellationToken)
        {
            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                timestampedOctets, Sha256Length, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using(writer.PushSequence())
            {
                writer.WriteInteger(1);
                writer.WriteObjectIdentifier("1.2.3.4.1");
                using(writer.PushSequence())
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(Sha256Oid);
                        writer.WriteNull();
                    }

                    writer.WriteOctetString(imprint.AsReadOnlySpan());
                }

                writer.WriteInteger(2);
                writer.WriteGeneralizedTime(generationTime);
            }

            return CmsSignedDataTestFactory.SignAsCms(writer.Encode(), TimestampTokenContentTypeOid, authority);
        }


        /// <summary>
        /// Adds an archive time-stamp of the deprecated v2 form (ETSI EN 319 122-1 clause A.2.4) beside the
        /// scenario's conformant one: a genuine token, carried in the <c>archive-time-stamp</c> attribute, with
        /// no <c>ats-hash-index-v3</c> naming what it covers. It is the shape for which the shipped binding
        /// states nothing, which is what
        /// <see cref="SignatureElementsConstraints.AcceptsUnverifiableTimestampCoverage"/> exists for.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The signature carrying both archive time-stamps, owned by this scenario.</returns>
        /// <remarks>
        /// Adding an unsigned attribute after the conformant archive time-stamp was applied leaves that
        /// time-stamp intact: clause 5.5.2 NOTE 5 has later additions not invalidate an index, and the imprint
        /// input of clause 5.5.3 excludes <c>unsignedAttrs</c> altogether.
        /// </remarks>
        public async ValueTask<CmsSignedData> WithDeprecatedArchiveTimestampAsync(CancellationToken cancellationToken)
        {
            using ECDsa deprecatedAuthorityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            X509Certificate2 deprecatedAuthority = Own(CmsSignedDataTestFactory.MintSelfSignedCertificate(
                deprecatedAuthorityKey, CurrentTime.AddDays(-1), CurrentTime.AddYears(1)));

            using CmsSignedData token = await MintTimestampTokenAsync(
                SignedDataObject.AsReadOnlyMemory(), deprecatedAuthority, ArchiveTimestampTime, cancellationToken).ConfigureAwait(false);
            using CmsAttribute archiveAttribute = CmsAttribute.Create(
                CAdESSignatureFacts.ArchiveTimestampV2AttributeOid, token.AsReadOnlySpan(), BaseMemoryPool.Shared);

            return Own(CmsSignedDataAugmentation.AppendUnsignedAttributes(
                SignedDataObject, signerIndex: 0, [archiveAttribute], BaseMemoryPool.Shared));
        }


        /// <summary>
        /// Wraps a few bytes in a revocation data carrier, for a scenario that needs a distinguishable object to
        /// prove the existence of rather than a parsable certificate revocation list.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>The carrier.</returns>
        private static PkiCertificateMemory MintRevocationData(byte[] bytes)
        {
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
            bytes.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.X509Crl);
        }


        /// <summary>
        /// Takes ownership of one disposable artefact.
        /// </summary>
        /// <typeparam name="T">The artefact's type.</typeparam>
        /// <param name="artefact">The artefact.</param>
        /// <returns>The same artefact.</returns>
        private T Own<T>(T artefact) where T: IDisposable
        {
            owned.Add(artefact);

            return artefact;
        }


        /// <summary>
        /// Takes ownership of a list of carriers.
        /// </summary>
        /// <param name="carriers">The carriers.</param>
        /// <returns>The same list.</returns>
        private IReadOnlyList<PkiCertificateMemory> OwnAll(IReadOnlyList<PkiCertificateMemory> carriers)
        {
            for(int i = 0; i < carriers.Count; ++i)
            {
                owned.Add(carriers[i]);
            }

            return carriers;
        }
    }
}
