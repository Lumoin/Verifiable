using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the ETSI TS 119 172-4 V1.2.1 signature applicability rules in
/// <see cref="SignatureApplicabilityRules"/>: the Annex A object identifiers, the REQ-4.2-03 constraint
/// composition, the clause 4.4.2 technical applicability (rules) checking process and the clause 4.5
/// report composition. Expected values are transcribed from the specification text — the Annex A arcs, the
/// REQ-4.2-03 c) ii) freshness pairing and the REQ-4.5-01 a) scope text are literal transcriptions, never
/// read back from the implementation — and the trusted-list scenarios mirror the fixture shapes of
/// <see cref="TrustedListQualificationTests"/> so the determinations under composition are the same shipped
/// ETSI TS 119 615 procedures those vectors pin.
/// </summary>
[TestClass]
internal sealed class SignatureApplicabilityRulesTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The DER-stand-in bytes of the signing certificate under checking; the byte-equality match seam treats them opaquely.</summary>
    private static byte[] CertificateUnderTestBytes { get; } = [0x30, 0x82, 0x01, 0x01, 0x11, 0x22, 0x33];

    /// <summary>The certificate policy identifier the fixture criteria trees assert, present in the default facts.</summary>
    private const string MatchingPolicyOid = "1.2.246.517.1.1";

    /// <summary>An evaluation instant safely inside the Regulation regime, used as the best signature time.</summary>
    private static DateTimeOffset RegulationEvaluationTime { get; } = new(2024, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The certificate-to-service match seam realised as byte equality against the identity's certificate
    /// entries, sufficient because the certificates are opaque stand-ins.
    /// </summary>
    private static MatchCertificateToTrustServiceAsyncDelegate ByteEqualityMatch { get; } = (certificate, serviceDigitalIdentity, validationTime, pool, cancellationToken) =>
    {
        foreach(ServiceDigitalIdentityEntry entry in serviceDigitalIdentity.Entries)
        {
            if(entry is X509CertificateIdentity certificateEntry
                && certificateEntry.Certificate.AsReadOnlySpan().SequenceEqual(certificate.AsReadOnlySpan()))
            {
                return ValueTask.FromResult(true);
            }
        }

        return ValueTask.FromResult(false);
    };


    /// <summary>
    /// The Annex A allocations, each pairing the dotted value transcribed from the specification's own
    /// ASN.1 arc — <c>id-etsi-sars</c> under itu-t(0) identified-organization(4) etsi(0)
    /// idsigapprules(191724) 1 — with the shipped constant and the ASN.1 name the specification allocates.
    /// </summary>
    /// <returns>One transcription per allocated identifier.</returns>
    public static IEnumerable<object[]> AnnexAAllocations()
    {
        yield return ["0.4.0.191724.1", WellKnownOids.SignatureApplicabilityRules, "id-etsi-sars"];
        yield return ["0.4.0.191724.1.1", WellKnownOids.SignatureApplicabilityRulesSpCompliance, "id-etsi-sars-SpCompliance"];
        yield return ["0.4.0.191724.1.1.1", WellKnownOids.SignatureApplicabilityRulesRealTimeRequired, "id-etsi-sarc-realTimeReq"];
        yield return ["0.4.0.191724.1.1.2", WellKnownOids.SignatureApplicabilityRulesRealTimeNotRequired, "id-etsi-sarc-realTimeNotReq"];
        yield return ["0.4.0.191724.1.2", WellKnownOids.SignatureApplicabilityRulesSigType, "id-etsi-sars-SigType"];
        yield return ["0.4.0.191724.1.2.1", WellKnownOids.DigitalSignatureTypeEuQualifiedSignature, "id-etsi-dst-euqesig"];
        yield return ["0.4.0.191724.1.2.2", WellKnownOids.DigitalSignatureTypeAdvancedSignatureWithQualifiedCertificate, "id-etsi-dst-adesigqc"];
        yield return ["0.4.0.191724.1.2.3", WellKnownOids.DigitalSignatureTypeAdvancedSignature, "id-etsi-dst-adesig"];
        yield return ["0.4.0.191724.1.2.4", WellKnownOids.DigitalSignatureTypeEuQualifiedSeal, "id-etsi-dst-euqeseal"];
        yield return ["0.4.0.191724.1.2.5", WellKnownOids.DigitalSignatureTypeAdvancedSealWithQualifiedCertificate, "id-etsi-dst-adesealqc"];
        yield return ["0.4.0.191724.1.2.6", WellKnownOids.DigitalSignatureTypeAdvancedSeal, "id-etsi-dst-adeseal"];
        yield return ["0.4.0.191724.1.2.7", WellKnownOids.DigitalSignatureTypeEuQualifiedTimeStamp, "id-etsi-dst-euqtst"];
    }


    /// <summary>
    /// Each Annex A object identifier the library ships is the specification's own arc value.
    /// </summary>
    /// <param name="transcribed">The dotted value transcribed from the Annex A ASN.1.</param>
    /// <param name="shipped">The shipped constant's value.</param>
    /// <param name="asn1Name">The ASN.1 name the specification allocates the identifier under.</param>
    [TestMethod]
    [DynamicData(nameof(AnnexAAllocations))]
    public void AnnexAObjectIdentifiersMatchTheSpecificationsArc(string transcribed, string shipped, string asn1Name)
    {
        Assert.AreEqual(transcribed, shipped, $"{asn1Name} must carry the specification's Annex A arc value.");
    }


    /// <summary>
    /// The two rule sets carry their Annex A identifiers and the REQ-4.2-03 c) ii) freshness pairing: 24
    /// hours under <c>id-etsi-sarc-realTimeReq</c> and zero under <c>id-etsi-sarc-realTimeNotReq</c>.
    /// </summary>
    [TestMethod]
    public void RuleSetsCarryTheSpecificationsPolicyOidsAndFreshnessValues()
    {
        Assert.AreEqual("0.4.0.191724.1.1.1", EuSignatureApplicabilityRuleSet.RealTimeRequired.PolicyOid, "Set 1 is id-etsi-sarc-realTimeReq.");
        Assert.AreEqual(TimeSpan.FromHours(24), EuSignatureApplicabilityRuleSet.RealTimeRequired.MaximumAcceptedRevocationFreshness, "REQ-4.2-03 c) ii) 1): a maximum value of 24h under realTimeReq.");
        Assert.AreEqual("0.4.0.191724.1.1.2", EuSignatureApplicabilityRuleSet.RealTimeNotRequired.PolicyOid, "Set 2 is id-etsi-sarc-realTimeNotReq.");
        Assert.AreEqual(TimeSpan.Zero, EuSignatureApplicabilityRuleSet.RealTimeNotRequired.MaximumAcceptedRevocationFreshness, "REQ-4.2-03 c) ii) 2): a maximum value of 0 under realTimeNotReq.");
    }


    /// <summary>
    /// REQ-4.2-03: the composed constraints read their trust anchors from the clause 4.3 service match for
    /// CA/QC services, carry the rule set's identity and freshness, state the REQ-4.2-03 h) signed-binding
    /// constraint, and use none of the ETSI TS 119 172-1 table A.2 rows the specification excludes.
    /// </summary>
    [TestMethod]
    public async Task CreateValidationConstraintsComposesTheFixedConstraintValues()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        SignatureApplicabilityConstraintsResult result = await SignatureApplicabilityRules.CreateValidationConstraintsAsync(
            EuSignatureApplicabilityRuleSet.RealTimeRequired,
            trustedList, certificate, facts, CryptographicConstraints.Empty,
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        SignatureValidationConstraints constraints = result.Constraints;
        Assert.AreEqual(WellKnownOids.SignatureApplicabilityRulesRealTimeRequired, constraints.Identifier.Value, "The constraints identify as the applied rule set (clause 5.1.3 identity).");
        Assert.HasCount(1, constraints.X509.TrustAnchors, "REQ-4.2-03 a): the matched CA/QC service's digital identity is the trust anchor set.");
        Assert.IsTrue(constraints.X509.TrustAnchors[0].Anchor.AsReadOnlySpan().SequenceEqual(CertificateUnderTestBytes), "The anchor is the service digital identity's certificate.");
        Assert.IsNull(constraints.X509.TrustAnchors[0].SunsetDate, "The composition states no sunset date; the trusted list's status history governed the match.");
        Assert.AreEqual(TimeSpan.FromHours(24), constraints.X509.MaximumAcceptedRevocationFreshness, "REQ-4.2-03 c) ii): the rule set's fixed freshness.");
        Assert.AreEqual(CertificateValidityModel.Shell, constraints.X509.ValidityModel, "REQ-4.2-03 b): rows (m)1.2-(m)1.10 are not used, so the validity model stays the default.");
        Assert.IsEmpty(constraints.X509.CertificateMetadataConstraints, "REQ-4.2-03 b): no certificate meta-data constraints are stated.");
        Assert.IsEmpty(constraints.X509.CertificatesExemptFromRevocationChecking, "REQ-4.2-03 c) iii): rows (m)2.3 and (m)3 are not used.");
        Assert.IsFalse(constraints.X509.ExemptCertificatesWithOcspNoCheckExtension, "REQ-4.2-03 c) iii): no extension-based exemption is stated.");
        Assert.IsFalse(constraints.X509.ExemptCertificatesWithExtendedValidationAssuranceExtension, "REQ-4.2-03 c) iii): no extension-based exemption is stated.");
        Assert.IsTrue(constraints.SignatureElements.RequireSignedSigningCertificateBinding, "REQ-4.2-03 h): the presence of a signed reference or signed copy of the signing certificate is enforced.");
        Assert.IsEmpty(constraints.SignatureElements.MandatedSignedAttributeOids, "No signed attribute beyond REQ-4.2-03 h) is mandated.");
        Assert.AreEqual(TrustedListProcessStatus.Passed, result.TrustAnchorServiceMatch.Status, "The retained clause 4.3 intermediate reports its own status for the report.");
    }


    /// <summary>
    /// REQ-4.2-03 a) iii): the clause 4.3 <c>Date-time</c> is the signing certificate's <c>notBefore</c>.
    /// A service granted only after <c>notBefore</c> contributes no anchor even though it is granted at
    /// validation time, and the same service contributes its anchor for a certificate issued after the
    /// grant.
    /// </summary>
    [TestMethod]
    public async Task CreateValidationConstraintsEvaluatesTheServiceMatchAtNotBefore()
    {
        DateTimeOffset grantTime = new(2021, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);

        using(TrustedList trustedList = CreateSingleServiceTrustedList(grantTime))
        {
            QualifiedCertificateFacts factsBeforeGrant = CreateFacts(
                hasQcCompliance: true,
                qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
                notBefore: new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero));

            SignatureApplicabilityConstraintsResult beforeGrant = await SignatureApplicabilityRules.CreateValidationConstraintsAsync(
                EuSignatureApplicabilityRuleSet.RealTimeNotRequired,
                trustedList, certificate, factsBeforeGrant, CryptographicConstraints.Empty,
                ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsEmpty(beforeGrant.Constraints.X509.TrustAnchors, "A certificate issued before the service's grant finds no applicable service state at its notBefore.");
        }

        using(TrustedList trustedList = CreateSingleServiceTrustedList(grantTime))
        {
            QualifiedCertificateFacts factsAfterGrant = CreateFacts(
                hasQcCompliance: true,
                qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
                notBefore: new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero));

            SignatureApplicabilityConstraintsResult afterGrant = await SignatureApplicabilityRules.CreateValidationConstraintsAsync(
                EuSignatureApplicabilityRuleSet.RealTimeNotRequired,
                trustedList, certificate, factsAfterGrant, CryptographicConstraints.Empty,
                ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.HasCount(1, afterGrant.Constraints.X509.TrustAnchors, "The same service contributes its anchor for a certificate issued after the grant.");
            Assert.AreEqual(TimeSpan.Zero, afterGrant.Constraints.X509.MaximumAcceptedRevocationFreshness, "REQ-4.2-03 c) ii) 2): zero freshness under realTimeNotReq.");
        }
    }


    /// <summary>
    /// Two matched services carrying byte-identical digital identity certificates yield one stated trust
    /// anchor: the constraint set states each distinct anchor once.
    /// </summary>
    [TestMethod]
    public async Task CreateValidationConstraintsStatesEachDistinctAnchorOnce()
    {
        using TrustedList trustedList = CreateTwoServiceTrustedList(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        SignatureApplicabilityConstraintsResult result = await SignatureApplicabilityRules.CreateValidationConstraintsAsync(
            EuSignatureApplicabilityRuleSet.RealTimeRequired,
            trustedList, certificate, facts, CryptographicConstraints.Empty,
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(2, result.TrustAnchorServiceMatch.Matches, "Both services match the certificate.");
        Assert.HasCount(1, result.Constraints.X509.TrustAnchors, "Byte-identical anchors are stated once.");
    }


    /// <summary>
    /// A clause 4.3 run that fails — here PRO-4.3.4-03A's disordered service history — still reports the
    /// services it inspected, and an unsound match seeds no trust anchor: the constraint composition reads
    /// the <c>SI-Status</c> fail-closed, the same way PRO-4.4.4-04 makes the determinations consume a
    /// failed matching. The failed match is still retained for the report.
    /// </summary>
    [TestMethod]
    public async Task CreateValidationConstraintsSeedsNoAnchorsFromAFailedServiceMatch()
    {
        using TrustedList trustedList = CreateDisorderedHistoryTrustedList();
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        SignatureApplicabilityConstraintsResult result = await SignatureApplicabilityRules.CreateValidationConstraintsAsync(
            EuSignatureApplicabilityRuleSet.RealTimeRequired,
            trustedList, certificate, facts, CryptographicConstraints.Empty,
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.TrustAnchorServiceMatch.Status, "PRO-4.3.4-03A: a disordered service history fails the clause 4.3 run.");
        Assert.IsNotEmpty(result.TrustAnchorServiceMatch.Matches, "The failed run still reports the services it inspected — the shape that makes the status gate load-bearing.");
        Assert.IsEmpty(result.Constraints.X509.TrustAnchors, "An unsound match seeds no trust anchor; the constraint set stays fail-closed.");
    }


    /// <summary>
    /// REQ-4.4.2-06 affirmative arm: a certificate the trusted list qualifies for electronic signatures,
    /// created on a confirmed qualified device, whose validation concluded <c>TOTAL-PASSED</c>, is
    /// determined technically suitable as an EU qualified electronic signature — and REQ-4.5-02 maps the
    /// outcome to <c>id-etsi-dst-euqesig</c>.
    /// </summary>
    [TestMethod]
    public async Task CheckDeterminesSuitabilityForAQualifiedSignatureWithQscdAndTotalPassed()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            hasQcSscdStatement: true);

        TechnicalApplicabilityCheckResult result = await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.TotalPassed, RegulationEvaluationTime),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.SuitableAsQualifiedElectronicSignature, "REQ-4.4.2-06: all three conditions hold in the electronic-signature dimension.");
        Assert.IsFalse(result.SuitableAsQualifiedElectronicSeal, "The certificate is not qualified for electronic seals.");
        Assert.IsTrue(result.IsTechnicallySuitable, "The clause 4.4.1 main output is affirmative.");
        Assert.IsNotNull(result.DeviceDetermination, "REQ-4.4.2-04 ran because REQ-4.4.2-02 did not stop the process.");
        Assert.AreEqual(QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice, result.DeviceDetermination.Indication, "REQ-4.4.2-05: QSCD_YES.");
        Assert.AreEqual(RegulationEvaluationTime, result.BestSignatureTime, "The determinations were evaluated at the best signature time.");
        Assert.AreEqual(WellKnownOids.DigitalSignatureTypeEuQualifiedSignature, SignatureApplicabilityRules.DetermineSignatureTypeIdentifier(result), "REQ-4.5-02: the suitable outcome maps to id-etsi-dst-euqesig.");
    }


    /// <summary>
    /// The "respectively" arm of REQ-4.4.2-02/-05/-06: a certificate qualified for electronic seals on a
    /// for-eSeals service state yields the seal-dimension determination and <c>id-etsi-dst-euqeseal</c>.
    /// </summary>
    [TestMethod]
    public async Task CheckDeterminesSuitabilityForAQualifiedSeal()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSeals]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSeal],
            hasQcSscdStatement: true);

        TechnicalApplicabilityCheckResult result = await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.TotalPassed, RegulationEvaluationTime),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.SuitableAsQualifiedElectronicSeal, "REQ-4.4.2-06: all three conditions hold in the electronic-seal dimension.");
        Assert.IsFalse(result.SuitableAsQualifiedElectronicSignature, "The certificate is not qualified for electronic signatures.");
        Assert.AreEqual(WellKnownOids.DigitalSignatureTypeEuQualifiedSeal, SignatureApplicabilityRules.DetermineSignatureTypeIdentifier(result), "REQ-4.5-02: the suitable seal outcome maps to id-etsi-dst-euqeseal.");
    }


    /// <summary>
    /// REQ-4.4.2-02 b): when the certificate determination confirms no qualified indication the process
    /// stops — the device determination never runs — and the signature is determined technically as
    /// neither, with the intermediate certificate determination retained for the report.
    /// </summary>
    [TestMethod]
    public async Task CheckStopsWithoutDeviceDeterminationWhenTheCertificateIsNotQualified()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: false, qcTypes: []);

        TechnicalApplicabilityCheckResult result = await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.TotalPassed, RegulationEvaluationTime),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result.DeviceDetermination, "REQ-4.4.2-02 b) i): the process stops before the device determination.");
        Assert.IsFalse(result.IsTechnicallySuitable, "REQ-4.4.2-02 b) ii): technically neither an EU qualified electronic signature nor seal.");
        Assert.IsNotEmpty(result.CertificateDetermination.Indications, "REQ-4.4.2-02 b) iii): the intermediate results stay available for the report.");
        Assert.IsNull(SignatureApplicabilityRules.DetermineSignatureTypeIdentifier(result), "No Annex A type is determinable for an unqualified certificate.");
    }


    /// <summary>
    /// REQ-4.4.2-02's status conjunct read strictly: a certificate determination whose <c>QC-Status</c> is
    /// <c>PROCESS_FAILED</c> does not qualify the certificate even though its <c>QC-Results</c> retain a
    /// qualified indication — here PRO-4.4.4-36's mismatch between the best-signature-time and
    /// <c>notBefore</c> evaluations, produced by a service granted only after the certificate was issued.
    /// The process stops, and no Annex A type follows.
    /// </summary>
    [TestMethod]
    public async Task CheckStopsWhenTheCertificateDeterminationFailsEvenWithAQualifiedIndicationRetained()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            notBefore: new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            hasQcSscdStatement: true);

        TechnicalApplicabilityCheckResult result = await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.TotalPassed, RegulationEvaluationTime),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TrustedListProcessStatus.Failed, result.CertificateDetermination.Status, "PRO-4.4.4-36: the notBefore re-run disagrees with the best-signature-time run, failing the determination.");
        Assert.Contains(EuQualifiedCertificateIndication.QualifiedForESignature, result.CertificateDetermination.Indications, "The failed determination retains the qualified indication — the shape that makes the strict status gate load-bearing.");
        Assert.IsNull(result.DeviceDetermination, "REQ-4.4.2-02 b) i): the process stops before the device determination.");
        Assert.IsFalse(result.IsTechnicallySuitable, "A failed determination never qualifies the certificate, whatever its retained indications say.");
        Assert.IsNull(SignatureApplicabilityRules.DetermineSignatureTypeIdentifier(result), "No Annex A type is determinable off a failed certificate determination.");
    }


    /// <summary>
    /// A qualified certificate without a confirmed qualified creation device is not suitable
    /// (REQ-4.4.2-05), and REQ-4.5-02 maps the <c>TOTAL-PASSED</c> outcome to
    /// <c>id-etsi-dst-adesigqc</c> — an advanced electronic signature supported by an EU qualified
    /// certificate.
    /// </summary>
    [TestMethod]
    public async Task CheckWithoutQscdMapsToAdvancedSignatureWithQualifiedCertificate()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            hasQcSscdStatement: false);

        TechnicalApplicabilityCheckResult result = await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.TotalPassed, RegulationEvaluationTime),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result.DeviceDetermination, "The device determination ran; only its outcome is negative.");
        Assert.AreNotEqual(QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice, result.DeviceDetermination.Indication, "The trusted list does not confirm a qualified device.");
        Assert.IsFalse(result.IsTechnicallySuitable, "REQ-4.4.2-06 b) of REQ-4.4.2-05 fails.");
        Assert.AreEqual(WellKnownOids.DigitalSignatureTypeAdvancedSignatureWithQualifiedCertificate, SignatureApplicabilityRules.DetermineSignatureTypeIdentifier(result), "REQ-4.5-02: TOTAL-PASSED on a qualified certificate without QSCD is AdES supported by a qualified certificate.");
    }


    /// <summary>
    /// The seal arm of the REQ-4.5-02 mapping's qualified-certificate-without-QSCD branch: a certificate
    /// qualified for electronic seals without a confirmed qualified creation device maps to
    /// <c>id-etsi-dst-adesealqc</c> — an advanced electronic seal supported by an EU qualified certificate.
    /// </summary>
    [TestMethod]
    public async Task CheckWithoutQscdOnASealCertificateMapsToAdvancedSealWithQualifiedCertificate()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(
            new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            [TrustServiceAdditionalInformationType.ForElectronicSeals]);
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSeal],
            hasQcSscdStatement: false);

        TechnicalApplicabilityCheckResult result = await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.TotalPassed, RegulationEvaluationTime),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsTechnicallySuitable, "The trusted list does not confirm a qualified device, so REQ-4.4.2-06 b) fails.");
        Assert.AreEqual(WellKnownOids.DigitalSignatureTypeAdvancedSealWithQualifiedCertificate, SignatureApplicabilityRules.DetermineSignatureTypeIdentifier(result), "REQ-4.5-02: TOTAL-PASSED on a seal-qualified certificate without QSCD is AdES seal supported by a qualified certificate.");
    }


    /// <summary>
    /// REQ-4.4.2-06 c): without <c>TOTAL-PASSED</c> from the REQ-4.2-01 validation, a qualified
    /// certificate on a qualified device is still not determined suitable, and no Annex A type follows.
    /// </summary>
    [TestMethod]
    public async Task CheckWithoutTotalPassedYieldsNoSuitability()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            hasQcSscdStatement: true);

        TechnicalApplicabilityCheckResult result = await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.Indeterminate, RegulationEvaluationTime),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsTechnicallySuitable, "REQ-4.4.2-06 c) requires TOTAL-PASSED.");
        Assert.IsNull(SignatureApplicabilityRules.DetermineSignatureTypeIdentifier(result), "No type is determinable without TOTAL-PASSED.");
    }


    /// <summary>
    /// A conclusion determining no best signature time violates the REQ-4.2-01 precondition — the mandated
    /// validation process always determines one — and is refused as a composition error.
    /// </summary>
    [TestMethod]
    public async Task CheckRefusesAConclusionWithoutBestSignatureTime()
    {
        using TrustedList trustedList = CreateSingleServiceTrustedList(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero));
        using PkiCertificateMemory certificate = CreateCertificateMemory(CertificateUnderTestBytes);
        QualifiedCertificateFacts facts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () => await SignatureApplicabilityRules.CheckTechnicalApplicabilityAsync(
            trustedList, certificate, facts,
            CreateConclusion(SignatureValidationIndication.TotalPassed, bestSignatureTime: null),
            ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false),
            "A conclusion without a best signature time cannot come from the process REQ-4.2-01 mandates.").ConfigureAwait(false);
    }


    /// <summary>
    /// REQ-4.5-01: the composed report carries the specification's exact a) scope text, derives the c)
    /// pseudonym indication from the signing certificate's subject attribute types, states the applied
    /// rules identifier, and maps the outcome to its REQ-4.5-02 type identifier.
    /// </summary>
    [TestMethod]
    public void BuildReportCarriesTheScopeTextAndDerivesPseudonymAndTypeIdentifier()
    {
        TechnicalApplicabilityCheckResult applicability = new()
        {
            CertificateDetermination = new EuQualifiedCertificateDeterminationResult
            {
                Status = TrustedListProcessStatus.Passed,
                SubStatuses = [],
                Indications = [EuQualifiedCertificateIndication.QualifiedForESignature],
                ESignatureQualificationElements = [],
                ESealQualificationElements = [],
                WebsiteAuthenticationQualificationElements = []
            },
            DeviceDetermination = new QualifiedSignatureCreationDeviceDeterminationResult
            {
                Status = TrustedListProcessStatus.Passed,
                SubStatuses = [],
                Indication = QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice
            },
            ValidationIndication = SignatureValidationIndication.TotalPassed,
            BestSignatureTime = RegulationEvaluationTime,
            SuitableAsQualifiedElectronicSignature = true,
            SuitableAsQualifiedElectronicSeal = false
        };
        SignatureValidationConclusion conclusion = CreateConclusion(SignatureValidationIndication.TotalPassed, RegulationEvaluationTime);
        QualifiedCertificateFacts pseudonymousFacts = CreateFacts(
            hasQcCompliance: true,
            qcTypes: [EuQualifiedCertificateType.ElectronicSignature],
            subjectAttributeTypeOids: [WellKnownOids.CountryName, WellKnownOids.Pseudonym]);

        SignatureApplicabilityCheckingReport report = SignatureApplicabilityRules.BuildReport(new SignatureApplicabilityReportInputs
        {
            RuleSet = EuSignatureApplicabilityRuleSet.RealTimeRequired,
            TechnicalApplicability = applicability,
            ValidationConclusion = conclusion,
            SigningCertificateFacts = pseudonymousFacts,
            SignerSubject = "C=FI, O=Example Provider Oy, pseudonym=Signer One",
            SubjectAlternativeNames = ["signer.one@example.fi"],
            TimingInformation =
            [
                new ApplicabilityTimingInformation { Kind = ApplicabilityTimingKind.BestSignatureTime, Time = RegulationEvaluationTime }
            ],
            SignedDataPresentations = ["invoice-2024-06.pdf (application/pdf, 12 345 octets)"],
            SignatureAttributes = [new SignatureAttributeFacts("1.2.840.113549.1.9.3", SignatureAttributeScope.Signed, IsWellFormed: true)],
            CryptographicSuites = new CryptographicSuitesReport
            {
                RulesSource = SignatureApplicabilityRulesWellKnown.CryptographicSuitesSpecificationRulesSource
            },
            SigningCertificateRevocationFreshness = TimeSpan.FromHours(3),
            FormatComplianceWarnings = ["The signature does not comply with the CAdES baseline profile: the content-type signed attribute is absent."]
        });

        string expectedScope =
            "Signature applicability rules checking (validation rules) for European qualified electronic "
            + "signatures/seals using trusted lists: validation of digital signature to identify whether it can "
            + "be considered technically suitable to implement a European qualified electronic signature/seal "
            + "using EUMS trusted lists in the sense of the applicable European legislation at the time of "
            + "signing, i.e. either Directive 1999/93/EC or Regulation (EU) No 910/2014.";
        Assert.AreEqual(expectedScope, report.ScopeStatement, "REQ-4.5-01 a): the specification's own scope text, transcribed.");
        Assert.IsTrue(report.UsesPseudonym, "REQ-4.5-01 c): the X.520 pseudonym attribute type in the subject is indicated.");
        Assert.AreEqual(WellKnownOids.SignatureApplicabilityRulesRealTimeRequired, report.AppliedRulesIdentifier, "REQ-4.5-02: the applied rule set's Annex A identifier.");
        Assert.AreEqual(WellKnownOids.DigitalSignatureTypeEuQualifiedSignature, report.SignatureTypeIdentifier, "REQ-4.5-02: the outcome's Annex A type identifier.");
        Assert.HasCount(1, report.SubjectAlternativeNames, "REQ-4.5-01 b): the Subject Alternative Name data passes through.");
        Assert.HasCount(1, report.TimingInformation, "REQ-4.5-01 d): the timing information points pass through.");
        Assert.HasCount(1, report.SignedDataPresentations, "REQ-4.5-01 e): the signed data presentation passes through.");
        Assert.ContainsSingle(attribute => attribute.Scope == SignatureAttributeScope.Signed, report.SignatureAttributes, "REQ-4.5-01 f): each attribute states whether it was signed.");
        Assert.AreEqual("ETSI TS 119 312", report.CryptographicSuites!.RulesSource, "REQ-4.5-01 h): the rules source is stated clearly.");
        Assert.AreEqual(TimeSpan.FromHours(3), report.SigningCertificateRevocationFreshness, "REQ-4.5-01 i): the observed revocation freshness passes through.");
        Assert.ContainsSingle(warning => warning.Contains("does not comply", StringComparison.Ordinal), report.FormatComplianceWarnings, "REQ-4.2-03 g): the format-compliance warning with its reasons is carried, never an invalidation.");
        Assert.IsNull(report.DetailedOutcome, "REQ-4.5-01 j): the detailed outcome is optional and none was attached.");
        Assert.IsTrue(report.TechnicalApplicability.IsTechnicallySuitable, "REQ-4.5-01 g): the overall status is the checking outcome.");
    }


    /// <summary>
    /// REQ-4.5-01 c) counter-case: a subject without the X.520 pseudonym attribute type is reported as not
    /// pseudonymous.
    /// </summary>
    [TestMethod]
    public void BuildReportIndicatesNoPseudonymForAnOrdinarySubject()
    {
        TechnicalApplicabilityCheckResult applicability = new()
        {
            CertificateDetermination = new EuQualifiedCertificateDeterminationResult
            {
                Status = TrustedListProcessStatus.Passed,
                SubStatuses = [],
                Indications = [EuQualifiedCertificateIndication.NotQualified],
                ESignatureQualificationElements = [],
                ESealQualificationElements = [],
                WebsiteAuthenticationQualificationElements = []
            },
            DeviceDetermination = null,
            ValidationIndication = SignatureValidationIndication.Indeterminate,
            BestSignatureTime = RegulationEvaluationTime,
            SuitableAsQualifiedElectronicSignature = false,
            SuitableAsQualifiedElectronicSeal = false
        };

        SignatureApplicabilityCheckingReport report = SignatureApplicabilityRules.BuildReport(new SignatureApplicabilityReportInputs
        {
            RuleSet = EuSignatureApplicabilityRuleSet.RealTimeNotRequired,
            TechnicalApplicability = applicability,
            ValidationConclusion = CreateConclusion(SignatureValidationIndication.Indeterminate, RegulationEvaluationTime),
            SigningCertificateFacts = CreateFacts(hasQcCompliance: true, qcTypes: [EuQualifiedCertificateType.ElectronicSignature]),
            SignerSubject = "C=FI, O=Example Provider Oy, CN=Signer One"
        });

        Assert.IsFalse(report.UsesPseudonym, "An ordinary subject is not reported as pseudonymous.");
        Assert.IsNull(report.SignatureTypeIdentifier, "No Annex A type is determinable for the unsuitable outcome.");
        Assert.IsEmpty(report.AdditionalRequirementsIndications, "REQ-4.2-02 b): no additional requirements were used, and none are indicated.");
    }


    /// <summary>Creates a REQ-4.2-01 process conclusion with the given indication and best signature time.</summary>
    private static SignatureValidationConclusion CreateConclusion(SignatureValidationIndication indication, DateTimeOffset? bestSignatureTime) => new()
    {
        Indication = indication,
        SubIndications = [],
        ReportData = [],
        ValidationTime = RegulationEvaluationTime,
        PolicyIdentifier = new SignatureValidationPolicyIdentifier(WellKnownOids.SignatureApplicabilityRulesRealTimeRequired),
        ProcessIdentifier = SignatureValidationProcessIdentifier.LongTermAvailability,
        BestSignatureTime = bestSignatureTime
    };


    /// <summary>Creates the certificate facts the fixture criteria trees identify, mirroring the TS 119 615 vector fixtures.</summary>
    private static QualifiedCertificateFacts CreateFacts(
        bool hasQcCompliance,
        IReadOnlyList<EuQualifiedCertificateType> qcTypes,
        DateTimeOffset? notBefore = null,
        bool hasQcSscdStatement = false,
        IReadOnlyList<string>? subjectAttributeTypeOids = null) => new()
    {
        IssuerCountryCode = "FI",
        IssuerOrganizationNames = ["Example Provider Oy"],
        IssuerCommonNames = ["Example Provider Root CA"],
        SubjectCountryCode = "FI",
        SubjectOrganizationNames = ["Example Provider Oy"],
        NotBefore = notBefore ?? new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
        HasQcCompliance = hasQcCompliance,
        QcTypes = qcTypes,
        HasQcSscdStatement = hasQcSscdStatement,
        HasCertificatePoliciesExtension = true,
        CertificatePolicyOids = [MatchingPolicyOid],
        HasKeyUsageExtension = true,
        SetKeyUsageBits = [KeyUsageBitName.NonRepudiation],
        HasExtendedKeyUsageExtension = false,
        ExtendedKeyUsageOids = [],
        SubjectAttributeTypeOids = subjectAttributeTypeOids ?? [WellKnownOids.CountryName, WellKnownOids.OrganizationName, WellKnownOids.CommonName]
    };


    /// <summary>Creates a trusted list with one provider carrying one CA/QC service granted from the given instant.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created service transfers to the returned TrustedList, which the caller disposes.")]
    private static TrustedList CreateSingleServiceTrustedList(
        DateTimeOffset statusStartingTime,
        IReadOnlyList<TrustServiceAdditionalInformationType>? additionalServiceInformation = null) =>
        CreateTrustedList([CreateProvider([CreateService(
            statusStartingTime,
            additionalServiceInformation ?? [TrustServiceAdditionalInformationType.ForElectronicSignatures])])]);


    /// <summary>Creates a trusted list whose one provider carries two services with byte-identical digital identity certificates.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created services transfers to the returned TrustedList, which the caller disposes.")]
    private static TrustedList CreateTwoServiceTrustedList(DateTimeOffset statusStartingTime) =>
        CreateTrustedList([CreateProvider(
        [
            CreateService(statusStartingTime, [TrustServiceAdditionalInformationType.ForElectronicSignatures]),
            CreateService(statusStartingTime, [TrustServiceAdditionalInformationType.ForElectronicSignatures])
        ])]);


    /// <summary>
    /// Creates a trusted list whose one matching CA/QC service carries history instances in ascending
    /// status-starting-time order — the disorder PRO-4.3.4-03A fails the clause 4.3 run for while the run
    /// still reports the matched service.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created service and history carriers transfers to the returned TrustedList, which the caller disposes.")]
    private static TrustedList CreateDisorderedHistoryTrustedList() =>
        CreateTrustedList([CreateProvider([new TrustService
        {
            ServiceTypeIdentifier = TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
            ServiceNames = [new LocalizedText("en", "Example CA")],
            DigitalIdentity = new ServiceDigitalIdentity { Entries = [new X509CertificateIdentity(CreateCertificateMemory(CertificateUnderTestBytes))] },
            Status = TrustServiceStatus.Granted,
            StatusStartingTime = new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
            AdditionalServiceInformation = [TrustServiceAdditionalInformationType.ForElectronicSignatures],
            Qualifications = [],
            History =
            [
                CreateHistoryEntry(new DateTimeOffset(2010, 1, 1, 0, 0, 0, TimeSpan.Zero)),
                CreateHistoryEntry(new DateTimeOffset(2012, 1, 1, 0, 0, 0, TimeSpan.Zero))
            ]
        }])]);


    /// <summary>Creates a granted-state history instance recognising the certificate under test, starting at the given instant.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the certificate carrier transfers to the returned history instance's digital identity, disposed through the owning TrustedList.")]
    private static TrustServiceHistoryEntry CreateHistoryEntry(DateTimeOffset statusStartingTime) => new()
    {
        ServiceTypeIdentifier = TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
        ServiceNames = [new LocalizedText("en", "Example CA")],
        DigitalIdentity = new ServiceDigitalIdentity { Entries = [new X509CertificateIdentity(CreateCertificateMemory(CertificateUnderTestBytes))] },
        PreviousStatus = TrustServiceStatus.Granted,
        StatusStartingTime = statusStartingTime,
        AdditionalServiceInformation = [TrustServiceAdditionalInformationType.ForElectronicSignatures],
        Qualifications = []
    };


    /// <summary>Creates a trusted list carrying the given providers under a minimal, well-formed scheme.</summary>
    private static TrustedList CreateTrustedList(IReadOnlyList<TrustServiceProvider> providers) => new()
    {
        SchemeInformation = new TrustedListSchemeInformation
        {
            TslVersionIdentifier = 6,
            TslSequenceNumber = 1,
            TslType = TrustedListKind.Generic,
            SchemeOperatorNames = [new LocalizedText("en", "Example Supervisory Body")],
            SchemeOperatorPostalAddresses = [],
            SchemeOperatorElectronicAddresses = [],
            SchemeNames = [new LocalizedText("en", "FI: Example Trusted List")],
            SchemeInformationUris = [],
            StatusDeterminationApproach = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
            SchemeTerritory = "FI",
            HistoricalInformationPeriodYears = 65535,
            ListIssueDateTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero)
        },
        TrustServiceProviders = providers
    };


    /// <summary>Creates a provider with the given services.</summary>
    private static TrustServiceProvider CreateProvider(IReadOnlyList<TrustService> services) => new()
    {
        Names = [new LocalizedText("en", "Example Provider Oy")],
        TradeNames = [new LocalizedText("en", "Example Provider Oy Trade")],
        PostalAddresses = [],
        ElectronicAddresses = [],
        InformationUris = [],
        Services = services
    };


    /// <summary>Creates a granted CA/QC service recognising the certificate under test from the given instant.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the certificate carrier transfers to the returned service's digital identity, disposed through the owning TrustedList.")]
    private static TrustService CreateService(
        DateTimeOffset statusStartingTime,
        IReadOnlyList<TrustServiceAdditionalInformationType> additionalServiceInformation) => new()
    {
        ServiceTypeIdentifier = TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
        ServiceNames = [new LocalizedText("en", "Example CA")],
        DigitalIdentity = new ServiceDigitalIdentity { Entries = [new X509CertificateIdentity(CreateCertificateMemory(CertificateUnderTestBytes))] },
        Status = TrustServiceStatus.Granted,
        StatusStartingTime = statusStartingTime,
        AdditionalServiceInformation = additionalServiceInformation,
        Qualifications = [],
        History = []
    };


    /// <summary>Rents a <see cref="PkiCertificateMemory"/> carrier over the given DER-stand-in bytes.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PkiCertificateMemory, which the caller disposes.")]
    private static PkiCertificateMemory CreateCertificateMemory(byte[] bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
