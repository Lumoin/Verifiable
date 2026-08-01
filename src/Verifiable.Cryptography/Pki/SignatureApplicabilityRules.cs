using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The signature applicability rules of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11917204/01.02.01_60/ts_11917204v010201p.pdf">
/// ETSI TS 119 172-4 V1.2.1</see> for determining whether a digital signature is technically suitable to
/// implement an EU qualified electronic signature or seal using EU Member State trusted lists: the
/// REQ-4.2-03 composition of validation constraints, the clause 4.4.2 technical applicability (rules)
/// checking (TARC) process, and the clause 4.5 report composition — each a pure composition over the
/// ETSI EN 319 102-1 validation engine and the ETSI TS 119 615 qualification procedures this library ships.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Where each fixed constraint of REQ-4.2-03 lands.</strong> a) the trust anchors are read from the
/// clause 4.3 <c>SI-Results</c> for <see cref="TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates"/>
/// at the signing certificate's <c>notBefore</c>; b) the constraints of ETSI TS 119 172-1 table A.2 rows
/// (m)1.2 to (m)1.10 are not used — the composed constraints state no certificate meta-data constraints and
/// keep the default shell validity model; c) i) revocation checking accepts either a CRL or an OCSP
/// response, which is how the validation engine's revocation reading behaves with no per-source
/// restriction; c) ii) the revocation freshness is the rule set's fixed value; c) iii) rows (m)2.3 and (m)3
/// are not used — no certificate is exempted from revocation checking by these constraints; d) no
/// constraints apply to an end-entity certificate representing a trust anchor, which is inherent in the
/// certificate validation building block's step 1 trust-anchor short-circuit; e) and f) are behaviors of
/// the cryptographic constraint assessment and the cryptographic verification building block (an
/// unsupported suite concludes <c>INDETERMINATE</c> with a diagnostic, never <c>TOTAL-FAILED</c>);
/// g) profile non-compliance never invalidates a signature in this engine, which applies no baseline-profile
/// gate; h) is stated through
/// <see cref="SignatureElementsConstraints.RequireSignedSigningCertificateBinding"/>.
/// </para>
/// <para>
/// <strong>Strict status readings.</strong> REQ-4.4.2-02 and REQ-4.4.2-05 condition on the status
/// including <c>"PROCESS_PASSED"</c>; this composition reads that as exactly
/// <see cref="TrustedListProcessStatus.Passed"/> — a <c>PROCESS_PASSED_WITH_WARNING</c> status is a
/// different value and does not satisfy the condition, keeping the determination fail-closed. Warnings the
/// procedures raise while still passing travel in the sub-statuses of the retained determinations.
/// </para>
/// <para>
/// <strong>REQ-4.4.2-04 NOTE 3.</strong> The clause 4.5 device determination this library ships re-runs the
/// clause 4.4 certificate determination internally (its PRO-4.5.4-01 step); the note merely permits reusing
/// prior clause 4.4 results, so performing the procedure in full is conformant.
/// </para>
/// </remarks>
public static class SignatureApplicabilityRules
{
    /// <summary>
    /// Composes the REQ-4.2-03 validation constraints for one signing certificate under one rule set: the
    /// input the REQ-4.2-01 validation process is then run with.
    /// </summary>
    /// <param name="ruleSet">The applicability rule set, keying the fixed revocation freshness and naming the constraints' identity.</param>
    /// <param name="trustedList">The authenticated member state trusted list the trust anchors are read from.</param>
    /// <param name="signingCertificate">The signing certificate, as successfully identified per REQ-4.2-03 a) i). The caller retains ownership.</param>
    /// <param name="certificateFacts">The signing certificate's extracted facts; <see cref="QualifiedCertificateFacts.NotBefore"/> is the clause 4.3 <c>Date-time</c> per REQ-4.2-03 a) iii).</param>
    /// <param name="cryptographicConstraints">The cryptographic constraints table (REQ-4.2-03's cryptographic constraints; NOTE 7 points at ETSI TS 119 312 for values).</param>
    /// <param name="matchCertificateToService">The seam deciding certificate-to-service matching for the clause 4.3 run.</param>
    /// <param name="pool">The memory pool the matching seam rents any scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The composed constraints and the clause 4.3 outputs they were derived from.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The composition is fail-closed by construction rather than by a separate refusal: a clause 4.3 run
    /// that matches no service yields an empty trust anchor set, and a run whose <c>SI-Status</c> is
    /// <c>PROCESS_FAILED</c> — which still reports the services it inspected, per PRO-4.3.4-03A and
    /// PRO-4.3.4-11 — seeds no anchor from them, the same reading PRO-4.4.4-04 applies when the
    /// determinations consume a failed matching. Under an empty anchor set certificate path validation
    /// cannot succeed. The failed match is still returned for the report.
    /// </remarks>
    public static async ValueTask<SignatureApplicabilityConstraintsResult> CreateValidationConstraintsAsync(
        EuSignatureApplicabilityRuleSet ruleSet,
        TrustedList trustedList,
        PkiCertificateMemory signingCertificate,
        QualifiedCertificateFacts certificateFacts,
        CryptographicConstraints cryptographicConstraints,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);
        ArgumentNullException.ThrowIfNull(trustedList);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(certificateFacts);
        ArgumentNullException.ThrowIfNull(cryptographicConstraints);
        ArgumentNullException.ThrowIfNull(matchCertificateToService);
        ArgumentNullException.ThrowIfNull(pool);

        //REQ-4.2-03 a): the SI-Results of clause 4.3 of ETSI TS 119 615, with the CA/QC service type and
        //the signing certificate's notBefore as the Date-time indication.
        ListedServicesMatchResult serviceMatch = await TrustedListQualification.ObtainListedServicesMatchingCertificateAsync(
            trustedList,
            signingCertificate,
            TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
            certificateFacts.NotBefore,
            matchCertificateToService,
            pool,
            cancellationToken).ConfigureAwait(false);

        //The "relevant information from the 'Service digital identity' field(s)": the certificate entries
        //of each matched service's digital identity, exact-duplicate entries stated once. The constraints
        //set no sunset dates — the trusted list's own status history governed the match instead. A FAILED
        //clause 4.3 run still reports the services it inspected (PRO-4.3.4-03A, PRO-4.3.4-11); an unsound
        //match seeds no anchor, mirroring the PRO-4.4.4-04 reading the determinations apply.
        List<TrustAnchorConstraint> trustAnchors = [];
        if(serviceMatch.Status != TrustedListProcessStatus.Failed)
        {
            for(int i = 0; i < serviceMatch.Matches.Count; ++i)
            {
                IReadOnlyList<ServiceDigitalIdentityEntry> entries = serviceMatch.Matches[i].DigitalIdentity.Entries;
                for(int j = 0; j < entries.Count; ++j)
                {
                    if(entries[j] is X509CertificateIdentity certificateEntry
                        && !ContainsAnchor(trustAnchors, certificateEntry.Certificate))
                    {
                        trustAnchors.Add(new TrustAnchorConstraint(certificateEntry.Certificate, SunsetDate: null));
                    }
                }
            }
        }

        SignatureValidationConstraints constraints = new()
        {
            Identifier = new SignatureValidationPolicyIdentifier(ruleSet.PolicyOid),
            X509 = new X509ValidationConstraints
            {
                //REQ-4.2-03 b) and c) iii): rows (m)1.2-(m)1.10, (m)2.3 and (m)3 are not used, so the
                //meta-data constraints stay empty, the validity model stays the default and nothing is
                //exempted from revocation checking; c) ii): the rule set's fixed freshness.
                TrustAnchors = trustAnchors,
                MaximumAcceptedRevocationFreshness = ruleSet.MaximumAcceptedRevocationFreshness
            },
            Cryptographic = cryptographicConstraints,
            SignatureElements = new SignatureElementsConstraints
            {
                //REQ-4.2-03 h): the presence of a signed reference or signed copy of the signing
                //certificate is enforced.
                RequireSignedSigningCertificateBinding = true
            }
        };

        return new SignatureApplicabilityConstraintsResult
        {
            Constraints = constraints,
            TrustAnchorServiceMatch = serviceMatch
        };

        //Reports whether an exact-DER-equal anchor is already stated.
        static bool ContainsAnchor(List<TrustAnchorConstraint> anchors, PkiCertificateMemory candidate)
        {
            for(int i = 0; i < anchors.Count; ++i)
            {
                if(anchors[i].Anchor.Equals(candidate))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Performs the technical applicability (rules) checking process of clause 4.4.2 over a completed
    /// REQ-4.2-01 validation: the REQ-4.4.2-01 certificate determination, the REQ-4.4.2-04 device
    /// determination (unless REQ-4.4.2-02 b) stopped the process), and the REQ-4.4.2-06 suitability
    /// determination.
    /// </summary>
    /// <param name="trustedList">The authenticated member state trusted list.</param>
    /// <param name="signingCertificate">The signing certificate (<c>CERT</c>). The caller retains ownership.</param>
    /// <param name="certificateFacts">The signing certificate's extracted facts.</param>
    /// <param name="validationConclusion">The conclusion of the REQ-4.2-01 validation process; its best signature time is the <c>Date-time</c> of REQ-4.4.2-01 and REQ-4.4.2-04, and its indication is condition c) of REQ-4.4.2-06.</param>
    /// <param name="matchCertificateToService">The seam deciding certificate-to-service matching for the determinations' clause 4.3 runs.</param>
    /// <param name="pool">The memory pool the matching seam rents any scratch buffers from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The checking outcome, carrying every intermediate determination for the report.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="validationConclusion"/> determines no best signature time: REQ-4.2-01 mandates the validation process for Signatures providing Long Term Availability and Integrity of Validation Material, which always determines one.</exception>
    public static async ValueTask<TechnicalApplicabilityCheckResult> CheckTechnicalApplicabilityAsync(
        TrustedList trustedList,
        PkiCertificateMemory signingCertificate,
        QualifiedCertificateFacts certificateFacts,
        SignatureValidationConclusion validationConclusion,
        MatchCertificateToTrustServiceAsyncDelegate matchCertificateToService,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(trustedList);
        ArgumentNullException.ThrowIfNull(signingCertificate);
        ArgumentNullException.ThrowIfNull(certificateFacts);
        ArgumentNullException.ThrowIfNull(validationConclusion);
        ArgumentNullException.ThrowIfNull(matchCertificateToService);
        ArgumentNullException.ThrowIfNull(pool);

        if(validationConclusion.BestSignatureTime is not DateTimeOffset bestSignatureTime)
        {
            throw new ArgumentException(
                "The validation conclusion determines no best signature time. The process REQ-4.2-01 mandates always determines one.",
                nameof(validationConclusion));
        }

        //REQ-4.4.2-01: the clause 4.4 determination of ETSI TS 119 615, with CERT set to the signing
        //certificate and Date-time set to the best signature time.
        EuQualifiedCertificateDeterminationResult certificateDetermination = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList,
            signingCertificate,
            certificateFacts,
            bestSignatureTime,
            matchCertificateToService,
            pool,
            cancellationToken).ConfigureAwait(false);

        //REQ-4.4.2-02: PROCESS_PASSED exactly (see the type remarks on strict status readings), and a
        //qualified indication in either the electronic-signature or the electronic-seal dimension.
        bool certificatePassed = certificateDetermination.Status == TrustedListProcessStatus.Passed;
        bool qualifiedForSignatures = certificatePassed
            && IncludesIndication(certificateDetermination.Indications, EuQualifiedCertificateIndication.QualifiedForESignature);
        bool qualifiedForSeals = certificatePassed
            && IncludesIndication(certificateDetermination.Indications, EuQualifiedCertificateIndication.QualifiedForESeal);

        if(!qualifiedForSignatures && !qualifiedForSeals)
        {
            //REQ-4.4.2-02 b): the process stops, the signature is determined technically as neither, and
            //the retained determination carries the intermediate results for the report.
            return new TechnicalApplicabilityCheckResult
            {
                CertificateDetermination = certificateDetermination,
                DeviceDetermination = null,
                ValidationIndication = validationConclusion.Indication,
                BestSignatureTime = bestSignatureTime,
                SuitableAsQualifiedElectronicSignature = false,
                SuitableAsQualifiedElectronicSeal = false
            };
        }

        //REQ-4.4.2-04: the clause 4.5 determination at the same CERT and Date-time.
        QualifiedSignatureCreationDeviceDeterminationResult deviceDetermination = await TrustedListQualification.DetermineQualifiedSignatureCreationDeviceAsync(
            trustedList,
            signingCertificate,
            certificateFacts,
            bestSignatureTime,
            matchCertificateToService,
            pool,
            cancellationToken).ConfigureAwait(false);

        //REQ-4.4.2-05: PROCESS_PASSED exactly, and QSCD_YES.
        bool createdByQualifiedDevice = deviceDetermination.Status == TrustedListProcessStatus.Passed
            && deviceDetermination.Indication == QualifiedSignatureCreationDeviceIndication.PrivateKeyOnDevice;

        //REQ-4.4.2-06: all three conditions per dimension, condition c) being TOTAL-PASSED.
        bool totalPassed = validationConclusion.Indication == SignatureValidationIndication.TotalPassed;

        return new TechnicalApplicabilityCheckResult
        {
            CertificateDetermination = certificateDetermination,
            DeviceDetermination = deviceDetermination,
            ValidationIndication = validationConclusion.Indication,
            BestSignatureTime = bestSignatureTime,
            SuitableAsQualifiedElectronicSignature = qualifiedForSignatures && createdByQualifiedDevice && totalPassed,
            SuitableAsQualifiedElectronicSeal = qualifiedForSeals && createdByQualifiedDevice && totalPassed
        };

        //Reports whether the determination's indications include one value.
        static bool IncludesIndication(IReadOnlyList<EuQualifiedCertificateIndication> indications, EuQualifiedCertificateIndication value)
        {
            for(int i = 0; i < indications.Count; ++i)
            {
                if(indications[i] == value)
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Determines the Annex A 2 digital signature type identifier for a checking outcome, where the outcome
    /// itself determines one (REQ-4.5-02).
    /// </summary>
    /// <param name="result">The checking outcome.</param>
    /// <returns>
    /// <see cref="WellKnownOids.DigitalSignatureTypeEuQualifiedSignature"/> or
    /// <see cref="WellKnownOids.DigitalSignatureTypeEuQualifiedSeal"/> when the signature was determined
    /// technically suitable (the signature dimension stated first for a certificate qualified in both);
    /// <see cref="WellKnownOids.DigitalSignatureTypeAdvancedSignatureWithQualifiedCertificate"/> or
    /// <see cref="WellKnownOids.DigitalSignatureTypeAdvancedSealWithQualifiedCertificate"/> when validation
    /// concluded <c>TOTAL-PASSED</c> on a determined EU qualified certificate without a confirmed qualified
    /// creation device; <see langword="null"/> otherwise — the plain advanced types and the qualified
    /// time-stamp type are not determinable by this process (the trusted list states nothing about a
    /// signature whose certificate it does not qualify, and time stamps are the subject of the
    /// ETSI TS 119 615 clause 4.7 determination instead).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="result"/> is <see langword="null"/>.</exception>
    public static string? DetermineSignatureTypeIdentifier(TechnicalApplicabilityCheckResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if(result.SuitableAsQualifiedElectronicSignature)
        {
            return WellKnownOids.DigitalSignatureTypeEuQualifiedSignature;
        }

        if(result.SuitableAsQualifiedElectronicSeal)
        {
            return WellKnownOids.DigitalSignatureTypeEuQualifiedSeal;
        }

        if(result.ValidationIndication != SignatureValidationIndication.TotalPassed
            || result.CertificateDetermination.Status != TrustedListProcessStatus.Passed)
        {
            return null;
        }

        IReadOnlyList<EuQualifiedCertificateIndication> indications = result.CertificateDetermination.Indications;
        for(int i = 0; i < indications.Count; ++i)
        {
            if(indications[i] == EuQualifiedCertificateIndication.QualifiedForESignature)
            {
                return WellKnownOids.DigitalSignatureTypeAdvancedSignatureWithQualifiedCertificate;
            }
        }

        for(int i = 0; i < indications.Count; ++i)
        {
            if(indications[i] == EuQualifiedCertificateIndication.QualifiedForESeal)
            {
                return WellKnownOids.DigitalSignatureTypeAdvancedSealWithQualifiedCertificate;
            }
        }

        return null;
    }


    /// <summary>
    /// Composes the REQ-4.5-01 applicability rules checking report from the process outcomes and the
    /// Driving Application's presentation elements.
    /// </summary>
    /// <param name="inputs">The report inputs.</param>
    /// <returns>The composed report.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="inputs"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The composition derives what the inputs already prove: the REQ-4.5-01 c) pseudonym indication from
    /// the signing certificate's subject attribute types, and the REQ-4.5-02 signature type identifier from
    /// the checking outcome via <see cref="DetermineSignatureTypeIdentifier"/>.
    /// </remarks>
    public static SignatureApplicabilityCheckingReport BuildReport(SignatureApplicabilityReportInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);

        return new SignatureApplicabilityCheckingReport
        {
            AppliedRulesIdentifier = inputs.RuleSet.PolicyOid,
            SignerSubject = inputs.SignerSubject,
            SubjectAlternativeNames = inputs.SubjectAlternativeNames,
            UsesPseudonym = UsesPseudonym(inputs.SigningCertificateFacts),
            TimingInformation = inputs.TimingInformation,
            SignedDataPresentations = inputs.SignedDataPresentations,
            SignatureAttributes = inputs.SignatureAttributes,
            TechnicalApplicability = inputs.TechnicalApplicability,
            ValidationConclusion = inputs.ValidationConclusion,
            TrustAnchorServiceMatch = inputs.TrustAnchorServiceMatch,
            CryptographicSuites = inputs.CryptographicSuites,
            SigningCertificateRevocationFreshness = inputs.SigningCertificateRevocationFreshness,
            DetailedOutcome = inputs.DetailedOutcome,
            FormatComplianceWarnings = inputs.FormatComplianceWarnings,
            AdditionalRequirementsIndications = inputs.AdditionalRequirementsIndications,
            SignatureTypeIdentifier = DetermineSignatureTypeIdentifier(inputs.TechnicalApplicability)
        };

        //Reports whether the subject distinguished name carries the X.520 pseudonym attribute type.
        static bool UsesPseudonym(QualifiedCertificateFacts facts)
        {
            for(int i = 0; i < facts.SubjectAttributeTypeOids.Count; ++i)
            {
                if(string.Equals(facts.SubjectAttributeTypeOids[i], WellKnownOids.Pseudonym, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
