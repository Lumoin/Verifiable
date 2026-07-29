using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the validation process for Basic Signatures concluded — the outputs of clause 5.3.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>, together with the intermediate results steps 4)a), 6) and 7) of clause 5.5.4
/// branch on when the validation process for Signatures with Time continues from here.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier this record references belongs to the
/// <see cref="SignatureValidationResources"/> of the run that produced it; the record owns nothing and disposing
/// it would be meaningless.
/// </remarks>
[DebuggerDisplay("BasicSignatureValidationResult: {Conclusion.Indication}")]
public sealed record BasicSignatureValidationResult
{
    /// <summary>The process conclusion in the building-block vocabulary of clause 5.1.3, which clause 5.1.2 steps 5) to 7) promote to a main status indication.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>The facts the format checking building block extracted in step 1), which every later step read.</summary>
    public required SignatureFacts Signature { get; init; }

    /// <summary>The validation constraints the validation context initialization building block selected in step 3); <see langword="null"/> when the process did not reach that step.</summary>
    public SignatureValidationConstraints? Constraints { get; init; }

    /// <summary>The signing certificate the identification building block settled on in step 2); <see langword="null"/> when it identified none.</summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>The certificate chain step 4) built, which step 7) returns with the success indication.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateChain { get; init; } = [];

    /// <summary>Whether <see cref="CertificateChain"/> is a validated chain or merely the last one built.</summary>
    public CertificateChainReportKind ChainKind { get; init; }

    /// <summary>The certificate validation data the validation context initialization building block gathered — the certificates, revocation lists and OCSP responses the run consulted.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateValidationData { get; init; } = [];

    /// <summary>The revocation status information the X.509 certificate validation building block consulted.</summary>
    public IReadOnlyList<RevocationStatusInformation> RevocationStatusInformationUsed { get; init; } = [];

    /// <summary>The claimed signing time the signature declares, which step 5) of clause 5.5.4 checks the time-stamp delay against; <see langword="null"/> when the signature declares none.</summary>
    public DateTimeOffset? ClaimedSigningTime { get; init; }

    /// <summary>The revocation time step 4)a) of clause 5.5.4 compares with best-signature-time; <see langword="null"/> when the conclusion is about no revocation.</summary>
    public DateTimeOffset? RevocationTime { get; init; }

    /// <summary>Why the X.509 certificate validation building block reported <c>TRY_LATER</c>, which steps 6) and 7) of clause 5.5.4 branch on.</summary>
    public RevocationTryLaterReason TryLaterReason { get; init; }

    /// <summary>The instance of revocation status information the conclusion turns on, which step 6) of clause 5.5.4 hands back to the revocation freshness checker; <see langword="null"/> when no single instance decided it.</summary>
    public RevocationStatusInformation? DecisiveRevocationStatusInformation { get; init; }

    /// <summary>The algorithm assessments a cryptographic constraints failure is about, which step 4)c) of clause 5.5.4 re-assesses at best-signature-time; empty when the conclusion is about no such failure.</summary>
    public IReadOnlyList<AlgorithmReliabilityAssessment> UnreliableAlgorithms { get; init; } = [];

    /// <summary>The outcome of each validation constraint any building block of the process took into account.</summary>
    public IReadOnlyList<ValidationConstraintEvaluation> ConstraintEvaluations { get; init; } = [];


    /// <summary>
    /// Gets whether a cryptographic constraints failure concerns "the signature value or a signed attribute",
    /// which step 4)c) of clause 5.5.4 conditions its continuation on and step 6) of clause 5.3.4 conditions the
    /// content time-stamp branch on.
    /// </summary>
    public bool CryptographicFailureConcernsSignatureMaterial
    {
        get
        {
            for(int i = 0; i < UnreliableAlgorithms.Count; ++i)
            {
                if(SignatureMaterialIdentifiers.IsSignatureOwnMaterial(UnreliableAlgorithms[i].Use.MaterialIdentifier))
                {
                    return true;
                }
            }

            return false;
        }
    }
}


/// <summary>
/// The validation process for Basic Signatures of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.3</see>: the process that runs the seven building blocks of clause 5.2 in
/// the order of clause 5.3.4 and reports the validity of the signature at the validation time.
/// </summary>
/// <remarks>
/// <para>
/// NOTE 1 of clause 5.3.4 permits any ordering that produces the same results; the steps run in the clause's own
/// order here, which keeps the internal variable <c>X509_validation-status</c> of NOTE 2 exactly where the clause
/// puts it — set by step 4), consumed by step 5)e) and 5)f) after the cryptographic verification has run.
/// </para>
/// <para>
/// This process is also the building block the time-stamp validation building block of clause 5.4 runs on a
/// time-stamp token, and the process the validation process for Signatures with Time of clause 5.5 runs in its
/// step 2). The composition is finite by construction: a run that is validating a time-stamp token is given no
/// time-stamp validation seam, so the content time-stamp branches of steps 4) and 6) are not taken and no
/// further nesting is possible.
/// </para>
/// <para>
/// <strong>Determinism.</strong> Clause 5.1.3 requires that the same inputs yield the same result. Nothing here
/// reads a clock: <c>validationTime</c> is an explicit input the composition root obtained once, and every
/// comparison is against a value that was an input or was read from the material under validation.
/// </para>
/// </remarks>
public static class BasicSignatureValidation
{
    /// <summary>
    /// Runs the validation process for Basic Signatures.
    /// </summary>
    /// <param name="inputs">The inputs of Table 18.</param>
    /// <param name="seams">The format binding and the certificate seams the process composes.</param>
    /// <param name="validateTimestampToken">The clause 5.4 time-stamp validation the content time-stamp branches of steps 4) and 6) compose, or <see langword="null"/> when the run is itself validating a time-stamp token.</param>
    /// <param name="validationTime">The instant the signature is validated at, which clause 5.3.3 makes the current time.</param>
    /// <param name="resources">The ledger the carriers this run creates are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of clause 5.3.3, the certificate chain, and the intermediate results clause 5.5.4 continues from.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<BasicSignatureValidationResult> ValidateAsync(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        ValidateTimestampTokenAsyncDelegate? validateTimestampToken,
        DateTimeOffset validationTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        List<ValidationConstraintEvaluation> constraintEvaluations = [];

        //Step 1): format checking. The block's own parse is what produces the facts every later step reads, so
        //the facts are tracked here and never re-extracted.
        FormatCheckingResult formatChecking = await FormatChecking.CheckAsync(
            new SignatureFactsExtractionContext { SignedDataObject = inputs.SignedDataObject, SignerDocuments = inputs.SignerDocuments },
            seams.Format.Format,
            seams.Format.ExtractFacts,
            pool,
            cancellationToken).ConfigureAwait(false);
        SignatureFacts signature = resources.Track(formatChecking.Facts);
        constraintEvaluations.AddRange(formatChecking.Conclusion.ConstraintEvaluations);
        if(formatChecking.Conclusion.Indication != BuildingBlockIndication.Passed)
        {
            return new BasicSignatureValidationResult
            {
                Conclusion = formatChecking.Conclusion,
                Signature = signature,
                ConstraintEvaluations = [.. constraintEvaluations]
            };
        }

        //Step 2): identification of the signing certificate.
        SigningCertificateIdentificationResult identification = await SigningCertificateIdentification.IdentifyAsync(
            signature, inputs.SigningCertificate, pool, cancellationToken).ConfigureAwait(false);
        constraintEvaluations.AddRange(identification.Conclusion.ConstraintEvaluations);
        if(identification.SigningCertificate is not PkiCertificateMemory signingCertificate)
        {
            return new BasicSignatureValidationResult
            {
                Conclusion = identification.Conclusion,
                Signature = signature,
                ConstraintEvaluations = [.. constraintEvaluations]
            };
        }

        //Step 3): validation context initialization.
        ValidationContextInitializationResult context = await ValidationContextInitialization.InitializeAsync(
            signature,
            inputs.Constraints,
            inputs.SignaturePolicies,
            inputs.UnmappedSignaturePolicyHandling,
            seams.ResolveSignaturePolicy,
            inputs.CertificateValidationData,
            pool,
            cancellationToken).ConfigureAwait(false);
        constraintEvaluations.AddRange(context.Conclusion.ConstraintEvaluations);
        if(context.Constraints is not SignatureValidationConstraints constraints)
        {
            return new BasicSignatureValidationResult
            {
                Conclusion = context.Conclusion,
                Signature = signature,
                SigningCertificate = signingCertificate,
                CertificateValidationData = context.CertificateValidationData,
                ConstraintEvaluations = [.. constraintEvaluations]
            };
        }

        //Step 4): X.509 certificate validation. Only the certificates among the validation data may build the
        //chain, which is Table 12's "OtherCertificates" input.
        X509CertificateValidationResult x509 = await X509CertificateValidation.ValidateAsync(
            signingCertificate,
            constraints.X509,
            constraints.Cryptographic,
            SelectCertificates(context.CertificateValidationData),
            inputs.RevocationStatusInformation,
            seams.CompleteCertificateChain,
            seams.ValidateCertificateChain,
            seams.CheckRevocation,
            validationTime,
            pool,
            cancellationToken).ConfigureAwait(false);
        resources.TrackRange(x509.AcquiredCertificates);
        constraintEvaluations.AddRange(x509.Conclusion.ConstraintEvaluations);

        //Every outcome from here on reports the same material and differs only in its conclusion and in the
        //algorithm assessments a cryptographic constraints failure carries, so the shared part is built once.
        var outcome = new BasicSignatureValidationResult
        {
            Conclusion = x509.Conclusion,
            Signature = signature,
            Constraints = constraints,
            SigningCertificate = signingCertificate,
            CertificateChain = x509.CertificateChain,
            ChainKind = x509.ChainKind,
            CertificateValidationData = context.CertificateValidationData,
            RevocationStatusInformationUsed = x509.RevocationStatusInformationUsed,
            ClaimedSigningTime = signature.ClaimedSigningTime,
            RevocationTime = x509.RevocationTime,
            TryLaterReason = x509.TryLaterReason,
            DecisiveRevocationStatusInformation = x509.DecisiveRevocationStatusInformation
        };

        SignatureValidationSubIndication x509SubIndication = x509.Conclusion.SubIndications.Count > 0
            ? x509.Conclusion.SubIndications[0]
            : SignatureValidationSubIndication.Custom;

        //Step 4)'s NO_CERTIFICATE_CHAIN_FOUND early return, taken only for a signature algorithm that cannot
        //determine the public key without the full chain and therefore cannot reach step 5) at all.
        if(x509.Conclusion.Indication == BuildingBlockIndication.Indeterminate
            && x509SubIndication.Equals(SignatureValidationSubIndication.NoCertificateChainFound)
            && seams.SignatureAlgorithmRequiresFullCertificateChain)
        {
            return outcome with { ConstraintEvaluations = [.. constraintEvaluations] };
        }

        BuildingBlockConclusion x509ValidationStatus = x509.Conclusion;
        if(x509.Conclusion.Indication == BuildingBlockIndication.Indeterminate && validateTimestampToken is not null)
        {
            DateTimeOffset? contentTimestampTime = await LatestPassingContentTimestampTimeAsync(
                signature, validateTimestampToken, validationTime, pool, cancellationToken).ConfigureAwait(false);

            if(x509SubIndication.Equals(SignatureValidationSubIndication.RevokedNoProofOfExistence)
                && contentTimestampTime is DateTimeOffset afterRevocation
                && x509.RevocationTime is DateTimeOffset revocationTime
                && afterRevocation > revocationTime)
            {
                //Step 4): a content time-stamp proves the signature value was produced after its generation time,
                //so a generation time after the revocation time proves the signature was created after it.
                x509ValidationStatus = BuildingBlockConclusion.Failed(SignatureValidationSubIndication.Revoked, x509.Conclusion.ReportData);
            }
            else if((x509SubIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence)
                    || x509SubIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNotRevoked))
                && contentTimestampTime is DateTimeOffset afterExpiration
                && TryReadExpirationDate(signingCertificate) is DateTimeOffset notAfter
                && afterExpiration > notAfter)
            {
                x509ValidationStatus = BuildingBlockConclusion.Failed(SignatureValidationSubIndication.Expired, x509.Conclusion.ReportData);
            }
        }

        //Step 5): cryptographic verification.
        CryptographicVerificationResult cryptographic = await CryptographicVerification.VerifyAsync(
            signature,
            signingCertificate,
            x509.CertificateChain,
            inputs.SignerDocuments,
            seams.Format.VerifyCryptography,
            pool,
            cancellationToken).ConfigureAwait(false);
        constraintEvaluations.AddRange(cryptographic.Conclusion.ConstraintEvaluations);
        if(cryptographic.Conclusion.Indication != BuildingBlockIndication.Passed)
        {
            return outcome with { Conclusion = cryptographic.Conclusion, ConstraintEvaluations = [.. constraintEvaluations] };
        }

        //Step 5)f): the X.509 status the cryptographic verification was waiting for.
        if(x509ValidationStatus.Indication != BuildingBlockIndication.Passed)
        {
            return outcome with { Conclusion = x509ValidationStatus, ConstraintEvaluations = [.. constraintEvaluations] };
        }

        //Step 6): signature acceptance validation.
        SignatureAcceptanceValidationResult acceptance = await SignatureAcceptanceValidation.ValidateAsync(
            signature,
            x509.CertificateChain,
            constraints.SignatureElements,
            constraints.Cryptographic,
            validateTimestampToken,
            validationTime,
            pool,
            cancellationToken).ConfigureAwait(false);
        constraintEvaluations.AddRange(acceptance.Conclusion.ConstraintEvaluations);
        List<AlgorithmReliabilityAssessment> unreliableAlgorithms = SelectAssessments(acceptance.Conclusion.ReportData);
        if(acceptance.Conclusion.Indication != BuildingBlockIndication.Passed)
        {
            SignatureValidationSubIndication acceptanceSubIndication = acceptance.Conclusion.SubIndications.Count > 0
                ? acceptance.Conclusion.SubIndications[0]
                : SignatureValidationSubIndication.Custom;
            bool concernsSignatureMaterial = ConcernsSignatureOwnMaterial(unreliableAlgorithms);
            if(acceptanceSubIndication.Equals(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence)
                && concernsSignatureMaterial
                && validateTimestampToken is not null)
            {
                DateTimeOffset? contentTimestampTime = await LatestPassingContentTimestampTimeAsync(
                    signature, validateTimestampToken, validationTime, pool, cancellationToken).ConfigureAwait(false);
                if(contentTimestampTime is DateTimeOffset provenAfter && AllUnreliableAt(unreliableAlgorithms, provenAfter))
                {
                    //Step 6): the algorithms were already no longer reliable when the content time-stamp was
                    //generated, and the signature value was produced after that, so no proof of existence can
                    //place the signature in the period the algorithms were still considered reliable.
                    return outcome with
                    {
                        Conclusion = BuildingBlockConclusion.Indeterminate(
                            SignatureValidationSubIndication.CryptographicConstraintsFailure, acceptance.Conclusion.ReportData),
                        UnreliableAlgorithms = unreliableAlgorithms,
                        ConstraintEvaluations = [.. constraintEvaluations]
                    };
                }
            }

            return outcome with
            {
                Conclusion = acceptance.Conclusion,
                UnreliableAlgorithms = unreliableAlgorithms,
                ConstraintEvaluations = [.. constraintEvaluations]
            };
        }

        //Step 7).
        return outcome with
        {
            Conclusion = BuildingBlockConclusion.PassedWith(x509.Conclusion.ReportData),
            ConstraintEvaluations = [.. constraintEvaluations]
        };
    }


    /// <summary>
    /// Validates every time-stamp on a Signed Data Object the signature carries and states the latest generation
    /// time among those that validated, which is the strongest lower bound on the time the signature value was
    /// produced that NOTE 3 of clause 5.3.4 lets the content time-stamps establish.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="validateTimestampToken">The clause 5.4 time-stamp validation seam.</param>
    /// <param name="validationTime">The instant the tokens are validated at.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The latest generation time among the content time-stamps that validated, or <see langword="null"/> when none did.</returns>
    private static async ValueTask<DateTimeOffset?> LatestPassingContentTimestampTimeAsync(
        SignatureFacts signature,
        ValidateTimestampTokenAsyncDelegate validateTimestampToken,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<EmbeddedTimestamp> contentTimestamps = signature.TimestampsOfClass(SignatureTimestampClass.ContentTimestamp);
        DateTimeOffset? latest = null;
        for(int i = 0; i < contentTimestamps.Count; ++i)
        {
            BuildingBlockConclusion conclusion;
            try
            {
                conclusion = await validateTimestampToken(
                    new TimestampTokenValidationContext { Token = contentTimestamps[i].Token, ValidationTime = validationTime },
                    pool,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(exception is not OperationCanceledException)
            {
                //A seam that throws has validated nothing, which is the branch "in all other cases" of step 4).
                continue;
            }

            if(conclusion.Indication != BuildingBlockIndication.Passed)
            {
                continue;
            }

            using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(
                contentTimestamps[i].Token, pool, cancellationToken).ConfigureAwait(false);
            if(info.IsRead && (latest is null || info.GenerationTime > latest))
            {
                latest = info.GenerationTime;
            }
        }

        return latest;
    }


    /// <summary>
    /// Reads the <c>notAfter</c> date of a certificate, for the expiration comparison of step 4).
    /// </summary>
    /// <param name="certificate">The certificate to read.</param>
    /// <returns>The expiration date, or <see langword="null"/> when the certificate does not parse.</returns>
    private static DateTimeOffset? TryReadExpirationDate(PkiCertificateMemory certificate)
    {
        try
        {
            return ManagedCertificate.Parse(certificate.AsReadOnlyMemory()).NotAfter;
        }
        catch(AsnContentException)
        {
            //A certificate whose validity dates cannot be read proves no expiration, so the branch is not taken.
            return null;
        }
    }


    /// <summary>
    /// Selects the X.509 certificates among a certificate validation data set, which is the "OtherCertificates"
    /// input of Table 12.
    /// </summary>
    /// <param name="validationData">The validation data, each entry carrying its own kind discriminator.</param>
    /// <returns>The certificates, in the order they were gathered.</returns>
    private static List<PkiCertificateMemory> SelectCertificates(IReadOnlyList<PkiCertificateMemory> validationData)
    {
        List<PkiCertificateMemory> certificates = [];
        for(int i = 0; i < validationData.Count; ++i)
        {
            if(validationData[i].IsX509Certificate)
            {
                certificates.Add(validationData[i]);
            }
        }

        return certificates;
    }


    /// <summary>
    /// Selects the algorithm assessments a block's report data carries, which is what a cryptographic constraints
    /// failure is about.
    /// </summary>
    /// <param name="reportData">The block's report data.</param>
    /// <returns>The assessments; empty when the report data carries none.</returns>
    private static List<AlgorithmReliabilityAssessment> SelectAssessments(IReadOnlyList<SignatureValidationReportData> reportData)
    {
        List<AlgorithmReliabilityAssessment> assessments = [];
        for(int i = 0; i < reportData.Count; ++i)
        {
            if(reportData[i] is CryptographicConstraintsFailureReportData failure)
            {
                for(int a = 0; a < failure.UnreliableAlgorithms.Count; ++a)
                {
                    assessments.Add(failure.UnreliableAlgorithms[a]);
                }
            }
        }

        return assessments;
    }


    /// <summary>
    /// Reports whether any assessment is about the signature's own material — the signature value or the digest
    /// over the signed attributes.
    /// </summary>
    /// <param name="assessments">The assessments a cryptographic constraints failure is about.</param>
    /// <returns><see langword="true"/> when at least one is.</returns>
    private static bool ConcernsSignatureOwnMaterial(List<AlgorithmReliabilityAssessment> assessments)
    {
        for(int i = 0; i < assessments.Count; ++i)
        {
            if(SignatureMaterialIdentifiers.IsSignatureOwnMaterial(assessments[i].Use.MaterialIdentifier))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Reports whether every algorithm concerned by a failure was already no longer considered reliable at an
    /// instant — the condition step 6) of clause 5.3.4 turns <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c> into
    /// <c>CRYPTO_CONSTRAINTS_FAILURE</c> on.
    /// </summary>
    /// <param name="assessments">The assessments the failure is about.</param>
    /// <param name="instant">The instant to judge at.</param>
    /// <returns><see langword="true"/> when no assessment states reliability extending to that instant.</returns>
    private static bool AllUnreliableAt(List<AlgorithmReliabilityAssessment> assessments, DateTimeOffset instant)
    {
        if(assessments.Count == 0)
        {
            return false;
        }

        for(int i = 0; i < assessments.Count; ++i)
        {
            if(assessments[i].TrustedUntil is DateTimeOffset trustedUntil && trustedUntil >= instant)
            {
                return false;
            }
        }

        return true;
    }
}
