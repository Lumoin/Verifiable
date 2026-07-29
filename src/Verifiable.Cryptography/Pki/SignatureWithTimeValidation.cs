using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the validation process for Signatures with Time and Signatures with Long-Term Validation Material
/// concluded — the outputs of clause 5.5.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>: the status, the earliest time proven that the signature has existed, and the
/// certificate chain used for validation.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier this record references belongs to the
/// <see cref="SignatureValidationResources"/> of the run that produced it.
/// </remarks>
[DebuggerDisplay("SignatureWithTimeValidationResult: {Conclusion.Indication}, best-signature-time {BestSignatureTime}")]
public sealed record SignatureWithTimeValidationResult
{
    /// <summary>The process conclusion in the building-block vocabulary of clause 5.1.3.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>Best-signature-time: the earliest time at which the existence of the signature can be proven using the procedures of clause 5.5.4, which step 11) returns.</summary>
    public required DateTimeOffset BestSignatureTime { get; init; }

    /// <summary>What the validation process for Basic Signatures made of the signature in step 2), which the process of clause 5.6.3 continues from.</summary>
    public required BasicSignatureValidationResult BasicValidation { get; init; }

    /// <summary>The validation results of the signature time-stamp tokens, which step 11) says the process should return as intermediate results.</summary>
    public IReadOnlyList<TimestampValidationResult> SignatureTimestampValidations { get; init; } = [];

    /// <summary>The signature time-stamp tokens that remained in the set after steps 3)a) and 3)b) removed the ones that did not bind or did not validate.</summary>
    public IReadOnlyList<EmbeddedTimestamp> AcceptedSignatureTimestamps { get; init; } = [];
}


/// <summary>
/// The validation process for Signatures with Time and Signatures with Long-Term Validation Material of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.5</see>: the process that determines best-signature-time from the signature
/// time-stamp tokens and re-decides the status of a Basic Signature validation against it.
/// </summary>
/// <remarks>
/// <para>
/// The whole algorithm turns on one internal variable, best-signature-time, which NOTE 1 of clause 5.5.4 defines
/// as "the earliest time when it can be trusted by the SVA ... that a signature has existed". Step 1) initializes
/// it to the Driving Application's time indication for signature existence or, when there is none, to the current
/// time; step 3)b) lowers it to the generation time of every signature time-stamp token that validates; and
/// step 4) compares it against the revocation, issuance and expiration instants the Basic Signature validation
/// reported.
/// </para>
/// <para>
/// <strong>Determinism.</strong> Nothing here reads a clock. The current time reaches this process as the
/// explicit <c>currentTime</c> argument the composition root obtained once, exactly as clause 5.1.3's rule that
/// the same inputs yield the same result requires.
/// </para>
/// </remarks>
public static class SignatureWithTimeValidation
{
    /// <summary>
    /// Runs the validation process for Signatures with Time and Signatures with Long-Term Validation Material.
    /// </summary>
    /// <param name="inputs">The inputs of Table 20.</param>
    /// <param name="seams">The format binding and the certificate seams the process composes.</param>
    /// <param name="currentTime">The current time, obtained once by the composition root.</param>
    /// <param name="resources">The ledger the carriers this run creates are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of clause 5.5.3, best-signature-time and the intermediate results.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<SignatureWithTimeValidationResult> ValidateAsync(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(resources);
        ArgumentNullException.ThrowIfNull(pool);

        //Step 1): best-signature-time is the Driving Application's time indication for signature existence, or
        //the current time when the Driving Application used no such parameter. The set of signature time-stamp
        //tokens is initialized once the format binding has surfaced the signature's attributes in step 2), which
        //is the same set: nothing between the two steps reads it.
        DateTimeOffset bestSignatureTime = inputs.TimeIndicationForSignatureExistence ?? currentTime;

        //Step 2): the validation process for Basic Signatures, with a time-stamp validation seam so that the
        //content time-stamp branches of clause 5.3.4 steps 4) and 6) are available to it.
        var timestampSeam = new TimestampSeamContext(inputs, seams, resources, currentTime);
        BasicSignatureValidationResult basic = await BasicSignatureValidation.ValidateAsync(
            inputs, seams, timestampSeam.ValidateAsync, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

        SignatureValidationSubIndication basicSubIndication = basic.Conclusion.SubIndications.Count > 0
            ? basic.Conclusion.SubIndications[0]
            : SignatureValidationSubIndication.Custom;
        if(!ContinuesAfterBasicValidation(basic.Conclusion.Indication, basicSubIndication))
        {
            return new SignatureWithTimeValidationResult
            {
                Conclusion = basic.Conclusion,
                BestSignatureTime = bestSignatureTime,
                BasicValidation = basic
            };
        }

        SignatureValidationConstraints constraints = basic.Constraints ?? inputs.Constraints;
        IReadOnlyList<EmbeddedTimestamp> signatureTimestamps = basic.Signature.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp);

        //Step 3)a): the message imprint of every signature time-stamp token has to have been generated over the
        //octets the format specification binds it to; a token that does not bind them leaves the set.
        List<EmbeddedTimestamp> accepted = [];
        for(int i = 0; i < signatureTimestamps.Count; ++i)
        {
            if(basic.Signature.SignatureValue is not SignedContentMemory signatureValue)
            {
                //Without the octets a signature time-stamp binds, no token can be shown to bind them, which is
                //the verification failure step 3)a) removes a token on.
                break;
            }

            bool binds = await TimestampValidation.VerifyMessageImprintAsync(
                signatureTimestamps[i].Token, signatureValue.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
            if(binds)
            {
                accepted.Add(signatureTimestamps[i]);
            }
        }

        //Step 3)b): every remaining token is validated per clause 5.4, and a token that validates lowers
        //best-signature-time to its generation time.
        List<TimestampValidationResult> tokenValidations = [];
        List<EmbeddedTimestamp> remaining = [];
        List<TimestampOrderFacts> remainingFacts = [];
        for(int i = 0; i < accepted.Count; ++i)
        {
            TimestampValidationResult tokenValidation = await TimestampValidation.ValidateAsync(
                accepted[i].Token, inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);
            tokenValidations.Add(tokenValidation);

            if(tokenValidation.Conclusion.Indication == BuildingBlockIndication.Passed
                && tokenValidation.GenerationTime is DateTimeOffset generationTime)
            {
                if(generationTime < bestSignatureTime)
                {
                    bestSignatureTime = generationTime;
                }

                remaining.Add(accepted[i]);
                remainingFacts.Add(new TimestampOrderFacts(
                    accepted[i].Token, generationTime, tokenValidation.Accuracy ?? TimeSpan.Zero, tokenValidation.IsOrdered, tokenValidation.TimestampAuthorityName));

                continue;
            }

            if(constraints.SignatureElements.RequireSignatureTimestampValidity)
            {
                //"Otherwise, the process shall return the indication/sub-indication and associated explanations
                //returned from the Time-stamp token validation process."
                return new SignatureWithTimeValidationResult
                {
                    Conclusion = tokenValidation.Conclusion,
                    BestSignatureTime = bestSignatureTime,
                    BasicValidation = basic,
                    SignatureTimestampValidations = tokenValidations,
                    AcceptedSignatureTimestamps = remaining
                };
            }
        }

        //Best-signature-time is final once step 3) has run, so every outcome from here on differs only in its
        //conclusion and the shared part is built once.
        var outcome = new SignatureWithTimeValidationResult
        {
            Conclusion = basic.Conclusion,
            BestSignatureTime = bestSignatureTime,
            BasicValidation = basic,
            SignatureTimestampValidations = tokenValidations,
            AcceptedSignatureTimestamps = remaining
        };

        //Step 4): comparing times. The validity window of the signing certificate is what steps 4)a), 4)b) and
        //4)d) compare best-signature-time against.
        CertificateValidityWindow? window = TryReadValidityWindow(basic.SigningCertificate);
        bool performsCoherenceCheck = false;

        if(basic.Conclusion.Indication == BuildingBlockIndication.Indeterminate
            && (basicSubIndication.Equals(SignatureValidationSubIndication.RevokedNoProofOfExistence)
                || basicSubIndication.Equals(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence)))
        {
            //Step 4)a).
            if(basic.RevocationTime is DateTimeOffset revocationTime && revocationTime > bestSignatureTime)
            {
                if(window is CertificateValidityWindow validity && bestSignatureTime < validity.NotBefore)
                {
                    return WithConclusion(outcome, BuildingBlockConclusion.Failed(SignatureValidationSubIndication.NotYetValid, basic.Conclusion.ReportData));
                }

                if(window is CertificateValidityWindow expiry && bestSignatureTime < expiry.NotAfter)
                {
                    performsCoherenceCheck = true;
                }
                else
                {
                    return WithConclusion(outcome, BuildingBlockConclusion.Indeterminate(
                        SignatureValidationSubIndication.OutOfBoundsNotRevoked, basic.Conclusion.ReportData));
                }
            }
            else
            {
                return WithConclusion(outcome, basic.Conclusion);
            }
        }
        else if(basic.Conclusion.Indication == BuildingBlockIndication.Passed
            || basicSubIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence))
        {
            //Step 4)b).
            if(window is CertificateValidityWindow validity && bestSignatureTime < validity.NotBefore)
            {
                return WithConclusion(outcome, BuildingBlockConclusion.Failed(SignatureValidationSubIndication.NotYetValid, basic.Conclusion.ReportData));
            }

            if(basic.Conclusion.Indication == BuildingBlockIndication.Passed)
            {
                performsCoherenceCheck = true;
            }
            else
            {
                return WithConclusion(outcome, basic.Conclusion);
            }
        }
        else if(basicSubIndication.Equals(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence)
            && basic.CryptographicFailureConcernsSignatureMaterial)
        {
            //Step 4)c): the algorithms have to have been still considered reliable at best-signature-time.
            IReadOnlyList<AlgorithmReliabilityAssessment> stillUnreliable =
                constraints.Cryptographic.FindUnreliable(SelectUses(basic.UnreliableAlgorithms), bestSignatureTime);
            if(stillUnreliable.Count > 0)
            {
                return WithConclusion(outcome, BuildingBlockConclusion.Indeterminate(
                    SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence,
                    [new CryptographicConstraintsFailureReportData(stillUnreliable)]));
            }

            performsCoherenceCheck = true;
        }
        else if(basicSubIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNotRevoked))
        {
            //Step 4)d).
            if(window is CertificateValidityWindow validity && bestSignatureTime < validity.NotBefore)
            {
                return WithConclusion(outcome, BuildingBlockConclusion.Failed(SignatureValidationSubIndication.NotYetValid, basic.Conclusion.ReportData));
            }

            if(window is CertificateValidityWindow expiry && bestSignatureTime < expiry.NotAfter)
            {
                performsCoherenceCheck = true;
            }
            else
            {
                return WithConclusion(outcome, BuildingBlockConclusion.Indeterminate(
                    SignatureValidationSubIndication.OutOfBoundsNotRevoked, basic.Conclusion.ReportData));
            }
        }

        //Step 4)e): the coherence of the times the remaining tokens indicate, performed only where one of the
        //branches above asked for it. A TRY_LATER status matches no branch and continues at step 5).
        if(performsCoherenceCheck)
        {
            IReadOnlyList<PkiCertificateMemory> incoherent = await FindIncoherentTimestampsAsync(
                basic.Signature, remainingFacts, pool, cancellationToken).ConfigureAwait(false);
            if(incoherent.Count > 0)
            {
                return WithConclusion(outcome, BuildingBlockConclusion.Indeterminate(
                    SignatureValidationSubIndication.TimestampOrderFailure, [new TimestampOrderFailureReportData(incoherent)]));
            }
        }

        //Step 5): the time-stamp delay constraint. The step is conditioned on what the signature contains — "if
        //the signature contains a signature time-stamp token" — not on which tokens survived step 3), exactly as
        //step 8) of clause 5.6.3.4 words the same check.
        if(signatureTimestamps.Count > 0 && constraints.SignatureElements.TimestampDelay is TimeSpan timestampDelay)
        {
            if(basic.ClaimedSigningTime is not DateTimeOffset claimedSigningTime)
            {
                return WithConclusion(outcome, SignatureConstraintsFailure(ValidationConstraintIdentifier.TimestampDelay,
                    "The validation constraints specify a time-stamp delay and the signature carries no signing-time attribute."));
            }

            if(claimedSigningTime + timestampDelay <= bestSignatureTime)
            {
                return WithConclusion(outcome, SignatureConstraintsFailure(ValidationConstraintIdentifier.TimestampDelay,
                    "The claimed signing time plus the time-stamp delay is not after best-signature-time."));
            }
        }

        //Step 6): TRY_LATER because the revocation status information was not fresh enough is re-checked against
        //best-signature-time.
        if(basicSubIndication.Equals(SignatureValidationSubIndication.TryLater)
            && basic.TryLaterReason == RevocationTryLaterReason.RevocationStatusNotFresh
            && basic.DecisiveRevocationStatusInformation is RevocationStatusInformation notFresh)
        {
            RevocationFreshnessResult freshness = await RevocationFreshnessChecker.CheckAsync(
                notFresh, notFresh.SubjectCertificate, bestSignatureTime, constraints.X509, cancellationToken).ConfigureAwait(false);
            if(freshness.Conclusion.Indication != BuildingBlockIndication.Passed)
            {
                return WithConclusion(outcome, BuildingBlockConclusion.Indeterminate(
                    SignatureValidationSubIndication.TryLater,
                    [new TryLaterReportData(notFresh.NextUpdate, basic.CertificateChain, [notFresh.RevocationData])]));
            }
        }

        //Step 7): TRY_LATER because the certificate has been found to be suspended.
        if(basicSubIndication.Equals(SignatureValidationSubIndication.TryLater)
            && basic.TryLaterReason == RevocationTryLaterReason.CertificateSuspended
            && !(basic.RevocationTime is DateTimeOffset suspensionTime && bestSignatureTime < suspensionTime))
        {
            return WithConclusion(outcome, BuildingBlockConclusion.Indeterminate(
                SignatureValidationSubIndication.TryLater,
                [new TryLaterReportData(basic.DecisiveRevocationStatusInformation?.NextUpdate, basic.CertificateChain, [])]));
        }

        //Step 8): the signature acceptance validation is repeated with best-signature-time as validation time.
        //The step lists exactly three inputs — the Signed Data Object(s), best-signature-time and the
        //cryptographic constraints — and NOTE 6 states that "signature elements constraints have already been
        //dealt with in step 2) and need not be rechecked", so the element rules and the time-stamp validation
        //seam they would drive are not passed again.
        SignatureAcceptanceValidationResult acceptance = await SignatureAcceptanceValidation.ValidateAsync(
            basic.Signature,
            basic.CertificateChain,
            SignatureElementsConstraints.None,
            constraints.Cryptographic,
            validateTimestampToken: null,
            bestSignatureTime,
            pool,
            cancellationToken).ConfigureAwait(false);

        //Step 9).
        if(acceptance.Conclusion.Indication != BuildingBlockIndication.Passed)
        {
            return WithConclusion(outcome, acceptance.Conclusion);
        }

        //Step 10): the cryptographic constraints are applied at the current time to every certificate and every
        //instance of revocation status information the validation used, because best-signature-time is not in
        //general a proof of existence for them (NOTE 7).
        IReadOnlyList<AlgorithmReliabilityAssessment> unreliableAtCurrentTime = constraints.Cryptographic.FindUnreliable(
            ValidationMaterialUses(basic), currentTime);
        if(unreliableAtCurrentTime.Count > 0)
        {
            return WithConclusion(outcome, BuildingBlockConclusion.Indeterminate(
                SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence,
                [new CryptographicConstraintsFailureReportData(unreliableAtCurrentTime)]));
        }

        //Step 11).
        return WithConclusion(outcome, BuildingBlockConclusion.PassedWith(basic.Conclusion.ReportData));
    }


    /// <summary>
    /// Restates one outcome with another conclusion, so every step of clause 5.5.4 reports the same
    /// best-signature-time, Basic Signature validation result and time-stamp intermediate results and differs
    /// only in what it concluded.
    /// </summary>
    /// <param name="outcome">The shared part of the outcome.</param>
    /// <param name="conclusion">The conclusion the step reached.</param>
    /// <returns>The outcome.</returns>
    private static SignatureWithTimeValidationResult WithConclusion(SignatureWithTimeValidationResult outcome, BuildingBlockConclusion conclusion) =>
        outcome with { Conclusion = conclusion };


    /// <summary>
    /// Decides whether step 2) of clause 5.5.4 continues the process: it does for <c>PASSED</c> and for the six
    /// <c>INDETERMINATE</c> sub-indications the clause enumerates, whose NOTES 2 to 5 each explain what a proof
    /// of existence could still settle.
    /// </summary>
    /// <param name="indication">The indication the validation process for Basic Signatures returned.</param>
    /// <param name="subIndication">The sub-indication it returned.</param>
    /// <returns><see langword="true"/> when the process continues with step 3).</returns>
    private static bool ContinuesAfterBasicValidation(BuildingBlockIndication indication, SignatureValidationSubIndication subIndication) =>
        indication switch
        {
            BuildingBlockIndication.Passed => true,
            BuildingBlockIndication.Indeterminate =>
                subIndication.Equals(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence)
                || subIndication.Equals(SignatureValidationSubIndication.RevokedNoProofOfExistence)
                || subIndication.Equals(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence)
                || subIndication.Equals(SignatureValidationSubIndication.TryLater)
                || subIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence)
                || subIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNotRevoked),
            _ => false
        };


    /// <summary>
    /// Finds the signature time-stamp tokens whose indicated times are not coherent — the check of step 4)e) of
    /// clause 5.5.4: they have to be posterior to the times indicated in any time-stamp token computed on the
    /// signed data, applying the ordering rules of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3161">RFC 3161</see> §2.4.2 given the <c>accuracy</c> and
    /// <c>ordering</c> fields.
    /// </summary>
    /// <param name="signature">The signature's facts, holding the content time-stamps to compare against.</param>
    /// <param name="signatureTimestamps">The facts of the signature time-stamp tokens remaining in the set.</param>
    /// <param name="pool">The memory pool the token reads rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The tokens that violate the ordering constraints; empty when every check ends successfully.</returns>
    private static async ValueTask<IReadOnlyList<PkiCertificateMemory>> FindIncoherentTimestampsAsync(
        SignatureFacts signature,
        IReadOnlyList<TimestampOrderFacts> signatureTimestamps,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<EmbeddedTimestamp> contentTimestamps = signature.TimestampsOfClass(SignatureTimestampClass.ContentTimestamp);
        List<TimestampOrderFacts> contentFacts = [];
        for(int i = 0; i < contentTimestamps.Count; ++i)
        {
            TimestampOrderFacts? facts = await ReadOrderFactsAsync(contentTimestamps[i].Token, pool, cancellationToken).ConfigureAwait(false);
            if(facts is not null)
            {
                contentFacts.Add(facts);
            }
        }

        List<PkiCertificateMemory> incoherent = [];
        for(int i = 0; i < signatureTimestamps.Count; ++i)
        {
            for(int c = 0; c < contentFacts.Count; ++c)
            {
                if(!IsPosterior(signatureTimestamps[i], contentFacts[c]))
                {
                    incoherent.Add(signatureTimestamps[i].Token);

                    break;
                }
            }
        }

        return incoherent;
    }


    /// <summary>
    /// Reads the ordering-relevant fields of one time-stamp token.
    /// </summary>
    /// <param name="token">The DER-encoded time-stamp token.</param>
    /// <param name="pool">The memory pool the read rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The facts, or <see langword="null"/> when the token cannot be opened or read.</returns>
    private static async ValueTask<TimestampOrderFacts?> ReadOrderFactsAsync(
        PkiCertificateMemory token,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        try
        {
            using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(token, pool, cancellationToken).ConfigureAwait(false);

            return info.IsRead
                ? new TimestampOrderFacts(token, info.GenerationTime, info.Accuracy ?? TimeSpan.Zero, info.IsOrdered, info.TimestampAuthorityName)
                : null;
        }
        catch(InvalidOperationException)
        {
            //No CMS verification seam is registered, so the token indicates no time this check can compare.
            return null;
        }
    }


    /// <summary>
    /// Decides whether one time-stamp token's indicated time is posterior to another's under the rules of
    /// <see href="https://www.rfc-editor.org/rfc/rfc3161">RFC 3161</see> §2.4.2: two tokens from the same
    /// Time-Stamping Authority whose <c>ordering</c> field is set can always be ordered on <c>genTime</c> alone,
    /// and every other pair only when the generation times are further apart than the sum of their accuracies.
    /// </summary>
    /// <param name="later">The token asserted to be the later one.</param>
    /// <param name="earlier">The token asserted to be the earlier one.</param>
    /// <returns><see langword="true"/> when the ordering is asserted by the rules.</returns>
    private static bool IsPosterior(TimestampOrderFacts later, TimestampOrderFacts earlier)
    {
        bool sameAuthority = later.AuthorityName is not null
            && earlier.AuthorityName is not null
            && string.Equals(later.AuthorityName, earlier.AuthorityName, StringComparison.Ordinal);

        //The generation times and accuracies come out of attacker-reachable DER, where a genTime reaching the
        //year 9999 and an accuracy of decades are both legal encodings, so the arithmetic saturates instead of
        //leaving the representable range.
        return sameAuthority && later.IsOrdered
            ? later.GenerationTime > earlier.GenerationTime
            : PkiInstantArithmetic.SubtractSaturating(later.GenerationTime, later.Accuracy)
                > PkiInstantArithmetic.AddSaturating(earlier.GenerationTime, earlier.Accuracy);
    }


    /// <summary>
    /// Reads the validity window of the signing certificate, which steps 4)a), 4)b) and 4)d) of clause 5.5.4
    /// compare best-signature-time against.
    /// </summary>
    /// <param name="certificate">The signing certificate, or <see langword="null"/> when none was identified.</param>
    /// <returns>The window, or <see langword="null"/> when there is no certificate or it does not parse.</returns>
    private static CertificateValidityWindow? TryReadValidityWindow(PkiCertificateMemory? certificate)
    {
        if(certificate is null)
        {
            return null;
        }

        try
        {
            ManagedCertificate parsed = ManagedCertificate.Parse(certificate.AsReadOnlyMemory());

            return new CertificateValidityWindow(parsed.NotBefore, parsed.NotAfter);
        }
        catch(AsnContentException)
        {
            //A certificate whose validity dates cannot be read supports none of the comparisons of step 4), and
            //every branch that needs one therefore takes the branch that asserts nothing.
            return null;
        }
    }


    /// <summary>
    /// Selects the algorithm uses out of a set of assessments, so the same uses can be re-assessed at another
    /// instant.
    /// </summary>
    /// <param name="assessments">The assessments to take the uses from.</param>
    /// <returns>The uses, in the order the assessments name them.</returns>
    private static List<AlgorithmUse> SelectUses(IReadOnlyList<AlgorithmReliabilityAssessment> assessments)
    {
        List<AlgorithmUse> uses = [];
        for(int i = 0; i < assessments.Count; ++i)
        {
            uses.Add(assessments[i].Use);
        }

        return uses;
    }


    /// <summary>
    /// Builds the algorithm uses of "all the certificates and revocation status information used in the
    /// validation process" that step 10) of clause 5.5.4 assesses against the current time.
    /// </summary>
    /// <param name="basic">The Basic Signature validation result naming the material the run used.</param>
    /// <returns>One use per certificate of the chain, plus one per instance of revocation status information whose signature algorithm the caller's checker stated.</returns>
    private static List<AlgorithmUse> ValidationMaterialUses(BasicSignatureValidationResult basic)
    {
        List<AlgorithmUse> uses = [.. X509CertificateValidation.CertificateChainAlgorithmUses(basic.CertificateChain)];
        for(int i = 0; i < basic.RevocationStatusInformationUsed.Count; ++i)
        {
            RevocationStatusInformation information = basic.RevocationStatusInformationUsed[i];
            if(information.SignatureAlgorithm is AlgorithmIdentifier algorithm)
            {
                uses.Add(new AlgorithmUse(algorithm, information.SignatureKeySizeBits, "revocation status information"));
            }
        }

        return uses;
    }


    /// <summary>
    /// Builds the <c>SIG_CONSTRAINTS_FAILURE</c> outcome of steps 5)a) and 5)b) of clause 5.5.4, reporting the
    /// constraint that was not met.
    /// </summary>
    /// <param name="identifier">The constraint that was not met.</param>
    /// <param name="description">What was not met about it.</param>
    /// <returns>The conclusion.</returns>
    private static BuildingBlockConclusion SignatureConstraintsFailure(ValidationConstraintIdentifier identifier, string description)
    {
        var evaluation = new ValidationConstraintEvaluation(identifier, BuildingBlockIndication.Failed, description);

        return new BuildingBlockConclusion
        {
            Indication = BuildingBlockIndication.Indeterminate,
            SubIndications = [SignatureValidationSubIndication.SignatureConstraintsFailure],
            ReportData = [new UnsatisfiedSignatureConstraintsReportData([evaluation])],
            ConstraintEvaluations = [evaluation]
        };
    }


    /// <summary>The validity window of a certificate, as steps 4)a), 4)b) and 4)d) of clause 5.5.4 read it.</summary>
    /// <param name="NotBefore">The issuance date.</param>
    /// <param name="NotAfter">The expiration date.</param>
    private readonly record struct CertificateValidityWindow(DateTimeOffset NotBefore, DateTimeOffset NotAfter);


    /// <summary>The fields of a time-stamp token the ordering rules of RFC 3161 §2.4.2 turn on.</summary>
    /// <param name="Token">A non-owning reference to the token itself, for the report of a <c>TIMESTAMP_ORDER_FAILURE</c>.</param>
    /// <param name="GenerationTime">The token's <c>genTime</c>.</param>
    /// <param name="Accuracy">The token's <c>accuracy</c>, or <see cref="TimeSpan.Zero"/> when it states none.</param>
    /// <param name="IsOrdered">The token's <c>ordering</c> field.</param>
    /// <param name="AuthorityName">The token's <c>tsa</c> name hint, or <see langword="null"/> when it states none.</param>
    private sealed record TimestampOrderFacts(
        PkiCertificateMemory Token,
        DateTimeOffset GenerationTime,
        TimeSpan Accuracy,
        bool IsOrdered,
        string? AuthorityName);


    /// <summary>
    /// The per-run context the clause 5.4 time-stamp validation seam is bound to, so the delegate the building
    /// blocks receive carries the run's inputs as an object rather than as a lambda closure.
    /// </summary>
    /// <param name="inputs">The run's inputs.</param>
    /// <param name="seams">The run's seams.</param>
    /// <param name="resources">The run's resource ledger.</param>
    /// <param name="currentTime">The current time the run was given.</param>
    private sealed class TimestampSeamContext(
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        SignatureValidationResources resources,
        DateTimeOffset currentTime)
    {
        /// <summary>
        /// Validates one time-stamp token per clause 5.4 — the implementation of
        /// <see cref="ValidateTimestampTokenAsyncDelegate"/> the building blocks of clause 5.2 compose.
        /// </summary>
        /// <param name="context">The token and the instant to validate it at.</param>
        /// <param name="pool">The memory pool the run rents from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>What the time-stamp validation building block concluded.</returns>
        public async ValueTask<BuildingBlockConclusion> ValidateAsync(
            TimestampTokenValidationContext context,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            TimestampValidationResult result = await TimestampValidation.ValidateAsync(
                context.Token, inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

            return result.Conclusion;
        }
    }
}
