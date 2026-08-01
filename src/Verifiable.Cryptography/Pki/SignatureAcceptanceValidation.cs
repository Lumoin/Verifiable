using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the signature acceptance validation building block concluded — the outputs of Table 17 of clause
/// 5.2.8.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
[DebuggerDisplay("SignatureAcceptanceValidationResult: {Conclusion.Indication}")]
public sealed record SignatureAcceptanceValidationResult
{
    /// <summary>The block's conclusion.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>
    /// The claimed signing time the signature declares, which clause 5.2.8.4.2.2 requires the SVA to "make
    /// available to the DA" when the signature elements constraints state no rule about it;
    /// <see langword="null"/> when the signature declares none.
    /// </summary>
    public DateTimeOffset? ClaimedSigningTime { get; init; }
}


/// <summary>
/// The signature acceptance validation building block of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.2.8</see>: the additional verification performed on the signature itself
/// and on its attributes, against the signature elements constraints and the cryptographic constraints.
/// </summary>
/// <remarks>
/// <para>
/// The clause's general requirements (5.2.8.4.1) are implemented literally: a constraint that necessitates
/// processing an attribute processes it per the corresponding sub-clause; an attribute that is present but
/// malformed counts as absent; an algorithm the cryptographic constraints do not consider reliable at the
/// validation time yields <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c>; any other failed check yields
/// <c>SIG_CONSTRAINTS_FAILURE</c> together with the set of constraints that were not satisfied; and a signature
/// that satisfies every constraint yields <c>PASSED</c>.
/// </para>
/// <para>
/// The attribute rules implemented here are the presence and absence rules of clause 5.2.8.4.1, the signing
/// certificate reference constraint of clause 5.2.8.4.2.1, the claimed signing time of clause 5.2.8.4.2.2 and
/// the time-stamps on Signed Data Objects of clause 5.2.8.4.2.5. Clause 5.2.8.4.2.3 (Signed Data Object format),
/// 5.2.8.4.2.4 (production place), 5.2.8.4.2.6 (countersignatures) and 5.2.8.4.2.7 (signer attributes) each
/// begin with "if the signature elements constraints contain constraints regarding this property"; where the
/// constraints record states no such rule, the clause's own other branch applies — the value is surfaced to the
/// Driving Application through the signature's facts and nothing is checked — and clause 5.2.8.4.2.6 states
/// outright that without a constraint a countersignature that fails must not fail the signature. Their presence
/// is still reportable through the mandated- and forbidden-attribute rules.
/// </para>
/// </remarks>
public static class SignatureAcceptanceValidation
{
    /// <summary>
    /// Applies the signature elements constraints and the cryptographic constraints to a signature.
    /// </summary>
    /// <param name="signature">Table 16's mandatory "Signature" input, in the form the engine holds it.</param>
    /// <param name="certificateChain">Table 16's optional "Certificate Chain" input, which clause 5.2.8.4.2.1 checks the signing certificate references against; empty when no chain was validated.</param>
    /// <param name="signatureElementsConstraints">Table 16's optional "Signature Elements Constraints" input.</param>
    /// <param name="cryptographicConstraints">Table 16's optional "Cryptographic Constraints" input.</param>
    /// <param name="validateTimestampToken">The clause 5.4 time-stamp validation step 1) of clause 5.2.8.4.2.5 composes, or <see langword="null"/> when the caller configures none.</param>
    /// <param name="validationTime">Table 16's optional "Validation time" input, at which the cryptographic constraints are assessed. Mandatory here so nothing reads an ambient clock.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of Table 17, and the claimed signing time for the Driving Application.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<SignatureAcceptanceValidationResult> ValidateAsync(
        SignatureFacts signature,
        IReadOnlyList<PkiCertificateMemory> certificateChain,
        SignatureElementsConstraints signatureElementsConstraints,
        CryptographicConstraints cryptographicConstraints,
        ValidateTimestampTokenAsyncDelegate? validateTimestampToken,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(certificateChain);
        ArgumentNullException.ThrowIfNull(signatureElementsConstraints);
        ArgumentNullException.ThrowIfNull(cryptographicConstraints);
        ArgumentNullException.ThrowIfNull(pool);

        List<ValidationConstraintEvaluation> unsatisfied = [];

        CheckMandatedAndForbiddenAttributes(signature, signatureElementsConstraints, unsatisfied);
        CheckClaimedSigningTime(signature, signatureElementsConstraints, unsatisfied);
        await CheckSigningCertificateReferencesAsync(
            signature, certificateChain, signatureElementsConstraints, unsatisfied, pool, cancellationToken).ConfigureAwait(false);
        await CheckContentTimestampsAsync(
            signature, signatureElementsConstraints, validateTimestampToken, validationTime, unsatisfied, pool, cancellationToken).ConfigureAwait(false);

        //Clause 5.2.8.4.1, second bullet: an unreliable algorithm or key size is reported on its own, with the
        //list of algorithms and the time up to which each was considered secure.
        IReadOnlyList<AlgorithmReliabilityAssessment> unreliable =
            cryptographicConstraints.FindUnreliable(signature.AlgorithmUses, validationTime);
        if(unreliable.Count > 0)
        {
            return new SignatureAcceptanceValidationResult
            {
                Conclusion = BuildingBlockConclusion.Indeterminate(
                    SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence,
                    [new CryptographicConstraintsFailureReportData(unreliable)]),
                ClaimedSigningTime = signature.ClaimedSigningTime
            };
        }

        //Clause 5.2.8.4.1, third and fourth bullets.
        BuildingBlockConclusion conclusion = unsatisfied.Count > 0
            ? new BuildingBlockConclusion
            {
                Indication = BuildingBlockIndication.Indeterminate,
                SubIndications = [SignatureValidationSubIndication.SignatureConstraintsFailure],
                ReportData = [new UnsatisfiedSignatureConstraintsReportData(unsatisfied)],
                ConstraintEvaluations = unsatisfied
            }
            : BuildingBlockConclusion.Passed;

        return new SignatureAcceptanceValidationResult
        {
            Conclusion = conclusion,
            ClaimedSigningTime = signature.ClaimedSigningTime
        };
    }


    /// <summary>
    /// Applies the mandated and forbidden signed attribute constraints, treating an attribute that is present
    /// but malformed as absent per clause 5.2.8.4.1's first bullet.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="constraints">The signature elements constraints.</param>
    /// <param name="unsatisfied">The list unmet constraints are appended to.</param>
    private static void CheckMandatedAndForbiddenAttributes(
        SignatureFacts signature,
        SignatureElementsConstraints constraints,
        List<ValidationConstraintEvaluation> unsatisfied)
    {
        for(int i = 0; i < constraints.MandatedSignedAttributeOids.Count; ++i)
        {
            string identifier = constraints.MandatedSignedAttributeOids[i];
            if(!IsPresentAndWellFormed(signature, identifier))
            {
                unsatisfied.Add(new ValidationConstraintEvaluation(
                    ValidationConstraintIdentifier.MandatedSignedAttributes,
                    BuildingBlockIndication.Failed,
                    $"The signature does not carry a well-formed signed attribute '{identifier}'."));
            }
        }

        for(int i = 0; i < constraints.ForbiddenSignedAttributeOids.Count; ++i)
        {
            string identifier = constraints.ForbiddenSignedAttributeOids[i];
            if(IsPresentAndWellFormed(signature, identifier))
            {
                unsatisfied.Add(new ValidationConstraintEvaluation(
                    ValidationConstraintIdentifier.ForbiddenSignedAttributes,
                    BuildingBlockIndication.Failed,
                    $"The signature carries the forbidden signed attribute '{identifier}'."));
            }
        }
    }


    /// <summary>
    /// Reports whether a signed attribute of a given identity is present and decoded.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="identifier">The attribute's identity in the format's own vocabulary.</param>
    /// <returns><see langword="true"/> when a signed attribute with that identity is present and well-formed.</returns>
    private static bool IsPresentAndWellFormed(SignatureFacts signature, string identifier)
    {
        for(int i = 0; i < signature.Attributes.Count; ++i)
        {
            SignatureAttributeFacts attribute = signature.Attributes[i];
            if(attribute.Scope == SignatureAttributeScope.Signed
                && attribute.IsWellFormed
                && string.Equals(attribute.Identifier, identifier, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Applies the claimed signing time rules of clause 5.2.8.4.2.2, when the constraints state any.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="constraints">The signature elements constraints.</param>
    /// <param name="unsatisfied">The list unmet constraints are appended to.</param>
    private static void CheckClaimedSigningTime(
        SignatureFacts signature,
        SignatureElementsConstraints constraints,
        List<ValidationConstraintEvaluation> unsatisfied)
    {
        bool hasRule = constraints.EarliestAcceptedClaimedSigningTime is not null
            || constraints.LatestAcceptedClaimedSigningTime is not null;
        if(!hasRule)
        {
            //The clause's other branch: the value is made available to the Driving Application and not checked.
            return;
        }

        if(signature.ClaimedSigningTime is not DateTimeOffset claimed)
        {
            unsatisfied.Add(new ValidationConstraintEvaluation(
                ValidationConstraintIdentifier.MandatedSignedAttributes,
                BuildingBlockIndication.Failed,
                "The constraints state a rule for the claimed signing time, which the signature does not carry."));

            return;
        }

        bool tooEarly = constraints.EarliestAcceptedClaimedSigningTime is DateTimeOffset earliest && claimed < earliest;
        bool tooLate = constraints.LatestAcceptedClaimedSigningTime is DateTimeOffset latest && claimed > latest;
        if(tooEarly || tooLate)
        {
            unsatisfied.Add(new ValidationConstraintEvaluation(
                ValidationConstraintIdentifier.MandatedSignedAttributes,
                BuildingBlockIndication.Failed,
                "The claimed signing time lies outside the window the constraints accept."));
        }
    }


    /// <summary>
    /// Applies the signing certificate reference constraint of clause 5.2.8.4.2.1: every reference has to name a
    /// certificate of the certification path, and — when the policy mandates it — every certificate of the path
    /// has to be referenced.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="certificateChain">The certification path.</param>
    /// <param name="constraints">The signature elements constraints.</param>
    /// <param name="unsatisfied">The list unmet constraints are appended to.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask CheckSigningCertificateReferencesAsync(
        SignatureFacts signature,
        IReadOnlyList<PkiCertificateMemory> certificateChain,
        SignatureElementsConstraints constraints,
        List<ValidationConstraintEvaluation> unsatisfied,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(signature.SigningCertificateReferences.Count == 0)
        {
            if(constraints.RequireSignedSigningCertificateBinding)
            {
                unsatisfied.Add(new ValidationConstraintEvaluation(
                    ValidationConstraintIdentifier.SigningCertificateReferences,
                    BuildingBlockIndication.Failed,
                    "The constraints require a signed binding of the signing certificate, and the signature carries none."));
            }

            return;
        }

        if(certificateChain.Count == 0)
        {
            return;
        }

        bool[] chainReferenced = new bool[certificateChain.Count];
        for(int r = 0; r < signature.SigningCertificateReferences.Count; ++r)
        {
            SigningCertificateReference reference = signature.SigningCertificateReferences[r];
            bool referencesPathCertificate = false;
            for(int c = 0; c < certificateChain.Count; ++c)
            {
                bool matches;
                try
                {
                    matches = await MatchesAsync(reference, certificateChain[c], pool, cancellationToken).ConfigureAwait(false);
                }
                catch(InvalidOperationException)
                {
                    //Without a registered digest seam no reference can be checked against the path, so nothing
                    //establishes that the references are the path's — which is the failure this clause reports.
                    matches = false;
                }

                if(matches)
                {
                    referencesPathCertificate = true;
                    chainReferenced[c] = true;

                    break;
                }
            }

            if(!referencesPathCertificate)
            {
                unsatisfied.Add(new ValidationConstraintEvaluation(
                    ValidationConstraintIdentifier.SigningCertificateReferences,
                    BuildingBlockIndication.Failed,
                    "The signing certificate identifier attribute references a certificate that is not in the certification path."));
            }
        }

        if(!constraints.RequireSigningCertificateReferencesForFullPath)
        {
            return;
        }

        for(int c = 0; c < chainReferenced.Length; ++c)
        {
            if(!chainReferenced[c])
            {
                unsatisfied.Add(new ValidationConstraintEvaluation(
                    ValidationConstraintIdentifier.SigningCertificateReferences,
                    BuildingBlockIndication.Failed,
                    "The signature policy mandates references to all the certificates in the certification path, and one is not referenced."));

                return;
            }
        }
    }


    /// <summary>
    /// Applies the constraints on time-stamps on Signed Data Objects of clause 5.2.8.4.2.5: each content
    /// time-stamp is validated per clause 5.4 and its message imprint is checked against the signed data.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="constraints">The signature elements constraints.</param>
    /// <param name="validateTimestampToken">The clause 5.4 validation seam of step 1), or <see langword="null"/>.</param>
    /// <param name="validationTime">The instant the tokens are validated at.</param>
    /// <param name="unsatisfied">The list unmet constraints are appended to.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask CheckContentTimestampsAsync(
        SignatureFacts signature,
        SignatureElementsConstraints constraints,
        ValidateTimestampTokenAsyncDelegate? validateTimestampToken,
        DateTimeOffset validationTime,
        List<ValidationConstraintEvaluation> unsatisfied,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(!constraints.RequireContentTimestampValidity)
        {
            //The clause conditions the whole check on the constraints containing specific constraints for
            //time-stamps on Signed Data Objects.
            return;
        }

        IReadOnlyList<EmbeddedTimestamp> contentTimestamps = signature.TimestampsOfClass(SignatureTimestampClass.ContentTimestamp);
        for(int i = 0; i < contentTimestamps.Count; ++i)
        {
            EmbeddedTimestamp timestamp = contentTimestamps[i];

            //Step 1): the validation process for AdES time-stamps.
            if(validateTimestampToken is not null)
            {
                BuildingBlockConclusion tokenConclusion;
                try
                {
                    tokenConclusion = await validateTimestampToken(
                        new TimestampTokenValidationContext { Token = timestamp.Token, ValidationTime = validationTime },
                        pool,
                        cancellationToken).ConfigureAwait(false);
                }
                catch(Exception exception) when(exception is not OperationCanceledException)
                {
                    tokenConclusion = BuildingBlockConclusion.Indeterminate(
                        SignatureValidationSubIndication.Custom, [new CustomDiagnosticReportData(exception.Message)]);
                }

                if(tokenConclusion.Indication != BuildingBlockIndication.Passed)
                {
                    unsatisfied.Add(new ValidationConstraintEvaluation(
                        ValidationConstraintIdentifier.ContentTimestampValidity,
                        BuildingBlockIndication.Failed,
                        "A content time-stamp attribute did not validate as a time-stamp."));

                    continue;
                }
            }

            //Step 2): the message imprint over the signed data.
            if(signature.SignedContent is not SignedContentMemory content)
            {
                unsatisfied.Add(new ValidationConstraintEvaluation(
                    ValidationConstraintIdentifier.ContentTimestampValidity,
                    BuildingBlockIndication.Failed,
                    "A content time-stamp attribute is present but the signed data it would bind is not available."));

                continue;
            }

            using TimestampTokenInfo info = await TimestampTokenInfo.ReadFromTokenAsync(timestamp.Token, pool, cancellationToken).ConfigureAwait(false);
            bool binds = info.IsRead
                && await info.VerifyMessageImprintAsync(content.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
            if(!binds)
            {
                unsatisfied.Add(new ValidationConstraintEvaluation(
                    ValidationConstraintIdentifier.ContentTimestampValidity,
                    BuildingBlockIndication.Failed,
                    "A content time-stamp attribute's message imprint does not bind the signed data."));
            }
        }
    }


    /// <summary>
    /// Checks whether one signing certificate reference's hash is the digest of a certificate.
    /// </summary>
    /// <param name="reference">The reference.</param>
    /// <param name="certificate">The certificate.</param>
    /// <param name="pool">The memory pool the computed digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> only when the digests are equal.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no <see cref="ComputeDigestDelegate"/> has been registered.</exception>
    private static async ValueTask<bool> MatchesAsync(
        SigningCertificateReference reference,
        PkiCertificateMemory certificate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(reference.CertificateDigest is null)
        {
            return false;
        }

        PkiDigestAlgorithm? algorithm = PkiDigestAlgorithm.FromOid(reference.DigestAlgorithm.Oid);
        if(algorithm is null)
        {
            return false;
        }

        using DigestValue computed = await CryptographicKeyEvents.ComputeDigestAsync(
            certificate.AsReadOnlyMemory(), algorithm.Value.OutputByteLength, algorithm.Value.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return computed.AsReadOnlySpan().SequenceEqual(reference.CertificateDigest.AsReadOnlySpan());
    }
}
