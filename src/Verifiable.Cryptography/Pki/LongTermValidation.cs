using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What the validation process for Signatures providing Long Term Availability and Integrity of Validation
/// Material concluded — the output of clause 5.6.3.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>, together with the best-signature-time and intermediate results step 10) says
/// the SVA should return.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier this record references belongs to the
/// <see cref="SignatureValidationResources"/> of the run that produced it.
/// </remarks>
[DebuggerDisplay("LongTermValidationResult: {Conclusion.Indication}, best-signature-time {BestSignatureTime}")]
public sealed record LongTermValidationResult
{
    /// <summary>The process conclusion in the building-block vocabulary of clause 5.1.3.</summary>
    public required BuildingBlockConclusion Conclusion { get; init; }

    /// <summary>Best-signature-time as step 6) determined it from the accumulated set of proofs of existence.</summary>
    public required DateTimeOffset BestSignatureTime { get; init; }

    /// <summary>What the validation process for Signatures with Time made of the signature in step 3).</summary>
    public required SignatureWithTimeValidationResult SignatureWithTimeValidation { get; init; }

    /// <summary>The set of proofs of existence the process accumulated, which a report presents as the evidence the conclusion rests on.</summary>
    public required ProofOfExistenceSet ProofsOfExistence { get; init; }

    /// <summary>The validation results of the time-stamp attributes step 5) processed, newest first.</summary>
    public IReadOnlyList<TimestampValidationResult> TimestampValidations { get; init; } = [];

    /// <summary>Whether the signature carries attributes for long term availability and integrity of validation material at all, which step 3) branches on.</summary>
    public bool HasLongTermAvailabilityAttributes { get; init; }
}


/// <summary>
/// The validation process for Signatures providing Long Term Availability and Integrity of Validation Material of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.6.3</see>: it accumulates proofs of existence from the signature's
/// time-stamp attributes and re-decides an indeterminate status through the past validation building blocks of
/// clause 5.6.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Evidence records.</strong> Step 1) validates Evidence Records per
/// <see href="https://www.rfc-editor.org/rfc/rfc4998">RFC 4998</see> or
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">RFC 6283</see>. No Evidence Record reaches this process,
/// because none is modelled in this library's inputs, so step 1) is skipped — exactly as clause A.3.7 skips it
/// ("There is no evidence record, so step 1) is skipped"). The step is a stated gap, not an implicit one.
/// </para>
/// <para>
/// <strong>The order of step 5).</strong> Step 5)a) selects "the newest time-stamp that has not been processed".
/// The generation times the ordering needs are read from the tokens before any of them is validated, and they
/// order a loop rather than decide anything: every token the ordering selected is then validated through the
/// time-stamp validation building block of clause 5.4, and only the generation time that block returns reaches a
/// conclusion.
/// </para>
/// <para>
/// <strong>Determinism.</strong> The current time is an explicit argument. Steps 2) and 4) add proofs of
/// existence at that time and at best-signature-time, and both are values the run was given or derived from the
/// material under validation.
/// </para>
/// </remarks>
public static class LongTermValidation
{
    /// <summary>
    /// Runs the validation process for Signatures providing Long Term Availability and Integrity of Validation
    /// Material.
    /// </summary>
    /// <param name="inputs">The inputs of Table 27.</param>
    /// <param name="seams">The format binding and the certificate seams the process composes.</param>
    /// <param name="currentTime">The current time, obtained once by the composition root.</param>
    /// <param name="resources">The ledger the carriers this run creates are tracked in.</param>
    /// <param name="pool">The memory pool the run rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The conclusion of clause 5.6.3.3, best-signature-time and the accumulated proofs of existence.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<LongTermValidationResult> ValidateAsync(
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

        //Step 3) is run first because every later step needs the facts the format binding extracts, and the
        //process of clause 5.5 is what extracts them. Step 2)'s proofs of existence at the current time are added
        //below over exactly the objects those facts name, which is the same set and the same instant.
        SignatureWithTimeValidationResult withTime = await SignatureWithTimeValidation.ValidateAsync(
            inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

        SignatureFacts signature = withTime.BasicValidation.Signature;
        SignatureValidationConstraints constraints = withTime.BasicValidation.Constraints ?? inputs.Constraints;
        bool hasLongTermAttributes = signature.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp).Count > 0;

        //Step 2) and NOTE 3: the Driving Application's own proofs are used without additional processing, and a
        //proof at the current time is added for every object in the signature.
        ProofOfExistenceSet proofs = inputs.ProofsOfExistence.Union(await ProofsAtCurrentTimeAsync(
            signature, inputs.CertificateValidationData, currentTime, resources, pool, cancellationToken).ConfigureAwait(false));

        ValidationObjectIdentity signatureValueIdentity = await SignatureValueIdentityAsync(
            signature, resources, pool, cancellationToken).ConfigureAwait(false);

        var outcome = new LongTermValidationResult
        {
            Conclusion = withTime.Conclusion,
            BestSignatureTime = withTime.BestSignatureTime,
            SignatureWithTimeValidation = withTime,
            ProofsOfExistence = proofs,
            HasLongTermAvailabilityAttributes = hasLongTermAttributes
        };

        //Step 3)'s branches on what the process of clause 5.5 returned.
        SignatureValidationSubIndication withTimeSubIndication = withTime.Conclusion.SubIndications.Count > 0
            ? withTime.Conclusion.SubIndications[0]
            : SignatureValidationSubIndication.Custom;
        if(!hasLongTermAttributes)
        {
            //"If the signature does not contain any attributes for long term availability and integrity of
            //validation material, the process shall return the indication/sub-indication and information returned
            //by the Validation process for Signatures with Time", with additional information stating that only
            //that process was performed — which is what HasLongTermAvailabilityAttributes reports.
            return outcome;
        }

        if(withTime.Conclusion.Indication == BuildingBlockIndication.Passed)
        {
            if(!constraints.SignatureElements.RequireLongTermAvailabilityAttributeValidity)
            {
                return outcome;
            }
        }
        else if(!ContinuesAfterSignatureWithTimeValidation(withTime.Conclusion.Indication, withTimeSubIndication))
        {
            return outcome;
        }

        //Step 4): best-signature-time is initialized from step 3) and added as a proof for the signature.
        DateTimeOffset bestSignatureTime = withTime.BestSignatureTime;
        proofs = proofs.With(new ProofOfExistence
        {
            ObjectIdentity = signatureValueIdentity,
            Instant = bestSignatureTime,
            Scope = ProofOfExistenceScope.Object,
            Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
        });

        //Step 5): the time-stamp attributes, newest first.
        List<TimestampValidationResult> timestampValidations = [];
        IReadOnlyList<EmbeddedTimestamp> orderedTimestamps = await OrderNewestFirstAsync(
            signature, pool, cancellationToken).ConfigureAwait(false);
        for(int i = 0; i < orderedTimestamps.Count; ++i)
        {
            EmbeddedTimestamp timestamp = orderedTimestamps[i];

            //Step 5)a).
            TimestampValidationResult tokenValidation = await TimestampValidation.ValidateAsync(
                timestamp.Token, inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);
            timestampValidations.Add(tokenValidation);

            if(tokenValidation.Conclusion.Indication == BuildingBlockIndication.Passed
                && tokenValidation.GenerationTime is DateTimeOffset generationTime)
            {
                //Step 5)b): a validated token whose own message-imprint hash function is reliable at a time the
                //token is proven to have existed at yields proofs of existence for everything it protects.
                if(await IsTokenHashReliableAsync(
                    timestamp, tokenValidation, proofs, constraints.Cryptographic, currentTime, resources, pool, cancellationToken).ConfigureAwait(false))
                {
                    proofs = proofs.Union(await ProofOfExistenceExtraction.ExtractAsync(
                        signature, timestamp, generationTime, proofs, constraints.Cryptographic, constraints.SignatureElements,
                        seams, resources, pool, cancellationToken).ConfigureAwait(false));
                }

                continue;
            }

            SignatureValidationSubIndication tokenSubIndication = tokenValidation.Conclusion.SubIndications.Count > 0
                ? tokenValidation.Conclusion.SubIndications[0]
                : SignatureValidationSubIndication.Custom;

            //Step 5)c): an indeterminate token status that proofs of existence may still settle.
            if(ContinuesAfterTimestampValidation(tokenValidation.Conclusion.Indication, tokenSubIndication)
                && tokenValidation.TimestampCertificate is PkiCertificateMemory timestampCertificate)
            {
                ValidationObjectIdentity tokenIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                    timestamp.Token.AsReadOnlyMemory(), ValidationObjectKind.TimestampToken, timestamp.Identifier, resources, pool, cancellationToken).ConfigureAwait(false);

                PastSignatureValidationResult past = await PastSignatureValidation.ValidateAsync(
                    new PastSignatureValidationInputs
                    {
                        SignatureValueIdentity = tokenIdentity,
                        CurrentTimeStatus = tokenValidation.Conclusion,
                        TargetCertificate = timestampCertificate,
                        BestSignatureTime = bestSignatureTime,
                        ProofsOfExistence = proofs,
                        CertificateValidationData = withTime.BasicValidation.CertificateValidationData,
                        RevocationStatusInformation = inputs.RevocationStatusInformation,
                        CertificationAuthorityRevocationTime = tokenValidation.TokenSignatureValidation.RevocationTime,
                        TryLaterReason = tokenValidation.TokenSignatureValidation.TryLaterReason,
                        DecisiveRevocationStatusInformation = tokenValidation.TokenSignatureValidation.DecisiveRevocationStatusInformation,
                        UnreliableAlgorithms = tokenValidation.TokenSignatureValidation.UnreliableAlgorithms
                    },
                    constraints,
                    seams,
                    currentTime,
                    resources,
                    pool,
                    cancellationToken).ConfigureAwait(false);

                if(past.Conclusion.Indication == BuildingBlockIndication.Passed)
                {
                    //Step 5)c)i) and 5)c)ii): the acceptance validation is repeated at the earliest time the
                    //existence of the time-stamp can be proven.
                    //Step 5)c)ii) lists exactly three inputs — the Signed Data Object(s), the time determined in
                    //step i) and the cryptographic constraints — so the signature elements constraints NOTE 6
                    //says need not be rechecked are not passed again.
                    DateTimeOffset provenTokenTime = proofs.EarliestInstantFor(tokenIdentity) ?? bestSignatureTime;
                    SignatureAcceptanceValidationResult acceptance = await SignatureAcceptanceValidation.ValidateAsync(
                        signature,
                        withTime.BasicValidation.CertificateChain,
                        SignatureElementsConstraints.None,
                        constraints.Cryptographic,
                        validateTimestampToken: null,
                        provenTokenTime,
                        pool,
                        cancellationToken).ConfigureAwait(false);
                    if(acceptance.Conclusion.Indication == BuildingBlockIndication.Passed)
                    {
                        //Step 5)c)iii).
                        if(tokenValidation.GenerationTime is DateTimeOffset provenGenerationTime
                            && await IsTokenHashReliableAsync(
                                timestamp, tokenValidation, proofs, constraints.Cryptographic, currentTime, resources, pool, cancellationToken).ConfigureAwait(false))
                        {
                            proofs = proofs.Union(await ProofOfExistenceExtraction.ExtractAsync(
                                signature, timestamp, provenGenerationTime, proofs, constraints.Cryptographic, constraints.SignatureElements,
                                seams, resources, pool, cancellationToken).ConfigureAwait(false));
                        }

                        continue;
                    }
                }
            }

            //Step 5)d).
            if(constraints.SignatureElements.RequireLongTermAvailabilityAttributeValidity)
            {
                return outcome with
                {
                    Conclusion = tokenValidation.Conclusion,
                    ProofsOfExistence = proofs,
                    TimestampValidations = timestampValidations
                };
            }
        }

        //Step 6): best-signature-time is the earliest time the accumulated proofs prove the signature existed.
        bestSignatureTime = proofs.EarliestInstantFor(signatureValueIdentity) ?? bestSignatureTime;

        outcome = outcome with
        {
            BestSignatureTime = bestSignatureTime,
            ProofsOfExistence = proofs,
            TimestampValidations = timestampValidations
        };

        //Step 7): past signature validation for the signature itself, with the status step 3) returned.
        if(withTime.BasicValidation.SigningCertificate is not PkiCertificateMemory signingCertificate)
        {
            return outcome with { Conclusion = withTime.Conclusion };
        }

        PastSignatureValidationResult pastSignature = await PastSignatureValidation.ValidateAsync(
            new PastSignatureValidationInputs
            {
                SignatureValueIdentity = signatureValueIdentity,
                CurrentTimeStatus = withTime.Conclusion,
                TargetCertificate = signingCertificate,
                BestSignatureTime = bestSignatureTime,
                ProofsOfExistence = proofs,
                CertificateValidationData = withTime.BasicValidation.CertificateValidationData,
                RevocationStatusInformation = inputs.RevocationStatusInformation,
                CertificationAuthorityRevocationTime = withTime.BasicValidation.RevocationTime,
                TryLaterReason = withTime.BasicValidation.TryLaterReason,
                DecisiveRevocationStatusInformation = withTime.BasicValidation.DecisiveRevocationStatusInformation,
                UnreliableAlgorithms = withTime.BasicValidation.UnreliableAlgorithms
            },
            constraints,
            seams,
            currentTime,
            resources,
            pool,
            cancellationToken).ConfigureAwait(false);
        if(pastSignature.Conclusion.Indication != BuildingBlockIndication.Passed)
        {
            return outcome with { Conclusion = pastSignature.Conclusion };
        }

        //Step 8): the time-stamp delay constraint against the best-signature-time of step 6).
        if(signature.TimestampsOfClass(SignatureTimestampClass.SignatureTimestamp).Count > 0
            && constraints.SignatureElements.TimestampDelay is TimeSpan timestampDelay)
        {
            if(withTime.BasicValidation.ClaimedSigningTime is not DateTimeOffset claimedSigningTime)
            {
                return outcome with
                {
                    Conclusion = SignatureConstraintsFailure(
                        "The validation constraints specify a time-stamp delay and the signature carries no signing-time attribute.")
                };
            }

            if(claimedSigningTime + timestampDelay <= bestSignatureTime)
            {
                return outcome with
                {
                    Conclusion = SignatureConstraintsFailure(
                        "The claimed signing time plus the time-stamp delay is not after best-signature-time.")
                };
            }
        }

        //Step 9): the acceptance validation is repeated at the time step 7) established the signature existed at,
        //with the three inputs the step lists and without the signature elements constraints NOTE 6 excludes.
        SignatureAcceptanceValidationResult finalAcceptance = await SignatureAcceptanceValidation.ValidateAsync(
            signature,
            withTime.BasicValidation.CertificateChain,
            SignatureElementsConstraints.None,
            constraints.Cryptographic,
            validateTimestampToken: null,
            bestSignatureTime,
            pool,
            cancellationToken).ConfigureAwait(false);
        if(finalAcceptance.Conclusion.Indication != BuildingBlockIndication.Passed)
        {
            return outcome with { Conclusion = finalAcceptance.Conclusion };
        }

        //Step 10).
        return outcome with { Conclusion = BuildingBlockConclusion.PassedWith(withTime.Conclusion.ReportData) };
    }


    /// <summary>
    /// Decides whether step 3) of clause 5.6.3.4 continues the process after an indeterminate result from the
    /// validation process for Signatures with Time — it does for the eight sub-indications the step enumerates,
    /// whose NOTE 4 explains that "additional proof of existences can help to go from INDETERMINATE to a
    /// determined status".
    /// </summary>
    /// <param name="indication">The indication that process returned.</param>
    /// <param name="subIndication">The sub-indication it returned.</param>
    /// <returns><see langword="true"/> when the process continues with step 4).</returns>
    private static bool ContinuesAfterSignatureWithTimeValidation(BuildingBlockIndication indication, SignatureValidationSubIndication subIndication) =>
        indication == BuildingBlockIndication.Indeterminate
        && (subIndication.Equals(SignatureValidationSubIndication.RevokedNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNotRevoked)
            || subIndication.Equals(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.SignatureConstraintsFailure)
            || subIndication.Equals(SignatureValidationSubIndication.TryLater));


    /// <summary>
    /// Decides whether step 5)c) of clause 5.6.3.4 runs the past signature validation building block for a
    /// time-stamp attribute — it does for the six sub-indications the step enumerates.
    /// </summary>
    /// <param name="indication">The indication the time-stamp validation building block returned.</param>
    /// <param name="subIndication">The sub-indication it returned.</param>
    /// <returns><see langword="true"/> when past signature validation is performed for the token.</returns>
    private static bool ContinuesAfterTimestampValidation(BuildingBlockIndication indication, SignatureValidationSubIndication subIndication) =>
        indication == BuildingBlockIndication.Indeterminate
        && (subIndication.Equals(SignatureValidationSubIndication.RevokedNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.RevokedCertificationAuthorityNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.OutOfBoundsNotRevoked)
            || subIndication.Equals(SignatureValidationSubIndication.CryptographicConstraintsFailureNoProofOfExistence)
            || subIndication.Equals(SignatureValidationSubIndication.RevocationOutOfBoundsNoProofOfExistence));


    /// <summary>
    /// Builds the proofs of existence step 2) of clause 5.6.3.4 adds: one at the current time for every object in
    /// the signature, and for the certificate validation data the Driving Application supplied alongside it.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="callerSuppliedValidationData">The certificate validation data the Driving Application supplied.</param>
    /// <param name="currentTime">The instant the objects are proven to exist at, which is now.</param>
    /// <param name="resources">The ledger the computed identities are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The proofs.</returns>
    private static async ValueTask<ProofOfExistenceSet> ProofsAtCurrentTimeAsync(
        SignatureFacts signature,
        IReadOnlyList<PkiCertificateMemory> callerSuppliedValidationData,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        List<ProofOfExistence> proofs = [];

        if(signature.SignedDataObject is SensitiveMemory signedDataObject)
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                signedDataObject.AsReadOnlyMemory(), ValidationObjectKind.Signature, reference: null, resources, pool, cancellationToken).ConfigureAwait(false), currentTime));
        }

        if(signature.SignatureValue is SignedContentMemory signatureValue)
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                signatureValue.AsReadOnlyMemory(), ValidationObjectKind.SignatureValue, reference: null, resources, pool, cancellationToken).ConfigureAwait(false), currentTime));
        }

        if(signature.SignedContent is SignedContentMemory content)
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                content.AsReadOnlyMemory(), ValidationObjectKind.SignedDataObject, signature.SignedContentIdentifier, resources, pool, cancellationToken).ConfigureAwait(false), currentTime));
        }

        await AddCarrierProofsAsync(signature.EmbeddedCertificates, ValidationObjectKind.Certificate, proofs, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarrierProofsAsync(signature.EmbeddedCertificateRevocationLists, ValidationObjectKind.RevocationData, proofs, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarrierProofsAsync(signature.EmbeddedOcspResponses, ValidationObjectKind.RevocationData, proofs, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarrierProofsAsync(callerSuppliedValidationData, ValidationObjectKind.Certificate, proofs, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

        for(int i = 0; i < signature.Timestamps.Count; ++i)
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                signature.Timestamps[i].Token.AsReadOnlyMemory(), ValidationObjectKind.TimestampToken, signature.Timestamps[i].Identifier, resources, pool, cancellationToken).ConfigureAwait(false), currentTime));
        }

        return ProofOfExistenceSet.Create(proofs);
    }


    /// <summary>
    /// Adds a proof of existence at one instant for every carrier of a list.
    /// </summary>
    /// <param name="carriers">The carriers to prove.</param>
    /// <param name="kind">What the carriers are; a carrier that declares a revocation kind of its own overrides it.</param>
    /// <param name="proofs">The list of proofs being built.</param>
    /// <param name="instant">The instant the objects are proven to exist at.</param>
    /// <param name="resources">The ledger the computed identities are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddCarrierProofsAsync(
        IReadOnlyList<PkiCertificateMemory> carriers,
        ValidationObjectKind kind,
        List<ProofOfExistence> proofs,
        DateTimeOffset instant,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        for(int i = 0; i < carriers.Count; ++i)
        {
            ValidationObjectKind carrierKind = carriers[i].IsCrl || carriers[i].IsOcspResponse
                ? ValidationObjectKind.RevocationData
                : carriers[i].IsTimestampToken ? ValidationObjectKind.TimestampToken : kind;
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                carriers[i].AsReadOnlyMemory(), carrierKind, reference: null, resources, pool, cancellationToken).ConfigureAwait(false), instant));
        }
    }


    /// <summary>
    /// States the identity of the signature value, the object clause 5.6.2.4 asks proofs of existence about, and
    /// falls back to the whole Signed Data Object when the format binding could not isolate the value.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="resources">The ledger the computed identity is tracked in.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The identity.</returns>
    private static async ValueTask<ValidationObjectIdentity> SignatureValueIdentityAsync(
        SignatureFacts signature,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(signature.SignatureValue is SignedContentMemory signatureValue)
        {
            return await ProofOfExistenceExtraction.CreateIdentityAsync(
                signatureValue.AsReadOnlyMemory(), ValidationObjectKind.SignatureValue, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);
        }

        ReadOnlyMemory<byte> signedDataObject = signature.SignedDataObject is SensitiveMemory carrier
            ? carrier.AsReadOnlyMemory()
            : ReadOnlyMemory<byte>.Empty;

        return await ProofOfExistenceExtraction.CreateIdentityAsync(
            signedDataObject, ValidationObjectKind.Signature, reference: null, resources, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Decides whether "a POE exists for the time-stamp for a time when the cryptographic hash function used in
    /// the time-stamp has been considered reliable", which steps 5)b) and 5)c)iii) of clause 5.6.3.4 gate proof
    /// extraction on and clause 5.6.2.3.1 states as an assumption of the extraction building block.
    /// </summary>
    /// <param name="timestamp">The time-stamp attribute.</param>
    /// <param name="tokenValidation">What the time-stamp validation building block returned for it.</param>
    /// <param name="proofsOfExistence">The proofs accumulated so far.</param>
    /// <param name="cryptographicConstraints">The constraints asserting hash-function reliability.</param>
    /// <param name="currentTime">The current time, the instant a token with no earlier proof is known to exist at.</param>
    /// <param name="resources">The ledger the computed identity is tracked in.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when such a proof exists.</returns>
    private static async ValueTask<bool> IsTokenHashReliableAsync(
        EmbeddedTimestamp timestamp,
        TimestampValidationResult tokenValidation,
        ProofOfExistenceSet proofsOfExistence,
        CryptographicConstraints cryptographicConstraints,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(tokenValidation.MessageImprintAlgorithm is not AlgorithmIdentifier imprintAlgorithm)
        {
            return false;
        }

        ValidationObjectIdentity tokenIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
            timestamp.Token.AsReadOnlyMemory(), ValidationObjectKind.TimestampToken, timestamp.Identifier, resources, pool, cancellationToken).ConfigureAwait(false);
        DateTimeOffset provenAt = proofsOfExistence.EarliestInstantFor(tokenIdentity) ?? currentTime;

        return cryptographicConstraints.IsHashTrustedUntilAtLeast(imprintAlgorithm, provenAt);
    }


    /// <summary>
    /// Orders the signature's time-stamp attributes newest first, as step 5)a) of clause 5.6.3.4 processes them.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="pool">The memory pool the token reads rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The time-stamp attributes, newest first; a token whose generation time cannot be read is ordered last.</returns>
    /// <remarks>
    /// The ordering is a sort rather than an insertion walk, because the number of time-stamp attributes is
    /// chosen by whoever produced the Signed Data Object. Ties are broken by the position the signature carries
    /// the attribute at, which makes the order total and therefore the run deterministic (clause 5.1.3).
    /// </remarks>
    private static async ValueTask<IReadOnlyList<EmbeddedTimestamp>> OrderNewestFirstAsync(
        SignatureFacts signature,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        List<TimestampOrdinalPosition> positions = [];
        for(int i = 0; i < signature.Timestamps.Count; ++i)
        {
            DateTimeOffset generationTime = await TimestampValidation.ReadGenerationTimeAsync(
                signature.Timestamps[i].Token, pool, cancellationToken).ConfigureAwait(false) ?? DateTimeOffset.MinValue;
            positions.Add(new TimestampOrdinalPosition(generationTime, i));
        }

        positions.Sort(static (left, right) => left.GenerationTime == right.GenerationTime
            ? left.Position.CompareTo(right.Position)
            : right.GenerationTime.CompareTo(left.GenerationTime));

        List<EmbeddedTimestamp> ordered = [];
        for(int i = 0; i < positions.Count; ++i)
        {
            ordered.Add(signature.Timestamps[positions[i].Position]);
        }

        return ordered;
    }


    /// <summary>
    /// Builds one proof of existence for an object at an instant, established by the process itself rather than
    /// by a time-stamp — the proofs step 2) and step 4) of clause 5.6.3.4 add.
    /// </summary>
    /// <param name="objectIdentity">The object the proof is about.</param>
    /// <param name="instant">The instant it is proven to have existed at.</param>
    /// <returns>The proof.</returns>
    private static ProofOfExistence Proof(ValidationObjectIdentity objectIdentity, DateTimeOffset instant) => new()
    {
        ObjectIdentity = objectIdentity,
        Instant = instant,
        Scope = ProofOfExistenceScope.Object,
        Origin = ProofOfExistenceOrigin.DrivingApplicationAssertion
    };


    /// <summary>The generation time of one time-stamp attribute and the position the signature carries it at, which is what step 5)a) of clause 5.6.3.4 orders the attributes by.</summary>
    /// <param name="GenerationTime">The token's <c>genTime</c>, or <see cref="DateTimeOffset.MinValue"/> when it could not be read.</param>
    /// <param name="Position">The attribute's index in the signature's own order.</param>
    private readonly record struct TimestampOrdinalPosition(DateTimeOffset GenerationTime, int Position);


    /// <summary>
    /// Builds the <c>SIG_CONSTRAINTS_FAILURE</c> outcome of steps 8)a) and 8)b) of clause 5.6.3.4.
    /// </summary>
    /// <param name="description">What was not met about the time-stamp delay constraint.</param>
    /// <returns>The conclusion.</returns>
    private static BuildingBlockConclusion SignatureConstraintsFailure(string description)
    {
        var evaluation = new ValidationConstraintEvaluation(
            ValidationConstraintIdentifier.TimestampDelay, BuildingBlockIndication.Failed, description);

        return new BuildingBlockConclusion
        {
            Indication = BuildingBlockIndication.Indeterminate,
            SubIndications = [SignatureValidationSubIndication.SignatureConstraintsFailure],
            ReportData = [new UnsatisfiedSignatureConstraintsReportData([evaluation])],
            ConstraintEvaluations = [evaluation]
        };
    }
}
