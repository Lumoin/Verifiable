using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
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

    /// <summary>
    /// What step 1) made of each Evidence Record the Driving Application supplied, in the order it supplied them;
    /// empty when it supplied none, which is the state the step has nothing to do in.
    /// </summary>
    public IReadOnlyList<EvidenceRecordValidationResult> EvidenceRecordValidations { get; init; } = [];

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
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">RFC 6283</see>. The records the Driving Application
/// supplies in <see cref="SignatureValidationInputs.EvidenceRecords"/> are verified through
/// <see cref="EvidenceRecords.VerifyAsync"/>, their most recent Archive Timestamp through the time-stamp
/// validation building block of clause 5.4, and each chain's digest algorithm through the caller's dated
/// cryptographic constraints at the instant the chain after it was created (RFC 4998 clause 5.3 step 2 d). A
/// record that satisfies all three yields a proof of existence at its initial Archive Timestamp's <c>genTime</c>
/// for every object whose own unbroken run of proofs reaches that validated token, and — when the object is the
/// Signed Data Object itself — for everything the signature CONTAINS, which is clause 5.6.2.3 step 5)'s own
/// containment rule; a Signer's Document that travelled beside a detached signature is not contained in it and
/// is not claimed. A run that supplies no Evidence Record has nothing for the step to do and reaches exactly
/// the conclusion it reached before the input existed, which is also how clause A.3.7 runs it ("There is no
/// evidence record, so step 1) is skipped"). The RFC 6283 XML form is not verified by this library; a caller
/// meeting one is refused with a typed status where it is met rather than having it silently ignored here.
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
        BaseMemoryPool pool,
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

        //Step 1): every Evidence Record the Driving Application supplied is verified per RFC 4998, its most
        //recent Archive Timestamp validated through the building block of clause 5.4, and the proofs a record
        //that satisfies both establishes are collected. A run supplying none reaches an empty result and an
        //empty proof set here, and every later step behaves as it did before this step existed.
        EvidenceRecordStepOutcome evidenceRecords = await ValidateEvidenceRecordsAsync(
            inputs, signature, seams, constraints.Cryptographic, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);

        //An Evidence Record IS material for long term availability and integrity: EN 319 162-1 clause 4.4.5 item
        //2 offers it as the alternative to a time-stamp chain, and a signature accompanied by one that verifies
        //is therefore not the signature step 3)'s early return describes ("does not contain any attributes for
        //long term availability and integrity of validation material").
        bool hasLongTermAttributes = signature.TimestampsOfClass(SignatureTimestampClass.ArchiveTimestamp).Count > 0
            || evidenceRecords.EstablishedAnyProof;

        //Step 2) and NOTE 3: the Driving Application's own proofs are used without additional processing, and a
        //proof at the current time is added for every object in the signature.
        ProofOfExistenceSet proofs = inputs.ProofsOfExistence.Union(await ProofsAtCurrentTimeAsync(
            signature, inputs.CertificateValidationData, currentTime, resources, pool, cancellationToken).ConfigureAwait(false));
        proofs = proofs.Union(evidenceRecords.Proofs);

        ValidationObjectIdentity signatureValueIdentity = await SignatureValueIdentityAsync(
            signature, resources, pool, cancellationToken).ConfigureAwait(false);

        var outcome = new LongTermValidationResult
        {
            Conclusion = withTime.Conclusion,
            BestSignatureTime = withTime.BestSignatureTime,
            SignatureWithTimeValidation = withTime,
            ProofsOfExistence = proofs,
            EvidenceRecordValidations = evidenceRecords.Results,
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
    private static ValueTask<ProofOfExistenceSet> ProofsAtCurrentTimeAsync(
        SignatureFacts signature,
        IReadOnlyList<PkiCertificateMemory> callerSuppliedValidationData,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken) => ContainedObjectProofsAsync(
            signature,
            callerSuppliedValidationData,
            currentTime,
            ProofOfExistenceOrigin.DrivingApplicationAssertion,
            establishedBy: null,
            //Step 2) with NOTE 3 is about what the run holds in its hands at the current time, not about what one
            //object contains: a Signer's Document the Driving Application supplied beside a detached signature is
            //demonstrably in existence now, so the proof at the current time covers it exactly as it covers the
            //objects the signature encapsulates.
            provesContentSuppliedBeside: true,
            resources,
            pool,
            cancellationToken);


    /// <summary>
    /// Builds one proof of existence per object the signature contains, at one instant and attributed to one
    /// origin — the set of objects clause 5.6.2.3 step 5) adds a proof for once the object containing them is
    /// itself proven to have existed.
    /// </summary>
    /// <param name="signature">The signature's facts.</param>
    /// <param name="callerSuppliedValidationData">The certificate validation data the Driving Application supplied, which is proven only where the caller's own assertion covers it; empty for a proof derived from an object that contains only what the signature itself carries.</param>
    /// <param name="instant">The instant the objects are proven to exist at.</param>
    /// <param name="origin">Where the proof came from.</param>
    /// <param name="establishedBy">The identity of the object that established the proof, or <see langword="null"/> when the process itself asserted it.</param>
    /// <param name="provesContentSuppliedBeside">Whether the proof also covers signed content that travelled BESIDE the Signed Data Object rather than inside it (<see cref="SignedContentPlacement.Detached"/>): <see langword="true"/> for the proof the process itself asserts at the current time about everything the run holds, <see langword="false"/> for a proof derived from an object, which reaches only what that object contains.</param>
    /// <param name="resources">The ledger the computed identities are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The proofs.</returns>
    /// <remarks>
    /// <strong>Containment is a fact about octets.</strong> Clause 5.6.2.3 step 5) adds a proof for "each object
    /// contained in" the proven one, and for a detached signature the Signer's Document is not one of them: the
    /// Signed Data Object holds a digest of it in the <c>message-digest</c> signed attribute of
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.4">IETF RFC 5652 clause 5.4</see> and nothing
    /// more, which is the digest-reference rule of step 4) rather than the containment rule of step 5). A proof
    /// derived from a proven Signed Data Object therefore passes <paramref name="provesContentSuppliedBeside"/>
    /// as <see langword="false"/> and states nothing about a document it does not carry.
    /// </remarks>
    private static async ValueTask<ProofOfExistenceSet> ContainedObjectProofsAsync(
        SignatureFacts signature,
        IReadOnlyList<PkiCertificateMemory> callerSuppliedValidationData,
        DateTimeOffset instant,
        ProofOfExistenceOrigin origin,
        ValidationObjectIdentity? establishedBy,
        bool provesContentSuppliedBeside,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        List<ProofOfExistence> proofs = [];

        if(signature.SignedDataObject is SensitiveMemory signedDataObject)
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                signedDataObject.AsReadOnlyMemory(), ValidationObjectKind.Signature, reference: null, resources, pool, cancellationToken).ConfigureAwait(false), instant, origin, establishedBy));
        }

        if(signature.SignatureValue is SignedContentMemory signatureValue)
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                signatureValue.AsReadOnlyMemory(), ValidationObjectKind.SignatureValue, reference: null, resources, pool, cancellationToken).ConfigureAwait(false), instant, origin, establishedBy));
        }

        if(signature.SignedContent is SignedContentMemory content
            && (provesContentSuppliedBeside || signature.SignedContentPlacement == SignedContentPlacement.Encapsulated))
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                content.AsReadOnlyMemory(), ValidationObjectKind.SignedDataObject, signature.SignedContentIdentifier, resources, pool, cancellationToken).ConfigureAwait(false), instant, origin, establishedBy));
        }

        await AddCarrierProofsAsync(signature.EmbeddedCertificates, ValidationObjectKind.Certificate, proofs, instant, origin, establishedBy, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarrierProofsAsync(signature.EmbeddedCertificateRevocationLists, ValidationObjectKind.RevocationData, proofs, instant, origin, establishedBy, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarrierProofsAsync(signature.EmbeddedOcspResponses, ValidationObjectKind.RevocationData, proofs, instant, origin, establishedBy, resources, pool, cancellationToken).ConfigureAwait(false);
        await AddCarrierProofsAsync(callerSuppliedValidationData, ValidationObjectKind.Certificate, proofs, instant, origin, establishedBy, resources, pool, cancellationToken).ConfigureAwait(false);

        for(int i = 0; i < signature.Timestamps.Count; ++i)
        {
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                signature.Timestamps[i].Token.AsReadOnlyMemory(), ValidationObjectKind.TimestampToken, signature.Timestamps[i].Identifier, resources, pool, cancellationToken).ConfigureAwait(false), instant, origin, establishedBy));
        }

        return ProofOfExistenceSet.Create(proofs);
    }


    /// <summary>
    /// Runs step 1) of clause 5.6.3.4: every Evidence Record the Driving Application supplied is verified per
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">IETF RFC 4998 clause 5.3</see>, its most
    /// recent Archive Timestamp is validated through the time-stamp validation building block of clause 5.4, and
    /// a record that satisfies both establishes a proof of existence at its initial Archive Timestamp's
    /// <c>genTime</c> for every object it carries.
    /// </summary>
    /// <param name="inputs">The run's inputs, whose <see cref="SignatureValidationInputs.EvidenceRecords"/> the step processes.</param>
    /// <param name="signature">The signature's facts, needed to expand a proof about the Signed Data Object into proofs about what it contains.</param>
    /// <param name="seams">The format binding and certificate seams the embedded time-stamp's own validation composes.</param>
    /// <param name="cryptographicConstraints">The dated algorithm-reliability table clause 5.3 step 2 d) needs, applied to each <c>ArchiveTimeStampChain</c>'s own digest algorithm at the instant the chain after it was created.</param>
    /// <param name="currentTime">The instant the embedded time-stamp is validated at, which is what clause 5.3's "the last Archive Timestamp has to be valid at the time the verification is performed" names.</param>
    /// <param name="resources">The ledger the carriers this step creates are tracked in.</param>
    /// <param name="pool">The memory pool the step rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The per-record conclusions and the proofs they established; both empty when no record was supplied.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Which time-stamp is validated, and why it is the most recent one.</strong> RFC 4998 clause 5.3
    /// makes each earlier Archive Timestamp's validity a consequence of the following one — the renewal
    /// procedures of clause 5.2 bind the whole prior sequence into the next tree — and states outright that "the
    /// last Archive Timestamp has to be valid at the time the verification is performed". Validating the initial
    /// token against the present instead would refuse every record whose authority certificate has since expired,
    /// which is the situation the whole mechanism exists to survive.
    /// </para>
    /// <para>
    /// <strong>The instant a proof states is the initial Archive Timestamp's, and what makes that instant
    /// good is EVERY link and algorithm between it and the token validated above.</strong> Three things are
    /// required before the proof is stated, because clause 5.3 makes all three separate obligations. The
    /// record's own conclusion has to be
    /// <see cref="EvidenceRecordVerificationStatus.Verified"/>, which is reached only when every chain of the
    /// sequence verified structurally (steps 2 a) and 3 a)). The object's own unbroken run of proofs has to
    /// reach the record's most recent Archive Timestamp — coverage is a per-chain fact, since clause 5.2's
    /// Hash-Tree Renewal admits dropping data objects, so
    /// <see cref="EvidenceRecordVerification.CoveredUntil"/> is compared against
    /// <see cref="EvidenceRecordVerification.LatestArchiveTime"/> rather than assumed to be it. And each chain's
    /// digest algorithm has to be asserted reliable at the instant the chain after it was created, which is step
    /// 2 d)'s "this algorithm MUST be secure at the time of the first Archive Timestamp of the following
    /// ArchiveTimeStampChain" and the only half of clause 5.3 that needs a policy input.
    /// </para>
    /// <para>
    /// <strong>The reliability table is consulted when the caller supplied one.</strong> A table with no rows is
    /// a caller who stated no algorithm policy, and this library invents none — the dated values belong to a
    /// cryptographic-suites publication, not to source code. Such a run is left exactly as it was; it is also a
    /// run the clause 5.4 validation of the record's own most recent Archive Timestamp already refuses on the
    /// token's own algorithms, so the absence of a table cannot be used to carry a proof past a stated policy.
    /// </para>
    /// </remarks>
    private static async ValueTask<EvidenceRecordStepOutcome> ValidateEvidenceRecordsAsync(
        SignatureValidationInputs inputs,
        SignatureFacts signature,
        SignatureValidationSeams seams,
        CryptographicConstraints cryptographicConstraints,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(inputs.EvidenceRecords.Count == 0)
        {
            return new EvidenceRecordStepOutcome([], ProofOfExistenceSet.Empty, EstablishedAnyProof: false);
        }

        var results = new List<EvidenceRecordValidationResult>(inputs.EvidenceRecords.Count);
        ProofOfExistenceSet proofs = ProofOfExistenceSet.Empty;
        bool establishedAnyProof = false;

        for(int i = 0; i < inputs.EvidenceRecords.Count; ++i)
        {
            EvidenceRecordValidationInput input = inputs.EvidenceRecords[i];
            ValidationObjectIdentity recordIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                input.EvidenceRecord.AsReadOnlyMemory(), ValidationObjectKind.EvidenceRecord, input.Identifier, resources, pool, cancellationToken).ConfigureAwait(false);

            TimestampValidationResult? tokenValidation = await ValidateLatestArchiveTimestampAsync(
                input.EvidenceRecord, inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);
            bool tokenValid = tokenValidation is not null && tokenValidation.Conclusion.Indication == BuildingBlockIndication.Passed;

            var objectResults = new List<EvidenceRecordProtectedObjectResult>(input.ProtectedObjects.Count);
            EvidenceRecordVerificationStatus recordStatus = EvidenceRecordVerificationStatus.NotVerified;
            DateTimeOffset? initialArchiveTime = null;
            DateTimeOffset? latestArchiveTime = null;
            IReadOnlyList<AlgorithmReliabilityAssessment> unreliableChainAlgorithms = [];
            bool recordProvedAnything = false;

            for(int objectIndex = 0; objectIndex < input.ProtectedObjects.Count; ++objectIndex)
            {
                EvidenceRecordProtectedObject protectedObject = input.ProtectedObjects[objectIndex];
                using EvidenceRecordVerification verification = await EvidenceRecords.VerifyAsync(
                    new EvidenceRecordVerificationContext
                    {
                        EvidenceRecord = input.EvidenceRecord,
                        DataObject = protectedObject.Object.AsReadOnlyMemory()
                    },
                    pool,
                    cancellationToken).ConfigureAwait(false);

                //RFC 4998 clause 5.3: the whole sequence has to hold, not only the token validated above. The
                //record's own conclusion covers every chain's structure, and the object's own run of proofs has
                //to REACH the record's most recent Archive Timestamp, because that is the only token this step
                //validated. Coverage is a per-chain fact (clause 5.2's deletion tolerance admits dropping a data
                //object at a renewal), so an object whose run ended earlier is one this step establishes nothing
                //about rather than one it proves on the strength of a token that says nothing about it; the
                //per-object result still reports how far the record did carry it.
                bool structureHeld = verification.Status == EvidenceRecordVerificationStatus.Verified;
                bool sequenceHeld = structureHeld
                    && verification.CoveredUntil is DateTimeOffset coveredUntil
                    && verification.LatestArchiveTime is DateTimeOffset latestOfRecord
                    && coveredUntil == latestOfRecord;

                //Step 2 d): each chain's digest algorithm has to be secure at the time of the first Archive
                //Timestamp of the chain that follows it, and the most recent chain's at the time the
                //verification is performed.
                IReadOnlyList<AlgorithmReliabilityAssessment> unreliable = sequenceHeld
                    ? StateUnreliableChainAlgorithms(verification, cryptographicConstraints, currentTime)
                    : [];
                if(unreliable.Count > 0 && unreliableChainAlgorithms.Count == 0)
                {
                    unreliableChainAlgorithms = unreliable;
                }

                bool proven = sequenceHeld && unreliable.Count == 0 && tokenValid && verification.InitialArchiveTime is not null;
                initialArchiveTime ??= verification.InitialArchiveTime;
                latestArchiveTime ??= verification.LatestArchiveTime;
                if(recordStatus == EvidenceRecordVerificationStatus.NotVerified || structureHeld)
                {
                    recordStatus = verification.Status;
                }

                objectResults.Add(new EvidenceRecordProtectedObjectResult
                {
                    Object = protectedObject.Object,
                    Kind = protectedObject.Kind,
                    Reference = protectedObject.Reference,
                    Status = verification.Status,
                    CoveredUntil = verification.CoveredUntil,
                    IsProven = proven
                });

                if(!proven || verification.InitialArchiveTime is not DateTimeOffset provenAt)
                {
                    continue;
                }

                recordProvedAnything = true;
                proofs = proofs.With(new ProofOfExistence
                {
                    ObjectIdentity = await ProofOfExistenceExtraction.CreateIdentityAsync(
                        protectedObject.Object.AsReadOnlyMemory(), protectedObject.Kind, protectedObject.Reference, resources, pool, cancellationToken).ConfigureAwait(false),
                    Instant = provenAt,
                    Scope = ProofOfExistenceScope.Object,
                    Origin = ProofOfExistenceOrigin.EvidenceRecord,
                    EstablishedBy = recordIdentity
                });

                //Clause 5.6.2.3 step 5): a proof for an object gives a proof for each object it contains, and the
                //Signed Data Object contains the signature value, the certificates, the revocation material, the
                //time-stamp tokens the signature carries and the content it ENCAPSULATES.
                if(signature.SignedDataObject is SensitiveMemory signedDataObject
                    && signedDataObject.AsReadOnlySpan().SequenceEqual(protectedObject.Object.AsReadOnlySpan()))
                {
                    //A detached Signer's Document is NOT among them: the record's hash tree carries the Signed
                    //Data Object's octets, and those hold a digest of the document rather than the document.
                    proofs = proofs.Union(await ContainedObjectProofsAsync(
                        signature, [], provenAt, ProofOfExistenceOrigin.EvidenceRecord, recordIdentity,
                        provesContentSuppliedBeside: false, resources, pool, cancellationToken).ConfigureAwait(false));
                }
            }

            establishedAnyProof = establishedAnyProof || recordProvedAnything;
            results.Add(new EvidenceRecordValidationResult
            {
                EvidenceRecord = input.EvidenceRecord,
                Identifier = input.Identifier,
                Identity = recordIdentity,
                Status = recordStatus,
                ProtectedObjects = objectResults,
                ArchiveTimestampValidation = tokenValidation,
                InitialArchiveTime = initialArchiveTime,
                LatestArchiveTime = latestArchiveTime,
                UnreliableChainAlgorithms = unreliableChainAlgorithms,
                EstablishedProofOfExistence = recordProvedAnything
            });
        }

        return new EvidenceRecordStepOutcome(results, proofs, establishedAnyProof);

        //States which of a record's chain digest algorithms the caller's table does not assert reliable at the
        //instant step 2 d) of RFC 4998 clause 5.3 names: for every chain but the last, the generation time of
        //the first Archive Timestamp of the chain that follows it; for the last chain, the time the verification
        //is performed, which is clause 5.3's "the last Archive Timestamp has to be valid at the time the
        //verification is performed" together with the assumption clause 5.6.2.3.1 states about a time-stamp's
        //own message imprint — the same gate IsTokenHashReliableAsync applies on the time-stamp attribute path.
        //A caller who supplied no table at all is left where it was: this library ships no dated table and
        //invents none.
        static IReadOnlyList<AlgorithmReliabilityAssessment> StateUnreliableChainAlgorithms(
            EvidenceRecordVerification verification,
            CryptographicConstraints cryptographicConstraints,
            DateTimeOffset currentTime)
        {
            if(cryptographicConstraints.Entries.Count == 0)
            {
                return [];
            }

            List<AlgorithmReliabilityAssessment>? unreliable = null;
            for(int chainIndex = 0; chainIndex < verification.Chains.Count; ++chainIndex)
            {
                DateTimeOffset instant = chainIndex + 1 < verification.Chains.Count
                    && verification.Chains[chainIndex + 1].ArchiveTimeStamps.Count > 0
                        ? verification.Chains[chainIndex + 1].ArchiveTimeStamps[0].GenerationTime
                        : currentTime;

                AlgorithmIdentifier chainAlgorithm = verification.Chains[chainIndex].DigestAlgorithm;
                if(!cryptographicConstraints.IsHashTrustedUntilAtLeast(chainAlgorithm, instant))
                {
                    unreliable ??= [];
                    unreliable.Add(cryptographicConstraints.Assess(
                        new AlgorithmUse(
                            chainAlgorithm,
                            KeySizeBits: null,
                            string.Create(CultureInfo.InvariantCulture, $"evidence record ArchiveTimeStampChain {chainIndex} digest algorithm")),
                        instant));
                }
            }

            return unreliable ?? [];
        }
    }


    /// <summary>
    /// Validates the time-stamp of an Evidence Record's most recent <c>ArchiveTimeStamp</c> through the
    /// time-stamp validation building block of clause 5.4.
    /// </summary>
    /// <param name="evidenceRecord">The record.</param>
    /// <param name="inputs">The run's inputs, whose time-stamp constraints the block applies.</param>
    /// <param name="seams">The seams the token's own validation composes.</param>
    /// <param name="currentTime">The instant the token is validated at.</param>
    /// <param name="resources">The ledger the token carrier is tracked in.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>What the building block concluded, or <see langword="null"/> when the record carries no Archive Timestamp to validate.</returns>
    private static async ValueTask<TimestampValidationResult?> ValidateLatestArchiveTimestampAsync(
        EvidenceRecord evidenceRecord,
        SignatureValidationInputs inputs,
        SignatureValidationSeams seams,
        DateTimeOffset currentTime,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<EvidenceRecordArchiveTimeStampChain> chains = evidenceRecord.ArchiveTimeStampSequence.Chains;
        if(chains.Count == 0)
        {
            return null;
        }

        IReadOnlyList<EvidenceRecordArchiveTimeStamp> members = chains[chains.Count - 1].ArchiveTimeStamps;
        if(members.Count == 0)
        {
            return null;
        }

        ReadOnlyMemory<byte> tokenBytes = members[members.Count - 1].TimeStamp;
        PkiCertificateMemory token = resources.Track(
            new PkiCertificateMemory(CopyToPooled(tokenBytes.Span, pool), PkiCertificateTags.TimestampToken));

        return await TimestampValidation.ValidateAsync(
            token, inputs, seams, currentTime, resources, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Copies octets into memory rented from a pool, for a carrier that has to own what it holds.
    /// </summary>
    /// <param name="source">The octets to copy.</param>
    /// <param name="pool">The pool the memory is rented from.</param>
    /// <returns>The rented memory, holding a copy of the octets.</returns>
    private static IMemoryOwner<byte> CopyToPooled(ReadOnlySpan<byte> source, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(source.Length, 1));
        try
        {
            source.CopyTo(owner.Memory.Span);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>What step 1) of clause 5.6.3.4 produced: the per-record conclusions, the proofs of existence they established, and whether any record established one at all.</summary>
    /// <param name="Results">The per-record conclusions, in the order the Driving Application supplied the records.</param>
    /// <param name="Proofs">The proofs the verified records established.</param>
    /// <param name="EstablishedAnyProof">Whether at least one record established a proof, which is what makes an Evidence Record long term availability material for step 3)'s branch.</param>
    private readonly record struct EvidenceRecordStepOutcome(
        IReadOnlyList<EvidenceRecordValidationResult> Results,
        ProofOfExistenceSet Proofs,
        bool EstablishedAnyProof);


    /// <summary>
    /// Adds a proof of existence at one instant for every carrier of a list.
    /// </summary>
    /// <param name="carriers">The carriers to prove.</param>
    /// <param name="kind">What the carriers are; a carrier that declares a revocation kind of its own overrides it.</param>
    /// <param name="proofs">The list of proofs being built.</param>
    /// <param name="instant">The instant the objects are proven to exist at.</param>
    /// <param name="origin">Where the proof came from.</param>
    /// <param name="establishedBy">The identity of the object that established the proof, or <see langword="null"/> when the process itself asserted it.</param>
    /// <param name="resources">The ledger the computed identities are tracked in.</param>
    /// <param name="pool">The memory pool the digests are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    private static async ValueTask AddCarrierProofsAsync(
        IReadOnlyList<PkiCertificateMemory> carriers,
        ValidationObjectKind kind,
        List<ProofOfExistence> proofs,
        DateTimeOffset instant,
        ProofOfExistenceOrigin origin,
        ValidationObjectIdentity? establishedBy,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        for(int i = 0; i < carriers.Count; ++i)
        {
            ValidationObjectKind carrierKind = carriers[i].IsCrl || carriers[i].IsOcspResponse
                ? ValidationObjectKind.RevocationData
                : carriers[i].IsTimestampToken ? ValidationObjectKind.TimestampToken : kind;
            proofs.Add(Proof(await ProofOfExistenceExtraction.CreateIdentityAsync(
                carriers[i].AsReadOnlyMemory(), carrierKind, reference: null, resources, pool, cancellationToken).ConfigureAwait(false), instant, origin, establishedBy));
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
        BaseMemoryPool pool,
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
        BaseMemoryPool pool,
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
        BaseMemoryPool pool,
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
    /// Builds one proof of existence for an object at an instant — the proofs steps 1), 2) and 4) of clause
    /// 5.6.3.4 add, which differ only in what established them.
    /// </summary>
    /// <param name="objectIdentity">The object the proof is about.</param>
    /// <param name="instant">The instant it is proven to have existed at.</param>
    /// <param name="origin">Where the proof came from.</param>
    /// <param name="establishedBy">The identity of the object that established the proof, or <see langword="null"/> when the process itself asserted it.</param>
    /// <returns>The proof.</returns>
    private static ProofOfExistence Proof(
        ValidationObjectIdentity objectIdentity,
        DateTimeOffset instant,
        ProofOfExistenceOrigin origin,
        ValidationObjectIdentity? establishedBy) => new()
    {
        ObjectIdentity = objectIdentity,
        Instant = instant,
        Scope = ProofOfExistenceScope.Object,
        Origin = origin,
        EstablishedBy = establishedBy
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
