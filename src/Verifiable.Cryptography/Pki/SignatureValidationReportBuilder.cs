using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Builds the clause 4 validation report graph of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf">
/// ETSI TS 119 102-2 V1.4.1</see> from one completed <see cref="SignatureValidationOutcome"/> of the
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> engine.
/// </summary>
/// <remarks>
/// <para>
/// This is the one place the engine's raw evidence (<see cref="SignatureFacts"/>, the per-block results, the
/// accumulated <see cref="ProofOfExistenceSet"/>) is turned into the report shape a Driving Application
/// consumes — the checklist item 1 separation between raw evidence and process output. Every member of
/// <see cref="ValidationReport"/> that a block or process already stated is copied across as a non-owning
/// reference; nothing here re-decides an indication or re-runs a check.
/// </para>
/// <para>
/// <strong>Call this before disposing the outcome.</strong> The returned graph references the same carriers
/// <paramref name="outcome"/> (via its <see cref="SignatureValidationOutcome.Resources"/>) owns, exactly as the
/// engine's own result records do; disposing the outcome invalidates the report.
/// </para>
/// <para>
/// <strong>Why this is asynchronous.</strong> Attaching the accurate proof of existence to a
/// <see cref="ValidationTimeInfo.BestSignatureTime"/> or a <see cref="ValidationObject.ProofOfExistence"/>
/// requires recomputing the canonical object identity of <see cref="ProofOfExistenceExtraction.CreateIdentityAsync"/>
/// for a carrier the report is describing, which hashes through the registered digest seam.
/// </para>
/// </remarks>
public static class SignatureValidationReportBuilder
{
    /// <summary>
    /// Builds the validation report for one completed signature validation run.
    /// </summary>
    /// <param name="outcome">The completed run.</param>
    /// <param name="inputs">The Driving Application's inputs to that run, for the facts the outcome itself does not restate (the detached Signer's Documents, the Driving Application's time indication for signature existence).</param>
    /// <param name="pool">The memory pool any digest recomputed while building the report is rented from.</param>
    /// <param name="validator">The Validator Information Element of clause 4.5, when the caller wants one attached; <see langword="null"/> to omit it, since identifying the validation service is a hosting concern this library does not decide.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The report, referencing carriers <paramref name="outcome"/> owns (see remarks).</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is <see langword="null"/>.</exception>
    public static async ValueTask<ValidationReport> BuildAsync(
        SignatureValidationOutcome outcome,
        SignatureValidationInputs inputs,
        BaseMemoryPool pool,
        SignatureValidatorInformation? validator = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(pool);

        SignatureValidationReportElement element = await BuildSignatureReportAsync(outcome, inputs, pool, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ValidationObject> objects = await BuildValidationObjectsAsync(outcome, pool, cancellationToken).ConfigureAwait(false);

        return new ValidationReport
        {
            SignatureValidationReports = [element],
            SignatureValidationObjects = objects,
            Validator = validator
        };
    }


    /// <summary>
    /// Builds the Signature-Validation-Report-Element (clause 4.3) for the run's own signature.
    /// </summary>
    private static async ValueTask<SignatureValidationReportElement> BuildSignatureReportAsync(
        SignatureValidationOutcome outcome,
        SignatureValidationInputs inputs,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        SignatureFacts facts = outcome.BasicValidation.Signature;
        SignatureValidationConclusion conclusion = outcome.Conclusion;

        return new SignatureValidationReportElement
        {
            SignatureIdentifier = BuildSignatureIdentifier(facts, inputs),
            ValidationConstraintsEvaluationReport = BuildConstraintsReport(conclusion),
            ValidationTimeInfo = await BuildValidationTimeInfoAsync(outcome, inputs, pool, cancellationToken).ConfigureAwait(false),
            SignersDocument = BuildSignersDocument(facts, inputs),
            SignatureAttributes = BuildSignatureAttributes(facts),
            SignerInformation = BuildSignerInformation(outcome.BasicValidation),
            SignatureValidationProcessInfo = new SignatureValidationProcessInfo { ProcessIdentifier = conclusion.ProcessIdentifier },
            Status = ValidationStatus.FromProcessConclusion(conclusion)
        };
    }


    /// <summary>
    /// Builds the Signature Identification Element (clause 4.3.3), or <see langword="null"/> per its clause
    /// 4.3.3.1 conditional presence rule.
    /// </summary>
    private static SignatureIdentifierElement? BuildSignatureIdentifier(SignatureFacts facts, SignatureValidationInputs inputs)
    {
        if(facts.Status == SignatureFactsStatus.FormatFailure)
        {
            //Clause 4.3.3.1: absent when validation was not possible because the format checking building
            //block could not process the signature at all (TOTAL-FAILED/FORMAT_FAILURE).
            return null;
        }

        bool hasDetachedReferences = inputs.SignerDocuments.Count > 0;
        bool anyDetachedContentSupplied = false;
        for(int i = 0; i < inputs.SignerDocuments.Count; ++i)
        {
            if(inputs.SignerDocuments[i].Content is not null)
            {
                anyDetachedContentSupplied = true;

                break;
            }
        }

        //A detached signature whose Signer's Documents were all named but none supplied means only the hash
        //carried in the signature was ever processed — clause 4.3.3.1's HashOnly/DocHashOnly branch.
        bool hashOnly = hasDetachedReferences && !anyDetachedContentSupplied;

        return new SignatureIdentifierElement
        {
            SignatureValue = facts.SignatureValue,
            HashOnly = hashOnly,
            DocHashOnly = hashOnly
        };
    }


    /// <summary>
    /// Builds the Validation Constraints Evaluation Report (clause 4.3.5) from a conclusion's per-constraint
    /// outcomes and the checks the constraints disabled.
    /// </summary>
    private static ValidationConstraintsEvaluationReport BuildConstraintsReport(SignatureValidationConclusion conclusion)
    {
        var constraints = new List<IndividualValidationConstraintReport>(
            conclusion.ConstraintEvaluations.Count + conclusion.ChecksDisabledByPolicy.Count);

        for(int i = 0; i < conclusion.ConstraintEvaluations.Count; ++i)
        {
            ValidationConstraintEvaluation evaluation = conclusion.ConstraintEvaluations[i];
            constraints.Add(new IndividualValidationConstraintReport
            {
                ConstraintIdentifier = evaluation.Identifier,
                Status = ConstraintApplicationStatus.Applied,
                Result = new ValidationStatus
                {
                    MainIndication = BuildingBlockIndicationMapping.ToWireValue(evaluation.Indication)
                }
            });
        }

        for(int i = 0; i < conclusion.ChecksDisabledByPolicy.Count; ++i)
        {
            ValidationConstraintIdentifier disabled = conclusion.ChecksDisabledByPolicy[i];
            if(!EvaluatesIdentifier(conclusion.ConstraintEvaluations, disabled))
            {
                //Clause 4.3.5.4.1: ValidationStatus is present exactly when the constraint was applied, so a
                //disabled constraint carries no result.
                constraints.Add(new IndividualValidationConstraintReport
                {
                    ConstraintIdentifier = disabled,
                    Status = ConstraintApplicationStatus.Disabled
                });
            }
        }

        return new ValidationConstraintsEvaluationReport { ValidationConstraints = constraints };

        //Reports whether a constraint identifier already has an applied outcome, so it is not also listed as
        //disabled: EN 319 102-1 clause 5.1.4.1's ChecksDisabledByPolicy set and a block's own per-constraint
        //outcomes can name the same identifier when a later run of the same constraint under different
        //material both applied and skipped parts of it.
        static bool EvaluatesIdentifier(IReadOnlyList<ValidationConstraintEvaluation> evaluations, ValidationConstraintIdentifier identifier)
        {
            for(int i = 0; i < evaluations.Count; ++i)
            {
                if(evaluations[i].Identifier.Equals(identifier))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Builds the Signature Validation Time Info (clause 4.3.6), attaching the most accurate proof of existence
    /// this run can state for best-signature-time.
    /// </summary>
    private static async ValueTask<ValidationTimeInfo> BuildValidationTimeInfoAsync(
        SignatureValidationOutcome outcome,
        SignatureValidationInputs inputs,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        SignatureValidationConclusion conclusion = outcome.Conclusion;

        //NOTE of clause 4.3.6.1: the current time for Basic Signature validation, best-signature-time otherwise.
        DateTimeOffset instant = conclusion.BestSignatureTime ?? conclusion.ValidationTime;

        ValidationObjectIdentity signatureValueIdentity = await SignatureValueIdentityAsync(
            outcome.BasicValidation.Signature, outcome.Resources, pool, cancellationToken).ConfigureAwait(false);

        //When the validation process for Signatures providing Long Term Availability and Integrity of
        //Validation Material ran, its accumulated proofs of existence carry the real origin and, where one
        //established it, the time-stamp token that did — strictly more information than this method could
        //otherwise state.
        if(outcome.LongTermValidation is LongTermValidationResult longTerm
            && EarliestObjectProof(longTerm.ProofsOfExistence, signatureValueIdentity) is ProofOfExistence actual)
        {
            return new ValidationTimeInfo { ValidationTime = conclusion.ValidationTime, BestSignatureTime = actual };
        }

        ProofOfExistenceOrigin origin = outcome.SignatureWithTimeValidation is SignatureWithTimeValidationResult withTime
            && withTime.AcceptedSignatureTimestamps.Count > 0
                ? ProofOfExistenceOrigin.TimestampToken
                : inputs.TimeIndicationForSignatureExistence is not null
                    ? ProofOfExistenceOrigin.DrivingApplicationAssertion
                    : ProofOfExistenceOrigin.Unknown;

        return new ValidationTimeInfo
        {
            ValidationTime = conclusion.ValidationTime,
            BestSignatureTime = new ProofOfExistence
            {
                ObjectIdentity = signatureValueIdentity,
                Instant = instant,
                Scope = ProofOfExistenceScope.Object,
                Origin = origin
            }
        };
    }


    /// <summary>
    /// States the identity clause 5.6.2.4 of EN 319 102-1 asks proofs of existence about — the signature value,
    /// or the whole Signed Data Object when the format binding could not isolate the value. Mirrors
    /// <c>LongTermValidation</c>'s own (private) derivation exactly, so a carrier this method identifies matches
    /// one that process may already have proofs for.
    /// </summary>
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


    /// <summary>States the earliest proof of an object's own existence (as opposed to a digest of it) a set holds.</summary>
    private static ProofOfExistence? EarliestObjectProof(ProofOfExistenceSet proofs, ValidationObjectIdentity identity)
    {
        IReadOnlyList<ProofOfExistence> candidates = proofs.For(identity);
        ProofOfExistence? earliest = null;
        for(int i = 0; i < candidates.Count; ++i)
        {
            if(candidates[i].Scope == ProofOfExistenceScope.Object && (earliest is null || candidates[i].Instant < earliest.Instant))
            {
                earliest = candidates[i];
            }
        }

        return earliest;
    }


    /// <summary>
    /// Builds the Signer's Document Element (clause 4.3.7) from the signed content the signature encapsulates,
    /// or the detached content the Driving Application supplied.
    /// </summary>
    private static SignersDocument? BuildSignersDocument(SignatureFacts facts, SignatureValidationInputs inputs)
    {
        if(!facts.IsExtracted)
        {
            return null;
        }

        SensitiveMemory? representation = facts.SignedContent;
        for(int i = 0; representation is null && i < inputs.SignerDocuments.Count; ++i)
        {
            representation = inputs.SignerDocuments[i].Content;
        }

        return new SignersDocument { Representation = representation };
    }


    /// <summary>Builds one Signature Attribute Element (clause 4.3.8) per attribute the format binding surfaced.</summary>
    private static List<SignatureAttributeElement> BuildSignatureAttributes(SignatureFacts facts)
    {
        if(!facts.IsExtracted)
        {
            return [];
        }

        var elements = new List<SignatureAttributeElement>(facts.Attributes.Count);
        for(int i = 0; i < facts.Attributes.Count; ++i)
        {
            SignatureAttributeFacts attribute = facts.Attributes[i];
            elements.Add(new SignatureAttributeElement(attribute.Identifier, attribute.Scope == SignatureAttributeScope.Signed, attribute.IsWellFormed));
        }

        return elements;
    }


    /// <summary>Builds the Signer Information Element (clause 4.3.9), or <see langword="null"/> when no signing certificate was identified.</summary>
    private static SignerInformationElement? BuildSignerInformation(BasicSignatureValidationResult basic)
    {
        if(basic.SigningCertificate is not PkiCertificateMemory signingCertificate)
        {
            return null;
        }

        string? signer;
        try
        {
            ManagedCertificate parsed = ManagedCertificate.Parse(signingCertificate.AsReadOnlyMemory());
            signer = PkiDistinguishedNameText.FromDer(parsed.SubjectDer);
        }
        catch(AsnContentException)
        {
            //A certificate whose subject cannot be rendered still identifies the signer by the certificate
            //reference itself; the human-readable form is optional (clause 4.3.9.1).
            signer = null;
        }

        return new SignerInformationElement { SignerCertificate = signingCertificate, Signer = signer };
    }


    /// <summary>
    /// Builds the Signature Validation Objects (clause 4.4): the certificate chain, the validation data the
    /// conclusion consulted, every time-stamp token the signature embeds, and the signed content, each with a
    /// proof of existence (clause 4.4.6) when the validation process for Signatures providing Long Term
    /// Availability and Integrity of Validation Material ran and accumulated one for it, and each time-stamp
    /// token with the POE Provisioning of clause 4.4.7 naming what it proved.
    /// </summary>
    /// <param name="outcome">The completed run.</param>
    /// <param name="pool">The memory pool the recomputed identities are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The objects.</returns>
    /// <remarks>
    /// The time-stamp tokens come from the signature's own facts rather than from
    /// <see cref="SignatureValidationConclusion.ValidationDataUsed"/>, which clause 5.1.3 fills with the
    /// certificate and revocation material alone: a token the long-term process validated and derived proofs
    /// from is an object "used during the validation" in the sense of clause 4.4, and clause 4.4.7 is defined
    /// about a time-stamp token in the first place, so a report that never carried one could never populate it.
    /// </remarks>
    private static async ValueTask<IReadOnlyList<ValidationObject>> BuildValidationObjectsAsync(
        SignatureValidationOutcome outcome,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        SignatureValidationConclusion conclusion = outcome.Conclusion;
        SignatureFacts signature = outcome.BasicValidation.Signature;
        LongTermValidationResult? longTerm = outcome.LongTermValidation;

        var carriers = new List<PkiCertificateMemory>(conclusion.ValidatedCertificateChain.Count + conclusion.ValidationDataUsed.Count);
        AddDistinct(carriers, conclusion.ValidatedCertificateChain);
        AddDistinct(carriers, conclusion.ValidationDataUsed);

        var described = new List<DescribedValidationObject>(carriers.Count + signature.Timestamps.Count + 1);
        for(int i = 0; i < carriers.Count; ++i)
        {
            described.Add(await DescribeAsync(
                carriers[i], Classify(carriers[i]), reference: null, longTerm, outcome.Resources, pool, cancellationToken).ConfigureAwait(false));
        }

        for(int i = 0; i < signature.Timestamps.Count; ++i)
        {
            EmbeddedTimestamp timestamp = signature.Timestamps[i];
            if(HoldsCarrier(described, timestamp.Token))
            {
                continue;
            }

            //The reference is the attribute the token was carried in, which is exactly what
            //ProofOfExistenceExtraction names a token by; an identity built with any other reference would not
            //compare equal to the EstablishedBy of the proofs that token established.
            described.Add(await DescribeAsync(
                timestamp.Token, ValidationObjectKind.TimestampToken, timestamp.Identifier, longTerm, outcome.Resources, pool, cancellationToken).ConfigureAwait(false));
        }

        if(signature.SignedContent is SignedContentMemory content)
        {
            described.Add(await DescribeAsync(
                content, ValidationObjectKind.SignedDataObject, signature.SignedContentIdentifier, longTerm, outcome.Resources, pool, cancellationToken).ConfigureAwait(false));
        }

        //Every Evidence Record step 1) of clause 5.6.3.4 processed is an object the validation used, and clause
        //4.4.7 names an evidence record beside a time-stamp token as something that provides proofs of existence
        //for others. The identity is the one that step computed rather than a recomputation: a record's octets
        //are the ones its own carrier states, and an identity taken over anything else would not compare equal to
        //the EstablishedBy of the proofs the record established, which is what the provisioning below matches on.
        if(longTerm is not null)
        {
            for(int i = 0; i < longTerm.EvidenceRecordValidations.Count; ++i)
            {
                EvidenceRecordValidationResult evidenceRecord = longTerm.EvidenceRecordValidations[i];
                if(HoldsCarrier(described, evidenceRecord.EvidenceRecord))
                {
                    continue;
                }

                described.Add(new DescribedValidationObject(
                    ValidationObjectKind.EvidenceRecord, evidenceRecord.EvidenceRecord, evidenceRecord.Identity));
            }
        }

        var objects = new List<ValidationObject>(described.Count);
        for(int i = 0; i < described.Count; ++i)
        {
            DescribedValidationObject entry = described[i];
            objects.Add(new ValidationObject
            {
                ObjectType = entry.Kind,
                Representation = entry.Representation,
                ProofOfExistence = entry.Identity is null || longTerm is null ? null : EarliestObjectProof(longTerm.ProofsOfExistence, entry.Identity),
                ProvidesProofOfExistenceFor = entry.Identity is null || longTerm is null
                    ? []
                    : BuildProofOfExistenceProvisioning(longTerm.ProofsOfExistence, entry.Identity, described)
            });
        }

        return objects;

        //Adds every carrier of a source list the destination does not already hold, by content equality — the
        //certificate chain and the validation-data-used list can name the same certificate.
        static void AddDistinct(List<PkiCertificateMemory> destination, IReadOnlyList<PkiCertificateMemory> source)
        {
            for(int i = 0; i < source.Count; ++i)
            {
                bool alreadyPresent = false;
                for(int d = 0; d < destination.Count; ++d)
                {
                    if(destination[d].Equals(source[i]))
                    {
                        alreadyPresent = true;

                        break;
                    }
                }

                if(!alreadyPresent)
                {
                    destination.Add(source[i]);
                }
            }
        }

        //Reports whether an object with the same octets is already described, so a token that also reached the
        //validation-data list is projected once.
        static bool HoldsCarrier(List<DescribedValidationObject> described, SensitiveMemory carrier)
        {
            for(int i = 0; i < described.Count; ++i)
            {
                if(described[i].Representation.AsReadOnlySpan().SequenceEqual(carrier.AsReadOnlySpan()))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Classifies one carrier into the object-type vocabulary clause 4.4.4 fixes.
    /// </summary>
    /// <param name="carrier">The carrier to classify.</param>
    /// <returns>The kind.</returns>
    /// <remarks>
    /// No <c>PkiObjectKind</c> is exposed as a public property on <see cref="PkiCertificateMemory"/>;
    /// classification goes through its public <c>Is*</c> predicates, mirroring the same ternary chain
    /// <c>LongTermValidation.AddCarrierProofsAsync</c> already uses for the same carriers.
    /// </remarks>
    private static ValidationObjectKind Classify(PkiCertificateMemory carrier) => carrier.IsX509Certificate
        ? ValidationObjectKind.Certificate
        : carrier.IsCrl || carrier.IsOcspResponse
            ? ValidationObjectKind.RevocationData
            : carrier.IsTimestampToken ? ValidationObjectKind.TimestampToken : ValidationObjectKind.Unknown;


    /// <summary>
    /// Pairs one object with the canonical identity the proofs of existence name it by, recomputing that
    /// identity only when a long-term run accumulated proofs to match it against.
    /// </summary>
    /// <param name="representation">The object itself (clause 4.4.5).</param>
    /// <param name="kind">The object's type (clause 4.4.4), which takes part in the identity.</param>
    /// <param name="reference">The object's own identifier where its format supplies one, which also takes part in the identity.</param>
    /// <param name="longTerm">The long-term validation result, or <see langword="null"/> when that process did not run.</param>
    /// <param name="resources">The ledger the recomputed digest is tracked in.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The described object.</returns>
    private static async ValueTask<DescribedValidationObject> DescribeAsync(
        SensitiveMemory representation,
        ValidationObjectKind kind,
        string? reference,
        LongTermValidationResult? longTerm,
        SignatureValidationResources resources,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ValidationObjectIdentity? identity = longTerm is null
            ? null
            : await ProofOfExistenceExtraction.CreateIdentityAsync(
                representation.AsReadOnlyMemory(), kind, reference, resources, pool, cancellationToken).ConfigureAwait(false);

        return new DescribedValidationObject(kind, representation, identity);
    }


    /// <summary>
    /// Builds the POE Provisioning elements of clause 4.4.7 for one validation object: the objects it itself
    /// established a proof of existence for, grouped by the time value of that proof.
    /// </summary>
    /// <param name="proofs">Every proof the long-term run accumulated.</param>
    /// <param name="identity">The identity of the object whose provisioning is being built.</param>
    /// <param name="described">Every object the report projects, which is what a covered object can be named as.</param>
    /// <returns>The elements, or an empty list when the object established no proof.</returns>
    /// <remarks>
    /// A proof carries the identity of what established it (<see cref="ProofOfExistence.EstablishedBy"/>), which
    /// in this engine is a time-stamp token or an Evidence Record — the two objects clause 4.4.7 names. An object
    /// a proof is about that the report does not project as a validation object of its own (the signature value,
    /// the Signed Data Object itself) is not named here, because clause 4.4.7 names validation objects.
    /// </remarks>
    private static List<ProofOfExistenceProvisioning> BuildProofOfExistenceProvisioning(
        ProofOfExistenceSet proofs,
        ValidationObjectIdentity identity,
        List<DescribedValidationObject> described)
    {
        List<ProofOfExistenceProvisioning> provisioning = [];
        List<DateTimeOffset> instants = [];
        List<List<SensitiveMemory>> covered = [];

        for(int i = 0; i < proofs.Proofs.Count; ++i)
        {
            ProofOfExistence proof = proofs.Proofs[i];
            if(proof.EstablishedBy is not ValidationObjectIdentity establishedBy || !establishedBy.Equals(identity))
            {
                continue;
            }

            if(FindRepresentation(described, proof.ObjectIdentity) is not SensitiveMemory representation)
            {
                continue;
            }

            int group = instants.IndexOf(proof.Instant);
            if(group < 0)
            {
                instants.Add(proof.Instant);
                covered.Add([]);
                group = instants.Count - 1;
            }

            if(!covered[group].Contains(representation))
            {
                covered[group].Add(representation);
            }
        }

        for(int i = 0; i < instants.Count; ++i)
        {
            provisioning.Add(new ProofOfExistenceProvisioning { ProofTime = instants[i], CoveredObjects = covered[i] });
        }

        return provisioning;

        //Finds the object a proof is about among the ones the report projects, by the identity each was
        //described with; an object the report does not project has no representation to name.
        static SensitiveMemory? FindRepresentation(List<DescribedValidationObject> described, ValidationObjectIdentity objectIdentity)
        {
            for(int i = 0; i < described.Count; ++i)
            {
                if(described[i].Identity is ValidationObjectIdentity candidate && candidate.Equals(objectIdentity))
                {
                    return described[i].Representation;
                }
            }

            return null;
        }
    }


    /// <summary>
    /// One object the report projects, with the canonical identity the accumulated proofs of existence name it
    /// by — the pairing clauses 4.4.6 and 4.4.7 both need and which is computed once per object.
    /// </summary>
    /// <param name="Kind">The object's type (clause 4.4.4).</param>
    /// <param name="Representation">The object itself (clause 4.4.5), a non-owning reference to memory the run owns.</param>
    /// <param name="Identity">The identity the proofs name it by, or <see langword="null"/> when no long-term run accumulated proofs.</param>
    private sealed record DescribedValidationObject(
        ValidationObjectKind Kind,
        SensitiveMemory Representation,
        ValidationObjectIdentity? Identity);
}
