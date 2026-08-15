using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One object an Evidence Record supplied to a signature validation run is claimed to protect, together with what
/// the object is, so a proof of existence the record establishes can be named in the vocabulary the past
/// validation building blocks of clause 5.6.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> ask about.
/// </summary>
/// <remarks>
/// <para>
/// An Evidence Record proves the existence of the <em>data objects</em> its initial reduced hash tree carries
/// (<see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.3">IETF RFC 4998 clause 4.3</see>), and what those
/// objects are is not stated anywhere inside the record: the record holds hash values only. The Driving
/// Application therefore names them, exactly as clause 5.6.3.2's Table 27 has it name the Signed Data Object.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="Object"/> is a non-owning reference to memory the caller owns for at
/// least the duration of the validation run.
/// </para>
/// </remarks>
[DebuggerDisplay("EvidenceRecordProtectedObject: {Kind}, {Reference}")]
public sealed record EvidenceRecordProtectedObject
{
    /// <summary>The object's octets, as the Evidence Record's hash tree was built over them.</summary>
    public required SensitiveMemory Object { get; init; }

    /// <summary>What the object is, which takes part in the identity a proof of existence names it by.</summary>
    public required ValidationObjectKind Kind { get; init; }

    /// <summary>The object's own identifier where the caller has one — a container entry name, a URI — for a report to present; <see langword="null"/> when it has none.</summary>
    public string? Reference { get; init; }
}


/// <summary>
/// One Evidence Record accompanying the signature under validation — the input step 1) of clause 5.6.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> validates "according to
/// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see> or
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>".
/// </summary>
/// <remarks>
/// <para>
/// Only the <see href="https://www.rfc-editor.org/rfc/rfc4998">RFC 4998</see> form reaches this input, because
/// only that form has a shipped verification (the XML form of RFC 6283 is refused with a typed status wherever it
/// is met, never silently skipped). An Evidence Record whose octets a caller holds in the XML form has no
/// <see cref="EvidenceRecord"/> to build.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the caller owns for at
/// least the duration of the validation run.
/// </para>
/// </remarks>
[DebuggerDisplay("EvidenceRecordValidationInput: {ProtectedObjects.Count} protected objects, {Identifier}")]
public sealed record EvidenceRecordValidationInput
{
    /// <summary>The Evidence Record to verify.</summary>
    public required EvidenceRecord EvidenceRecord { get; init; }

    /// <summary>The objects the record is claimed to protect; a record protecting none proves nothing and is reported as such.</summary>
    public required IReadOnlyList<EvidenceRecordProtectedObject> ProtectedObjects { get; init; }

    /// <summary>
    /// The record's own identifier where the caller has one — the container entry name it was read from, for
    /// example — which takes part in the identity a report and a proof of existence name the record by;
    /// <see langword="null"/> when it has none.
    /// </summary>
    public string? Identifier { get; init; }
}


/// <summary>
/// What step 1) of clause 5.6.3.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> concluded about one Evidence Record: what
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">RFC 4998 clause 5.3</see> made of its
/// structure, what the time-stamp validation building block of clause 5.4 made of the time-stamp the step also
/// requires validated, and which of the objects the caller named the record actually carries.
/// </summary>
/// <remarks>
/// <para>
/// The step states two obligations and this record answers both separately, because a record can satisfy one and
/// not the other: a structurally sound record whose most recent time-stamp does not validate establishes no proof
/// of existence, and neither does a record with a perfectly good time-stamp over a hash tree that does not carry
/// the object.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns.
/// </para>
/// </remarks>
[DebuggerDisplay("EvidenceRecordValidationResult: {Status}, {ProvenObjectCount} of {ProtectedObjects.Count} proven")]
public sealed record EvidenceRecordValidationResult
{
    /// <summary>The record that was validated.</summary>
    public required EvidenceRecord EvidenceRecord { get; init; }

    /// <summary>The record's identifier, as the input stated it.</summary>
    public string? Identifier { get; init; }

    /// <summary>The identity a proof of existence this record established names it by, and a report projects it as.</summary>
    public required ValidationObjectIdentity Identity { get; init; }

    /// <summary>
    /// What RFC 4998 clause 5.3 made of the record over the objects the caller named: the status of the first
    /// object the record does carry, or the status of the first object when it carries none.
    /// </summary>
    public required EvidenceRecordVerificationStatus Status { get; init; }

    /// <summary>The objects the caller named as protected, with what the record made of each.</summary>
    public required IReadOnlyList<EvidenceRecordProtectedObjectResult> ProtectedObjects { get; init; }

    /// <summary>What the time-stamp validation building block of clause 5.4 made of the record's most recent Archive Timestamp — the one clause 5.3 requires "to be valid at the time the verification is performed"; <see langword="null"/> when the run supplied no seams to validate it with.</summary>
    public TimestampValidationResult? ArchiveTimestampValidation { get; init; }

    /// <summary>The <c>genTime</c> of the record's initial Archive Timestamp — the instant a proof this record establishes is stated at; <see langword="null"/> when the record states none.</summary>
    public DateTimeOffset? InitialArchiveTime { get; init; }

    /// <summary>The <c>genTime</c> of the record's most recent Archive Timestamp; <see langword="null"/> when the record states none.</summary>
    public DateTimeOffset? LatestArchiveTime { get; init; }

    /// <summary>
    /// The <c>ArchiveTimeStampChain</c> digest algorithms the caller's cryptographic constraints do not assert
    /// reliable at the instant step 2 d) of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.3">RFC 4998 clause 5.3</see> names — the
    /// generation time of the first Archive Timestamp of the chain that follows, and the validation time for the
    /// most recent chain. A record with any entry here establishes no proof of existence, because the instant its
    /// initial Archive Timestamp states is carried forward by exactly those algorithms.
    /// </summary>
    /// <remarks>
    /// Empty in the two cases a caller must not confuse: every chain algorithm was asserted reliable, and no
    /// table was supplied at all. The material identifiers name the chain by its position in the sequence, which
    /// is what a <c>CRYPTO_CONSTRAINTS_FAILURE</c> report of Table 6 of EN 319 102-1 clause 5.1.3 presents.
    /// </remarks>
    public IReadOnlyList<AlgorithmReliabilityAssessment> UnreliableChainAlgorithms { get; init; } = [];

    /// <summary>Whether the record established any proof of existence at all — its structure held, its most recent time-stamp validated, and at least one named object is carried by its hash tree.</summary>
    public bool EstablishedProofOfExistence { get; init; }


    /// <summary>How many of the named objects the record proved.</summary>
    private int ProvenObjectCount
    {
        get
        {
            int count = 0;
            for(int i = 0; i < ProtectedObjects.Count; ++i)
            {
                count += ProtectedObjects[i].IsProven ? 1 : 0;
            }

            return count;
        }
    }
}


/// <summary>
/// What one Evidence Record made of one object the Driving Application named as protected.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Every carrier here is a non-owning reference to memory the validation run owns.
/// </remarks>
[DebuggerDisplay("EvidenceRecordProtectedObjectResult: {Kind}, {Status}, {Reference}")]
public sealed record EvidenceRecordProtectedObjectResult
{
    /// <summary>The object the record was asked about.</summary>
    public required SensitiveMemory Object { get; init; }

    /// <summary>What the object is.</summary>
    public required ValidationObjectKind Kind { get; init; }

    /// <summary>The object's identifier, as the input stated it.</summary>
    public string? Reference { get; init; }

    /// <summary>What RFC 4998 clause 5.3 made of the record over this object.</summary>
    public required EvidenceRecordVerificationStatus Status { get; init; }

    /// <summary>
    /// The instant the record's own unbroken run of proofs carries this object to — the value
    /// <see cref="EvidenceRecordVerification.CoveredUntil"/> states, which is not in general the record's most
    /// recent Archive Timestamp; <see langword="null"/> when even the initial one does not carry the object.
    /// </summary>
    public DateTimeOffset? CoveredUntil { get; init; }

    /// <summary>Whether the record carries this object and everything the step requires held, so a proof of existence was established for it.</summary>
    public bool IsProven { get; init; }
}
