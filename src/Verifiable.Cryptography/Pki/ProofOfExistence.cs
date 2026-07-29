using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What an object a proof of existence is about actually is, so that a report can name it and the past
/// validation building blocks of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.6.2</see> can ask about the right kind of object — clause 5.6.2.4 asks
/// separately about the signature value, the signing certificate's issuer certificate, and the revocation data
/// containing the revocation status information of the signing certificate.
/// </summary>
public enum ValidationObjectKind
{
    /// <summary>Not a stated kind: the value of an unset field. An identity carrying it names no object anything can be asserted about.</summary>
    Unknown = 0,

    /// <summary>The signature value itself — the object clause 5.6.2.4 calls "the signature value" when determining best-signature-time.</summary>
    SignatureValue = 1,

    /// <summary>The signature as a whole, including its attributes.</summary>
    Signature = 2,

    /// <summary>A Signed Data Object, or a signer's document representation of one.</summary>
    SignedDataObject = 3,

    /// <summary>One signed or unsigned attribute of the signature.</summary>
    SignatureAttribute = 4,

    /// <summary>An X.509 certificate.</summary>
    Certificate = 5,

    /// <summary>Revocation data — a CRL or an OCSP response — containing revocation status information.</summary>
    RevocationData = 6,

    /// <summary>An RFC 3161 time-stamp token.</summary>
    TimestampToken = 7,

    /// <summary>An evidence record or comparable long-term preservation evidence.</summary>
    EvidenceRecord = 8
}


/// <summary>
/// The identity of one object a proof of existence can be about: what the object is, plus the digest that
/// distinguishes it from every other object of that kind.
/// </summary>
/// <remarks>
/// <para>
/// The digest is the identity because the objects the POE machinery of clause 5.6.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> reasons about reach it exactly that way — as references carrying "a hash
/// value of the referenced object O". <see cref="DigestAlgorithm"/> is carried alongside the
/// <see cref="DigestValue"/> and takes part in equality on purpose: a <see cref="DigestValue"/>'s own equality
/// is byte-level only, by that type's documented design, so two digests of different objects under different
/// algorithms could otherwise compare equal by accident.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="Digest"/> is a non-owning reference to a carrier the validation run
/// owns. An identity, and any <see cref="ProofOfExistenceSet"/> holding one, must not outlive the digest it
/// points at; disposing an identity disposes nothing.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record ValidationObjectIdentity
{
    /// <summary>What the object is.</summary>
    public required ValidationObjectKind Kind { get; init; }

    /// <summary>A non-owning reference to the digest of the object under <see cref="DigestAlgorithm"/>.</summary>
    public required DigestValue Digest { get; init; }

    /// <summary>The algorithm <see cref="Digest"/> was computed with.</summary>
    public required AlgorithmIdentifier DigestAlgorithm { get; init; }

    /// <summary>
    /// The object's own identifier where its format supplies one — a URI, an OID, a certificate's issuer and
    /// serial — for a report to present; <see langword="null"/> when the format supplies none. Part of
    /// equality, so two objects a format distinguishes by reference stay distinct even where their digests
    /// were computed over the same bytes.
    /// </summary>
    public string? Reference { get; init; }


    /// <summary>
    /// Determines whether two identities name the same object, comparing the kind, the digest algorithm, the
    /// reference ordinally, and the digest bytes.
    /// </summary>
    /// <param name="other">The identity to compare with.</param>
    /// <returns><see langword="true"/> when both name the same object.</returns>
    public bool Equals(ValidationObjectIdentity? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Kind == other.Kind
            && DigestAlgorithm.Equals(other.DigestAlgorithm)
            && string.Equals(Reference, other.Reference, StringComparison.Ordinal)
            && Digest.AsReadOnlySpan().SequenceEqual(other.Digest.AsReadOnlySpan());
    }


    /// <summary>Returns a hash code over the same members <see cref="Equals(ValidationObjectIdentity)"/> compares.</summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Kind);
        hash.Add(DigestAlgorithm);
        hash.Add(Reference, StringComparer.Ordinal);
        hash.AddBytes(Digest.AsReadOnlySpan());

        return hash.ToHashCode();
    }


    private string DebuggerDisplay => $"ValidationObjectIdentity[{Kind}, {DigestAlgorithm.Name ?? DigestAlgorithm.Oid}, {Reference ?? "no reference"}]";
}


/// <summary>
/// Whether a proof of existence proves the object itself existed, or only that a digest of it existed — the
/// distinction steps 4)a) and 5) of clause 5.6.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> draw when a time-stamp covers a reference carrying a hash value rather than
/// the referenced object.
/// </summary>
public enum ProofOfExistenceScope
{
    /// <summary>Not a stated scope: the value of an unset field, which proves nothing. Membership queries never match it.</summary>
    Unknown = 0,

    /// <summary>The object itself is proven to have existed at the instant — the proof step 5) adds for each object contained in the set S, and the proof step 4)b) derives indirectly.</summary>
    Object = 1,

    /// <summary>Only a digest of the object is proven to have existed at the instant — the proof step 4)a) adds for the hash value h(O) of an object O.</summary>
    DigestOfObject = 2
}


/// <summary>
/// Where a proof of existence came from, so that a report can attribute it and the extraction building block
/// can distinguish a directly established proof from one derived indirectly.
/// </summary>
public enum ProofOfExistenceOrigin
{
    /// <summary>Not a stated origin: the value of an unset field.</summary>
    Unknown = 0,

    /// <summary>Established by a validated time-stamp token covering the object, per clause 5.6.2.3 step 5).</summary>
    TimestampToken = 1,

    /// <summary>Established by an evidence record or comparable long-term preservation evidence covering the object.</summary>
    EvidenceRecord = 2,

    /// <summary>Asserted by the Driving Application — the "time indication for signature existence" input of Table 20 of clause 5.5.2.</summary>
    DrivingApplicationAssertion = 3,

    /// <summary>Derived indirectly by clause 5.6.2.3 step 4)b) from a proof for a digest plus a later proof for the object, gated on the hash function's asserted reliability.</summary>
    IndirectDerivation = 4
}


/// <summary>
/// One proof of existence: the assertion that a named object — or a digest of it — existed at a stated
/// instant, per clause 5.6.2.3 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see>.
/// </summary>
/// <remarks>
/// This is the data model only. Deriving proofs from a time-stamp — determining the set S of protected
/// objects, adding the direct proofs of step 5) and the indirect proofs of step 4)b) — is the POE extraction
/// building block's own work, which composes this record and <see cref="ProofOfExistenceSet"/>.
/// </remarks>
[DebuggerDisplay("ProofOfExistence: {Scope} of {ObjectIdentity} at {Instant} from {Origin}")]
public sealed record ProofOfExistence
{
    /// <summary>The object the proof is about.</summary>
    public required ValidationObjectIdentity ObjectIdentity { get; init; }

    /// <summary>The instant at which the object — or its digest, per <see cref="Scope"/> — is proven to have existed.</summary>
    public required DateTimeOffset Instant { get; init; }

    /// <summary>Whether the proof covers the object itself or only a digest of it.</summary>
    public required ProofOfExistenceScope Scope { get; init; }

    /// <summary>Where the proof came from.</summary>
    public required ProofOfExistenceOrigin Origin { get; init; }

    /// <summary>
    /// The hash function the covering reference used, when <see cref="Scope"/> is
    /// <see cref="ProofOfExistenceScope.DigestOfObject"/> — the function h whose asserted reliability steps
    /// 4)a) and 4)b) gate the derivation on. <see langword="null"/> for a proof of the object itself.
    /// </summary>
    public AlgorithmIdentifier? ReferenceDigestAlgorithm { get; init; }

    /// <summary>
    /// The identity of the object that established the proof — the time-stamp token or evidence record —
    /// where one did; <see langword="null"/> for a proof the Driving Application asserted.
    /// </summary>
    public ValidationObjectIdentity? EstablishedBy { get; init; }
}


/// <summary>
/// A set of proofs of existence, with the membership queries the past validation building blocks of clause
/// 5.6.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1</see> ask of it — "the set of POEs contains a proof of existence of the
/// certificate and the revocation data ... at (or before) control-time" (clause 5.6.2.2 step 2)a)), "if there
/// is a POE of the signature value at (or before) the validation time" (clause 5.6.2.4 step 3)), and "the
/// lowest time at which there exists a POE for the signature value in the set of POEs" (clause 5.6.2.4 step
/// 3)).
/// </summary>
/// <remarks>
/// <para>
/// Immutable: every operation that adds proofs returns a new set, matching clause 5.6.2.3, whose extraction
/// building block "shall return a set P of POEs" that the caller then unions into the set it holds. Adding a
/// proof already present returns a set with the same contents, so repeatedly extracting from the same
/// time-stamp does not grow the set.
/// </para>
/// <para>
/// Queries scan <see cref="Proofs"/> linearly and iteratively; there is no recursion and no index whose
/// consistency would have to be maintained. A validation run accumulates proofs from the archive and signature
/// time-stamps of one signature, which is a small collection.
/// </para>
/// <para>
/// <strong>Ownership.</strong> The identities a set holds carry non-owning references to caller-owned digests,
/// so a set must not outlive them.
/// </para>
/// </remarks>
[DebuggerDisplay("ProofOfExistenceSet: {Proofs.Count} proofs")]
public sealed class ProofOfExistenceSet
{
    /// <summary>The proofs in this set, in the order they were added.</summary>
    public IReadOnlyList<ProofOfExistence> Proofs { get; }


    /// <summary>Initializes a set over an already-deduplicated list.</summary>
    /// <param name="proofs">The proofs, which the caller has ensured contain no duplicates.</param>
    private ProofOfExistenceSet(IReadOnlyList<ProofOfExistence> proofs)
    {
        Proofs = proofs;
    }


    /// <summary>The empty set — the initial value of the set P of clause 5.6.2.3 step 3), and the "may be empty" input of Table 25.</summary>
    public static ProofOfExistenceSet Empty { get; } = new([]);


    /// <summary>
    /// Creates a set from a sequence of proofs, discarding duplicates.
    /// </summary>
    /// <param name="proofs">The proofs to include.</param>
    /// <returns>The set.</returns>
    public static ProofOfExistenceSet Create(IReadOnlyList<ProofOfExistence> proofs)
    {
        ArgumentNullException.ThrowIfNull(proofs);

        return Empty.WithRange(proofs);
    }


    /// <summary>
    /// Returns a set containing this set's proofs plus one more, or this set unchanged when it already
    /// contains an equal proof.
    /// </summary>
    /// <param name="proof">The proof to add.</param>
    /// <returns>The resulting set.</returns>
    public ProofOfExistenceSet With(ProofOfExistence proof)
    {
        ArgumentNullException.ThrowIfNull(proof);

        if(Contains(proof))
        {
            return this;
        }

        List<ProofOfExistence> combined = new(Proofs.Count + 1);
        combined.AddRange(Proofs);
        combined.Add(proof);

        return new ProofOfExistenceSet(combined);
    }


    /// <summary>
    /// Returns a set containing this set's proofs plus every one of a sequence that this set does not already
    /// contain.
    /// </summary>
    /// <param name="proofs">The proofs to add.</param>
    /// <returns>The resulting set.</returns>
    public ProofOfExistenceSet WithRange(IReadOnlyList<ProofOfExistence> proofs)
    {
        ArgumentNullException.ThrowIfNull(proofs);

        List<ProofOfExistence> combined = new(Proofs.Count + proofs.Count);
        combined.AddRange(Proofs);

        bool added = false;
        for(int i = 0; i < proofs.Count; ++i)
        {
            ProofOfExistence candidate = proofs[i];
            ArgumentNullException.ThrowIfNull(candidate);

            if(!combined.Contains(candidate))
            {
                combined.Add(candidate);
                added = true;
            }
        }

        return added ? new ProofOfExistenceSet(combined) : this;
    }


    /// <summary>
    /// Returns the union of this set and another — the operation a caller performs on the set the POE
    /// extraction building block returns.
    /// </summary>
    /// <param name="other">The set to union with.</param>
    /// <returns>The resulting set.</returns>
    public ProofOfExistenceSet Union(ProofOfExistenceSet other)
    {
        ArgumentNullException.ThrowIfNull(other);

        return WithRange(other.Proofs);
    }


    /// <summary>Determines whether this set already contains an equal proof.</summary>
    /// <param name="proof">The proof to look for.</param>
    /// <returns><see langword="true"/> when an equal proof is present.</returns>
    public bool Contains(ProofOfExistence proof)
    {
        ArgumentNullException.ThrowIfNull(proof);

        for(int i = 0; i < Proofs.Count; ++i)
        {
            if(Proofs[i].Equals(proof))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Determines whether this set proves the object itself existed at or before an instant — the
    /// "the set of POEs contains a proof of existence of ... at (or before) control-time" query of clause
    /// 5.6.2.2 step 2)a) and the "if there is a POE of the signature value at (or before) the validation time"
    /// query of clause 5.6.2.4 step 3).
    /// </summary>
    /// <param name="objectIdentity">The object to ask about.</param>
    /// <param name="instant">The instant the proof has to be at or before.</param>
    /// <returns><see langword="true"/> when a proof of scope <see cref="ProofOfExistenceScope.Object"/> for that object exists at or before <paramref name="instant"/>.</returns>
    public bool ExistsAtOrBefore(ValidationObjectIdentity objectIdentity, DateTimeOffset instant)
    {
        ArgumentNullException.ThrowIfNull(objectIdentity);

        for(int i = 0; i < Proofs.Count; ++i)
        {
            ProofOfExistence proof = Proofs[i];
            if(proof.Scope == ProofOfExistenceScope.Object
                && proof.Instant <= instant
                && proof.ObjectIdentity.Equals(objectIdentity))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Determines whether this set proves a digest of the object, taken under a stated hash function, existed
    /// at or before an instant — the "there is a POE for h(DATA) at a date T1" premise of clause 5.6.2.3.1 and
    /// the proofs step 4)a) adds.
    /// </summary>
    /// <param name="objectIdentity">The object whose digest to ask about.</param>
    /// <param name="referenceDigestAlgorithm">The hash function the covering reference used.</param>
    /// <param name="instant">The instant the proof has to be at or before.</param>
    /// <returns><see langword="true"/> when such a proof exists at or before <paramref name="instant"/>.</returns>
    public bool DigestExistsAtOrBefore(ValidationObjectIdentity objectIdentity, AlgorithmIdentifier referenceDigestAlgorithm, DateTimeOffset instant)
    {
        ArgumentNullException.ThrowIfNull(objectIdentity);

        for(int i = 0; i < Proofs.Count; ++i)
        {
            ProofOfExistence proof = Proofs[i];
            if(proof.Scope == ProofOfExistenceScope.DigestOfObject
                && proof.Instant <= instant
                && proof.ReferenceDigestAlgorithm is AlgorithmIdentifier algorithm
                && algorithm.Equals(referenceDigestAlgorithm)
                && proof.ObjectIdentity.Equals(objectIdentity))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// States the earliest instant this set proves the object itself existed at — "the lowest time at which
    /// there exists a POE for the signature value in the set of POEs", which clause 5.6.2.4 step 3) reads as
    /// best-signature-time, and the time clause 5.6.2.4 step 5)a) determines before re-running the revocation
    /// freshness checker.
    /// </summary>
    /// <param name="objectIdentity">The object to ask about.</param>
    /// <returns>The earliest instant, or <see langword="null"/> when this set proves nothing about that object.</returns>
    public DateTimeOffset? EarliestInstantFor(ValidationObjectIdentity objectIdentity)
    {
        ArgumentNullException.ThrowIfNull(objectIdentity);

        DateTimeOffset? earliest = null;
        for(int i = 0; i < Proofs.Count; ++i)
        {
            ProofOfExistence proof = Proofs[i];
            if(proof.Scope == ProofOfExistenceScope.Object
                && proof.ObjectIdentity.Equals(objectIdentity)
                && (earliest is null || proof.Instant < earliest))
            {
                earliest = proof.Instant;
            }
        }

        return earliest;
    }


    /// <summary>
    /// States the earliest instant this set proves a digest of the object, taken under a stated hash function,
    /// existed at — the date T1 of the indirect derivation of clause 5.6.2.3.1.
    /// </summary>
    /// <param name="objectIdentity">The object whose digest to ask about.</param>
    /// <param name="referenceDigestAlgorithm">The hash function the covering reference used.</param>
    /// <returns>The earliest instant, or <see langword="null"/> when this set proves nothing about that digest.</returns>
    public DateTimeOffset? EarliestDigestInstantFor(ValidationObjectIdentity objectIdentity, AlgorithmIdentifier referenceDigestAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(objectIdentity);

        DateTimeOffset? earliest = null;
        for(int i = 0; i < Proofs.Count; ++i)
        {
            ProofOfExistence proof = Proofs[i];
            if(proof.Scope == ProofOfExistenceScope.DigestOfObject
                && proof.ReferenceDigestAlgorithm is AlgorithmIdentifier algorithm
                && algorithm.Equals(referenceDigestAlgorithm)
                && proof.ObjectIdentity.Equals(objectIdentity)
                && (earliest is null || proof.Instant < earliest))
            {
                earliest = proof.Instant;
            }
        }

        return earliest;
    }


    /// <summary>
    /// Returns every proof this set holds about one object, whatever their scope — the material a report needs
    /// to explain why a past validation step did or did not find the proof it required.
    /// </summary>
    /// <param name="objectIdentity">The object to ask about.</param>
    /// <returns>The proofs, in the order they were added; empty when this set holds none.</returns>
    public IReadOnlyList<ProofOfExistence> For(ValidationObjectIdentity objectIdentity)
    {
        ArgumentNullException.ThrowIfNull(objectIdentity);

        List<ProofOfExistence> matches = [];
        for(int i = 0; i < Proofs.Count; ++i)
        {
            if(Proofs[i].ObjectIdentity.Equals(objectIdentity))
            {
                matches.Add(Proofs[i]);
            }
        }

        return matches;
    }
}
