using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The identity of a cryptographic algorithm a cryptographic constraint is stated about, keyed by its
/// dotted-decimal object identifier — the identity every DER structure the validation algorithm reads
/// (a certificate's <c>signatureAlgorithm</c>, a CMS <c>digestAlgorithm</c>, an RFC 3161
/// <c>messageImprint.hashAlgorithm</c>, an OCSP <c>CertID.hashAlgorithm</c>) carries on the wire.
/// </summary>
/// <remarks>
/// <para>
/// Anchored to the cryptographic constraints of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.3</see>, which state "requirements on algorithms and parameters used
/// when creating signatures or used when validating signed objects".
/// </para>
/// <para>
/// Only the digest algorithms this library already names in <see cref="WellKnownOids"/> are provided as
/// curated statics: those are the identities the hash-reliability gating of clause 5.6.2.3 and the
/// message-imprint checks of clause 5.4 consult by name. Signature-algorithm identities are read off the
/// material under validation at run time, so a caller mints them from the identifier the DER carried rather
/// than picking one from a list.
/// </para>
/// <para>
/// The optional <see cref="Name"/> carries a human-readable label for reports; it takes no part in equality,
/// which is by <see cref="Oid"/> alone, so a table entry and a use-site identifier for the same algorithm
/// match whether or not either supplied a label.
/// </para>
/// </remarks>
/// <param name="Oid">The dotted-decimal object identifier of the algorithm.</param>
[DebuggerDisplay("AlgorithmIdentifier: {Oid}")]
public readonly record struct AlgorithmIdentifier(string Oid)
{
    /// <summary>A human-readable label for reports, or <see langword="null"/> when none was supplied. Not part of equality.</summary>
    public string? Name { get; init; }


    /// <summary>The SHA-1 digest algorithm (OID 1.3.14.3.2.26).</summary>
    public static AlgorithmIdentifier Sha1 { get; } = new(WellKnownOids.Sha1) { Name = WellKnownHashAlgorithms.Sha1 };

    /// <summary>The SHA-256 digest algorithm (OID 2.16.840.1.101.3.4.2.1).</summary>
    public static AlgorithmIdentifier Sha256 { get; } = new(WellKnownOids.Sha256) { Name = WellKnownHashAlgorithms.Sha256 };

    /// <summary>The SHA-384 digest algorithm (OID 2.16.840.1.101.3.4.2.2).</summary>
    public static AlgorithmIdentifier Sha384 { get; } = new(WellKnownOids.Sha384) { Name = WellKnownHashAlgorithms.Sha384 };

    /// <summary>The SHA-512 digest algorithm (OID 2.16.840.1.101.3.4.2.3).</summary>
    public static AlgorithmIdentifier Sha512 { get; } = new(WellKnownOids.Sha512) { Name = WellKnownHashAlgorithms.Sha512 };


    /// <summary>
    /// Determines whether two identifiers name the same algorithm, comparing <see cref="Oid"/> ordinally and
    /// ignoring <see cref="Name"/>.
    /// </summary>
    /// <param name="other">The identifier to compare with.</param>
    /// <returns><see langword="true"/> when both name the same object identifier.</returns>
    public bool Equals(AlgorithmIdentifier other) => string.Equals(Oid, other.Oid, StringComparison.Ordinal);


    /// <summary>Returns a hash code derived from <see cref="Oid"/> alone, consistent with <see cref="Equals(AlgorithmIdentifier)"/>.</summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => Oid is null ? 0 : StringComparer.Ordinal.GetHashCode(Oid);


    /// <summary>
    /// Maps a framework hash algorithm name to its object identifier, for callers holding a
    /// <see cref="HashAlgorithmName"/> rather than an OID.
    /// </summary>
    /// <param name="hashAlgorithmName">The hash algorithm name.</param>
    /// <param name="identifier">The matching identifier when this method returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when the name is one of the digest algorithms named here.</returns>
    public static bool TryFromHashAlgorithmName(HashAlgorithmName hashAlgorithmName, out AlgorithmIdentifier identifier)
    {
        identifier = hashAlgorithmName.Name switch
        {
            WellKnownHashAlgorithms.Sha1 => Sha1,
            WellKnownHashAlgorithms.Sha256 => Sha256,
            WellKnownHashAlgorithms.Sha384 => Sha384,
            WellKnownHashAlgorithms.Sha512 => Sha512,
            _ => default
        };

        return identifier.Oid is not null;
    }


    /// <summary>
    /// Maps the hash algorithm a <see cref="Tag"/> carries — the algorithm-agile identity the registered
    /// digest seam dispatches on — to its object identifier, so a cryptographic constraints table keyed by
    /// OID can be consulted about a digest the library computed through that seam.
    /// </summary>
    /// <param name="tag">The tag to read the hash algorithm from.</param>
    /// <param name="identifier">The matching identifier when this method returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when the tag carries a hash algorithm name this type names.</returns>
    public static bool TryFromTag(Tag tag, out AlgorithmIdentifier identifier)
    {
        ArgumentNullException.ThrowIfNull(tag);

        if(tag.TryGet(out HashAlgorithmName hashAlgorithmName))
        {
            return TryFromHashAlgorithmName(hashAlgorithmName, out identifier);
        }

        identifier = default;

        return false;
    }
}


/// <summary>
/// One row of the dated algorithm-reliability table the cryptographic constraints of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.3</see> consist of: an algorithm, the smallest key size accepted with
/// it, and the instant up to which it is asserted reliable.
/// </summary>
/// <remarks>
/// The "trusted until" instant is the one Table 6 asks a <c>CRYPTO_CONSTRAINTS_FAILURE</c> report to carry
/// ("if known, the time up to which the algorithm or key size were considered secure"), the one step 2)d) of
/// clause 5.6.2.2 slides control-time back to, and the one steps 4)a) and 4)b) of clause 5.6.2.3 gate hash
/// reliability on. A table of these rows is caller-supplied input; this library ships no default table, since
/// the values belong to a dated cryptographic-suites publication rather than to source code.
/// </remarks>
/// <param name="Algorithm">The algorithm the row is about.</param>
/// <param name="MinimumKeySizeBits">The smallest key size, in bits, accepted with <paramref name="Algorithm"/>; <see langword="null"/> when the algorithm takes no key (a hash function) or the table sets no floor.</param>
/// <param name="TrustedUntil">The instant up to which the algorithm is asserted reliable; <see langword="null"/> when the table asserts no expiry, the "if such a time is known" case Table 6 allows for.</param>
[DebuggerDisplay("AlgorithmReliabilityEntry: {Algorithm.Oid}, min {MinimumKeySizeBits} bits, until {TrustedUntil}")]
public sealed record AlgorithmReliabilityEntry(
    AlgorithmIdentifier Algorithm,
    int? MinimumKeySizeBits,
    DateTimeOffset? TrustedUntil);


/// <summary>
/// One use of an algorithm by a concrete piece of material in the validation — the "identification of the
/// material (signature, certificate) that is produced using an algorithm or key size" Table 6 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.3</see> mandates a <c>CRYPTO_CONSTRAINTS_FAILURE</c> report to carry.
/// </summary>
/// <param name="Algorithm">The algorithm the material used.</param>
/// <param name="KeySizeBits">The key size in bits where the algorithm takes a key; <see langword="null"/> for a hash function.</param>
/// <param name="MaterialIdentifier">What used the algorithm, in terms a Driving Application can present — for example "signature value", a certificate's subject and serial, or a revocation data identifier.</param>
[DebuggerDisplay("AlgorithmUse: {MaterialIdentifier} uses {Algorithm.Oid} ({KeySizeBits} bits)")]
public sealed record AlgorithmUse(
    AlgorithmIdentifier Algorithm,
    int? KeySizeBits,
    string MaterialIdentifier);


/// <summary>
/// Why a cryptographic constraints table did or did not consider one <see cref="AlgorithmUse"/> reliable at an
/// instant.
/// </summary>
public enum AlgorithmReliabilityVerdict
{
    /// <summary>
    /// The table holds no row for the algorithm, so nothing asserts it reliable. Fail-closed, and the value of
    /// an unset field: clause 5.1.4.1 forbids a constraint set from forcing the SVA to skip a check that would
    /// otherwise lead to a determinate negative result, so an unlisted algorithm is never treated as reliable.
    /// </summary>
    Unknown = 0,

    /// <summary>The table lists the algorithm, the key size meets its floor, and the instant is at or before its trusted-until instant (or the table asserts no expiry).</summary>
    Reliable = 1,

    /// <summary>The table lists the algorithm but the material's key size is below the row's minimum.</summary>
    KeySizeBelowMinimum = 2,

    /// <summary>The table lists the algorithm and the key size meets its floor, but the instant is after the row's trusted-until instant.</summary>
    NoLongerReliable = 3
}


/// <summary>
/// What a cryptographic constraints table says about one <see cref="AlgorithmUse"/> at one instant.
/// </summary>
/// <param name="Use">The use assessed.</param>
/// <param name="Verdict">Why the use was or was not considered reliable.</param>
/// <param name="TrustedUntil">The instant up to which the table asserts the algorithm reliable, when it lists one; <see langword="null"/> when the algorithm is unlisted or the row asserts no expiry.</param>
[DebuggerDisplay("AlgorithmReliabilityAssessment: {Use.MaterialIdentifier} is {Verdict}")]
public sealed record AlgorithmReliabilityAssessment(
    AlgorithmUse Use,
    AlgorithmReliabilityVerdict Verdict,
    DateTimeOffset? TrustedUntil)
{
    /// <summary>Gets whether the table considered the use reliable at the assessed instant.</summary>
    public bool IsReliable => Verdict == AlgorithmReliabilityVerdict.Reliable;
}


/// <summary>
/// The cryptographic constraints of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1 V1.4.1 clause 5.1.4.3</see>: a dated table of algorithm-reliability rows the X.509
/// certificate validation (clause 5.2.6 step 6), the signature acceptance validation (clause 5.2.8.4.1), the
/// validation time sliding process (clause 5.6.2.2 step 2)d)) and the POE extraction building block (clause
/// 5.6.2.3 step 4) all consult.
/// </summary>
/// <remarks>
/// <para>
/// Pure caller-supplied declarative input. There is no parser for a formal policy artefact here — clause
/// 5.1.4.1 allows constraints to be defined by a formal policy specification, by system-specific control data,
/// or implicitly, and this record is the shape the algorithm consumes whichever of those the caller used.
/// </para>
/// <para>
/// Lookups scan <see cref="Entries"/> linearly. A cryptographic-suites table holds tens of rows, and a linear
/// scan keeps the record a plain value with no built index to keep consistent with its own contents.
/// </para>
/// </remarks>
[DebuggerDisplay("CryptographicConstraints: {Entries.Count} entries")]
public sealed record CryptographicConstraints
{
    /// <summary>The algorithm-reliability rows. An algorithm absent from this list is never considered reliable.</summary>
    public required IReadOnlyList<AlgorithmReliabilityEntry> Entries { get; init; }


    /// <summary>A table with no rows, under which no algorithm is reliable at any instant.</summary>
    public static CryptographicConstraints Empty { get; } = new() { Entries = [] };


    /// <summary>
    /// Finds the row stating the reliability of one algorithm.
    /// </summary>
    /// <param name="algorithm">The algorithm to look up.</param>
    /// <returns>The row, or <see langword="null"/> when the table lists no row for the algorithm.</returns>
    public AlgorithmReliabilityEntry? Find(AlgorithmIdentifier algorithm)
    {
        for(int i = 0; i < Entries.Count; ++i)
        {
            if(Entries[i].Algorithm.Equals(algorithm))
            {
                return Entries[i];
            }
        }

        return null;
    }


    /// <summary>
    /// States what this table says about one use of an algorithm at one instant.
    /// </summary>
    /// <param name="use">The use to assess.</param>
    /// <param name="instant">The instant to assess it at — the validation time, best-signature-time, or control-time, depending on which clause is asking.</param>
    /// <returns>The assessment.</returns>
    public AlgorithmReliabilityAssessment Assess(AlgorithmUse use, DateTimeOffset instant)
    {
        ArgumentNullException.ThrowIfNull(use);

        AlgorithmReliabilityEntry? entry = Find(use.Algorithm);
        if(entry is null)
        {
            return new AlgorithmReliabilityAssessment(use, AlgorithmReliabilityVerdict.Unknown, TrustedUntil: null);
        }

        if(entry.MinimumKeySizeBits is int minimumKeySizeBits && (use.KeySizeBits is null || use.KeySizeBits < minimumKeySizeBits))
        {
            return new AlgorithmReliabilityAssessment(use, AlgorithmReliabilityVerdict.KeySizeBelowMinimum, entry.TrustedUntil);
        }

        if(entry.TrustedUntil is DateTimeOffset trustedUntil && instant > trustedUntil)
        {
            return new AlgorithmReliabilityAssessment(use, AlgorithmReliabilityVerdict.NoLongerReliable, entry.TrustedUntil);
        }

        return new AlgorithmReliabilityAssessment(use, AlgorithmReliabilityVerdict.Reliable, entry.TrustedUntil);
    }


    /// <summary>
    /// States which of a set of algorithm uses this table does not consider reliable at one instant — the list
    /// Table 6 mandates a <c>CRYPTO_CONSTRAINTS_FAILURE</c> or <c>CRYPTO_CONSTRAINTS_FAILURE_NO_POE</c> report
    /// to carry, and the list clause 5.2.8.4.1 and clause 5.5.4 step 10 build.
    /// </summary>
    /// <param name="uses">The uses to assess.</param>
    /// <param name="instant">The instant to assess them at.</param>
    /// <returns>The assessments whose verdict is not <see cref="AlgorithmReliabilityVerdict.Reliable"/>, in the order the uses were given; empty when every use is reliable.</returns>
    public IReadOnlyList<AlgorithmReliabilityAssessment> FindUnreliable(IReadOnlyList<AlgorithmUse> uses, DateTimeOffset instant)
    {
        ArgumentNullException.ThrowIfNull(uses);

        List<AlgorithmReliabilityAssessment> unreliable = [];
        for(int i = 0; i < uses.Count; ++i)
        {
            AlgorithmReliabilityAssessment assessment = Assess(uses[i], instant);
            if(!assessment.IsReliable)
            {
                unreliable.Add(assessment);
            }
        }

        return unreliable;
    }


    /// <summary>
    /// States the latest instant up to which every one of a set of algorithm uses was considered reliable —
    /// the value step 2)d) of clause 5.6.2.2 slides control-time back to when a certificate or its revocation
    /// data does not match the cryptographic constraints.
    /// </summary>
    /// <param name="uses">The uses to consider.</param>
    /// <returns>
    /// The earliest of the listed trusted-until instants, which is the latest instant all of them were reliable;
    /// <see langword="null"/> when the table lists no row for one of the algorithms or one of the key sizes is
    /// below its row's floor (no instant can be asserted), and also <see langword="null"/> when every listed row
    /// asserts no expiry (no instant needs to be asserted). A caller distinguishes the two by asking
    /// <see cref="FindUnreliable"/> first.
    /// </returns>
    public DateTimeOffset? LatestInstantAllReliable(IReadOnlyList<AlgorithmUse> uses)
    {
        ArgumentNullException.ThrowIfNull(uses);

        DateTimeOffset? earliest = null;
        for(int i = 0; i < uses.Count; ++i)
        {
            AlgorithmReliabilityEntry? entry = Find(uses[i].Algorithm);
            if(entry is null)
            {
                return null;
            }

            if(entry.MinimumKeySizeBits is int minimumKeySizeBits && (uses[i].KeySizeBits is null || uses[i].KeySizeBits < minimumKeySizeBits))
            {
                return null;
            }

            if(entry.TrustedUntil is DateTimeOffset trustedUntil && (earliest is null || trustedUntil < earliest))
            {
                earliest = trustedUntil;
            }
        }

        return earliest;
    }


    /// <summary>
    /// States whether this table asserts a cryptographic hash function reliable at an instant — the gate step
    /// 4)b) of clause 5.6.2.3 puts on deriving a proof of existence for the referenced object ("h is asserted in
    /// the cryptographic constraints to be trusted until at least T2"), and the assumption clause 5.6.2.3.1
    /// states about a time-stamp's <c>messageImprint.hashAlgorithm</c>.
    /// </summary>
    /// <param name="hashAlgorithm">The hash function to ask about.</param>
    /// <param name="instant">The instant the hash function has to be reliable at or after.</param>
    /// <returns><see langword="true"/> when the table lists the hash function and asserts it trusted until at least <paramref name="instant"/>.</returns>
    public bool IsHashTrustedUntilAtLeast(AlgorithmIdentifier hashAlgorithm, DateTimeOffset instant)
    {
        AlgorithmReliabilityEntry? entry = Find(hashAlgorithm);

        return entry is not null && (entry.TrustedUntil is null || entry.TrustedUntil >= instant);
    }


    /// <summary>
    /// States whether this table asserts a cryptographic hash function reliable until strictly after an instant —
    /// the gate step 4) of clause 5.6.2.3 puts on reasoning over a reference at all: "the cryptographic hash
    /// function h is asserted in the cryptographic constraints to be trusted until at least a date <em>after</em>
    /// the time of the generation of the timestamp (named T1)".
    /// </summary>
    /// <param name="hashAlgorithm">The hash function to ask about.</param>
    /// <param name="instant">The instant the asserted reliability has to extend past.</param>
    /// <returns><see langword="true"/> when the table lists the hash function and asserts it trusted until a date after <paramref name="instant"/>.</returns>
    /// <remarks>
    /// The boundary case — a table row whose asserted reliability ends exactly at <paramref name="instant"/> —
    /// is the one this differs from <see cref="IsHashTrustedUntilAtLeast"/> in, and the clause's "a date after"
    /// excludes it.
    /// </remarks>
    public bool IsHashTrustedAfter(AlgorithmIdentifier hashAlgorithm, DateTimeOffset instant)
    {
        AlgorithmReliabilityEntry? entry = Find(hashAlgorithm);

        return entry is not null && (entry.TrustedUntil is null || entry.TrustedUntil > instant);
    }
}
