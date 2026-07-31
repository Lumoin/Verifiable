using System;
using System.Buffers;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One <c>PartialHashtree</c> of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.1">IETF RFC 4998 clause 4.1</see>: the hash
/// values that sit under one father node of a reduced hash tree, held in the binary ascending order clause 4.2
/// arranges them in.
/// </summary>
/// <remarks>
/// <para>
/// The syntax is <c>PartialHashtree ::= SEQUENCE OF OCTET STRING</c>. It is a <c>SEQUENCE OF</c> rather than a
/// <c>SET OF</c> precisely because the order is the payload: clause 4.3 step 3 concatenates the list's values in
/// the order they are encoded, so a canonical <c>SET OF</c> resort would silently change the hash the
/// concatenation produces.
/// </para>
/// <para>
/// The same type serves both directions. A generator fills it from the digests
/// <see cref="EvidenceRecordHashTree"/> computed while reducing a tree, and a verifier reads it as views into
/// the octets an <see cref="EvidenceRecord"/> owns. Nothing distinguishes the two, which is what keeps the one
/// Merkle implementation from drifting apart between generation and verification.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EvidenceRecordPartialHashtree
{
    /// <summary>
    /// Gets the hash values of this list, in the order they are encoded — which for a well-formed reduced hash
    /// tree is the binary ascending order of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.2">clause 4.2</see>.
    /// </summary>
    public required IReadOnlyList<ReadOnlyMemory<byte>> HashValues { get; init; }


    /// <summary>A short debugger string showing how many hash values the list holds.</summary>
    private string DebuggerDisplay => $"EvidenceRecordPartialHashtree({HashValues.Count} hash values)";
}


/// <summary>
/// One <c>ArchiveTimeStamp</c> of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-4.1">IETF RFC 4998 clause 4.1</see>: a reduced
/// hash tree for one archived data object together with the time-stamp taken over that tree's root.
/// </summary>
/// <remarks>
/// <para>
/// The syntax is:
/// </para>
/// <code>
/// ArchiveTimeStamp ::= SEQUENCE {
///   digestAlgorithm [0] AlgorithmIdentifier OPTIONAL,
///   attributes      [1] Attributes OPTIONAL,
///   reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
///   timeStamp       ContentInfo }
/// </code>
/// <para>
/// Every field but <c>timeStamp</c> is optional, so the degenerate form clause 4.2 explicitly admits — "An
/// Archive Timestamp may consist only of one list of hash-values and a timestamp or only a timestamp with no
/// hash value lists" — is a conformant value this type carries without complaint.
/// </para>
/// <para>
/// <strong>The octets are the value.</strong> <see cref="Encoding"/> is the whole <c>ArchiveTimeStamp</c>
/// element and <see cref="TimeStamp"/> the whole <c>ContentInfo</c> element, tag and length octets included,
/// both as views into the octets the owning <see cref="EvidenceRecord"/> holds. Clause 5.2's Timestamp Renewal
/// hashes the <c>timeStamp</c> field's encoding and its Hash-Tree Renewal hashes a standalone encoding of every
/// prior chain, so re-encoding a value that was read would silently break every renewal built on top of it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EvidenceRecordArchiveTimeStamp
{
    /// <summary>
    /// Gets the <c>digestAlgorithm</c> field, or <see langword="null"/> when it is absent. Clause 4.1 states
    /// that "If the optional field digestAlgorithm is not present, the digest algorithm of the timestamp MUST
    /// be used", which <see cref="EvidenceRecords"/> resolves from the embedded token's own message imprint.
    /// </summary>
    public AlgorithmIdentifier? DigestAlgorithm { get; init; }

    /// <summary>
    /// Gets the whole encodings of the members of the <c>attributes [1] Attributes</c> field, in the order they
    /// are encoded, or an empty list when the field is absent. <c>Attributes</c> is a <c>SET SIZE (1..MAX) OF
    /// Attribute</c>, so a writer emits them in the canonical order DER requires while a reader accepts whatever
    /// order it is shown.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Attributes { get; init; } = [];

    /// <summary>
    /// Gets the <c>reducedHashtree</c> lists, leaf level first, or an empty list when the field is absent — the
    /// path clause 4.3 walks from the archived data object's own hash up to the root the time-stamp covers.
    /// </summary>
    public IReadOnlyList<EvidenceRecordPartialHashtree> ReducedHashtree { get; init; } = [];

    /// <summary>
    /// Gets the whole encoding of the <c>timeStamp</c> field: a <c>ContentInfo</c> which clause 4.1 states
    /// "should contain the timestamp as defined in Section 1.3. (e.g., as defined with TimeStampToken in
    /// [RFC3161])", while permitting other forms that carry the same three facts.
    /// </summary>
    public required ReadOnlyMemory<byte> TimeStamp { get; init; }

    /// <summary>Gets the whole encoding of this <c>ArchiveTimeStamp</c>, tag and length octets included.</summary>
    public required ReadOnlyMemory<byte> Encoding { get; init; }


    /// <summary>A short debugger string showing the reduced tree's depth and whether the algorithm field is present.</summary>
    private string DebuggerDisplay =>
        $"EvidenceRecordArchiveTimeStamp({ReducedHashtree.Count} partial hash trees, algorithm {DigestAlgorithm?.Oid ?? "from time-stamp"})";
}


/// <summary>
/// One <c>ArchiveTimeStampChain</c> of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.1">IETF RFC 4998 clause 5.1</see>: the
/// <c>ArchiveTimeStamp</c> values a single Timestamp Renewal lineage accumulated, all under one hash algorithm.
/// </summary>
/// <remarks>
/// The syntax is <c>ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp</c>. Clause 5.1 binds two properties
/// on it: the members are "ordered ascending by time of timestamp", and "Within an ArchiveTimeStampChain, all
/// reducedHashtrees of the contained ArchiveTimeStamps MUST use the same Hash-Algorithm".
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EvidenceRecordArchiveTimeStampChain
{
    /// <summary>Gets the chain's <c>ArchiveTimeStamp</c> values, in the order they are encoded.</summary>
    public required IReadOnlyList<EvidenceRecordArchiveTimeStamp> ArchiveTimeStamps { get; init; }

    /// <summary>Gets the whole encoding of this <c>ArchiveTimeStampChain</c>, tag and length octets included.</summary>
    public required ReadOnlyMemory<byte> Encoding { get; init; }


    /// <summary>A short debugger string showing how many archive time-stamps the chain holds.</summary>
    private string DebuggerDisplay => $"EvidenceRecordArchiveTimeStampChain({ArchiveTimeStamps.Count} archive time-stamps)";
}


/// <summary>
/// The <c>ArchiveTimeStampSequence</c> of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.1">IETF RFC 4998 clause 5.1</see>: every
/// <c>ArchiveTimeStampChain</c> an Evidence Record has accumulated, one per Hash-Tree Renewal, in chronological
/// order.
/// </summary>
/// <remarks>
/// The syntax is <c>ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain</c>. Its standalone DER
/// encoding is what clause 5.2's Hash-Tree Renewal calls <c>atsc(i)</c> — "the encoded
/// ArchiveTimeStampSequence", whose own outer <c>SEQUENCE</c> tag and length octets are part of the hashed
/// input, which is why <see cref="Encoding"/> carries the whole element rather than its content octets.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record EvidenceRecordArchiveTimeStampSequence
{
    /// <summary>Gets the chains, in the order they are encoded, which clause 5.1 requires to be chronological.</summary>
    public required IReadOnlyList<EvidenceRecordArchiveTimeStampChain> Chains { get; init; }

    /// <summary>Gets the whole encoding of this <c>ArchiveTimeStampSequence</c>, tag and length octets included.</summary>
    public required ReadOnlyMemory<byte> Encoding { get; init; }


    /// <summary>A short debugger string showing how many chains the sequence holds.</summary>
    private string DebuggerDisplay => $"EvidenceRecordArchiveTimeStampSequence({Chains.Count} chains)";
}


/// <summary>
/// An <c>EvidenceRecord</c> of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-3.1">IETF RFC 4998 clause 3.1</see>: the unit of
/// long-term non-repudiable proof of existence for one archived data object or data object group, held as the
/// DER octets it was created from or read from.
/// </summary>
/// <remarks>
/// <para>
/// The syntax is the one Appendix B states, which clause 2.1 makes precede the 1997-syntax module of
/// Appendix C on any conflict:
/// </para>
/// <code>
/// EvidenceRecord ::= SEQUENCE {
///   version                   INTEGER { v1(1) } ,
///   digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
///   cryptoInfos               [0] CryptoInfos OPTIONAL,
///   encryptionInfo            [1] EncryptionInfo OPTIONAL,
///   archiveTimeStampSequence  ArchiveTimeStampSequence }
/// </code>
/// <para>
/// <strong>One instance, both directions.</strong> <see cref="Create"/> encodes a record from chains a
/// generator built and <see cref="Read"/> decodes one a verifier was handed; both end in the same decoding
/// step, so a record this library writes is one it has also read back.
/// </para>
/// <para>
/// <strong>The octets are the value.</strong> An instance owns the exact octets it was created from or read
/// from. Clause 5.2's Hash-Tree Renewal hashes a standalone DER encoding of the chains accumulated so far, and
/// Appendix A requires that when an Evidence Record is removed from a CMS object to reconstruct an earlier view
/// "the existing coding must not be modified"; a round trip through this type therefore never re-encodes what
/// it read, and every structural member is a view into the owned octets rather than a copy.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> An Evidence Record arrives as a container entry or as a CMS
/// unsigned attribute value. <see cref="Read"/> decodes under <see cref="AsnEncodingRules.DER"/> with
/// bounds-checked cursors, rejects octets trailing the structure, rejects a constructed (non-DER)
/// <c>OCTET STRING</c> hash value, and bounds the number of digest algorithms, of <c>cryptoInfos</c>, of
/// chains, of archive time-stamps per chain, of partial hash trees per reduced tree, and of hash values per
/// partial hash tree. Decoding is straight-line over a fixed-depth grammar — there is no recursion, so nesting
/// cannot be used to exhaust the stack.
/// </para>
/// <para>
/// <strong><c>encryptionInfo</c> is recognised, never emitted.</strong> Clause 6 leaves
/// <c>encryptionInfoType</c>/<c>encryptionInfoValue</c> an open extension point with no algorithm registered by
/// the RFC itself ("The use of the specified encryptionInfoType and encryptionInfoValue may be heavily
/// dependent on the mechanisms and has to be defined in other specifications"). A record carrying the field is
/// read and the field's octets surfaced through <see cref="EncryptionInfo"/>, so a caller can fail closed on a
/// record whose data objects it cannot reconstruct; <see cref="Create"/> never writes one.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EvidenceRecord: SensitiveMemory, IEquatable<EvidenceRecord>
{
    /// <summary>
    /// The largest number of <c>AlgorithmIdentifier</c> values the <c>digestAlgorithms</c> field is read with.
    /// The syntax bounds it at <c>MAX</c>; one entry per Hash-Tree Renewal is what a real record carries.
    /// </summary>
    private const int MaximumDigestAlgorithms = 64;

    /// <summary>
    /// The largest number of <c>Attribute</c> values the optional <c>cryptoInfos</c> field is read with. Clause
    /// 3.1 leaves the field unprotected by any time-stamp, so its size costs a verifier memory and buys it
    /// nothing that is authenticated.
    /// </summary>
    private const int MaximumCryptoInfos = 256;

    /// <summary>The largest number of <c>ArchiveTimeStampChain</c> values an <c>ArchiveTimeStampSequence</c> is read with.</summary>
    private const int MaximumChains = 256;

    /// <summary>The largest number of <c>ArchiveTimeStamp</c> values one <c>ArchiveTimeStampChain</c> is read with.</summary>
    private const int MaximumArchiveTimeStampsPerChain = 1024;

    /// <summary>The largest number of <c>Attribute</c> values one <c>ArchiveTimeStamp.attributes</c> field is read with.</summary>
    private const int MaximumArchiveTimeStampAttributes = 64;


    /// <summary>
    /// Initialises a new instance over owned, already-encoded octets and the views into them.
    /// </summary>
    /// <param name="encodedValue">The DER-encoded <c>EvidenceRecord</c>. Ownership transfers to this instance.</param>
    /// <param name="length">The number of valid octets in <paramref name="encodedValue"/>.</param>
    /// <param name="version">The <c>version</c> field.</param>
    /// <param name="digestAlgorithms">The <c>digestAlgorithms</c> field's members.</param>
    /// <param name="cryptoInfos">The whole encodings of the <c>cryptoInfos</c> members, as views into the owned octets.</param>
    /// <param name="encryptionInfo">The whole encoding of the <c>encryptionInfo</c> field, empty when absent.</param>
    /// <param name="archiveTimeStampSequence">The decoded <c>archiveTimeStampSequence</c> field.</param>
    private EvidenceRecord(
        IMemoryOwner<byte> encodedValue,
        int length,
        int version,
        IReadOnlyList<AlgorithmIdentifier> digestAlgorithms,
        IReadOnlyList<ReadOnlyMemory<byte>> cryptoInfos,
        ReadOnlyMemory<byte> encryptionInfo,
        EvidenceRecordArchiveTimeStampSequence archiveTimeStampSequence)
        : base(encodedValue, ValueTag)
    {
        Length = length;
        Version = version;
        DigestAlgorithms = digestAlgorithms;
        CryptoInfos = cryptoInfos;
        EncryptionInfo = encryptionInfo;
        ArchiveTimeStampSequence = archiveTimeStampSequence;
    }


    /// <summary>
    /// The tag every instance carries for CBOM and OpenTelemetry provenance: a DER-encoded proof-of-existence
    /// structure. It mirrors <see cref="AtsHashIndexV3.ValueTag"/>, the tag the sibling long-term-availability
    /// carrier of ETSI EN 319 122-1 uses.
    /// </summary>
    public static Tag ValueTag { get; } = Tag.Create(Purpose.Signature).With(EncodingScheme.Der);

    /// <summary>
    /// The only <c>version</c> value RFC 4998 defines, <c>v1(1)</c>. Clause 3.1 states that "An implementation
    /// conforming to this specification SHOULD reject a version value below 1", which
    /// <see cref="Read"/> enforces as the floor; this is the value <see cref="Create"/> writes.
    /// </summary>
    public static int Version1 { get; } = 1;


    /// <summary>Gets the number of valid octets of the DER-encoded value (the rented buffer may be larger).</summary>
    public int Length { get; }

    /// <summary>Gets the <c>version</c> field. RFC 4998 defines <c>v1(1)</c> only; see <see cref="Version1"/>.</summary>
    public int Version { get; }

    /// <summary>
    /// Gets the <c>digestAlgorithms</c> field's members. Clause 3.1 states that "The ordering of the values is
    /// not relevant", so nothing here depends on the order they were encoded in.
    /// </summary>
    public IReadOnlyList<AlgorithmIdentifier> DigestAlgorithms { get; }

    /// <summary>
    /// Gets the whole encodings of the optional <c>cryptoInfos</c> members. Clause 3.1 makes the field
    /// unprotected — "Since this data is not protected within any timestamp, the data should be verifiable
    /// through other mechanisms" — so nothing a record places here is self-certifying, and this library never
    /// treats it as trust material.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> CryptoInfos { get; }

    /// <summary>
    /// Gets the whole encoding of the optional <c>encryptionInfo</c> field, or an empty value when it is
    /// absent. Recognised so a caller can fail closed; never emitted (see the type's remarks).
    /// </summary>
    public ReadOnlyMemory<byte> EncryptionInfo { get; }

    /// <summary>Gets whether the record carries an <c>encryptionInfo</c> field.</summary>
    public bool HasEncryptionInfo => !EncryptionInfo.IsEmpty;

    /// <summary>Gets the <c>archiveTimeStampSequence</c> field: every chain, in the order they are encoded.</summary>
    public EvidenceRecordArchiveTimeStampSequence ArchiveTimeStampSequence { get; }


    /// <summary>
    /// Gets the DER-encoded <c>EvidenceRecord</c> as a span, sliced to <see cref="Length"/> (the base member
    /// returns the whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only span over exactly the encoded value.</returns>
    public new ReadOnlySpan<byte> AsReadOnlySpan() => MemoryOwner.Memory.Span[..Length];


    /// <summary>
    /// Gets the DER-encoded <c>EvidenceRecord</c> as memory, sliced to <see cref="Length"/> (the base member
    /// returns the whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only memory over exactly the encoded value.</returns>
    public new ReadOnlyMemory<byte> AsReadOnlyMemory() => MemoryOwner.Memory[..Length];


    /// <summary>
    /// Encodes an Evidence Record from chains a generator has already built — the creation direction of clause
    /// 3.2, where the chains arrive as the exact octets they must keep so that a later Hash-Tree Renewal hashing
    /// them reaches the same value this record was written with.
    /// </summary>
    /// <param name="digestAlgorithms">The <c>digestAlgorithms</c> field's members: one per chain's hash algorithm, in the order the chains were created.</param>
    /// <param name="cryptoInfos">The optional <c>cryptoInfos</c> attributes, or <see langword="null"/> to omit the field.</param>
    /// <param name="archiveTimeStampChains">The whole encodings of every <c>ArchiveTimeStampChain</c>, in chronological order (clause 5.1).</param>
    /// <param name="pool">The memory pool the encoded value is rented from.</param>
    /// <returns>The encoded record. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When no digest algorithm or no chain is supplied, or a list exceeds the count this type reads back.</exception>
    /// <exception cref="AsnContentException">When a supplied chain is not exactly one DER-encoded value.</exception>
    public static EvidenceRecord Create(
        IReadOnlyList<AlgorithmIdentifier> digestAlgorithms,
        IReadOnlyList<CmsAttribute>? cryptoInfos,
        IReadOnlyList<ReadOnlyMemory<byte>> archiveTimeStampChains,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(digestAlgorithms);
        ArgumentNullException.ThrowIfNull(archiveTimeStampChains);
        ArgumentNullException.ThrowIfNull(pool);

        if(digestAlgorithms.Count == 0 || digestAlgorithms.Count > MaximumDigestAlgorithms)
        {
            throw new ArgumentException(
                $"An EvidenceRecord names between 1 and {MaximumDigestAlgorithms} digest algorithms (RFC 4998 clause 3.1).", nameof(digestAlgorithms));
        }

        if(archiveTimeStampChains.Count == 0 || archiveTimeStampChains.Count > MaximumChains)
        {
            throw new ArgumentException(
                $"An EvidenceRecord carries between 1 and {MaximumChains} ArchiveTimeStampChain values (RFC 4998 clause 5.1).", nameof(archiveTimeStampChains));
        }

        if(cryptoInfos is not null && cryptoInfos.Count > MaximumCryptoInfos)
        {
            throw new ArgumentException($"An EvidenceRecord is written with at most {MaximumCryptoInfos} cryptoInfos attributes.", nameof(cryptoInfos));
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteInteger(Version1);
            using(writer.PushSequence())
            {
                for(int i = 0; i < digestAlgorithms.Count; ++i)
                {
                    using(writer.PushSequence())
                    {
                        //AlgorithmIdentifier.parameters is omitted rather than written as NULL: RFC 5754 §2
                        //states that implementations generating SHA-2 algorithm identifiers omit the parameters
                        //field, while accepting either form when reading one.
                        writer.WriteObjectIdentifier(digestAlgorithms[i].Oid);
                    }
                }
            }

            if(cryptoInfos is { Count: > 0 })
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    for(int i = 0; i < cryptoInfos.Count; ++i)
                    {
                        writer.WriteEncodedValue(cryptoInfos[i].AsReadOnlySpan());
                    }
                }
            }

            //encryptionInfo [1] is never written: clause 6 registers no algorithm for it, so anything this
            //library emitted there would be a value no verifier could act on.
            using(writer.PushSequence())
            {
                for(int i = 0; i < archiveTimeStampChains.Count; ++i)
                {
                    writer.WriteEncodedValue(archiveTimeStampChains[i].Span);
                }
            }
        }

        int encodedLength = writer.GetEncodedLength();
        IMemoryOwner<byte> owner = pool.Rent(encodedLength);
        try
        {
            _ = writer.TryEncode(owner.Memory.Span, out int written);

            return Materialise(owner, written);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Decodes an Evidence Record — the verifier direction of clause 3.3. The octets are copied into pooled
    /// memory the returned instance owns, so every structural view stays valid however long the caller keeps it.
    /// </summary>
    /// <param name="encodedValue">The DER-encoded <c>EvidenceRecord</c>, tag and length octets included.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The decoded record. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="encodedValue"/> is empty.</exception>
    /// <exception cref="AsnContentException">When the octets are not a well-formed DER <c>EvidenceRecord</c>, carry trailing octets, or exceed the bounds this type reads within.</exception>
    public static EvidenceRecord Read(ReadOnlySpan<byte> encodedValue, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(encodedValue.IsEmpty)
        {
            throw new ArgumentException("An Evidence Record is one DER-encoded EvidenceRecord (RFC 4998 clause 3.1).", nameof(encodedValue));
        }

        IMemoryOwner<byte> owner = pool.Rent(encodedValue.Length);
        try
        {
            encodedValue.CopyTo(owner.Memory.Span);

            return Materialise(owner, encodedValue.Length);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Decodes octets that are already owned and wraps them in an instance whose members view them — the single
    /// decoding step both <see cref="Create"/> and <see cref="Read"/> end in.
    /// </summary>
    /// <param name="owner">The buffer holding the encoded value. Ownership transfers to the returned instance.</param>
    /// <param name="length">The number of valid octets in <paramref name="owner"/>.</param>
    /// <returns>The decoded record.</returns>
    /// <exception cref="AsnContentException">When the octets are not a well-formed DER <c>EvidenceRecord</c>.</exception>
    private static EvidenceRecord Materialise(IMemoryOwner<byte> owner, int length)
    {
        ReadOnlyMemory<byte> encoded = owner.Memory[..length];
        var outer = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader record = outer.ReadSequence();

        //Octets after the structure are rejected rather than ignored: accepting them would let an attacker
        //append content a differently written parser might read instead of the record that was verified.
        outer.ThrowIfNotEmpty();

        if(!record.TryReadInt32(out int version))
        {
            throw new AsnContentException("An EvidenceRecord's version is an INTEGER (RFC 4998 clause 3.1).");
        }

        if(version < Version1)
        {
            //Clause 3.1: "An implementation conforming to this specification SHOULD reject a version value
            //below 1." A value above 1 is left to the caller, which can read Version and decide.
            throw new AsnContentException($"An EvidenceRecord's version is at least {Version1} (RFC 4998 clause 3.1).");
        }

        List<AlgorithmIdentifier> digestAlgorithms = ReadDigestAlgorithms(record);
        List<ReadOnlyMemory<byte>> cryptoInfos = ReadCryptoInfos(record);
        ReadOnlyMemory<byte> encryptionInfo = record.HasData && record.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true)
            ? record.ReadEncodedValue()
            : ReadOnlyMemory<byte>.Empty;

        EvidenceRecordArchiveTimeStampSequence sequence = ReadArchiveTimeStampSequence(record);
        record.ThrowIfNotEmpty();

        return new EvidenceRecord(owner, length, version, digestAlgorithms, cryptoInfos, encryptionInfo, sequence);
    }


    /// <summary>
    /// Reads the <c>digestAlgorithms SEQUENCE OF AlgorithmIdentifier</c> field.
    /// </summary>
    /// <param name="record">The reader positioned inside the <c>EvidenceRecord</c> SEQUENCE.</param>
    /// <returns>The algorithms named, in the order they were encoded.</returns>
    /// <exception cref="AsnContentException">When the field is malformed or exceeds the supported count.</exception>
    private static List<AlgorithmIdentifier> ReadDigestAlgorithms(AsnReader record)
    {
        AsnReader algorithms = record.ReadSequence();
        List<AlgorithmIdentifier> named = [];
        while(algorithms.HasData)
        {
            if(named.Count == MaximumDigestAlgorithms)
            {
                throw new AsnContentException($"An EvidenceRecord is read with at most {MaximumDigestAlgorithms} digest algorithms.");
            }

            AsnReader algorithmIdentifier = algorithms.ReadSequence();
            string oid = algorithmIdentifier.ReadObjectIdentifier();
            if(algorithmIdentifier.HasData)
            {
                //AlgorithmIdentifier.parameters is ANY DEFINED BY algorithm OPTIONAL; a NULL is the other
                //encoding RFC 5754 §2 admits for the SHA-2 family and is consumed without interpretation.
                _ = algorithmIdentifier.ReadEncodedValue();
            }

            algorithmIdentifier.ThrowIfNotEmpty();
            named.Add(new AlgorithmIdentifier(oid));
        }

        return named;
    }


    /// <summary>
    /// Reads the optional <c>cryptoInfos [0] CryptoInfos</c> field as the whole encodings of its members.
    /// </summary>
    /// <param name="record">The reader positioned inside the <c>EvidenceRecord</c> SEQUENCE.</param>
    /// <returns>The members' encodings, or an empty list when the field is absent.</returns>
    /// <exception cref="AsnContentException">When the field is malformed or exceeds the supported count.</exception>
    private static List<ReadOnlyMemory<byte>> ReadCryptoInfos(AsnReader record)
    {
        List<ReadOnlyMemory<byte>> attributes = [];
        if(!record.HasData || record.PeekTag() != new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            return attributes;
        }

        AsnReader cryptoInfos = record.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        while(cryptoInfos.HasData)
        {
            if(attributes.Count == MaximumCryptoInfos)
            {
                throw new AsnContentException($"An EvidenceRecord is read with at most {MaximumCryptoInfos} cryptoInfos attributes.");
            }

            attributes.Add(cryptoInfos.ReadEncodedValue());
        }

        return attributes;
    }


    /// <summary>
    /// Reads the <c>archiveTimeStampSequence</c> field and every chain and archive time-stamp inside it. The
    /// walk is straight-line over the fixed-depth grammar of Appendix B, so no input nesting can drive it
    /// deeper.
    /// </summary>
    /// <param name="record">The reader positioned inside the <c>EvidenceRecord</c> SEQUENCE.</param>
    /// <returns>The decoded sequence.</returns>
    /// <exception cref="AsnContentException">When the field is malformed or exceeds the bounds this type reads within.</exception>
    private static EvidenceRecordArchiveTimeStampSequence ReadArchiveTimeStampSequence(AsnReader record)
    {
        ReadOnlyMemory<byte> sequenceEncoding = record.PeekEncodedValue();
        AsnReader sequence = record.ReadSequence();
        List<EvidenceRecordArchiveTimeStampChain> chains = [];
        while(sequence.HasData)
        {
            if(chains.Count == MaximumChains)
            {
                throw new AsnContentException($"An ArchiveTimeStampSequence is read with at most {MaximumChains} chains (RFC 4998 clause 5.1).");
            }

            ReadOnlyMemory<byte> chainEncoding = sequence.PeekEncodedValue();
            AsnReader chain = sequence.ReadSequence();
            List<EvidenceRecordArchiveTimeStamp> archiveTimeStamps = [];
            while(chain.HasData)
            {
                if(archiveTimeStamps.Count == MaximumArchiveTimeStampsPerChain)
                {
                    throw new AsnContentException(
                        $"An ArchiveTimeStampChain is read with at most {MaximumArchiveTimeStampsPerChain} archive time-stamps (RFC 4998 clause 5.1).");
                }

                archiveTimeStamps.Add(ReadArchiveTimeStamp(chain));
            }

            chains.Add(new EvidenceRecordArchiveTimeStampChain { ArchiveTimeStamps = archiveTimeStamps, Encoding = chainEncoding });
        }

        return new EvidenceRecordArchiveTimeStampSequence { Chains = chains, Encoding = sequenceEncoding };
    }


    /// <summary>
    /// Reads one <c>ArchiveTimeStamp</c>, keeping the whole encodings the renewal procedures of clause 5.2
    /// hash.
    /// </summary>
    /// <param name="chain">The reader positioned inside an <c>ArchiveTimeStampChain</c> SEQUENCE.</param>
    /// <returns>The decoded archive time-stamp.</returns>
    /// <exception cref="AsnContentException">When the structure is malformed or exceeds the bounds this type reads within.</exception>
    private static EvidenceRecordArchiveTimeStamp ReadArchiveTimeStamp(AsnReader chain)
    {
        ReadOnlyMemory<byte> archiveTimeStampEncoding = chain.PeekEncodedValue();
        AsnReader archiveTimeStamp = chain.ReadSequence();

        AlgorithmIdentifier? digestAlgorithm = null;
        if(archiveTimeStamp.HasData && archiveTimeStamp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            AsnReader algorithmIdentifier = archiveTimeStamp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            string oid = algorithmIdentifier.ReadObjectIdentifier();
            if(algorithmIdentifier.HasData)
            {
                _ = algorithmIdentifier.ReadEncodedValue();
            }

            algorithmIdentifier.ThrowIfNotEmpty();
            digestAlgorithm = new AlgorithmIdentifier(oid);
        }

        List<ReadOnlyMemory<byte>> attributes = [];
        if(archiveTimeStamp.HasData && archiveTimeStamp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            //Attributes is a SET OF, and clause 4.1 states its ordering is meant to be significant, which DER's
            //canonical SET OF rules do not preserve. Reading is therefore lenient about the order the members
            //arrive in (skipSortOrderValidation) while writing emits the canonical order DER requires.
            AsnReader set = archiveTimeStamp.ReadSetOf(skipSortOrderValidation: true, expectedTag: new Asn1Tag(TagClass.ContextSpecific, 1));
            while(set.HasData)
            {
                if(attributes.Count == MaximumArchiveTimeStampAttributes)
                {
                    throw new AsnContentException($"An ArchiveTimeStamp is read with at most {MaximumArchiveTimeStampAttributes} attributes.");
                }

                attributes.Add(set.ReadEncodedValue());
            }
        }

        List<EvidenceRecordPartialHashtree> reducedHashtree = [];
        if(archiveTimeStamp.HasData && archiveTimeStamp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true))
        {
            AsnReader lists = archiveTimeStamp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            while(lists.HasData)
            {
                if(reducedHashtree.Count == EvidenceRecordHashTree.MaximumReducedHashtreeDepth)
                {
                    throw new AsnContentException(
                        $"A reducedHashtree is read with at most {EvidenceRecordHashTree.MaximumReducedHashtreeDepth} partial hash trees (RFC 4998 clause 4.2).");
                }

                reducedHashtree.Add(ReadPartialHashtree(lists));
            }
        }

        ReadOnlyMemory<byte> timeStamp = archiveTimeStamp.ReadEncodedValue();
        archiveTimeStamp.ThrowIfNotEmpty();

        return new EvidenceRecordArchiveTimeStamp
        {
            DigestAlgorithm = digestAlgorithm,
            Attributes = attributes,
            ReducedHashtree = reducedHashtree,
            TimeStamp = timeStamp,
            Encoding = archiveTimeStampEncoding
        };
    }


    /// <summary>
    /// Reads one <c>PartialHashtree ::= SEQUENCE OF OCTET STRING</c>, returning each hash value as a view into
    /// the octets the reader is positioned over.
    /// </summary>
    /// <param name="lists">The reader positioned inside the <c>reducedHashtree</c> SEQUENCE.</param>
    /// <returns>The list's hash values, in the order they were encoded.</returns>
    /// <exception cref="AsnContentException">When a hash value is a constructed OCTET STRING, is empty or longer than a digest can be, or the list exceeds the supported count.</exception>
    private static EvidenceRecordPartialHashtree ReadPartialHashtree(AsnReader lists)
    {
        AsnReader list = lists.ReadSequence();
        List<ReadOnlyMemory<byte>> hashValues = [];
        while(list.HasData)
        {
            if(hashValues.Count == EvidenceRecordHashTree.MaximumPartialHashtreeEntries)
            {
                throw new AsnContentException(
                    $"A PartialHashtree is read with at most {EvidenceRecordHashTree.MaximumPartialHashtreeEntries} hash values (RFC 4998 clause 4.1).");
            }

            if(!list.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> hashValue))
            {
                throw new AsnContentException("A PartialHashtree hash value is a primitive OCTET STRING; an Evidence Record at rest is DER (RFC 4998 clause 5.2).");
            }

            if(hashValue.Length == 0 || hashValue.Length > EvidenceRecordHashTree.MaximumHashValueLength)
            {
                throw new AsnContentException(
                    $"A PartialHashtree hash value holds between 1 and {EvidenceRecordHashTree.MaximumHashValueLength} octets, the range a digest this library can compute occupies.");
            }

            hashValues.Add(hashValue);
        }

        return new EvidenceRecordPartialHashtree { HashValues = hashValues };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] EvidenceRecord? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return AsReadOnlySpan().SequenceEqual(other.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is EvidenceRecord other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(AsReadOnlySpan());

        return hash.ToHashCode();
    }


    /// <summary>A short debugger string showing the version and the shape of the archive time-stamp sequence.</summary>
    private string DebuggerDisplay =>
        $"EvidenceRecord(v{Version}, {ArchiveTimeStampSequence.Chains.Count} chains, {Length} bytes)";
}
