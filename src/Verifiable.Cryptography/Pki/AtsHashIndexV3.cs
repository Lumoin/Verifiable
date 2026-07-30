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
/// The <c>ats-hash-index-v3</c> attribute value of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1 clause 5.5.2</see>: the hash algorithm the index is built under together with the
/// three lists of hash values that name which certificates, which revocation information and which unsigned
/// attribute values an <c>archive-time-stamp-v3</c> protects.
/// </summary>
/// <remarks>
/// <para>
/// The syntax is the one Annex D states, which takes precedence over the clause bodies by that annex's own
/// preamble:
/// </para>
/// <code>
/// ATSHashIndexV3 ::= SEQUENCE {
///   hashIndAlgorithm             AlgorithmIdentifier,
///   certificatesHashIndex        SEQUENCE OF OCTET STRING,
///   crlsHashIndex                SEQUENCE OF OCTET STRING,
///   unsignedAttrValuesHashIndex  SEQUENCE OF OCTET STRING }
/// </code>
/// <para>
/// <strong>One instance, both directions.</strong> The same type is what a generator writes and what a verifier
/// reads: <see cref="Create"/> encodes an index from digests computed over the material a signature carries, and
/// <see cref="Read"/> decodes the instance found inside an archive time-stamp token. Both end in the same
/// decoding step, so an index this library writes is one it has also read back, and the two directions cannot
/// drift apart in what they consider well formed.
/// </para>
/// <para>
/// <strong>The octets are the value.</strong> An instance owns the exact octets it was created from or read
/// from, because clause 5.5.3 step 4) concatenates "a single instance of <c>ATSHashIndexV3</c> ... contained in
/// the <c>ats-hash-index-v3</c> attribute" into the archive time-stamp's message imprint input verbatim, tag and
/// length octets included. Re-encoding a decoded instance to rebuild that input would silently change the
/// imprint of any structure whose octets are not exactly what this library would emit; the octets are therefore
/// carried, never regenerated. The three hash lists are read-only views into those owned octets rather than
/// copies, for the same reason and to keep one buffer where one value lives.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> An index arrives inside a time-stamp token inside a signature.
/// Clause 5.5.2 requires the attribute value to be DER, so <see cref="Read"/> decodes under
/// <see cref="AsnEncodingRules.DER"/> with bounds-checked cursors, rejects octets trailing the structure,
/// rejects a constructed (non-DER) <c>OCTET STRING</c> entry, and bounds both the number of entries per list and
/// the length of one entry. A structure that fails any of these is malformed, which the coverage computation
/// treats as stating no coverage at all.
/// </para>
/// <para>
/// The hash algorithm is kept as the identifier that was encoded, exactly as
/// <see cref="TimestampTokenInfo.MessageImprintAlgorithm"/> keeps a token's; resolving it to something this
/// library can compute is <see cref="PkiDigestAlgorithm.FromOid"/>'s job at the point of use, and an algorithm
/// that does not resolve fails closed there rather than being rejected as a malformed encoding here.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class AtsHashIndexV3: SensitiveMemory, IEquatable<AtsHashIndexV3>
{
    /// <summary>
    /// The largest number of entries one hash-index list is read or written with. The syntax bounds none of the
    /// three lists, and every entry costs a verifier one comparison against every current object of its kind, so
    /// the count an attacker chooses is bounded here, at the parse boundary.
    /// </summary>
    private const int MaximumHashIndexEntries = 1024;

    /// <summary>
    /// The largest length one hash-index entry may have, which is the longest digest this library computes. A
    /// longer entry can match no digest at all and only costs memory to carry.
    /// </summary>
    private const int MaximumHashIndexEntryLength = 64;


    /// <summary>
    /// Initialises a new instance over owned, already-encoded octets and the views into them.
    /// </summary>
    /// <param name="encodedValue">The DER-encoded <c>ATSHashIndexV3</c>. Ownership transfers to this instance.</param>
    /// <param name="length">The number of valid octets in <paramref name="encodedValue"/>.</param>
    /// <param name="hashIndexAlgorithm">The <c>hashIndAlgorithm</c> field as it was encoded.</param>
    /// <param name="certificatesHashIndex">The <c>certificatesHashIndex</c> entries, as views into the owned octets.</param>
    /// <param name="crlsHashIndex">The <c>crlsHashIndex</c> entries, as views into the owned octets.</param>
    /// <param name="unsignedAttributeValuesHashIndex">The <c>unsignedAttrValuesHashIndex</c> entries, as views into the owned octets.</param>
    private AtsHashIndexV3(
        IMemoryOwner<byte> encodedValue,
        int length,
        AlgorithmIdentifier hashIndexAlgorithm,
        IReadOnlyList<ReadOnlyMemory<byte>> certificatesHashIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> crlsHashIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> unsignedAttributeValuesHashIndex)
        : base(encodedValue, ValueTag)
    {
        Length = length;
        HashIndexAlgorithm = hashIndexAlgorithm;
        CertificatesHashIndex = certificatesHashIndex;
        CrlsHashIndex = crlsHashIndex;
        UnsignedAttributeValuesHashIndex = unsignedAttributeValuesHashIndex;
    }


    /// <summary>
    /// The tag every instance carries for CBOM and OpenTelemetry provenance: the DER-encoded value of one CMS
    /// unsigned attribute. It is stated here rather than among the shared attribute tags because an
    /// <c>ats-hash-index-v3</c> value is an unsigned attribute's value, which is not what
    /// <see cref="CryptoTags.CmsSignedAttributeValue"/> names.
    /// </summary>
    public static Tag ValueTag { get; } = Tag.Create(Purpose.Signature).With(EncodingScheme.Der);


    /// <summary>Gets the number of valid octets of the DER-encoded value (the rented buffer may be larger).</summary>
    public int Length { get; }

    /// <summary>
    /// Gets the <c>hashIndAlgorithm</c> field: the algorithm every entry of the three lists was computed under.
    /// Clause 5.5.2 requires it to be the algorithm of the message imprint of the time-stamp token the archive
    /// time-stamp attribute envelopes, which the coverage computation enforces.
    /// </summary>
    public AlgorithmIdentifier HashIndexAlgorithm { get; }

    /// <summary>
    /// Gets the <c>certificatesHashIndex</c> entries — one hash value per instance of <c>CertificateChoices</c>
    /// the root <c>SignedData.certificates</c> field held when the archive time-stamp was requested.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> CertificatesHashIndex { get; }

    /// <summary>
    /// Gets the <c>crlsHashIndex</c> entries — one hash value per instance of <c>RevocationInfoChoice</c> the
    /// root <c>SignedData.crls</c> field held, which per clause 5.5.2 NOTE 1 covers both certificate revocation
    /// lists and OCSP responses.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> CrlsHashIndex { get; }

    /// <summary>
    /// Gets the <c>unsignedAttrValuesHashIndex</c> entries — one hash value per <c>AttributeValue</c> of every
    /// <c>Attribute</c> in <c>unsignedAttrs</c>, each computed over the concatenation of that attribute's
    /// <c>attrType</c> field and the one value, not per attribute.
    /// </summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> UnsignedAttributeValuesHashIndex { get; }


    /// <summary>
    /// Gets the DER-encoded <c>ATSHashIndexV3</c> as a span, sliced to <see cref="Length"/> (the base member
    /// returns the whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only span over exactly the encoded value.</returns>
    public new ReadOnlySpan<byte> AsReadOnlySpan() => MemoryOwner.Memory.Span[..Length];


    /// <summary>
    /// Gets the DER-encoded <c>ATSHashIndexV3</c> as memory, sliced to <see cref="Length"/> (the base member
    /// returns the whole, possibly larger, rented buffer).
    /// </summary>
    /// <returns>A read-only memory over exactly the encoded value.</returns>
    public new ReadOnlyMemory<byte> AsReadOnlyMemory() => MemoryOwner.Memory[..Length];


    /// <summary>
    /// Encodes an index from the digests of the material a signature carries — the generator direction of
    /// clause 5.5.2, where every hash value the three lists hold has already been computed over the octets the
    /// clause names.
    /// </summary>
    /// <param name="hashIndexAlgorithm">The algorithm every digest was computed under, which becomes <c>hashIndAlgorithm</c>.</param>
    /// <param name="certificateHashes">One digest per instance of <c>CertificateChoices</c> in <c>SignedData.certificates</c>, in the order they appear.</param>
    /// <param name="revocationInformationHashes">One digest per instance of <c>RevocationInfoChoice</c> in <c>SignedData.crls</c>, in the order they appear.</param>
    /// <param name="unsignedAttributeValueHashes">One digest per <c>AttributeValue</c> of every <c>Attribute</c> in <c>unsignedAttrs</c>.</param>
    /// <param name="pool">The memory pool the encoded value is rented from.</param>
    /// <returns>The encoded index. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When a digest is <see langword="null"/>, is not of the algorithm's output length, or a list exceeds the supported entry count.</exception>
    public static AtsHashIndexV3 Create(
        PkiDigestAlgorithm hashIndexAlgorithm,
        IReadOnlyList<DigestValue> certificateHashes,
        IReadOnlyList<DigestValue> revocationInformationHashes,
        IReadOnlyList<DigestValue> unsignedAttributeValueHashes,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(certificateHashes);
        ArgumentNullException.ThrowIfNull(revocationInformationHashes);
        ArgumentNullException.ThrowIfNull(unsignedAttributeValueHashes);
        ArgumentNullException.ThrowIfNull(pool);

        EnsureUsableDigests(certificateHashes, hashIndexAlgorithm, nameof(certificateHashes));
        EnsureUsableDigests(revocationInformationHashes, hashIndexAlgorithm, nameof(revocationInformationHashes));
        EnsureUsableDigests(unsignedAttributeValueHashes, hashIndexAlgorithm, nameof(unsignedAttributeValueHashes));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                //AlgorithmIdentifier.parameters is omitted rather than written as NULL: RFC 5754 §2 states that
                //implementations generating SHA-2 algorithm identifiers omit the parameters field, while
                //accepting either form when reading one.
                writer.WriteObjectIdentifier(hashIndexAlgorithm.Identifier.Oid);
            }

            WriteHashIndexList(writer, certificateHashes);
            WriteHashIndexList(writer, revocationInformationHashes);
            WriteHashIndexList(writer, unsignedAttributeValueHashes);
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
    /// Decodes the <c>ATSHashIndexV3</c> instance an <c>ats-hash-index-v3</c> attribute carries — the verifier
    /// direction of clause 5.5.2. The octets are copied into pooled memory the returned instance owns, so its
    /// three lists and its own encoding stay valid however long the caller keeps it.
    /// </summary>
    /// <param name="encodedValue">The DER-encoded <c>ATSHashIndexV3</c>, tag and length octets included.</param>
    /// <param name="pool">The memory pool the copy is rented from.</param>
    /// <returns>The decoded index. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="encodedValue"/> is empty.</exception>
    /// <exception cref="AsnContentException">When the octets are not a well-formed DER <c>ATSHashIndexV3</c>, carry trailing octets, or exceed the bounds this type reads within.</exception>
    public static AtsHashIndexV3 Read(ReadOnlySpan<byte> encodedValue, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(encodedValue.IsEmpty)
        {
            throw new ArgumentException("An ats-hash-index-v3 attribute value is one DER-encoded ATSHashIndexV3 (ETSI EN 319 122-1 clause 5.5.2).", nameof(encodedValue));
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
    /// Decodes octets that are already owned and wraps them in an instance whose lists view them — the single
    /// decoding step both <see cref="Create"/> and <see cref="Read"/> end in.
    /// </summary>
    /// <param name="owner">The buffer holding the encoded value. Ownership transfers to the returned instance.</param>
    /// <param name="length">The number of valid octets in <paramref name="owner"/>.</param>
    /// <returns>The decoded index.</returns>
    /// <exception cref="AsnContentException">When the octets are not a well-formed DER <c>ATSHashIndexV3</c>.</exception>
    private static AtsHashIndexV3 Materialise(IMemoryOwner<byte> owner, int length)
    {
        ReadOnlyMemory<byte> encoded = owner.Memory[..length];
        var outer = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader index = outer.ReadSequence();

        //Octets after the structure are rejected rather than ignored: accepting them would let an attacker append
        //content a differently written parser might read instead of the value the imprint was computed over.
        outer.ThrowIfNotEmpty();

        AsnReader algorithmIdentifier = index.ReadSequence();
        string algorithmOid = algorithmIdentifier.ReadObjectIdentifier();
        if(algorithmIdentifier.HasData)
        {
            //AlgorithmIdentifier.parameters is ANY DEFINED BY algorithm OPTIONAL; a NULL is the other encoding
            //RFC 5754 §2 admits for the SHA-2 family and is consumed without interpretation.
            _ = algorithmIdentifier.ReadEncodedValue();
        }

        algorithmIdentifier.ThrowIfNotEmpty();

        List<ReadOnlyMemory<byte>> certificates = ReadHashIndexList(index);
        List<ReadOnlyMemory<byte>> revocationInformation = ReadHashIndexList(index);
        List<ReadOnlyMemory<byte>> unsignedAttributeValues = ReadHashIndexList(index);
        index.ThrowIfNotEmpty();

        return new AtsHashIndexV3(owner, length, new AlgorithmIdentifier(algorithmOid), certificates, revocationInformation, unsignedAttributeValues);
    }


    /// <summary>
    /// Reads one <c>SEQUENCE OF OCTET STRING</c> hash-index list, returning each entry as a view into the octets
    /// the reader is positioned over.
    /// </summary>
    /// <param name="index">The reader positioned inside the <c>ATSHashIndexV3</c> SEQUENCE.</param>
    /// <returns>The list's entries, in the order they were encoded.</returns>
    /// <exception cref="AsnContentException">When the list is not well formed, an entry is a constructed OCTET STRING, an entry is empty or longer than a digest can be, or the list exceeds the supported entry count.</exception>
    private static List<ReadOnlyMemory<byte>> ReadHashIndexList(AsnReader index)
    {
        AsnReader list = index.ReadSequence();
        List<ReadOnlyMemory<byte>> entries = [];
        while(list.HasData)
        {
            if(entries.Count == MaximumHashIndexEntries)
            {
                throw new AsnContentException($"A hash-index list of an ats-hash-index-v3 attribute is read with at most {MaximumHashIndexEntries} entries.");
            }

            if(!list.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> entry))
            {
                throw new AsnContentException("A hash-index entry is a primitive OCTET STRING; clause 5.5.2 requires the ats-hash-index-v3 attribute value to be DER encoded.");
            }

            if(entry.Length == 0 || entry.Length > MaximumHashIndexEntryLength)
            {
                throw new AsnContentException($"A hash-index entry holds between 1 and {MaximumHashIndexEntryLength} octets, the range a digest this library can compute occupies.");
            }

            entries.Add(entry);
        }

        return entries;
    }


    /// <summary>
    /// Writes one <c>SEQUENCE OF OCTET STRING</c> hash-index list. The order the digests arrive in is the order
    /// they are written in: clause 5.5.2 states the membership of each list, never an ordering, and the verifier
    /// it describes recomputes a hash per current object and tests set membership.
    /// </summary>
    /// <param name="writer">The writer positioned inside the <c>ATSHashIndexV3</c> SEQUENCE.</param>
    /// <param name="hashes">The digests the list holds.</param>
    private static void WriteHashIndexList(AsnWriter writer, IReadOnlyList<DigestValue> hashes)
    {
        using(writer.PushSequence())
        {
            for(int i = 0; i < hashes.Count; ++i)
            {
                writer.WriteOctetString(hashes[i].AsReadOnlySpan());
            }
        }
    }


    /// <summary>
    /// Checks that every digest of one list can be written into an index under the stated algorithm: present,
    /// of that algorithm's output length, and within the entry count this type reads back.
    /// </summary>
    /// <param name="hashes">The digests to check.</param>
    /// <param name="hashIndexAlgorithm">The algorithm the index states.</param>
    /// <param name="parameterName">The parameter name reported on a failure.</param>
    /// <exception cref="ArgumentException">When a digest is absent, of the wrong length, or the list is too long.</exception>
    private static void EnsureUsableDigests(IReadOnlyList<DigestValue> hashes, PkiDigestAlgorithm hashIndexAlgorithm, string parameterName)
    {
        if(hashes.Count > MaximumHashIndexEntries)
        {
            throw new ArgumentException($"A hash-index list is written with at most {MaximumHashIndexEntries} entries.", parameterName);
        }

        for(int i = 0; i < hashes.Count; ++i)
        {
            if(hashes[i] is not DigestValue digest)
            {
                throw new ArgumentException("Every hash-index entry is a computed digest.", parameterName);
            }

            if(digest.AsReadOnlySpan().Length != hashIndexAlgorithm.OutputByteLength)
            {
                //A digest of another length was computed under another algorithm, and clause 5.5.2 has one
                //algorithm covering all three lists. Writing it would produce an index no verifier can match.
                throw new ArgumentException(
                    $"A hash-index entry of an index stating '{hashIndexAlgorithm.Identifier.Oid}' is {hashIndexAlgorithm.OutputByteLength} octets long.", parameterName);
            }
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] AtsHashIndexV3? other)
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
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is AtsHashIndexV3 other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(AsReadOnlySpan());

        return hash.ToHashCode();
    }


    /// <summary>A short debugger string showing the algorithm and the size of each of the three lists.</summary>
    private string DebuggerDisplay =>
        $"AtsHashIndexV3({HashIndexAlgorithm.Oid}, certificates {CertificatesHashIndex.Count}, crls {CrlsHashIndex.Count}, unsigned attribute values {UnsignedAttributeValuesHashIndex.Count})";
}
