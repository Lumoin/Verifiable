using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// One <c>ArchiveTimeStamp</c> as this oracle reads it: the algorithm it states (when it states one), the
/// reduced hash tree as plain octet lists, the whole encoding of its <c>timeStamp</c> field, and the message
/// imprint that field's <c>TSTInfo</c> carries.
/// </summary>
/// <param name="DigestAlgorithmOid">The <c>digestAlgorithm [0]</c> object identifier, or <see langword="null"/> when the field is absent.</param>
/// <param name="ReducedHashtree">The <c>reducedHashtree [2]</c> lists, leaf level first; empty when the field is absent.</param>
/// <param name="TimeStampEncoding">The whole encoding of the <c>timeStamp</c> field, tag and length octets included.</param>
/// <param name="MessageImprintAlgorithmOid">The <c>messageImprint.hashAlgorithm</c> object identifier of the embedded token.</param>
/// <param name="MessageImprint">The <c>messageImprint.hashedMessage</c> of the embedded token.</param>
internal sealed record OracleArchiveTimeStamp(
    string? DigestAlgorithmOid,
    List<List<byte[]>> ReducedHashtree,
    byte[] TimeStampEncoding,
    string MessageImprintAlgorithmOid,
    byte[] MessageImprint);


/// <summary>
/// One <c>EvidenceRecord</c> as this oracle reads it.
/// </summary>
/// <param name="Version">The <c>version</c> field.</param>
/// <param name="DigestAlgorithmOids">The <c>digestAlgorithms</c> field's object identifiers, in encoded order.</param>
/// <param name="Chains">The chains of the <c>archiveTimeStampSequence</c>, each as its own list of archive time-stamps.</param>
/// <param name="ChainEncodings">The whole encoding of each chain, tag and length octets included, in the same order as <paramref name="Chains"/>.</param>
internal sealed record OracleEvidenceRecord(
    int Version,
    List<string> DigestAlgorithmOids,
    List<List<OracleArchiveTimeStamp>> Chains,
    List<byte[]> ChainEncodings);


/// <summary>
/// An independent recomputation of the Merkle hash-tree machinery of IETF RFC 4998 clauses 4.2 and 4.3, and an
/// independent reader of the Appendix B structures, written for these tests from the specification text alone.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here calls the surface it checks. The structures are decoded by an <see cref="AsnReader"/> in this
/// file rather than through <see cref="EvidenceRecord"/>, the ordering rule and the node rule are written out
/// here rather than taken from <see cref="EvidenceRecordHashTree"/>, and every hash value is taken through the
/// BouncyCastle digest implementation (<see cref="BouncyCastleCryptographicFunctions.ComputeDigest"/>), which
/// is a different implementation from the one the test host registers for the SHA family and therefore an
/// independent answer to the same question. Digests are library carriers, never hand-rolled hashing.
/// </para>
/// <para>
/// The clause text this reimplements, so a reader can check it against the specification rather than against
/// the production code. Building (clause 4.2): "Choose a secure hash algorithm H and generate hash values for
/// the data objects. These values will be the leaves of the hash tree"; "For each data group containing more
/// than one document, its respective document hashes are binary sorted in ascending order, concatenated, and
/// hashed. The hash values are the complete output from the hash algorithm, i.e., leading zeros are not
/// removed, with the most significant bit first"; "If there is more than one hash value, place them in groups
/// and sort each group in binary ascending order. Concatenate these values and generate new hash values, which
/// are inner nodes of this tree ... Repeat this step until there is only one hash value, which is the root node
/// of the hash tree." Verifying (clause 4.3): "Search for hash value h in the first list ... If not present,
/// terminate verification process with negative result"; "Calculate hash value h' of the concatenated hash
/// values of the first list ... This hash value h' MUST become a member of the next higher list of hash values
/// (from the next partialHashtree). Continue step 3 until a root hash value is calculated." The single-value
/// first list is carried forward unhashed, which is clause 4.2 step 3's group rule read backwards and what
/// RFC 6283 clause 3.1.1 states outright for the XML form of the same syntax.
/// </para>
/// </remarks>
internal static class EvidenceRecordOracle
{
    /// <summary>
    /// Compares two hash values the way clause 4.2 arranges them: unsigned, octet by octet from the most
    /// significant, over the complete output with leading zeros retained.
    /// </summary>
    /// <param name="left">The first hash value.</param>
    /// <param name="right">The second hash value.</param>
    /// <returns>A negative number when <paramref name="left"/> sorts first, a positive number when <paramref name="right"/> does, zero when identical.</returns>
    internal static int Compare(byte[] left, byte[] right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        int shared = Math.Min(left.Length, right.Length);
        for(int i = 0; i < shared; ++i)
        {
            if(left[i] != right[i])
            {
                return left[i] < right[i] ? -1 : 1;
            }
        }

        return left.Length.CompareTo(right.Length);
    }


    /// <summary>
    /// Computes one hash value through the independent BouncyCastle digest implementation.
    /// </summary>
    /// <param name="input">The octets to hash.</param>
    /// <param name="algorithm">The algorithm to hash under.</param>
    /// <returns>The digest octets.</returns>
    internal static byte[] Hash(ReadOnlySpan<byte> input, PkiDigestAlgorithm algorithm)
    {
        using DigestValue digest = BouncyCastleCryptographicFunctions.ComputeDigest(
            input, algorithm.OutputByteLength, algorithm.DigestTag, BaseMemoryPool.Shared).Result;

        return digest.AsReadOnlySpan()[..algorithm.OutputByteLength].ToArray();
    }


    /// <summary>
    /// Applies the node rule: binary sort the hash values ascending, concatenate them, hash the concatenation.
    /// </summary>
    /// <param name="hashValues">The hash values under one father node.</param>
    /// <param name="algorithm">The algorithm the tree is built under.</param>
    /// <returns>The father node's hash value.</returns>
    internal static byte[] CombineNode(IReadOnlyList<byte[]> hashValues, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(hashValues);

        var sorted = new List<byte[]>(hashValues);
        sorted.Sort(Compare);

        var concatenated = new List<byte>();
        foreach(byte[] hashValue in sorted)
        {
            concatenated.AddRange(hashValue);
        }

        return Hash([.. concatenated], algorithm);
    }


    /// <summary>
    /// Builds the hash tree of clause 4.2 over data object groups and returns its root.
    /// </summary>
    /// <param name="dataObjectGroups">The groups, each a list of data object octets.</param>
    /// <param name="algorithm">The algorithm the tree is built under.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <returns>The root hash value.</returns>
    internal static byte[] BuildRoot(IReadOnlyList<IReadOnlyList<byte[]>> dataObjectGroups, PkiDigestAlgorithm algorithm, int nodeArity)
    {
        ArgumentNullException.ThrowIfNull(dataObjectGroups);

        var level = new List<byte[]>();
        foreach(IReadOnlyList<byte[]> group in dataObjectGroups)
        {
            level.Add(LeafOf(group, algorithm));
        }

        while(level.Count > 1)
        {
            var next = new List<byte[]>();
            for(int start = 0; start < level.Count; start += nodeArity)
            {
                int end = Math.Min(start + nodeArity, level.Count);
                if(end - start == 1)
                {
                    next.Add(level[start]);

                    continue;
                }

                var members = new List<byte[]>();
                for(int i = start; i < end; ++i)
                {
                    members.Add(level[i]);
                }

                next.Add(CombineNode(members, algorithm));
            }

            level = next;
        }

        return level[0];
    }


    /// <summary>
    /// The leaf value of one data object group: the single document's hash, or the hash of the binary sorted
    /// concatenation of every document's hash when the group holds more than one.
    /// </summary>
    /// <param name="group">The group's data object octets.</param>
    /// <param name="algorithm">The algorithm the tree is built under.</param>
    /// <returns>The leaf hash value.</returns>
    internal static byte[] LeafOf(IReadOnlyList<byte[]> group, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(group);

        var memberHashes = new List<byte[]>();
        foreach(byte[] dataObject in group)
        {
            memberHashes.Add(Hash(dataObject, algorithm));
        }

        return memberHashes.Count == 1 ? memberHashes[0] : CombineNode(memberHashes, algorithm);
    }


    /// <summary>
    /// Recomputes the root of clause 4.3 from a data object's hash and a reduced hash tree.
    /// </summary>
    /// <param name="dataObjectHash">The hash of the data object being proved.</param>
    /// <param name="reducedHashtree">The reduced hash tree, leaf level first.</param>
    /// <param name="algorithm">The algorithm the tree was built under.</param>
    /// <returns>The recomputed root, or <see langword="null"/> when the data object's hash is not in the first list.</returns>
    internal static byte[]? RecomputeRoot(byte[] dataObjectHash, IReadOnlyList<List<byte[]>> reducedHashtree, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(dataObjectHash);
        ArgumentNullException.ThrowIfNull(reducedHashtree);

        if(reducedHashtree.Count == 0)
        {
            return dataObjectHash;
        }

        if(!ContainsValue(reducedHashtree[0], dataObjectHash))
        {
            return null;
        }

        byte[] current = reducedHashtree[0].Count == 1 ? reducedHashtree[0][0] : CombineNode(reducedHashtree[0], algorithm);
        for(int listIndex = 1; listIndex < reducedHashtree.Count; ++listIndex)
        {
            var combined = new List<byte[]>(reducedHashtree[listIndex]) { current };
            current = CombineNode(combined, algorithm);
        }

        return current;
    }


    /// <summary>
    /// Determines whether a list holds a hash value octet for octet.
    /// </summary>
    /// <param name="hashValues">The list to search.</param>
    /// <param name="hashValue">The value searched for.</param>
    /// <returns><see langword="true"/> when the list holds the value.</returns>
    internal static bool ContainsValue(IReadOnlyList<byte[]> hashValues, byte[] hashValue)
    {
        ArgumentNullException.ThrowIfNull(hashValues);

        foreach(byte[] candidate in hashValues)
        {
            if(candidate.AsSpan().SequenceEqual(hashValue))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Builds the hash tree of clause 4.2 over leaf values that are already hash values — the tree clause 5.2
    /// step 5 builds over the values its step 4 produced — and returns its root.
    /// </summary>
    /// <param name="leafGroups">The groups, each a list of that group's leaf hash values.</param>
    /// <param name="algorithm">The algorithm the tree is built under.</param>
    /// <param name="nodeArity">How many children an inner node is given.</param>
    /// <returns>The root hash value.</returns>
    /// <remarks>
    /// The only difference from <see cref="BuildRoot"/> is that the leaves arrive hashed: clause 5.2 step 5
    /// builds "a new hash tree" whose inputs are the <c>h(i)'</c> of step 4, which are hash values already.
    /// Everything above the leaves is the same clause 4.2 construction.
    /// </remarks>
    internal static byte[] BuildRootFromHashValues(IReadOnlyList<IReadOnlyList<byte[]>> leafGroups, PkiDigestAlgorithm algorithm, int nodeArity)
    {
        ArgumentNullException.ThrowIfNull(leafGroups);

        var level = new List<byte[]>();
        foreach(IReadOnlyList<byte[]> group in leafGroups)
        {
            level.Add(group.Count == 1 ? group[0] : CombineNode(group, algorithm));
        }

        while(level.Count > 1)
        {
            var next = new List<byte[]>();
            for(int start = 0; start < level.Count; start += nodeArity)
            {
                int end = Math.Min(start + nodeArity, level.Count);
                if(end - start == 1)
                {
                    next.Add(level[start]);

                    continue;
                }

                var members = new List<byte[]>();
                for(int i = start; i < end; ++i)
                {
                    members.Add(level[i]);
                }

                next.Add(CombineNode(members, algorithm));
            }

            level = next;
        }

        return level[0];
    }


    /// <summary>
    /// Encodes the <c>atsc(i)</c> of clause 5.2 step 3: a standalone <c>ArchiveTimeStampSequence</c> holding the
    /// supplied chains, its own outer tag and length octets included on top of each chain's.
    /// </summary>
    /// <param name="chainEncodings">The whole encodings of the chains, in chronological order.</param>
    /// <returns>The encoded sequence.</returns>
    /// <remarks>
    /// The clause states the rule twice: "atsc(i) is the encoded ArchiveTimeStampSequence, the concatenation of
    /// all previous Archive Timestamp Chains (in chronological order) related to data object d(i)", and
    /// "Note: The ArchiveTimeStampChains used are DER encoded, i.e., they contain sequence and length tags."
    /// </remarks>
    internal static byte[] EncodeArchiveTimeStampSequence(IReadOnlyList<byte[]> chainEncodings)
    {
        ArgumentNullException.ThrowIfNull(chainEncodings);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(byte[] chain in chainEncodings)
            {
                writer.WriteEncodedValue(chain);
            }
        }

        return writer.Encode();
    }


    /// <summary>
    /// Computes the Timestamp Renewal value of clause 5.2 for one Archive Timestamp: the hash of the whole
    /// <c>timeStamp</c> element of the Archive Timestamp before it.
    /// </summary>
    /// <param name="previousTimeStampEncoding">The whole encoding of the previous Archive Timestamp's <c>timeStamp</c> field, tag and length octets included.</param>
    /// <param name="algorithm">The chain's algorithm, which a Timestamp Renewal does not change.</param>
    /// <returns>The value the new Archive Timestamp's first list is expected to hold, and which its own time-stamp binds when no reduced hash tree is written.</returns>
    /// <remarks>
    /// Clause 5.2 states it as "the content of the timeStamp field of the old Archive Timestamp has to be hashed
    /// and timestamped by a new Archive Timestamp", and clause 5.3 step 2 as "The first hash value list of each
    /// ArchiveTimeStamp MUST contain the hash value of the timestamp of the Archive Timestamp before". The
    /// octets hashed are the complete element; a reading that hashed only its content octets reaches a value the
    /// third-party records these tests read do not carry.
    /// </remarks>
    internal static byte[] TimestampRenewalValue(byte[] previousTimeStampEncoding, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(previousTimeStampEncoding);

        return Hash(previousTimeStampEncoding, algorithm);
    }


    /// <summary>
    /// Computes the Hash-Tree Renewal value of clause 5.2 step 4 for one data object: the hash of the data
    /// object's hash followed by the hash of the encoded sequence of every older chain.
    /// </summary>
    /// <param name="dataObject">The archived data object's octets.</param>
    /// <param name="olderChainEncodings">The whole encodings of every older chain, in chronological order.</param>
    /// <param name="algorithm">The new chain's algorithm.</param>
    /// <returns>The value the new chain's first list is expected to hold.</returns>
    /// <remarks>
    /// The concatenation is positional — <c>h(i)' = H (h(i)+ ha(i))</c>, the formula clause 5.2 step 4 states —
    /// which is what the third-party Hash-Tree Renewal artifacts these tests read are built with, and which the
    /// worked example of Figure 4 contradicts by sorting the pair. This oracle exists to state that fact
    /// independently of the library, so it writes the formula out here rather than calling it. The reading the
    /// figure states is written out separately in <see cref="HashTreeRenewalValueSorted"/>, so that a test can
    /// assert which of the two an artifact carries rather than only that one of them matches.
    /// </remarks>
    internal static byte[] HashTreeRenewalValue(byte[] dataObject, IReadOnlyList<byte[]> olderChainEncodings, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(dataObject);
        ArgumentNullException.ThrowIfNull(olderChainEncodings);

        byte[] dataObjectHash = Hash(dataObject, algorithm);
        byte[] sequenceHash = Hash(EncodeArchiveTimeStampSequence(olderChainEncodings), algorithm);

        return Hash([.. dataObjectHash, .. sequenceHash], algorithm);
    }


    /// <summary>
    /// Computes the Hash-Tree Renewal value the worked example of clause 5.2's Figure 4 states:
    /// <c>h1' = H( binary sorted and concatenated (H(d1), ha(1)))</c>, the same pair combined by the node rule
    /// of clause 4.2 instead of positionally.
    /// </summary>
    /// <param name="dataObject">The archived data object's octets.</param>
    /// <param name="olderChainEncodings">The whole encodings of every older chain, in chronological order.</param>
    /// <param name="algorithm">The new chain's algorithm.</param>
    /// <returns>The value the figure's reading produces, which differs from <see cref="HashTreeRenewalValue"/> whenever the data object's hash sorts after the sequence's.</returns>
    internal static byte[] HashTreeRenewalValueSorted(byte[] dataObject, IReadOnlyList<byte[]> olderChainEncodings, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(dataObject);
        ArgumentNullException.ThrowIfNull(olderChainEncodings);

        byte[] dataObjectHash = Hash(dataObject, algorithm);
        byte[] sequenceHash = Hash(EncodeArchiveTimeStampSequence(olderChainEncodings), algorithm);

        return CombineNode([dataObjectHash, sequenceHash], algorithm);
    }


    /// <summary>
    /// Reads an <c>EvidenceRecord</c> with this oracle's own decoder, following the Appendix B module.
    /// </summary>
    /// <param name="evidenceRecord">The DER-encoded record.</param>
    /// <returns>What the record states.</returns>
    internal static OracleEvidenceRecord ParseEvidenceRecord(byte[] evidenceRecord)
    {
        ArgumentNullException.ThrowIfNull(evidenceRecord);

        var outer = new AsnReader(evidenceRecord, AsnEncodingRules.DER);
        AsnReader record = outer.ReadSequence();
        outer.ThrowIfNotEmpty();

        int version = (int)record.ReadInteger();
        AsnReader algorithms = record.ReadSequence();
        var digestAlgorithmOids = new List<string>();
        while(algorithms.HasData)
        {
            AsnReader algorithm = algorithms.ReadSequence();
            digestAlgorithmOids.Add(algorithm.ReadObjectIdentifier());
            while(algorithm.HasData)
            {
                _ = algorithm.ReadEncodedValue();
            }
        }

        if(record.HasData && record.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = record.ReadEncodedValue();
        }

        if(record.HasData && record.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            _ = record.ReadEncodedValue();
        }

        AsnReader sequence = record.ReadSequence();
        record.ThrowIfNotEmpty();

        var chains = new List<List<OracleArchiveTimeStamp>>();
        var chainEncodings = new List<byte[]>();
        while(sequence.HasData)
        {
            chainEncodings.Add(sequence.PeekEncodedValue().ToArray());
            AsnReader chain = sequence.ReadSequence();
            var archiveTimeStamps = new List<OracleArchiveTimeStamp>();
            while(chain.HasData)
            {
                archiveTimeStamps.Add(ParseArchiveTimeStamp(chain));
            }

            chains.Add(archiveTimeStamps);
        }

        return new OracleEvidenceRecord(version, digestAlgorithmOids, chains, chainEncodings);
    }


    /// <summary>
    /// Reads one <c>ArchiveTimeStamp</c> and the message imprint of the token its <c>timeStamp</c> field holds.
    /// </summary>
    /// <param name="chain">The reader positioned inside an <c>ArchiveTimeStampChain</c>.</param>
    /// <returns>What the structure states.</returns>
    private static OracleArchiveTimeStamp ParseArchiveTimeStamp(AsnReader chain)
    {
        AsnReader archiveTimeStamp = chain.ReadSequence();

        string? digestAlgorithmOid = null;
        if(archiveTimeStamp.HasData && archiveTimeStamp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            AsnReader algorithm = archiveTimeStamp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            digestAlgorithmOid = algorithm.ReadObjectIdentifier();
            while(algorithm.HasData)
            {
                _ = algorithm.ReadEncodedValue();
            }
        }

        if(archiveTimeStamp.HasData && archiveTimeStamp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            _ = archiveTimeStamp.ReadEncodedValue();
        }

        var reducedHashtree = new List<List<byte[]>>();
        if(archiveTimeStamp.HasData && archiveTimeStamp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true))
        {
            AsnReader lists = archiveTimeStamp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            while(lists.HasData)
            {
                AsnReader list = lists.ReadSequence();
                var hashValues = new List<byte[]>();
                while(list.HasData)
                {
                    hashValues.Add(list.ReadOctetString());
                }

                reducedHashtree.Add(hashValues);
            }
        }

        byte[] timeStampEncoding = archiveTimeStamp.PeekEncodedValue().ToArray();
        AsnReader timeStamp = archiveTimeStamp.ReadSequence();
        archiveTimeStamp.ThrowIfNotEmpty();

        (string imprintAlgorithmOid, byte[] imprint) = ReadMessageImprint(timeStamp);

        return new OracleArchiveTimeStamp(digestAlgorithmOid, reducedHashtree, timeStampEncoding, imprintAlgorithmOid, imprint);
    }


    /// <summary>
    /// Reads the <c>messageImprint</c> of the <c>TSTInfo</c> a time-stamp token encapsulates, by position:
    /// <c>ContentInfo</c> to its content, the content's <c>SignedData</c>, that structure's third field
    /// <c>encapContentInfo</c>, its <c>eContent</c> OCTET STRING, and the <c>TSTInfo</c> inside.
    /// </summary>
    /// <param name="contentInfo">The reader positioned inside the <c>ContentInfo</c> SEQUENCE.</param>
    /// <returns>The imprint's algorithm identifier and its hashed message.</returns>
    private static (string AlgorithmOid, byte[] Imprint) ReadMessageImprint(AsnReader contentInfo)
    {
        _ = contentInfo.ReadObjectIdentifier();
        AsnReader content = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader signedData = content.ReadSequence();

        _ = signedData.ReadInteger();                          //version.
        _ = signedData.ReadSetOf(skipSortOrderValidation: true);//digestAlgorithms.
        AsnReader encapContentInfo = signedData.ReadSequence();
        _ = encapContentInfo.ReadObjectIdentifier();           //eContentType.
        AsnReader eContent = encapContentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        byte[] tstInfoOctets = eContent.ReadOctetString();

        var tstInfoReader = new AsnReader(tstInfoOctets, AsnEncodingRules.DER);
        AsnReader tstInfo = tstInfoReader.ReadSequence();
        _ = tstInfo.ReadInteger();                             //version.
        _ = tstInfo.ReadObjectIdentifier();                    //policy.
        AsnReader messageImprint = tstInfo.ReadSequence();
        AsnReader hashAlgorithm = messageImprint.ReadSequence();
        string algorithmOid = hashAlgorithm.ReadObjectIdentifier();
        byte[] imprint = messageImprint.ReadOctetString();

        return (algorithmOid, imprint);
    }
}
