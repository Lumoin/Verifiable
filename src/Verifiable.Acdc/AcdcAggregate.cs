using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Serializes a flat list of strings to its canonical bytes. This is the serialization seam the aggregate
/// identifier (AGID) depends on: the AGID is a digest over the ordered list of the blocks' SAIDs, and that list
/// serialization is kind-specific (a JSON array, a CESR count-coded group, …), so the kind is supplied as a
/// delegate (the deployment wires its serializer, for example the JSON aggregate-list arm in <c>Verifiable.Json</c>)
/// rather than referenced from this layer.
/// </summary>
/// <param name="elements">The list elements in order: the AGID (or its placeholder) followed by the blocks' SAIDs.</param>
/// <param name="output">The buffer the serialized bytes are written to.</param>
public delegate void AcdcAggregateListSerializer(IReadOnlyList<string> elements, IBufferWriter<byte> output);


/// <summary>
/// Computes and verifies the aggregate identifier (AGID) of an ACDC aggregate section, the digest that commits to
/// an ordered set of blinded attribute blocks and enables their selective disclosure. The AGID is the
/// self-addressing digest of the ordered list of the blocks' SAIDs (with the AGID's own zeroth slot dummied), so it
/// reuses the SAID primitive: deriving the AGID is computing that digest, and verifying a disclosure is
/// reconstructing the list of block SAIDs — recomputing each revealed block's SAID — and confirming the AGID over
/// it.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#computation-of-the-agid-aggregate-id">
/// computation of the AGID</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#inclusion-proof-via-aggregated-list-digest-agid">
/// inclusion proof via the aggregated list digest</see>: the blinded attribute list is
/// <c>[a₀, a₁, … a_N]</c> where each <c>aᵢ</c> for <c>i ≥ 1</c> is a block's SAID and <c>a₀</c> is the AGID; the
/// AGID is computed by setting <c>a₀</c> to a digest-length run of the dummy character, serializing the list,
/// digesting it, and CESR-encoding the digest back into <c>a₀</c>. Because each block is blinded by its own SAID and
/// UUID, the full list of SAIDs may be disclosed without revealing any block's attribute values, and any one block
/// may be revealed and proven a member by recomputing its SAID and confirming the AGID.
/// </para>
/// <para>
/// This treats each aggregate block as a leaf: its SAID is recomputed over its full detail. The worked aggregate
/// blocks are flat attribute blocks (<c>d</c>, <c>u</c>, and attribute fields) with no nested SAIDed subblocks.
/// </para>
/// </remarks>
public static class AcdcAggregate
{
    /// <summary>
    /// Derives the AGID of an aggregate section from the ordered SAIDs of its blocks: builds the blinded list with
    /// the zeroth slot dummied to the digest's placeholder, serializes it, and digests it with the given algorithm.
    /// This is the issuer-side derivation that <see cref="VerifyAgidAsync"/> checks.
    /// </summary>
    /// <param name="blockSaids">The blocks' SAIDs <c>a₁ … a_N</c> in order.</param>
    /// <param name="digestCode">The CESR digest derivation code that selects the AGID's algorithm and length (for example <c>E</c> for Blake3-256).</param>
    /// <param name="serializeList">The serialization seam: serializes the blinded list to its canonical bytes.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The derived AGID.</returns>
    /// <exception cref="CesrFormatException">The digest code is not a supported SAID digest code.</exception>
    public static ValueTask<string> DeriveAgidAsync(IReadOnlyList<string> blockSaids, string digestCode, AcdcAggregateListSerializer serializeList, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(blockSaids);
        ArgumentNullException.ThrowIfNull(digestCode);
        ArgumentNullException.ThrowIfNull(serializeList);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        var buffer = new ArrayBufferWriter<byte>();
        serializeList(BlindedList(CesrSaid.Placeholder(digestCode), blockSaids), buffer);

        return CesrSaid.ComputeAsync(buffer.WrittenMemory, digestCode, computeDigest, pool, cancellationToken);
    }


    /// <summary>
    /// Verifies a claimed AGID against the ordered SAIDs of its blocks: reconstructs the blinded list with the AGID
    /// in its zeroth slot and recomputes the AGID over it, resetting the AGID to its placeholder before digesting.
    /// </summary>
    /// <param name="agid">The claimed AGID.</param>
    /// <param name="blockSaids">The blocks' SAIDs <c>a₁ … a_N</c> in order.</param>
    /// <param name="serializeList">The serialization seam: serializes the blinded list to its canonical bytes.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns><see langword="true"/> when the recomputed AGID equals the claimed AGID.</returns>
    /// <exception cref="CesrFormatException">The claimed AGID's leading code is not a supported SAID digest code.</exception>
    public static ValueTask<bool> VerifyAgidAsync(string agid, IReadOnlyList<string> blockSaids, AcdcAggregateListSerializer serializeList, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(agid);
        ArgumentNullException.ThrowIfNull(blockSaids);
        ArgumentNullException.ThrowIfNull(serializeList);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        var buffer = new ArrayBufferWriter<byte>();
        serializeList(BlindedList(agid, blockSaids), buffer);

        return CesrSaid.VerifyEmbeddedAsync(buffer.WrittenMemory, agid, computeDigest, pool, cancellationToken);
    }


    /// <summary>
    /// Verifies a selectively disclosed aggregate section: recomputes the SAID of every revealed block and confirms
    /// it matches the block's own SAID, reconstructs the ordered list of block SAIDs (a revealed block by its
    /// recomputed SAID, a blinded block by its disclosed SAID), and confirms the section's AGID over that list. This
    /// is the verifier's selective-disclosure check — it proves each revealed block is authentic and a member of the
    /// aggregate without requiring the undisclosed blocks.
    /// </summary>
    /// <param name="section">The disclosed aggregate section: the AGID and the blocks, each a revealed detail block or a blinded SAID.</param>
    /// <param name="serializeBlock">The serialization seam for a block (a field map): used to recompute a revealed block's SAID.</param>
    /// <param name="serializeList">The serialization seam for the blinded list: used to recompute the AGID.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns><see langword="true"/> when every revealed block's SAID is authentic and the AGID matches; otherwise <see langword="false"/>.</returns>
    /// <exception cref="AcdcException">A revealed block has no SAID <c>d</c> field.</exception>
    /// <exception cref="CesrFormatException">A block SAID or the AGID does not begin with a supported digest code.</exception>
    public static async ValueTask<bool> VerifyDisclosureAsync(AcdcAggregateSection section, AcdcSerializer serializeBlock, AcdcAggregateListSerializer serializeList, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(section);
        ArgumentNullException.ThrowIfNull(serializeBlock);
        ArgumentNullException.ThrowIfNull(serializeList);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        var blockSaids = new List<string>(section.Blocks.Count);
        foreach(AcdcAggregateBlock block in section.Blocks)
        {
            //A revealed block must hash to its own claimed SAID (otherwise its detail was altered); a blinded block
            //contributes its disclosed SAID directly. Either way the block's SAID is what enters the AGID list.
            (bool authentic, string said) = block switch
            {
                CompactAggregateBlock compact => (true, compact.Said),
                ExpandedAggregateBlock expanded => await VerifyRevealedBlockAsync(expanded.Detail, serializeBlock, computeDigest, pool, cancellationToken).ConfigureAwait(false),
                _ => throw new AcdcException("An ACDC aggregate block is neither a blinded SAID nor a revealed detail block.")
            };

            if(!authentic)
            {
                return false;
            }

            blockSaids.Add(said);
        }

        return await VerifyAgidAsync(section.Agid, blockSaids, serializeList, computeDigest, pool, cancellationToken).ConfigureAwait(false);

        static async ValueTask<(bool Authentic, string Said)> VerifyRevealedBlockAsync(MessageFieldMap detail, AcdcSerializer serializeBlock, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken)
        {
            if(!detail.TryGetString(AcdcMessageFields.Said, out string? claimed))
            {
                throw new AcdcException("An ACDC revealed aggregate block has no SAID 'd' field to verify against.");
            }

            var buffer = new ArrayBufferWriter<byte>();
            serializeBlock(detail, buffer);
            string recomputed = await CesrSaid.RecomputeEmbeddedAsync(buffer.WrittenMemory, claimed, computeDigest, pool, cancellationToken).ConfigureAwait(false);

            return (string.Equals(recomputed, claimed, StringComparison.Ordinal), claimed);
        }
    }


    /// <summary>
    /// Builds the blinded attribute list the AGID is taken over: the AGID (or its placeholder) in the zeroth slot
    /// followed by the blocks' SAIDs in order.
    /// </summary>
    /// <param name="head">The AGID or its placeholder for the zeroth slot.</param>
    /// <param name="blockSaids">The blocks' SAIDs.</param>
    /// <returns>The blinded list.</returns>
    private static List<string> BlindedList(string head, IReadOnlyList<string> blockSaids)
    {
        var list = new List<string>(blockSaids.Count + 1) { head };
        list.AddRange(blockSaids);

        return list;
    }
}
