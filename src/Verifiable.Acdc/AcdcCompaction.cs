using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Serializes a field map to its canonical bytes. This is the serialization seam the ACDC compaction depends on:
/// computing a block's SAID requires serializing that block, and the serialization is kind-specific (JSON, CBOR,
/// …), so the kind is supplied as a delegate (the deployment wires its serializer, for example the JSON encode arm
/// in <c>Verifiable.Json</c>) rather than referenced from this layer.
/// </summary>
/// <param name="map">The field map to serialize, in its insertion order.</param>
/// <param name="output">The buffer the serialized bytes are written to.</param>
public delegate void AcdcSerializer(MessageFieldMap map, IBufferWriter<byte> output);


/// <summary>
/// Computes the most-compact form of an ACDC: each expanded top-level section block is replaced by its SAID, and the
/// top-level SAID is computed over the resulting compacted serialization. This is the issuer-side derivation that the
/// verifier-side <see cref="AcdcSaid"/> checks level by level.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#most-compact-form-said">
/// most compact form SAID</see> derivation: the SAID of a SAIDed block is computed on its block-level expanded form,
/// each SAIDed subblock having first been compacted to its own SAID, ascending the tree until the top-level ACDC.
/// Because compacting changes the byte count, the top-level version string's length field is restamped to the
/// compacted size before the top-level SAID is taken (the version string is part of the bytes it counts).
/// </para>
/// <para>
/// A section that nests SAIDed subblocks — a rule section whose rule-groups nest rules, or an edge section whose
/// edge-groups nest edges — is compacted depth-first by <see cref="DeriveSectionSaidAsync"/>: each nested subblock (a
/// field map carrying its own SAID, <c>d</c>) is first reduced to its SAID, ascending until the section's own SAID
/// is taken over its block-level expanded form. A leaf block (one with no SAIDed subblocks) has its SAID taken over
/// its full expanded form, which the depth-first walk produces as the degenerate case. The schema section's SAID
/// field is <c>$id</c> rather than <c>d</c>; compacting a schema given as a block lands with the schema section, so
/// a schema block (rather than a schema SAID) is rejected here.
/// </para>
/// </remarks>
public static class AcdcCompaction
{
    /// <summary>
    /// Computes the most-compact form of an expanded ACDC field map.
    /// </summary>
    /// <param name="expanded">The expanded ACDC field map, in canonical field order, whose top-level section values may be detail blocks.</param>
    /// <param name="serialize">The serialization seam: serializes a field map to its canonical bytes (the deployment wires its serializer).</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The compacted field map: each section reduced to its SAID (depth-first for a section with nested SAIDed subblocks), the version string restamped to the compacted size, and the top-level <c>d</c> set to the SAID over the compacted form.</returns>
    /// <exception cref="AcdcException">A required top-level field is missing, or a section block has no SAID field to compact against.</exception>
    public static async ValueTask<MessageFieldMap> ToCompactFormAsync(MessageFieldMap expanded, AcdcSerializer serialize, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expanded);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        var compact = new MessageFieldMap(StringComparer.Ordinal);
        foreach((string label, object? value) in expanded)
        {
            compact[label] = AcdcMessageFields.IsSection(label) && value is MessageFieldMap block
                ? await DeriveSectionSaidAsync(block, serialize, computeDigest, pool, cancellationToken).ConfigureAwait(false)
                : value;
        }

        //The top-level SAID is taken over the compacted form with its version string restamped to that form's byte
        //count. The claimed top SAID and the version string have fixed lengths, so the count measured before the
        //restamp equals the count after it.
        string topClaimed = RequireString(compact, AcdcMessageFields.Said);
        string version = RequireString(compact, AcdcMessageFields.Version);
        compact[AcdcMessageFields.Version] = CesrVersionString.WithLength(version, Measure(compact, serialize));
        compact[AcdcMessageFields.Said] = await ComputeSaidAsync(compact, topClaimed, serialize, computeDigest, pool, cancellationToken).ConfigureAwait(false);

        return compact;

        static string RequireString(MessageFieldMap map, string label)
        {
            if(!map.TryGetString(label, out string? value))
            {
                throw new AcdcException($"ACDC is missing the required string field '{label}' needed for compaction.");
            }

            return value;
        }

        static int Measure(MessageFieldMap map, AcdcSerializer serialize)
        {
            var buffer = new ArrayBufferWriter<byte>();
            serialize(map, buffer);

            return buffer.WrittenCount;
        }
    }


    /// <summary>
    /// Derives the SAID of a SAIDed ACDC section block by compacting it to its most-compact form depth-first: each
    /// nested SAIDed subblock is reduced to its own SAID before the enclosing block's SAID is taken over its
    /// block-level expanded form. A leaf section (no nested SAIDed subblocks, such as a single-clause rule section or
    /// a flat attribute block) is the degenerate case — its SAID is taken over its full expanded form. This is the
    /// issuer-side counterpart of the verifier-side section SAID tree that <see cref="AcdcSaid"/> descends.
    /// </summary>
    /// <remarks>
    /// The block tree is walked iteratively with an explicit work stack rather than by recursion, so the derivation
    /// uses bounded call-stack space however deeply the subblocks nest. A nested value is a SAIDed subblock when it
    /// is a field map carrying a SAID, <c>d</c>, field; any other nested value (a non-SAIDed data map, a list, or a
    /// scalar) is part of the enclosing block's content and stays as it is. Each subblock's SAID is inserted into its
    /// enclosing block's block-level expanded form in the subblock's field position, preserving the field order the
    /// enclosing block's SAID is taken over.
    /// </remarks>
    /// <param name="sectionBlock">The section's expanded detail block, whose nested values may be further SAIDed subblocks.</param>
    /// <param name="serialize">The serialization seam: serializes a field map to its canonical bytes.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The section's SAID, taken over its block-level expanded form with every nested SAIDed subblock compacted to its SAID.</returns>
    /// <exception cref="AcdcException">A SAIDed block has no SAID <c>d</c> field to compact against (for example a schema block, whose SAID field is <c>$id</c>).</exception>
    public static async ValueTask<string> DeriveSectionSaidAsync(MessageFieldMap sectionBlock, AcdcSerializer serialize, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sectionBlock);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        var stack = new Stack<Frame>();
        stack.Push(new Frame(sectionBlock, parentLabel: null));
        string? result = null;

        while(stack.Count > 0)
        {
            Frame frame = stack.Peek();
            if(frame.Cursor < frame.Fields.Count)
            {
                KeyValuePair<string, object?> field = frame.Fields[frame.Cursor];
                frame.Cursor++;

                //A nested SAIDed subblock (a field map with its own SAID) is compacted first: descend into it now,
                //and its SAID fills this block's slot when the child pops, before this block reaches its next field
                //— so the block-level expanded form preserves field order. Any other value is copied as it is.
                if(field.Value is MessageFieldMap subblock && subblock.ContainsKey(AcdcMessageFields.Said))
                {
                    stack.Push(new Frame(subblock, parentLabel: field.Key));
                }
                else
                {
                    frame.BlockLevelExpanded[field.Key] = field.Value;
                }

                continue;
            }

            //The block's subblocks are all compacted; take its SAID over its block-level expanded form and attach it
            //to the enclosing block's slot, or return it as the section SAID when there is no enclosing block.
            stack.Pop();
            string said = await ComputeSaidAsync(frame.BlockLevelExpanded, SaidOf(frame.BlockLevelExpanded), serialize, computeDigest, pool, cancellationToken).ConfigureAwait(false);
            if(stack.Count == 0)
            {
                result = said;
            }
            else
            {
                stack.Peek().BlockLevelExpanded[frame.ParentLabel!] = said;
            }
        }

        return result!;
    }


    /// <summary>
    /// Serializes a field map and recomputes the SAID embedded in it: the claimed SAID is reset to its placeholder
    /// and the digest is recomputed with the algorithm the claimed SAID's code names.
    /// </summary>
    /// <param name="map">The field map to serialize and digest (a block-level expanded form).</param>
    /// <param name="claimedSaid">The block's claimed SAID, naming the placeholder length and the digest algorithm.</param>
    /// <param name="serialize">The serialization seam.</param>
    /// <param name="computeDigest">The digest implementation.</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The CESR-encoded SAID recomputed over the serialization.</returns>
    private static ValueTask<string> ComputeSaidAsync(MessageFieldMap map, string claimedSaid, AcdcSerializer serialize, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var buffer = new ArrayBufferWriter<byte>();
        serialize(map, buffer);

        return CesrSaid.RecomputeEmbeddedAsync(buffer.WrittenMemory, claimedSaid, computeDigest, pool, cancellationToken);
    }


    /// <summary>
    /// Reads a SAIDed block's claimed SAID, the <c>d</c> field that names the digest the block-level expanded form
    /// must reproduce.
    /// </summary>
    /// <param name="block">The block whose SAID is read.</param>
    /// <returns>The block's claimed SAID.</returns>
    /// <exception cref="AcdcException">The block has no SAID <c>d</c> field (for example a schema block, whose SAID field is <c>$id</c>, which is not modeled yet).</exception>
    private static string SaidOf(MessageFieldMap block)
    {
        if(!block.TryGetString(AcdcMessageFields.Said, out string? said))
        {
            throw new AcdcException("An ACDC SAIDed block has no SAID 'd' field to compact against; schema-block compaction (the '$id' field) is not modeled yet.");
        }

        return said;
    }


    /// <summary>
    /// A mutable work item for the depth-first compaction walk: a block being compacted — its source fields, the
    /// block-level expanded form being built (each SAIDed subblock replaced by its SAID), and the slot in its
    /// enclosing block its SAID fills. Held as a class so the cursor and the built form mutate in place across
    /// <see cref="Stack{T}.Peek"/> calls; a struct frame would be copied and lose that progress.
    /// </summary>
    private sealed class Frame
    {
        /// <summary>
        /// Creates a frame for a block at the given position in its enclosing block.
        /// </summary>
        /// <param name="block">The block being compacted; its fields are snapshot so the walk reads them by position.</param>
        /// <param name="parentLabel">The label in the enclosing block's block-level expanded form this block's SAID fills, or <see langword="null"/> for the section root.</param>
        public Frame(MessageFieldMap block, string? parentLabel)
        {
            Fields = new List<KeyValuePair<string, object?>>(block);
            BlockLevelExpanded = new MessageFieldMap(StringComparer.Ordinal);
            ParentLabel = parentLabel;
        }

        /// <summary>The block's source fields in order.</summary>
        public List<KeyValuePair<string, object?>> Fields { get; }

        /// <summary>The block-level expanded form being built: scalars and non-SAIDed values copied as they are, each SAIDed subblock replaced by its SAID.</summary>
        public MessageFieldMap BlockLevelExpanded { get; }

        /// <summary>The label in the enclosing block this block's SAID fills, or <see langword="null"/> for the section root.</summary>
        public string? ParentLabel { get; }

        /// <summary>The index of the next source field to process.</summary>
        public int Cursor { get; set; }
    }
}
