using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Immutable;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The simulator's model of an open sequence context: the accumulator <c>TPM2_HashSequenceStart()</c>,
/// <c>TPM2_HMAC_Start()</c>, <c>TPM2_SignSequenceStart()</c>, or <c>TPM2_VerifySequenceStart()</c> opens and
/// <c>TPM2_SequenceUpdate()</c> feeds, addressed by a transient handle exactly as a loaded object is (TPM 2.0
/// Library Part 1, clause 27.2.3: a sequence handle's MSO is <c>TPM_HT_TRANSIENT</c>).
/// </summary>
/// <remarks>
/// <para>
/// A sequence context lives in the NULL hierarchy (Part 1, clause 27.2.4: "Sequence objects and sessions are
/// in the NULL hierarchy"), so this record carries NO <c>Hierarchy</c> field — unlike
/// <see cref="TransientKeyState.Hierarchy"/> — and is therefore untouched by <c>TPM2_Clear()</c> (which
/// rotates the storage hierarchy's proof and evicts the storage/endorsement/platform hierarchies' own
/// residents, never the NULL hierarchy's) or <c>TPM2_HierarchyControl()</c> (which can disable the storage,
/// endorsement, or platform hierarchy, but the NULL hierarchy is never disableable at all, Part 1, clause
/// 24.4). A sequence context is instead flushed by <c>TPM2_Startup()</c> (Part 1, clause 27.4: "An object
/// context is only removed from TPM memory with TPM2_FlushContext(), deletion of the associated hierarchy
/// seed, or TPM2_Startup()" — the NULL hierarchy's seed is itself re-derived on every <c>TPM2_Startup()</c>,
/// Part 1, clause 24.5), by an explicit <c>TPM2_FlushContext()</c> naming its handle (Part 3, clause 28.4), or
/// by its own owning command completing successfully — <c>{F}</c> on <c>TPM2_SequenceComplete()</c>,
/// <c>TPM2_EventSequenceComplete()</c>, <c>TPM2_SignSequenceComplete()</c>, and
/// <c>TPM2_VerifySequenceComplete()</c> (Part 3, clause 4.2.7; Part
/// 1, clause 29.4.6: "When TPM2_SequenceComplete(), ... TPM2_SignSequenceComplete(), or
/// TPM2_VerifySequenceComplete() completes successfully, the sequence context is flushed from the TPM").
/// </para>
/// <para>
/// A sequence's Name is the Empty Buffer for as long as it remains open (Part 1, clause 29.4.6: "the public
/// portion of a sequence is not readable with TPM2_ReadPublic()"; a session's cpHash/rpHash accordingly treats
/// <c>@sequenceHandle</c>'s Name term as present but zero-length) — this record carries no Name field of its
/// own for that reason, unlike <see cref="TransientKeyState.Name"/> and <see cref="KeyedHashObjectState.Name"/>.
/// Its <see cref="AuthValue"/> is exempt from dictionary-attack protection (Part 1, clause 29.4.6: "A sequence
/// is exempt from dictionary attack protection and authorization failures will not cause the TPM to enter
/// lockout"): a mismatch is refused but never charges <c>FailedTries</c>, and a correct value authorizes even
/// while the TPM is in lockout.
/// </para>
/// <para>
/// <see cref="Segments"/> retains the message as the parsed <c>TPM2B_MAX_BUFFER</c> octets from every
/// <c>TPM2_SequenceUpdate()</c> — the parse's own rental IS the retained segment, with no copy and no growth —
/// rather than an incrementally-updated running hash state, which is what a real TPM keeps. This is a
/// deliberate modelling simplification: it lets the completing command hash the whole accumulated message in
/// one pass through <see cref="BuildMessageSequence"/> and the registered digest seam
/// (<c>ReadOnlySequence{T}</c>-native, so no segment is ever copied into a combined buffer), at the cost of
/// holding the full, unbounded message in memory for the sequence's lifetime rather than only its digest
/// state.
/// </para>
/// <para>
/// Three Start commands — <c>TPM2_HashSequenceStart()</c> (TPM 2.0 Library Part 3, clause 17.4, Table 85, which
/// names no handle at all), <c>TPM2_SignSequenceStart()</c> (clause 17.5, Table 87) and
/// <c>TPM2_VerifySequenceStart()</c> (clause 17.6, Table 89) — allocate a sequence slot with no authorization
/// of any kind (<c>keyHandle</c>'s Auth Index is None on the key-bound pair); the fourth,
/// <c>TPM2_HMAC_Start()</c>, requires USER-role authorization of its <c>@handle</c> (clause 17.2.2, Table 80)
/// and claims its slot only after that ladder. What bounds the allocation for all four is the object-slot count
/// every transient object shares: an open sequence occupies
/// one of <see cref="TpmSimulatorState.MaxLoadedObjects"/> slots, and once they are exhausted every Start
/// command answers <c>TPM_RC_OBJECT_MEMORY</c> (Part 1, clauses 29.4.6 and 36.3.2). The octets a sequence
/// retains (<see cref="Segments"/>, above) are not bounded — a real TPM keeps only a running hash state per
/// open sequence, never the message itself; this simulator keeps the parsed segments for the registered
/// digest seam. A slot is released only by a successful <c>TPM2_SequenceComplete()</c> (clause 17.8),
/// <c>TPM2_EventSequenceComplete()</c> (clause 17.9), <c>TPM2_SignSequenceComplete()</c> (clause 20.6) or
/// <c>TPM2_VerifySequenceComplete()</c> (clause 20.3), or by an explicit flush.
/// </para>
/// <para>
/// For the key-bound kinds (<see cref="TpmSequenceKind.Signing"/>, <see cref="TpmSequenceKind.Verification"/>)
/// the key identity a completing command must match is bound by Name, not by handle:
/// <see cref="StartingKeyName"/> is a deep copy of the signing or verifying key's Name taken at
/// <c>TPM2_SignSequenceStart()</c> or <c>TPM2_VerifySequenceStart()</c>, so a key reloaded at a different
/// handle (Name-equal to the original) still completes the sequence, and a different key loaded at the same
/// numeric handle the original occupied does not (TPM 2.0 Library Part 3, clauses 20.3.1 and 20.6: "If
/// keyHandle refers to a key that is not the same as the key that was used to start the signature context,
/// the TPM shall return TPM_RC_SIGN_CONTEXT_KEY"). <see cref="Scheme"/> and <see cref="HashAlg"/> are resolved
/// once, from that same key's retained signing scheme, at <c>TPM2_SignSequenceStart()</c> or
/// <c>TPM2_VerifySequenceStart()</c> (clause 17.5/17.6: "The TPM will hash the message as required by the
/// key's scheme in order to sign it" — overriding the scheme at completion is not supported, clause 20.6).
/// The keyless kinds (<see cref="TpmSequenceKind.Hash"/>, <see cref="TpmSequenceKind.Event"/>) bind no key:
/// <see cref="StartingKeyName"/> is the Empty Buffer, <see cref="Scheme"/> is <c>TPM_ALG_NULL</c>, and
/// <see cref="HashAlg"/> is the <c>hashAlg</c> <c>TPM2_HashSequenceStart()</c> was given — the digest
/// algorithm of a hash sequence, or <c>TPM_ALG_NULL</c> for an Event Sequence (clause 17.4.1). An HMAC
/// sequence (<see cref="TpmSequenceKind.Hmac"/>) binds the KEY VALUE rather than the key's identity: no
/// completing command re-reads the key, so <see cref="StartingKeyName"/> is the Empty Buffer,
/// <see cref="Scheme"/> is <c>TPM_ALG_HMAC</c>, <see cref="HashAlg"/> is the hash Table 79 resolved at
/// <c>TPM2_HMAC_Start()</c>, and <see cref="HmacKey"/> is the sequence's own copy of the key's sensitive value
/// (Part 4 <c>ObjectCreateHMACSequence</c>), so the key may be flushed before the sequence completes.
/// </para>
/// </remarks>
/// <param name="Handle">The transient handle assigned to the sequence context.</param>
/// <param name="Kind">Which sequence-command family may complete this context (TPM 2.0 Library Part 1, clause 29.4.1); a mismatched completion command answers <c>TPM_RC_MODE</c>.</param>
/// <param name="StartingKeyName">
/// A deep copy of the signing (or verifying) key's Name (<c>TPM2B_NAME</c>) taken at
/// <c>TPM2_SignSequenceStart()</c>/<c>TPM2_VerifySequenceStart()</c>, owned by this record — the completing
/// command's <c>@keyHandle</c> must resolve to a key whose current Name matches this one
/// (<c>TPM_RC_SIGN_CONTEXT_KEY</c> otherwise). Deep-copied rather than borrowed from the live
/// <see cref="TransientKeyState"/> because the two records have independent lifetimes: the key may be flushed
/// and reloaded, or persist past the sequence's own flush, and neither owner's disposal may reach the other's
/// octets. The Empty Buffer for a keyless kind (<see cref="TpmSequenceKind.Hash"/>, <see cref="TpmSequenceKind.Event"/>).
/// </param>
/// <param name="Scheme">The signing scheme resolved from the key at <c>TPM2_SignSequenceStart()</c>/<c>TPM2_VerifySequenceStart()</c> (<see cref="TransientKeyState.SigningScheme"/>); not re-read from the key at completion. <c>TPM_ALG_NULL</c> for a keyless kind.</param>
/// <param name="HashAlg">The sequence's own accumulator digest algorithm: the scheme's hash resolved at <c>TPM2_SignSequenceStart()</c>/<c>TPM2_VerifySequenceStart()</c> (<see cref="TransientKeyState.SigningSchemeHashAlg"/>), or <c>TPM2_HashSequenceStart()</c>'s <c>hashAlg</c> — <c>TPM_ALG_NULL</c> for an Event Sequence.</param>
/// <param name="AuthValue">
/// The sequence's own authorization value (<c>TPM2B_AUTH</c>), supplied as <c>auth</c> at the Start command
/// and owned by this record — compared against every <c>TPM2_SequenceUpdate()</c>'s and the completing
/// command's own supplied password, exempt from dictionary-attack protection (Part 1, clause 29.4.6).
/// Ownership arrives with the started sequence at the installing transition and is released on eviction.
/// </param>
/// <param name="Segments">
/// The message accumulated so far, as the sequence of pool-rented <c>TPM2B_MAX_BUFFER</c> carriers each
/// <c>TPM2_SequenceUpdate()</c> parsed, owned by this record in presentation order. <see cref="BuildMessageSequence"/>
/// chains them into one <c>ReadOnlySequence{T}</c> — plus an optional trailing buffer from the completing
/// command — with no copy. Ownership of each element arrives with its <c>TPM2_SequenceUpdate()</c> at the
/// installing transition and is released on eviction.
/// </param>
/// <param name="FirstBlock">
/// The first-block safety verdict (TPM 2.0 Library Part 3, clauses 17.7 and 17.8), settled once from
/// <see cref="TpmSequenceFirstBlock.NotYetPresented"/> the first time a block reaches the sequence — by
/// <c>TPM2_SequenceUpdate()</c>, or by the completing command's own trailing buffer when no prior update ran.
/// Consulted when a restricted signing key completes a signing sequence, and when
/// <c>TPM2_SequenceComplete()</c> decides whether a hash sequence's digest earns a <c>TPMT_TK_HASHCHECK</c>.
/// </param>
/// <param name="HmacKey">
/// An OWNED, pinned deep copy of the KEYEDHASH key's sensitive value (<c>TPMT_SENSITIVE.sensitive.bits</c>)
/// taken in the <c>TPM2_HMAC_Start()</c> effect (TPM 2.0 Library Part 3, clause 17.2; Part 4
/// <c>ObjectCreateHMACSequence</c>) — never an alias of the live <see cref="KeyedHashObjectState.Data"/>, so
/// the key may be flushed before the sequence completes; released by <see cref="Dispose"/>. The dispose-immune
/// <see cref="Tpm2bSensitiveData.Empty"/> for every kind other than <see cref="TpmSequenceKind.Hmac"/>.
/// </param>
public sealed record SequenceObjectState(
    TpmiDhObject Handle,
    TpmSequenceKind Kind,
    Tpm2bName StartingKeyName,
    TpmiAlgSigScheme Scheme,
    TpmiAlgHash HashAlg,
    Tpm2bAuth AuthValue,
    ImmutableList<Tpm2bMaxBuffer> Segments,
    TpmSequenceFirstBlock FirstBlock,
    Tpm2bSensitiveData HmacKey): IDisposable
{
    /// <summary>
    /// Releases the sequence's owned carriers — <see cref="StartingKeyName"/>, <see cref="AuthValue"/>,
    /// <see cref="HmacKey"/>, and every buffer in <see cref="Segments"/>. Called when the sequence leaves the
    /// automaton's dictionary for good (a successful completion, an explicit <c>TPM2_FlushContext()</c>, or
    /// simulator teardown). The dispose-immune <see cref="Tpm2bSensitiveData.Empty"/> a non-HMAC sequence
    /// carries in <see cref="HmacKey"/> makes its release a no-op.
    /// </summary>
    public void Dispose()
    {
        StartingKeyName.Dispose();
        AuthValue.Dispose();
        HmacKey.Dispose();

        foreach(Tpm2bMaxBuffer segment in Segments)
        {
            segment.Dispose();
        }
    }

    /// <summary>
    /// Value equality with OWNERSHIP identity for the owned carriers: two records are equal only when they
    /// share the same <see cref="StartingKeyName"/> and <see cref="AuthValue"/> instances and the same
    /// <see cref="Segments"/> elements in order — reference comparison is ownership identity and never reads
    /// carrier content, so a superseded or disposed snapshot cannot throw here (see
    /// <see cref="TransientKeyState.Equals(TransientKeyState)"/> for the shared rationale).
    /// </summary>
    /// <param name="other">The record to compare against.</param>
    /// <returns><see langword="true"/> when every field matches and the carriers are the same instances.</returns>
    public bool Equals(SequenceObjectState? other) =>
        other is not null
        && Handle == other.Handle
        && Kind == other.Kind
        && ReferenceEquals(StartingKeyName, other.StartingKeyName)
        && Scheme == other.Scheme
        && HashAlg == other.HashAlg
        && ReferenceEquals(AuthValue, other.AuthValue)
        && ReferenceEquals(HmacKey, other.HmacKey)
        && Segments.Count == other.Segments.Count
        && SegmentsReferenceEqual(Segments, other.Segments)
        && FirstBlock == other.FirstBlock;

    /// <summary>
    /// Hashes the object's immutable identity fields, consistent with
    /// <see cref="Equals(SequenceObjectState)"/> without ever reading carrier content.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode() => HashCode.Combine(Handle, Kind, Scheme, HashAlg, Segments.Count, FirstBlock);

    /// <summary>
    /// Compares two segment lists element-by-element by reference identity, the carrier-content-free companion
    /// <see cref="Equals(SequenceObjectState)"/> applies to every other owned carrier.
    /// </summary>
    /// <param name="left">The first list.</param>
    /// <param name="right">The second list.</param>
    /// <returns><see langword="true"/> when both lists have the same length and every element is the same instance at the same position.</returns>
    private static bool SegmentsReferenceEqual(ImmutableList<Tpm2bMaxBuffer> left, ImmutableList<Tpm2bMaxBuffer> right)
    {
        for(int i = 0; i < left.Count; i++)
        {
            if(!ReferenceEquals(left[i], right[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Classifies a block of data against the first-block safety rule (TPM 2.0 Library Part 3, clauses 17.7 and
    /// 17.8): <see cref="TpmSequenceFirstBlock.SafeToSign"/> when the block has at least four octets and its
    /// first four octets are not <c>TPM_GENERATED_VALUE</c> in big-endian form; <see cref="TpmSequenceFirstBlock.NotSafeToSign"/>
    /// otherwise, including a block shorter than four octets (clause 17.8's "fewer than sizeof(TPM_GENERATED)
    /// octets" note — an empty first block is such a block; Part 4's <c>TicketIsSafe()</c> answers FALSE for
    /// it too).
    /// </summary>
    /// <param name="block">The candidate first block's octets.</param>
    /// <returns>The settled verdict.</returns>
    public static TpmSequenceFirstBlock ClassifyFirstBlock(ReadOnlySpan<byte> block)
    {
        if(block.Length < sizeof(uint))
        {
            return TpmSequenceFirstBlock.NotSafeToSign;
        }

        uint leadingOctets = BinaryPrimitives.ReadUInt32BigEndian(block);

        return leadingOctets == TpmConstants32.TPM_GENERATED_VALUE
            ? TpmSequenceFirstBlock.NotSafeToSign
            : TpmSequenceFirstBlock.SafeToSign;
    }

    /// <summary>
    /// Builds a zero-copy <see cref="ReadOnlySequence{T}"/> over <paramref name="segments"/> followed by an
    /// optional <paramref name="trailingBuffer"/> — the completing command's own <c>buffer</c> parameter,
    /// appended before hashing, signing, or verifying without a separate <c>TPM2_SequenceUpdate()</c> (TPM 2.0
    /// Library Part 3, clause 17.8: "the last part of data, if any"; clause 20.6: "data to be added to the
    /// signature"). An empty segment or an empty <paramref name="trailingBuffer"/> contributes no octets; a
    /// result with exactly one non-empty piece is a single-segment sequence.
    /// </summary>
    /// <param name="segments">The sequence's accumulated <c>TPM2B_MAX_BUFFER</c> carriers, in presentation order.</param>
    /// <param name="trailingBuffer">The completing command's own trailing octets, or empty when the command carries none.</param>
    /// <returns>The chained, zero-copy message sequence.</returns>
    public static ReadOnlySequence<byte> BuildMessageSequence(ImmutableList<Tpm2bMaxBuffer> segments, ReadOnlyMemory<byte> trailingBuffer = default)
    {
        ArgumentNullException.ThrowIfNull(segments);

        TpmSequenceSegment? first = null;
        TpmSequenceSegment? last = null;

        foreach(Tpm2bMaxBuffer segment in segments)
        {
            (first, last) = AppendSegment(first, last, segment.AsReadOnlyMemory());
        }

        (first, last) = AppendSegment(first, last, trailingBuffer);

        if(first is null || last is null)
        {
            return ReadOnlySequence<byte>.Empty;
        }

        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    /// <summary>
    /// Appends one memory block onto a segment chain being built, skipping an empty block entirely so it
    /// contributes no segment at all.
    /// </summary>
    /// <param name="first">The chain's first segment so far, or <see langword="null"/> when nothing has been appended yet.</param>
    /// <param name="last">The chain's last segment so far, or <see langword="null"/> when nothing has been appended yet.</param>
    /// <param name="memory">The block to append.</param>
    /// <returns>The chain's (possibly unchanged) first and last segments.</returns>
    private static (TpmSequenceSegment? First, TpmSequenceSegment? Last) AppendSegment(TpmSequenceSegment? first, TpmSequenceSegment? last, ReadOnlyMemory<byte> memory)
    {
        if(memory.IsEmpty)
        {
            return (first, last);
        }

        if(first is null || last is null)
        {
            var segment = new TpmSequenceSegment(memory);

            return (segment, segment);
        }

        return (first, last.Append(memory));
    }

    /// <summary>
    /// One link in the zero-copy segment chain <see cref="BuildMessageSequence"/> builds over the sequence's
    /// already-pooled buffers. Each instance borrows the memory it wraps — it never owns or disposes it, since
    /// the owning <see cref="Tpm2bMaxBuffer"/> (or the completing command's own trailing buffer) outlives the
    /// short-lived <see cref="ReadOnlySequence{T}"/> built over it.
    /// </summary>
    private sealed class TpmSequenceSegment: ReadOnlySequenceSegment<byte>
    {
        /// <summary>
        /// Initializes the chain's first link over <paramref name="memory"/>, at running index zero.
        /// </summary>
        /// <param name="memory">The borrowed memory this link wraps.</param>
        public TpmSequenceSegment(ReadOnlyMemory<byte> memory)
        {
            Memory = memory;
        }

        /// <summary>
        /// Links a new segment over <paramref name="memory"/> onto this one, at this link's running index plus
        /// its own length, and returns the new link as the chain's new tail.
        /// </summary>
        /// <param name="memory">The borrowed memory the new link wraps.</param>
        /// <returns>The newly linked, now-final segment.</returns>
        public TpmSequenceSegment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new TpmSequenceSegment(memory)
            {
                RunningIndex = RunningIndex + Memory.Length
            };

            Next = next;

            return next;
        }
    }
}
