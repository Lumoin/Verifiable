using System;
using System.Collections.Immutable;

namespace Verifiable.Core.EventLogs;

/// <summary>
/// A single entry in an authenticated append-only log.
/// </summary>
/// <remarks>
/// <para>
/// Each entry carries a typed operation, one or more typed proofs, the canonical
/// byte representation used to compute the entry digest, and the chain-linking
/// digests that make the log tamper-evident.
/// </para>
/// <para>
/// <strong>Domain payload and proof.</strong>
/// The type parameter <typeparamref name="TOperation"/> is the domain payload —
/// a DID document update, a CRDT delta, a supply chain event, a TPM attestation,
/// or any other append-only action. The type parameter <typeparamref name="TProof"/>
/// is the proof of authorization — a Data Integrity proof, a zero-knowledge role
/// proof, a hardware-bound signature, or any other verifiable evidence.
/// Neither type is constrained by the infrastructure; the caller defines both.
/// </para>
/// <para>
/// <strong>What the digest chain guarantees.</strong>
/// The combination of <see cref="PreviousDigest"/> and <see cref="Digest"/> forms
/// a cryptographic commitment chain. Each entry reduces uncertainty about the
/// current state of the subject — a reduction of uncertainty in the information-theoretic sense — and
/// <see cref="Digest"/>, computed over <see cref="CanonicalBytes"/>, commits that
/// reduction irrevocably. <see cref="PreviousDigest"/> chains this entry to its
/// predecessor so that the accumulated reduction cannot be selectively undone.
/// Any modification to any earlier entry changes that entry's digest, which
/// invalidates every subsequent <see cref="PreviousDigest"/> reference.
/// The <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> threads the
/// authoritative previous digest forward rather than trusting the value the entry
/// claims, making tampering detectable at the point it occurs. The log is therefore
/// as strong as its weakest verified link — this entry type is that link.
/// See <see href="https://lumoin.com/writings/mydata2025entropy"/> for the broader
/// framing of entropy, verified continuity, and chain-of-trust structures.
/// </para>
/// <para>
/// <strong>Multiple proofs within one entry.</strong>
/// Multiple proofs represent co-authorizing evidence over the same log stream.
/// In a DID event log the first proof is conventionally the controller proof
/// (the DID controller's authorization over the operation) and subsequent proofs
/// are witness proofs (independent attestations from witness services confirming
/// the entry was observed). The <see cref="ValidateProofDelegate{TState,TOperation,TProof,TContext}"/>
/// receives the full <see cref="ImmutableArray{T}"/> and implements whatever
/// threshold logic the log method requires — unanimity, a k-of-n quorum, or
/// controller-only for logs without witnesses.
/// </para>
/// <para>
/// Cross-stream proof composition — combining evidence from independent log
/// streams to establish a higher-order trust claim — is the responsibility of
/// the caller above this layer and is not represented within a single entry.
/// </para>
/// <para>
/// <strong>Heartbeat entries.</strong>
/// The <see cref="Operation"/> property is nullable to support entries that carry
/// no state mutation. A heartbeat entry re-witnesses the current digest to
/// establish liveness without changing the underlying state. The integrity
/// mechanism still advances and proofs are still validated, so a heartbeat entry extends the
/// evidence that the log controller remains active and that the current state has
/// not been repudiated since the last mutating entry.
/// </para>
/// </remarks>
/// <typeparam name="TOperation">The domain operation type carried by this entry.</typeparam>
/// <typeparam name="TProof">The proof type carried by this entry.</typeparam>
public sealed class LogEntry<TOperation, TProof>: IEquatable<LogEntry<TOperation, TProof>>
{
    /// <summary>
    /// Gets the zero-based position of this entry in the log.
    /// </summary>
    public required ulong Index { get; init; }

    /// <summary>
    /// Gets the digest of the previous entry, or <see langword="null"/> for the
    /// genesis entry (index zero).
    /// </summary>
    /// <remarks>
    /// This value is what the entry itself claims its predecessor's digest to be.
    /// The <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> compares
    /// this against the digest it independently observed from the previous entry.
    /// Trusting this field directly would allow an attacker to forge a consistent
    /// chain from a tampered log; the replayer's authoritative threading prevents that.
    /// </remarks>
    public required ReadOnlyMemory<byte>? PreviousDigest { get; init; }

    /// <summary>
    /// Gets the digest of this entry, computed over <see cref="CanonicalBytes"/>.
    /// </summary>
    public required ReadOnlyMemory<byte> Digest { get; init; }

    /// <summary>
    /// Gets the canonical byte representation of this entry used to compute
    /// <see cref="Digest"/> and to verify chain linkage.
    /// </summary>
    /// <remarks>
    /// The canonicalization algorithm is caller-defined and injected through
    /// <see cref="LogReplayContext{TState,TOperation,TProof,TContext}"/>. Common
    /// choices are JCS (RFC 8785) for JSON-based logs and CBOR deterministic
    /// encoding for binary logs. The canonical form must be deterministic: the
    /// same logical entry must always produce the same bytes, or digest verification
    /// will fail non-deterministically across replayers and verifiers.
    /// </remarks>
    public required ReadOnlyMemory<byte> CanonicalBytes { get; init; }

    /// <summary>
    /// Gets the domain operation carried by this entry, or <see langword="null"/>
    /// for entries that carry no state mutation such as heartbeat entries.
    /// </summary>
    public required TOperation? Operation { get; init; }

    /// <summary>
    /// Gets the proofs of authorization for this entry.
    /// </summary>
    /// <remarks>
    /// Contains at least one proof. The first proof is conventionally the
    /// controller proof. Subsequent proofs are witness proofs or other
    /// co-authorizing evidence over the same log stream.
    /// The <see cref="ValidateProofDelegate{TState,TOperation,TProof,TContext}"/>
    /// receives this array and is responsible for all threshold and ordering logic.
    /// </remarks>
    public required ImmutableArray<TProof> Proofs { get; init; }


    /// <inheritdoc/>
    public bool Equals(LogEntry<TOperation, TProof>? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Index == other.Index
            && Digest.Span.SequenceEqual(other.Digest.Span)
            && NullableSpanEqual(PreviousDigest, other.PreviousDigest)
            && CanonicalBytes.Span.SequenceEqual(other.CanonicalBytes.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is LogEntry<TOperation, TProof> other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(Index, MemoryHashCode(Digest), MemoryHashCode(CanonicalBytes));

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="left"/> and
    /// <paramref name="right"/> are equal.
    /// </summary>
    public static bool operator ==(LogEntry<TOperation, TProof>? left, LogEntry<TOperation, TProof>? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="left"/> and
    /// <paramref name="right"/> are not equal.
    /// </summary>
    public static bool operator !=(LogEntry<TOperation, TProof>? left, LogEntry<TOperation, TProof>? right) =>
        !(left == right);


    private static bool NullableSpanEqual(ReadOnlyMemory<byte>? a, ReadOnlyMemory<byte>? b)
    {
        if(a is null && b is null)
        {
            return true;
        }

        if(a is null || b is null)
        {
            return false;
        }

        return a.Value.Span.SequenceEqual(b.Value.Span);
    }

    private static int MemoryHashCode(ReadOnlyMemory<byte> memory)
    {
        HashCode hash = new();
        hash.AddBytes(memory.Span);

        return hash.ToHashCode();
    }
}