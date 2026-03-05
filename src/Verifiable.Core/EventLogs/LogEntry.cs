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
/// The type parameter <typeparamref name="TOperation"/> is the domain payload —
/// a DID document update, a CRDT delta, a supply chain event, a TPM attestation,
/// or any other append-only action. The type parameter <typeparamref name="TProof"/>
/// is the proof of authorization — a Data Integrity proof, a zero-knowledge role
/// proof, a hardware-bound signature, or any other verifiable evidence.
/// </para>
/// <para>
/// Multiple proofs within one entry represent co-authorizing evidence over the
/// same stream — for example, a controller proof and one or more witness proofs
/// in a DID event log. Cross-stream proof composition (combining evidence from
/// independent logs) is the responsibility of the caller above this layer.
/// </para>
/// <para>
/// The <see cref="Operation"/> property is nullable to support entries that carry
/// no state mutation — for example, a heartbeat entry that re-witnesses the current
/// digest to establish liveness without changing the underlying state.
/// </para>
/// </remarks>
/// <typeparam name="TOperation">The domain operation type carried by this entry.</typeparam>
/// <typeparam name="TProof">The proof type carried by this entry.</typeparam>
public sealed class LogEntry<TOperation, TProof>
    : IEquatable<LogEntry<TOperation, TProof>>
{
    /// <summary>
    /// Gets the zero-based position of this entry in the log.
    /// </summary>
    public required ulong Index { get; init; }

    /// <summary>
    /// Gets the digest of the previous entry, or <see langword="null"/> for the
    /// genesis entry (index zero).
    /// </summary>
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
    /// encoding for binary logs.
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