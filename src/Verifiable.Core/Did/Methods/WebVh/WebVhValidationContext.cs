using System;
using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// The cryptographic seams and clock the did:webvh proof validation uses while replaying a DID Log: the
/// fixed SHA-256 hash, the base58btc coders, a memory pool, and a <see cref="System.TimeProvider"/> for the
/// <c>versionTime</c> checks.
/// </summary>
/// <remarks>
/// This is the <c>TContext</c> the <see cref="EventLogs.LogReplayer{TState,TOperation,TProof,TContext}"/>
/// passes through to proof validation. Keeping the coders, hash function, pool and clock here lets the
/// did:webvh verification stay free of ambient singletons and stay testable with a fake clock.
/// </remarks>
public sealed record WebVhValidationContext
{
    /// <summary>The on-demand JCS canonicalizers producing the pooled bytes the SCID and proof checks hash and sign over.</summary>
    public required WebVhCanonicalizer Canonicalizer { get; init; }

    /// <summary>The SHA-256 hash function fixed by did:webvh v1.0, used for the SCID, entryHash and pre-rotation hashes.</summary>
    public required HashFunctionDelegate HashFunction { get; init; }

    /// <summary>The raw base58btc encoder (no multibase prefix) used by the did:webvh hash primitive.</summary>
    public required EncodeDelegate Base58Encoder { get; init; }

    /// <summary>The base58btc decoder used to decode update keys and proof values.</summary>
    public required DecodeDelegate Base58Decoder { get; init; }

    /// <summary>The memory pool for the transient hash, key and signature buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }

    /// <summary>The clock used to reject entries whose <c>versionTime</c> is in the future.</summary>
    public required TimeProvider TimeProvider { get; init; }
}
