using System;
using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// The seams, hash algorithm and clock the did:webplus microledger verification uses while replaying a
/// <c>did-documents.jsonl</c> history: the strict parser and JCS canonicalizer, the proof and update-rule
/// extractors, the self-hash algorithm, the multibase coders, a memory pool and a
/// <see cref="System.TimeProvider"/>.
/// </summary>
/// <remarks>
/// This is the <c>TContext</c> the <see cref="Verifiable.Cryptography.EventLogs.LogReplayer{TState,TOperation,TProof,TContext}"/> passes
/// to <see cref="WebPlusMicroledger.ValidateProofAsync"/>, and the configuration
/// <see cref="WebPlusMicroledger.CreateChainVerification"/> binds into the chain-integrity check. Keeping the
/// seams here lets the verification stay free of ambient singletons and testable with an independent hash oracle
/// and a fake clock. The self-hash algorithm (<see cref="MultihashCode"/>/<see cref="DigestLength"/>/
/// <see cref="ComputeDigest"/>/<see cref="DigestTag"/>) is supplied by the caller; the library pins none.
/// </remarks>
public sealed record WebPlusValidationContext
{
    /// <summary>The strict verifier parser producing the typed <see cref="WebPlusDidDocument"/> for single-document validation.</summary>
    public required WebPlusDidDocumentParser Parser { get; init; }

    /// <summary>The JCS canonicalizer used for the byte-equality (step 1) check.</summary>
    public required WebPlusJcsCanonicalizer Canonicalizer { get; init; }

    /// <summary>The extractor producing a document's proofs and the JCS of the document with <c>proofs</c> removed.</summary>
    public required WebPlusProofExtractor ProofExtractor { get; init; }

    /// <summary>The digest implementation (caller-supplied or the registered default) matching <see cref="MultihashCode"/>, used to verify each document's self-hash.</summary>
    public required ComputeDigestDelegate ComputeDigest { get; init; }

    /// <summary>The digest tag naming the self-hash's algorithm for the seam, e.g. <see cref="CryptoTags.Blake3Digest"/>.</summary>
    public required Tag DigestTag { get; init; }

    /// <summary>The multihash code naming the self-hash's hash function, e.g. <see cref="MultihashHeaders.Blake3"/>.</summary>
    public required ReadOnlyMemory<byte> MultihashCode { get; init; }

    /// <summary>The digest length in bytes for the self-hash's hash function.</summary>
    public required int DigestLength { get; init; }

    /// <summary>The base64url (no padding) encoder.</summary>
    public required EncodeDelegate Base64UrlEncoder { get; init; }

    /// <summary>The base64url (no padding) decoder.</summary>
    public required DecodeDelegate Base64UrlDecoder { get; init; }

    /// <summary>The base58btc decoder, used when an MBPubKey is in its base58btc (<c>z</c>) form.</summary>
    public required DecodeDelegate Base58Decoder { get; init; }

    /// <summary>Decides whether a valid-proof key satisfies a <c>hashedKey</c> pre-rotation commitment in an update rule.</summary>
    public required HashedKeyMatcher HashedKeyMatcher { get; init; }

    /// <summary>The memory pool for the transient hash, key and signature buffers.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }

    /// <summary>The clock the verification consults for any time-bounded check.</summary>
    public required TimeProvider TimeProvider { get; init; }
}
