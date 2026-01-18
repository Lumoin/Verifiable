using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Delegate for serializing an ecdsa-sd-2023 base proof to a multibase-encoded string.
/// </summary>
/// <param name="baseSignature">The issuer's signature bytes over the base proof data.</param>
/// <param name="ephemeralPublicKeyWithHeader">The ephemeral public key with multicodec header.</param>
/// <param name="hmacKey">The HMAC key used for blank node relabeling.</param>
/// <param name="statementSignatures">The signatures for each non-mandatory statement.</param>
/// <param name="mandatoryPointers">JSON pointer strings for mandatory claims.</param>
/// <param name="encoder">Base64URL encoder delegate.</param>
/// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
/// <remarks>
/// <para>
/// This delegate abstracts the proof serialization format (typically CBOR) from the
/// proof creation logic. Implementations should:
/// </para>
/// <list type="number">
/// <item><description>Serialize all components according to the ecdsa-sd-2023 specification.</description></item>
/// <item><description>Return a multibase-encoded string (base64url with 'u' prefix).</description></item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#add-base-proof-ecdsa-sd-2023">
/// VC Data Integrity ECDSA Cryptosuites: Add Base Proof (ecdsa-sd-2023)</see>.
/// </para>
/// </remarks>
public delegate string SerializeBaseProofDelegate(
    ReadOnlySpan<byte> baseSignature,
    ReadOnlySpan<byte> ephemeralPublicKeyWithHeader,
    ReadOnlySpan<byte> hmacKey,
    IReadOnlyList<byte[]> statementSignatures,
    IReadOnlyList<string> mandatoryPointers,
    EncodeDelegate encoder);


/// <summary>
/// Delegate for serializing an ecdsa-sd-2023 derived proof to a multibase-encoded string.
/// </summary>
/// <param name="baseSignature">The issuer's base signature bytes.</param>
/// <param name="ephemeralPublicKeyWithHeader">The ephemeral public key with multicodec header.</param>
/// <param name="disclosedSignatures">The signatures for disclosed statements.</param>
/// <param name="labelMap">Mapping from canonical to HMAC-derived blank node identifiers.</param>
/// <param name="mandatoryIndexes">Indexes of mandatory statements.</param>
/// <param name="encoder">Base64URL encoder delegate.</param>
/// <param name="decoder">Base64URL decoder delegate.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
/// <remarks>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#add-derived-proof-ecdsa-sd-2023">
/// VC Data Integrity ECDSA Cryptosuites: Add Derived Proof (ecdsa-sd-2023)</see>.
/// </para>
/// </remarks>
public delegate string SerializeDerivedProofDelegate(
    ReadOnlySpan<byte> baseSignature,
    ReadOnlySpan<byte> ephemeralPublicKeyWithHeader,
    IReadOnlyList<byte[]> disclosedSignatures,
    IReadOnlyDictionary<string, string> labelMap,
    IReadOnlyList<int> mandatoryIndexes,
    EncodeDelegate encoder,
    DecodeDelegate decoder,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Delegate for parsing an ecdsa-sd-2023 base proof value from a multibase-encoded string.
/// </summary>
/// <param name="proofValue">The multibase-encoded proof value string.</param>
/// <param name="decoder">Base64URL decoder delegate.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns>The parsed base proof components.</returns>
/// <remarks>
/// <para>
/// This delegate abstracts the proof parsing format (typically CBOR) from the
/// proof verification logic. The returned <see cref="BaseProofValue"/> is disposable
/// and owns all allocated memory.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsebaseproofvalue">
/// VC Data Integrity ECDSA Cryptosuites: parseBaseProofValue</see>.
/// </para>
/// </remarks>
public delegate BaseProofValue ParseBaseProofDelegate(
    string proofValue,
    DecodeDelegate decoder,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Delegate for parsing an ecdsa-sd-2023 derived proof value from a multibase-encoded string.
/// </summary>
/// <param name="proofValue">The multibase-encoded proof value string.</param>
/// <param name="decoder">Base64URL decoder delegate.</param>
/// <param name="encoder">Base64URL encoder delegate for label map reconstruction.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns>The parsed derived proof components.</returns>
/// <remarks>
/// <para>
/// This delegate abstracts the proof parsing format (typically CBOR) from the
/// proof verification logic. The returned <see cref="DerivedProofValue"/> is disposable
/// and owns all allocated memory.
/// </para>
/// <para>
/// The encoder is needed because label map values are stored as raw bytes in CBOR
/// and must be encoded back to base64url strings for the dictionary.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#parsederivedproofvalue">
/// VC Data Integrity ECDSA Cryptosuites: parseDerivedProofValue</see>.
/// </para>
/// </remarks>
public delegate DerivedProofValue ParseDerivedProofDelegate(
    string proofValue,
    DecodeDelegate decoder,
    EncodeDelegate encoder,
    MemoryPool<byte> memoryPool);