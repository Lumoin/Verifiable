using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Delegate for serializing a bbs-2023 base proof to a multibase-encoded string.
/// </summary>
/// <param name="bbsSignature">The 80-byte BBS signature.</param>
/// <param name="bbsHeader">The 64-byte BBS header (proofHash || mandatoryHash).</param>
/// <param name="publicKey">The issuer BLS12-381 G2 public key in its raw 96-byte CFRG encoding.</param>
/// <param name="hmacKey">The 32-byte HMAC key used for blank node relabeling.</param>
/// <param name="mandatoryPointers">JSON pointer strings for mandatory claims.</param>
/// <param name="encoder">Base64URL encoder delegate.</param>
/// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
/// <remarks>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#serializebaseproofvalue">
/// W3C VC DI BBS §3.3.1 serializeBaseProofValue</see>.
/// </para>
/// </remarks>
public delegate string SerializeBbsBaseProofDelegate(
    ReadOnlySpan<byte> bbsSignature,
    ReadOnlySpan<byte> bbsHeader,
    ReadOnlySpan<byte> publicKey,
    ReadOnlySpan<byte> hmacKey,
    IReadOnlyList<string> mandatoryPointers,
    EncodeDelegate encoder);


/// <summary>
/// Delegate for serializing a bbs-2023 derived proof to a multibase-encoded string.
/// </summary>
/// <param name="bbsProof">The BBS proof bytes.</param>
/// <param name="labelMap">Label map from canonical (<c>c14nN</c>) to shuffled (<c>bN</c>) identifiers.</param>
/// <param name="mandatoryIndexes">Indexes of mandatory statements in the reveal document.</param>
/// <param name="selectiveIndexes">Indexes of selectively disclosed statements relative to the non-mandatory list.</param>
/// <param name="presentationHeader">The BBS presentation header bytes.</param>
/// <param name="encoder">Base64URL encoder delegate.</param>
/// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
/// <remarks>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#serializederivedproofvalue">
/// W3C VC DI BBS §3.3.6 serializeDerivedProofValue</see>.
/// </para>
/// </remarks>
public delegate string SerializeBbsDerivedProofDelegate(
    ReadOnlySpan<byte> bbsProof,
    IReadOnlyDictionary<string, string> labelMap,
    IReadOnlyList<int> mandatoryIndexes,
    IReadOnlyList<int> selectiveIndexes,
    ReadOnlySpan<byte> presentationHeader,
    EncodeDelegate encoder);


/// <summary>
/// Delegate for parsing a bbs-2023 base proof value from a multibase-encoded string.
/// </summary>
/// <param name="proofValue">The multibase-encoded proof value string.</param>
/// <param name="decoder">Base64URL decoder delegate.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns>The parsed base proof components.</returns>
/// <remarks>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#parsebaseproofvalue">
/// W3C VC DI BBS §3.3.2 parseBaseProofValue</see>.
/// </para>
/// </remarks>
public delegate Bbs2023BaseProofValue ParseBbsBaseProofDelegate(
    string proofValue,
    DecodeDelegate decoder,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Delegate for parsing a bbs-2023 derived proof value from a multibase-encoded string.
/// </summary>
/// <param name="proofValue">The multibase-encoded proof value string.</param>
/// <param name="decoder">Base64URL decoder delegate.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns>The parsed derived proof components.</returns>
/// <remarks>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#parsederivedproofvalue">
/// W3C VC DI BBS §3.3.7 parseDerivedProofValue</see>.
/// </para>
/// </remarks>
public delegate Bbs2023DerivedProofValue ParseBbsDerivedProofDelegate(
    string proofValue,
    DecodeDelegate decoder,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Delegate that signs the non-mandatory BBS messages with the issuer's BBS secret key.
/// </summary>
/// <param name="bbsHeader">The 64-byte BBS header (proofHash || mandatoryHash).</param>
/// <param name="messages">The non-mandatory N-Quad statements, each UTF-8 encoded, in sorted order.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns>The 80-byte BBS signature.</returns>
/// <remarks>
/// <para>
/// This delegate wraps the BBS <c>Sign</c> operation. The implementation binds the issuer's
/// secret and public key material and the BLS12-381 algebraic operations; the cryptosuite
/// supplies the header (folding the mandatory statements) and the non-mandatory messages.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#base-proof-serialization-bbs-2023">
/// W3C VC DI BBS §3.4.5 Base Proof Serialization (bbs-2023)</see>.
/// </para>
/// </remarks>
public delegate byte[] BbsSignDelegate(
    ReadOnlyMemory<byte> bbsHeader,
    IReadOnlyList<byte[]> messages,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Delegate that verifies a BBS signature over the non-mandatory messages.
/// </summary>
/// <param name="bbsSignature">The 80-byte BBS signature from the base proof.</param>
/// <param name="bbsHeader">The 64-byte BBS header (proofHash || mandatoryHash).</param>
/// <param name="messages">The non-mandatory BBS messages (UTF-8 N-Quads) in sorted order.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns><see langword="true"/> if the signature verifies; otherwise <see langword="false"/>.</returns>
/// <remarks>
/// <para>
/// This delegate wraps the BBS <c>Verify</c> operation, which the holder uses to validate the base
/// proof. The implementation binds the issuer's public key and the BLS12-381 algebraic operations
/// including the pairing.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#bbs-2023">W3C VC DI BBS §3.4 bbs-2023</see>.
/// </para>
/// </remarks>
public delegate bool BbsVerifySignatureDelegate(
    ReadOnlyMemory<byte> bbsSignature,
    ReadOnlyMemory<byte> bbsHeader,
    IReadOnlyList<byte[]> messages,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Delegate that generates a BBS proof disclosing a subset of the signed messages.
/// </summary>
/// <param name="bbsSignature">The 80-byte BBS signature from the base proof.</param>
/// <param name="bbsHeader">The 64-byte BBS header (proofHash || mandatoryHash).</param>
/// <param name="presentationHeader">The BBS presentation header bytes.</param>
/// <param name="messages">All non-mandatory BBS messages (UTF-8 N-Quads) in sorted order.</param>
/// <param name="disclosedIndexes">Indexes into <paramref name="messages"/> that are selectively disclosed.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns>The BBS proof bytes.</returns>
/// <remarks>
/// <para>
/// This delegate wraps the BBS <c>ProofGen</c> operation. The implementation binds the issuer's
/// public key, the BLS12-381 algebraic operations, and the random-scalar source (a CSPRNG in
/// production, or a deterministic seeded source for test vectors).
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#createdisclosuredata">
/// W3C VC DI BBS §3.3.3 createDisclosureData</see>.
/// </para>
/// </remarks>
public delegate byte[] BbsProofGenDelegate(
    ReadOnlyMemory<byte> bbsSignature,
    ReadOnlyMemory<byte> bbsHeader,
    ReadOnlyMemory<byte> presentationHeader,
    IReadOnlyList<byte[]> messages,
    IReadOnlyList<int> disclosedIndexes,
    MemoryPool<byte> memoryPool);


/// <summary>
/// Delegate that verifies a BBS proof against the disclosed messages.
/// </summary>
/// <param name="bbsProof">The BBS proof bytes.</param>
/// <param name="bbsHeader">The 64-byte BBS header (proofHash || mandatoryHash).</param>
/// <param name="presentationHeader">The BBS presentation header bytes.</param>
/// <param name="disclosedMessages">The disclosed non-mandatory BBS messages (UTF-8 N-Quads).</param>
/// <param name="disclosedIndexes">The selective indexes corresponding to the disclosed messages.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <returns><see langword="true"/> if the proof verifies; otherwise <see langword="false"/>.</returns>
/// <remarks>
/// <para>
/// This delegate wraps the BBS <c>ProofVerify</c> operation. The implementation binds the issuer's
/// public key and the BLS12-381 algebraic operations including the pairing.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#verify-derived-proof-bbs-2023">
/// W3C VC DI BBS §3.4.7 Verify Derived Proof (bbs-2023)</see>.
/// </para>
/// </remarks>
public delegate bool BbsProofVerifyDelegate(
    ReadOnlyMemory<byte> bbsProof,
    ReadOnlyMemory<byte> bbsHeader,
    ReadOnlyMemory<byte> presentationHeader,
    IReadOnlyList<byte[]> disclosedMessages,
    IReadOnlyList<int> disclosedIndexes,
    MemoryPool<byte> memoryPool);
