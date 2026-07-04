using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Generates a <see cref="Nonce"/> of <paramref name="byteLength"/> bytes and
/// optionally produces a <see cref="CryptoEvent"/> describing the operation.
/// </summary>
public delegate (Nonce Result, CryptoEvent? Event) GenerateNonceDelegate(
    int byteLength,
    Tag tag,
    MemoryPool<byte> pool);


/// <summary>
/// Generates a <see cref="Salt"/> of <paramref name="byteLength"/> bytes and
/// optionally produces a <see cref="CryptoEvent"/> describing the operation.
/// </summary>
public delegate (Salt Result, CryptoEvent? Event) GenerateSaltDelegate(
    int byteLength,
    Tag tag,
    MemoryPool<byte> pool);


/// <summary>
/// Computes a <see cref="DigestValue"/> over <paramref name="input"/> and
/// optionally produces a <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <remarks>
/// <para>
/// The async shape and <see cref="ReadOnlySequence{T}"/> input accommodate both
/// software backends (which return a synchronously-completed
/// <see cref="ValueTask{TResult}"/>) and hardware-async backends (TPM2_Hash via
/// Linux async I/O; KMS hash-as-a-service).
/// </para>
/// <para>
/// One-shot callers pass <see cref="ReadOnlyMemory{T}"/> via the convenience
/// extension on <see cref="CryptographicKeyEvents"/> which wraps in
/// <c>new ReadOnlySequence&lt;byte&gt;(memory)</c>. Multi-segment callers build a
/// <see cref="ReadOnlySequence{T}"/> via <see cref="BufferSegment"/>-style linked
/// nodes and pass it directly.
/// </para>
/// <para>
/// This async seam is for digests that may be hardware- or network-backed (TPM2_Hash, KMS) or that live inside an
/// async verification pipeline (SAID, KERI/ACDC, did:webvh/peer/webplus). Hashes that are sync by nature — a hash
/// of public or local data with no async backend, such as a JWK thumbprint, a PKCE S256 challenge, or a Concat KDF
/// round — use the synchronous <see cref="HashFunctionDelegate"/> seam via
/// <see cref="CryptographicKeyEvents.ComputeDigest(System.ReadOnlySpan{byte}, int, Tag, MemoryPool{byte}, string?)"/>
/// instead, so no async colouring propagates into otherwise-synchronous code.
/// </para>
/// </remarks>
public delegate ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeDigestDelegate(
    ReadOnlySequence<byte> input,
    int outputByteLength,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);
