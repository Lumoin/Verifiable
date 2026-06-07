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
/// Sync callers that cannot propagate async (key derivation, JWK thumbprint
/// computation) bridge via the convenience helper
/// <see cref="CryptographicKeyEvents.ComputeDigestSyncBridge"/> which asserts the
/// underlying delegate completed synchronously before returning.
/// </para>
/// </remarks>
public delegate ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeDigestDelegate(
    ReadOnlySequence<byte> input,
    int outputByteLength,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);
