using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// Generates a <see cref="Nonce"/> of <paramref name="byteLength"/> bytes and
/// optionally produces a <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <param name="byteLength">The number of random bytes to generate.</param>
/// <param name="tag">Metadata identifying the purpose and entropy source.</param>
/// <param name="pool">The memory pool to allocate from.</param>
/// <returns>
/// The generated <see cref="Nonce"/> and an optional <see cref="CryptoEvent"/>.
/// <see langword="null"/> when the provider does not support observability.
/// </returns>
public delegate (Nonce Result, CryptoEvent? Event) GenerateNonceDelegate(
    int byteLength,
    Tag tag,
    MemoryPool<byte> pool);


/// <summary>
/// Generates a <see cref="Salt"/> of <paramref name="byteLength"/> bytes and
/// optionally produces a <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <param name="byteLength">The number of random bytes to generate.</param>
/// <param name="tag">Metadata identifying the purpose and entropy source.</param>
/// <param name="pool">The memory pool to allocate from.</param>
/// <returns>
/// The generated <see cref="Salt"/> and an optional <see cref="CryptoEvent"/>.
/// <see langword="null"/> when the provider does not support observability.
/// </returns>
public delegate (Salt Result, CryptoEvent? Event) GenerateSaltDelegate(
    int byteLength,
    Tag tag,
    MemoryPool<byte> pool);


/// <summary>
/// Computes a <see cref="DigestValue"/> over <paramref name="input"/> and
/// optionally produces a <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <param name="input">The bytes to hash.</param>
/// <param name="outputByteLength">The expected digest length in bytes.</param>
/// <param name="tag">Metadata identifying the algorithm and purpose.</param>
/// <param name="pool">The memory pool to allocate from.</param>
/// <returns>
/// The computed <see cref="DigestValue"/> and an optional <see cref="CryptoEvent"/>.
/// <see langword="null"/> when the provider does not support observability.
/// </returns>
public delegate (DigestValue Result, CryptoEvent? Event) ComputeDigestDelegate(
    ReadOnlySpan<byte> input,
    int outputByteLength,
    Tag tag,
    MemoryPool<byte> pool);