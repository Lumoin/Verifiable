using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Computes an HMAC (RFC 2104) over <paramref name="message"/> using the symmetric
/// key bytes in <paramref name="keyBytes"/>, and optionally produces a
/// <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <remarks>
/// <para>
/// The async shape matches <see cref="SigningDelegate"/>. Real hardware backends
/// compute HMAC — TPM2_HMAC, PKCS#11 C_Sign with CKM_SHA256_HMAC, AWS KMS
/// GenerateMac, Azure Key Vault HSM-backed sign with HMAC — and are async by
/// nature.
/// </para>
/// <para>
/// <see cref="ReadOnlySequence{T}"/> input accommodates single-segment (one-shot
/// hot path via <see cref="ReadOnlySequence{T}.IsSingleSegment"/>) and multi-segment
/// (per-segment iteration via <see cref="System.Security.Cryptography.IncrementalHash.AppendData(ReadOnlySpan{byte})"/>)
/// uniformly. One-shot callers use the convenience overloads on
/// <see cref="CryptographicKeyEvents"/> and <see cref="KeyExtensions"/> that wrap
/// a <see cref="ReadOnlyMemory{T}"/> in <c>new ReadOnlySequence&lt;byte&gt;(memory)</c>.
/// </para>
/// </remarks>
public delegate ValueTask<(HmacValue Result, CryptoEvent? Event)> ComputeHmacDelegate(
    ReadOnlySequence<byte> message,
    ReadOnlyMemory<byte> keyBytes,
    int outputByteLength,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Verifies an HMAC (RFC 2104) over <paramref name="message"/> against
/// <paramref name="expectedMac"/>, using constant-time comparison.
/// </summary>
public delegate ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyHmacDelegate(
    ReadOnlySequence<byte> message,
    ReadOnlyMemory<byte> keyBytes,
    ReadOnlyMemory<byte> expectedMac,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);
