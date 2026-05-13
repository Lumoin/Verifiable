using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Computes an HMAC (RFC 2104) over <paramref name="message"/> using the symmetric
/// key bytes in <paramref name="keyBytes"/>, and optionally produces a
/// <see cref="CryptoEvent"/> describing the operation.
/// </summary>
/// <param name="message">The bytes to authenticate.</param>
/// <param name="keyBytes">
/// The HMAC key bytes. The consumer surface that accepts <see cref="SymmetricKeyMemory"/>
/// (see <see cref="KeyExtensions"/>) unwraps the wrapper before calling the delegate.
/// </param>
/// <param name="outputByteLength">
/// The expected HMAC output length in bytes. Must match the hash family selected by
/// <paramref name="tag"/>: 32 for SHA-256, 48 for SHA-384, 64 for SHA-512.
/// </param>
/// <param name="tag">
/// Metadata identifying the algorithm and purpose. Must carry a
/// <see cref="System.Security.Cryptography.HashAlgorithmName"/> entry; the backend
/// dispatches internally on it. Expected
/// <see cref="Verifiable.Cryptography.Context.Purpose"/> is
/// <see cref="Verifiable.Cryptography.Context.Purpose.Hmac"/>.
/// </param>
/// <param name="pool">The memory pool to allocate the output from.</param>
/// <param name="context">Optional context parameters for the operation.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The computed <see cref="HmacValue"/> and an optional <see cref="CryptoEvent"/>.
/// <see langword="null"/> when the provider does not support observability.
/// </returns>
/// <remarks>
/// The async shape matches <see cref="SigningDelegate"/>, not the synchronous
/// <see cref="ComputeDigestDelegate"/>. The reason: HMAC is a primitive real
/// hardware backends compute — TPM2_HMAC, PKCS#11 C_Sign with CKM_SHA256_HMAC,
/// AWS KMS GenerateMac, Azure Key Vault HSM-backed sign with HMAC. All are async
/// by nature (network or device round-trip). Software backends return a
/// synchronously-completed <see cref="ValueTask{TResult}"/> with effectively zero
/// state-machine cost in .NET 10.
/// </remarks>
public delegate ValueTask<(HmacValue Result, CryptoEvent? Event)> ComputeHmacDelegate(
    ReadOnlyMemory<byte> message,
    ReadOnlyMemory<byte> keyBytes,
    int outputByteLength,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Verifies an HMAC (RFC 2104) over <paramref name="message"/> against
/// <paramref name="expectedMac"/> using the symmetric key bytes in
/// <paramref name="keyBytes"/>, and optionally produces a <see cref="CryptoEvent"/>
/// describing the operation.
/// </summary>
/// <param name="message">The bytes that were authenticated.</param>
/// <param name="keyBytes">The HMAC key bytes.</param>
/// <param name="expectedMac">
/// The HMAC tag to compare against. The consumer surface that accepts
/// <see cref="HmacValue"/> (see <see cref="KeyExtensions"/>) unwraps the wrapper
/// before calling the delegate.
/// </param>
/// <param name="tag">
/// Metadata identifying the algorithm. Must carry a
/// <see cref="System.Security.Cryptography.HashAlgorithmName"/> entry; the backend
/// dispatches internally on it.
/// </param>
/// <param name="pool">The memory pool to allocate intermediate buffers from.</param>
/// <param name="context">Optional context parameters for the operation.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// <see langword="true"/> when the HMAC matches; <see langword="false"/> otherwise.
/// The backend must use constant-time comparison
/// (<see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>).
/// Also returns an optional <see cref="CryptoEvent"/>.
/// </returns>
public delegate ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyHmacDelegate(
    ReadOnlyMemory<byte> message,
    ReadOnlyMemory<byte> keyBytes,
    ReadOnlyMemory<byte> expectedMac,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);
