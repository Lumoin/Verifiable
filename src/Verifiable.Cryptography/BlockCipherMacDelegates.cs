using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Computes a block-cipher MAC over <paramref name="message"/> using the symmetric key
/// bytes in <paramref name="keyBytes"/>, and optionally produces a <see cref="CryptoEvent"/>
/// describing the operation.
/// </summary>
/// <remarks>
/// <para>
/// The MAC construction is selected by the
/// <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> carried in
/// <paramref name="tag"/>: a Triple-DES / DES algorithm selects the ISO/IEC 9797-1 MAC
/// Algorithm 3 ("Retail MAC") used by ICAO Doc 9303 Basic Access Control and 3DES Secure
/// Messaging; an AES algorithm selects AES-CMAC (RFC 4493) used by PACE and AES Secure
/// Messaging. The shape mirrors <see cref="ComputeHmacDelegate"/>, differing only in that
/// the discriminator is the block cipher rather than a hash.
/// </para>
/// <para>
/// No padding is applied: <paramref name="message"/> MUST already be a whole number of cipher
/// blocks. eMRTD Secure Messaging pads the MAC input with ISO 9797-1 method 2 before calling,
/// keeping that padding visible and testable in the protocol layer. <paramref name="outputByteLength"/>
/// is the (possibly truncated) tag length — 8 bytes for both the eMRTD Retail MAC and the
/// AES-CMAC truncation it pairs with.
/// </para>
/// </remarks>
/// <param name="message">The block-aligned message to authenticate.</param>
/// <param name="keyBytes">The symmetric key material.</param>
/// <param name="outputByteLength">The desired MAC tag length in bytes.</param>
/// <param name="tag">Metadata carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the MAC construction.</param>
/// <param name="pool">Memory pool for the MAC buffer.</param>
/// <param name="context">Optional context parameters for the operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>The <see cref="MacValue"/> (owned by the caller) and an optional event.</returns>
public delegate ValueTask<(MacValue Result, CryptoEvent? Event)> ComputeBlockCipherMacDelegate(
    ReadOnlyMemory<byte> message,
    ReadOnlyMemory<byte> keyBytes,
    int outputByteLength,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Verifies a block-cipher MAC over <paramref name="message"/> against
/// <paramref name="expectedMac"/>, using constant-time comparison.
/// </summary>
/// <remarks>
/// The MAC construction is selected exactly as for <see cref="ComputeBlockCipherMacDelegate"/>.
/// Comparison uses
/// <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// </remarks>
/// <param name="message">The block-aligned message whose MAC is checked.</param>
/// <param name="keyBytes">The symmetric key material.</param>
/// <param name="expectedMac">The MAC tag to compare against.</param>
/// <param name="tag">Metadata carrying the <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> that selects the MAC construction.</param>
/// <param name="pool">Memory pool for the transient comparison buffer.</param>
/// <param name="context">Optional context parameters for the operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns><see langword="true"/> if the MAC is valid; otherwise <see langword="false"/>, plus an optional event.</returns>
public delegate ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyBlockCipherMacDelegate(
    ReadOnlyMemory<byte> message,
    ReadOnlyMemory<byte> keyBytes,
    ReadOnlyMemory<byte> expectedMac,
    Tag tag,
    MemoryPool<byte> pool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);
