using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for key derivation from a shared secret.
/// </summary>
/// <remarks>
/// <para>
/// Derives a content encryption key (CEK) from the shared secret Z produced by ECDH
/// key agreement. The default implementation uses Concat KDF per
/// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf">NIST SP 800-56A §5.8.1</see>.
/// </para>
/// <para>
/// This delegate is synchronous because key derivation is pure deterministic mathematics
/// with no I/O, no hardware boundary, and no deployment scenario where it would run
/// remotely. Spans are safe to use because there is no async boundary.
/// </para>
/// <para>
/// The caller must zero and dispose the returned <see cref="IMemoryOwner{T}"/> as soon
/// as the CEK has been used for encryption or decryption.
/// </para>
/// </remarks>
/// <param name="sharedSecret">
/// The shared secret Z from ECDH key agreement. Not disposed by this delegate — the
/// caller retains ownership and must zero and dispose it after the call.
/// </param>
/// <param name="algorithmId">
/// The algorithm identifier string used as the AlgorithmID input to the KDF.
/// In the JOSE profile this is the JWE <c>enc</c> value, e.g. <c>A128GCM</c>.
/// </param>
/// <param name="partyUInfo">
/// Producer party info. Pass <see cref="ReadOnlySpan{T}.Empty"/> when not used,
/// as in the JOSE profile per RFC 7518 §4.6.2.
/// </param>
/// <param name="partyVInfo">
/// Recipient party info. Pass <see cref="ReadOnlySpan{T}.Empty"/> when not used,
/// as in the JOSE profile per RFC 7518 §4.6.2.
/// </param>
/// <param name="keydataLenBits">
/// The required output key length in bits, e.g. 128 for A128GCM or 256 for A256GCM.
/// </param>
/// <param name="pool">Memory pool for the output CEK allocation.</param>
/// <returns>
/// The derived <see cref="ContentEncryptionKey"/> of exactly
/// <paramref name="keydataLenBits"/> / 8 bytes. The caller must dispose
/// it immediately after use — disposal zeroes the underlying memory.
/// </returns>
public delegate ContentEncryptionKey KeyDerivationDelegate(
    SharedSecret sharedSecret,
    string algorithmId,
    ReadOnlySpan<byte> partyUInfo,
    ReadOnlySpan<byte> partyVInfo,
    int keydataLenBits,
    MemoryPool<byte> pool);
