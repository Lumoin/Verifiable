using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Fido2;

/// <summary>
/// Computes the WebAuthn <c>clientDataHash</c> — the SHA-256 hash of the serialized
/// <c>clientDataJSON</c> bytes — the value fed into the assertion and attestation signature
/// transcripts.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication
/// Level 3, section 7.2: Verifying an Authentication Assertion</see>, step 20: "Let hash be the
/// result of computing a hash over the cData using SHA-256." Also
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">section 5.8.1: Client
/// Data Used in WebAuthn Signatures</see>, which names this value <c>clientDataHash</c>.
/// </para>
/// <para>
/// <c>clientDataHash</c> is a public-data digest — the serialized ceremony parameters, sent
/// openly on the wire as <c>clientDataJSON</c> — so it is computed through the synchronous
/// <see cref="CryptographicKeyEvents.ComputeDigest(ReadOnlySpan{byte}, int, Tag, MemoryPool{byte}, string?)"/>
/// seam rather than the async, potentially TPM/KMS-backed digest seam reserved for trust/custody
/// hashes (SAID, KERI/ACDC, did:webvh/peer/webplus self-hashing).
/// </para>
/// </remarks>
public static class Fido2ClientDataHash
{
    /// <summary>The SHA-256 digest length in bytes.</summary>
    private const int Sha256ByteLength = 32;

    /// <summary>
    /// Computes the SHA-256 <c>clientDataHash</c> over the raw <c>clientDataJSON</c> wire bytes.
    /// </summary>
    /// <param name="clientDataJson">The raw, UTF-8-encoded <c>clientDataJSON</c> wire bytes.</param>
    /// <param name="pool">The pool the returned digest's carrier rents from.</param>
    /// <returns>The 32-byte SHA-256 digest; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">No SHA-256 <see cref="HashFunctionDelegate"/> has been registered.</exception>
    public static DigestValue Compute(ReadOnlySpan<byte> clientDataJson, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return CryptographicKeyEvents.ComputeDigest(clientDataJson, Sha256ByteLength, CryptoTags.Sha256Digest, pool);
    }
}
