namespace Verifiable.JCose;

/// <summary>
/// The AEAD construction family of a JWE content encryption (<c>enc</c>) algorithm.
/// </summary>
/// <remarks>
/// The two families have different structural geometries — an
/// <see cref="AesCbcHmac"/> algorithm has a composite (MAC || ENC) key and a 16-byte IV per
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>, while an
/// <see cref="AesGcm"/> algorithm has a single AES key and a 12-byte IV per
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.3">RFC 7518 §5.3</see>. The
/// family is the discriminator the ECDH-1PU constraint dispatches on: Key Agreement with Key
/// Wrapping mode MUST reject content encryption that is not <see cref="AesCbcHmac"/>
/// (draft-madden-jose-ecdh-1pu-04 §2.1).
/// </remarks>
public enum JweContentEncryptionFamily
{
    /// <summary>
    /// AES-CBC with HMAC composition (RFC 7518 §5.2 AES_CBC_HMAC_SHA2). Composite key,
    /// 16-byte IV, truncated-HMAC tag. Compactly committing, so usable with ECDH-1PU
    /// Key Agreement with Key Wrapping.
    /// </summary>
    AesCbcHmac,

    /// <summary>
    /// AES in Galois/Counter Mode (RFC 7518 §5.3). Single AES key, 12-byte IV, 16-byte GCM tag.
    /// </summary>
    AesGcm,

    /// <summary>
    /// XChaCha20-Poly1305 (the JOSE <c>XC20P</c> content encryption algorithm,
    /// <see href="https://datatracker.ietf.org/doc/html/draft-amringer-jose-chacha-02">draft-amringer-jose-chacha-02</see> /
    /// <see href="https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03">draft-irtf-cfrg-xchacha-03</see>).
    /// A single 256-bit key, a 192-bit (24-byte) extended nonce, and a 128-bit Poly1305 tag.
    /// Like <see cref="AesGcm"/> it is not compactly committing, so — by the same ECDH-1PU
    /// constraint that bars AES-GCM — it MUST NOT be used with Key Agreement with Key Wrapping
    /// (authcrypt); DIDComm v2.1 pairs it only with ECDH-ES anoncrypt (Appendix C.3 example 1).
    /// </summary>
    XChaCha20Poly1305
}
