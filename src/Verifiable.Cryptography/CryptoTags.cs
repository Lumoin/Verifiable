using System.Security.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for common cryptographic key types
/// and symmetric operation components.
/// </summary>
/// <remarks>
/// <para>
/// Each tag contains the appropriate <see cref="CryptoAlgorithm"/>, <see cref="Purpose"/>,
/// and <see cref="EncodingScheme"/> metadata needed for routing and semantic checking.
/// </para>
/// <code>
/// var publicKey = new PublicKeyMemory(keyBytes, CryptoTags.P256PublicKey);
/// var algorithm = CryptoTags.Ed25519PrivateKey.Get&lt;CryptoAlgorithm&gt;();
/// </code>
/// </remarks>
public static class CryptoTags
{
    /// <summary>Tag for P-256 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag P256PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for P-256 private keys used for signing. Raw encoding.</summary>
    public static Tag P256PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for P-256 signature values.</summary>
    public static Tag P256Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for P-256 public keys used in ECDH key agreement.
    /// Uncompressed encoding: <c>0x04 || X || Y</c>.
    /// </summary>
    public static Tag P256ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for P-256 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag P256ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for P-384 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag P384PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for P-384 private keys used for signing. Raw encoding.</summary>
    public static Tag P384PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for P-384 signature values.</summary>
    public static Tag P384Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for P-521 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag P521PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for P-521 private keys used for signing. Raw encoding.</summary>
    public static Tag P521PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for P-521 signature values.</summary>
    public static Tag P521Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for secp256k1 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag Secp256k1PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Secp256k1),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for secp256k1 private keys used for signing. Raw encoding.</summary>
    public static Tag Secp256k1PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Secp256k1),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for secp256k1 signature values.</summary>
    public static Tag Secp256k1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Secp256k1),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-2048 public keys. DER encoding.</summary>
    public static Tag Rsa2048PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa2048),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Der));

    /// <summary>Tag for RSA-2048 private keys. PKCS#1 encoding.</summary>
    public static Tag Rsa2048PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa2048),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Pkcs1));

    /// <summary>Tag for RSA-2048 signature values.</summary>
    public static Tag Rsa2048Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa2048),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-4096 public keys. DER encoding.</summary>
    public static Tag Rsa4096PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa4096),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Der));

    /// <summary>Tag for RSA-4096 private keys. PKCS#1 encoding.</summary>
    public static Tag Rsa4096PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa4096),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Pkcs1));

    /// <summary>Tag for RSA-4096 signature values.</summary>
    public static Tag Rsa4096Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa4096),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-SHA256 PKCS#1 v1.5 signatures.</summary>
    public static Tag RsaSha256Pkcs1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha256),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-SHA256 PSS signatures.</summary>
    public static Tag RsaSha256PssSignature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha256Pss),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-SHA384 PKCS#1 v1.5 signatures.</summary>
    public static Tag RsaSha384Pkcs1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha384),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-SHA384 PSS signatures.</summary>
    public static Tag RsaSha384PssSignature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha384Pss),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-SHA512 PKCS#1 v1.5 signatures.</summary>
    public static Tag RsaSha512Pkcs1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha512),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA-SHA512 PSS signatures.</summary>
    public static Tag RsaSha512PssSignature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha512Pss),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for RSA ISO/IEC 9796-2 (Digital Signature scheme 1, message recovery) signatures, as used by eMRTD RSA Active Authentication.</summary>
    public static Tag RsaIso9796d2Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaIso9796d2),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Ed25519 public keys. Raw encoding.</summary>
    public static Tag Ed25519PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Ed25519),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Ed25519 private keys. Raw encoding.</summary>
    public static Tag Ed25519PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Ed25519),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Ed25519 signature values.</summary>
    public static Tag Ed25519Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Ed25519),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for X25519 public keys used in ECDH key agreement. Raw encoding.</summary>
    public static Tag X25519PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for X25519 private keys used in ECDH key agreement. Raw encoding.</summary>
    public static Tag X25519PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Windows platform encrypted data.</summary>
    public static Tag WindowsPlatformEncrypted { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.WindowsPlatformEncrypted),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-44 public keys (NIST FIPS 204, security level 2).</summary>
    public static Tag MlDsa44PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa44),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-44 private keys (NIST FIPS 204, security level 2).</summary>
    public static Tag MlDsa44PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa44),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-44 signature values.</summary>
    public static Tag MlDsa44Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa44),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-65 public keys (NIST FIPS 204, security level 3).</summary>
    public static Tag MlDsa65PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa65),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-65 private keys (NIST FIPS 204, security level 3).</summary>
    public static Tag MlDsa65PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa65),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-65 signature values.</summary>
    public static Tag MlDsa65Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa65),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-87 public keys (NIST FIPS 204, security level 5).</summary>
    public static Tag MlDsa87PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa87),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-87 private keys (NIST FIPS 204, security level 5).</summary>
    public static Tag MlDsa87PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa87),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-DSA-87 signature values.</summary>
    public static Tag MlDsa87Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa87),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-KEM-512 public keys (NIST FIPS 203, security level 1).</summary>
    public static Tag MlKem512PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlKem512),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-KEM-512 private keys (NIST FIPS 203, security level 1).</summary>
    public static Tag MlKem512PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlKem512),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-KEM-768 public keys (NIST FIPS 203, security level 3).</summary>
    public static Tag MlKem768PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlKem768),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-KEM-768 private keys (NIST FIPS 203, security level 3).</summary>
    public static Tag MlKem768PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlKem768),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-KEM-1024 public keys (NIST FIPS 203, security level 5).</summary>
    public static Tag MlKem1024PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlKem1024),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for ML-KEM-1024 private keys (NIST FIPS 203, security level 5).</summary>
    public static Tag MlKem1024PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlKem1024),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    //AES-GCM operation component tags.
    //Named after the symmetric algorithm and role, not after any higher-level protocol.
    //The P-256 algorithm discriminator identifies that these components arise specifically
    //from a P-256 ECDH-ES key agreement operation feeding into AES-GCM content encryption.

    /// <summary>
    /// Tag for the 96-bit (12-byte) AES-GCM initialization vector derived from a
    /// P-256 ECDH-ES key agreement. The IV is a nonce — unique per encryption operation
    /// under the same key.
    /// </summary>
    public static Tag AesGcmIv { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Nonce),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for AES-GCM ciphertext produced by a P-256 ECDH-ES content encryption operation.
    /// </summary>
    public static Tag AesGcmCiphertext { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for the 128-bit (16-byte) AES-GCM authentication tag (GHASH output) produced
    /// by a P-256 ECDH-ES content encryption operation. This is a MAC, not an HMAC.
    /// </summary>
    public static Tag AesGcmAuthTag { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Mac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for additional authenticated data fed into an AES-GCM operation whose content
    /// encryption key was derived via P-256 ECDH-ES.
    /// </summary>
    public static Tag AesGcmAad { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Data),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for plaintext produced by an AES-GCM decryption operation whose content
    /// encryption key was derived via P-256 ECDH-ES.
    /// </summary>
    public static Tag AesGcmDecryptedContent { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Decrypted),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for a content encryption key derived via P-256 ECDH-ES and Concat KDF for
    /// use in an AES-GCM operation.
    /// </summary>
    public static Tag AesGcmCek { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //XChaCha20-Poly1305 (the JOSE "XC20P" content encryption algorithm, draft-amringer-jose-chacha-02 /
    //draft-irtf-cfrg-xchacha-03) content-encryption buffers. DIDComm v2.1 pairs XC20P only with the
    //X25519 ECDH-ES anoncrypt path (Appendix C.3 example 1), so the algorithm discriminator is X25519 —
    //the agreement curve the content key is derived under — exactly as the AES-GCM content tags above use
    //the agreement curve (P-256) as their discriminator. The buffer role is carried by the Purpose; the
    //byte content (a 192-bit nonce, the ciphertext, the 128-bit Poly1305 tag) is what each tag labels.

    /// <summary>
    /// Tag for the 192-bit (24-byte) XChaCha20-Poly1305 extended nonce used with an X25519
    /// ECDH-ES content encryption operation. The nonce is unique per encryption operation.
    /// </summary>
    public static Tag Xc20pIv { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Nonce),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for XChaCha20-Poly1305 ciphertext produced by an X25519 ECDH-ES content encryption operation.
    /// </summary>
    public static Tag Xc20pCiphertext { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for the 128-bit (16-byte) XChaCha20-Poly1305 authentication tag (Poly1305 output)
    /// produced by an X25519 ECDH-ES content encryption operation. This is a MAC, not an HMAC.
    /// </summary>
    public static Tag Xc20pAuthTag { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Mac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for additional authenticated data fed into an XChaCha20-Poly1305 operation whose content
    /// encryption key was derived via X25519 ECDH-ES.
    /// </summary>
    public static Tag Xc20pAad { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Data),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for plaintext produced by an XChaCha20-Poly1305 decryption operation whose content
    /// encryption key was derived via X25519 ECDH-ES.
    /// </summary>
    public static Tag Xc20pDecryptedContent { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Decrypted),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for a 256-bit content encryption key derived via X25519 ECDH-ES and Concat KDF for use
    /// in an XChaCha20-Poly1305 operation.
    /// </summary>
    public static Tag Xc20pCek { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //AES Key Wrap (RFC 3394) tags. The wrap operation protects a content encryption
    //key under a key encryption key derived via ECDH-ES or ECDH-1PU Concat KDF, as in
    //the JWE "ECDH-ES+A256KW" and "ECDH-1PU+A256KW" key management algorithms.

    /// <summary>
    /// Tag for a 256-bit AES key encryption key derived via Concat KDF for wrapping
    /// a content encryption key per <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>.
    /// </summary>
    public static Tag AesKwKeyEncryptionKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for a content encryption key wrapped per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>. The wrapped
    /// bytes are public ciphertext carried in the JWE encrypted key slot.
    /// </summary>
    public static Tag AesKwWrappedKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Wrapped),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for a content encryption key recovered by
    /// <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see> unwrapping.
    /// </summary>
    public static Tag AesKwUnwrappedKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //AES-CBC with HMAC composition tags per RFC 7518 §5.2 (AES_CBC_HMAC_SHA2 family,
    //e.g. A256CBC-HS512). The composite key splits into a MAC half and an encryption
    //half; the authentication tag is a truncated HMAC over AAD || IV || ciphertext || AL.

    /// <summary>
    /// Tag for the 128-bit (16-byte) initialization vector of an AES-CBC operation in
    /// the <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>
    /// AES_CBC_HMAC_SHA2 composition.
    /// </summary>
    public static Tag AesCbcHmacIv { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Nonce),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ciphertext produced by an
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>
    /// AES_CBC_HMAC_SHA2 content encryption operation.
    /// </summary>
    public static Tag AesCbcHmacCiphertext { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for the truncated HMAC authentication tag of an
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>
    /// AES_CBC_HMAC_SHA2 operation. For A256CBC-HS512 this is the first 32 bytes of
    /// HMAC-SHA-512 output.
    /// </summary>
    public static Tag AesCbcHmacAuthTag { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Hmac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for additional authenticated data fed into an
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>
    /// AES_CBC_HMAC_SHA2 operation.
    /// </summary>
    public static Tag AesCbcHmacAad { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Data),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for plaintext produced by an
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>
    /// AES_CBC_HMAC_SHA2 decryption operation.
    /// </summary>
    public static Tag AesCbcHmacDecryptedContent { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Decrypted),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for the composite content encryption key of an
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>
    /// AES_CBC_HMAC_SHA2 operation. For A256CBC-HS512 this is 64 bytes: the initial
    /// 32 bytes are the HMAC key and the final 32 bytes are the AES-CBC key.
    /// </summary>
    public static Tag AesCbcHmacCek { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes256),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //Brainpool ECDSA curve tags per RFC 5639 / RFC 9864. The five r1 curves
    //(P-224r1, P-256r1, P-320r1, P-384r1, P-512r1) carry compressed public keys
    //and raw private-key scalars. They share the EC compression encoding with
    //the NIST P-curves; only the underlying curve parameters differ. (brainpoolP224r1
    //is an ECDH/key-agreement curve — notably eMRTD Chip Authentication — with no
    //RFC 9864 fully-specified ECDSA registration, so it has no COSE algorithm id.)

    /// <summary>Tag for Brainpool P-224r1 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag BrainpoolP224r1PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP224r1),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for Brainpool P-224r1 private keys used for signing. Raw encoding.</summary>
    public static Tag BrainpoolP224r1PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP224r1),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-224r1 signature values (IEEE P1363 r || s).</summary>
    public static Tag BrainpoolP224r1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP224r1),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-256r1 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag BrainpoolP256r1PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP256r1),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for Brainpool P-256r1 private keys used for signing. Raw encoding.</summary>
    public static Tag BrainpoolP256r1PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP256r1),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-256r1 signature values (IEEE P1363 r || s).</summary>
    public static Tag BrainpoolP256r1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP256r1),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-320r1 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag BrainpoolP320r1PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP320r1),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for Brainpool P-320r1 private keys used for signing. Raw encoding.</summary>
    public static Tag BrainpoolP320r1PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP320r1),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-320r1 signature values (IEEE P1363 r || s).</summary>
    public static Tag BrainpoolP320r1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP320r1),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-384r1 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag BrainpoolP384r1PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP384r1),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for Brainpool P-384r1 private keys used for signing. Raw encoding.</summary>
    public static Tag BrainpoolP384r1PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP384r1),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-384r1 signature values (IEEE P1363 r || s).</summary>
    public static Tag BrainpoolP384r1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP384r1),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-512r1 public keys used for signature verification. Compressed encoding.</summary>
    public static Tag BrainpoolP512r1PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP512r1),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>Tag for Brainpool P-512r1 private keys used for signing. Raw encoding.</summary>
    public static Tag BrainpoolP512r1PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP512r1),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-512r1 signature values (IEEE P1363 r || s).</summary>
    public static Tag BrainpoolP512r1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP512r1),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //Brainpool ECDH exchange-key tags. Distinct from the signing tags above by
    //Purpose.Exchange and the uncompressed public-point encoding ECDH agreement
    //consumes (0x04 || X || Y). RFC 5639 curves resolve through BouncyCastle's
    //ECNamedCurveTable for key agreement.

    /// <summary>Tag for Brainpool P-224r1 public keys used in ECDH key agreement. Uncompressed encoding.</summary>
    public static Tag BrainpoolP224r1ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP224r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for Brainpool P-224r1 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag BrainpoolP224r1ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP224r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-256r1 public keys used in ECDH key agreement. Uncompressed encoding.</summary>
    public static Tag BrainpoolP256r1ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP256r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for Brainpool P-256r1 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag BrainpoolP256r1ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP256r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-320r1 public keys used in ECDH key agreement. Uncompressed encoding.</summary>
    public static Tag BrainpoolP320r1ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP320r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for Brainpool P-320r1 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag BrainpoolP320r1ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP320r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-384r1 public keys used in ECDH key agreement. Uncompressed encoding.</summary>
    public static Tag BrainpoolP384r1ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP384r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for Brainpool P-384r1 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag BrainpoolP384r1ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP384r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for Brainpool P-512r1 public keys used in ECDH key agreement. Uncompressed encoding.</summary>
    public static Tag BrainpoolP512r1ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP512r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for Brainpool P-512r1 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag BrainpoolP512r1ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.BrainpoolP512r1),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //Mdoc operation component tags.
    //Named after the ISO/IEC 18013-5 structural slot they belong to. The
    //tag carries Purpose.Salt because the ISO "Random" element is
    //semantically a salt (precomputation-prevention for the issuer-side
    //digest computation); the ISO name is preserved in the identifier so
    //grep against the spec terminology finds it.

    /// <summary>
    /// Tag for the random value bound to each <c>IssuerSignedItem</c> per
    /// <see href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5 §9.1.2.5</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each <c>IssuerSignedItem</c> carries a <c>Random</c> field (≥ 16
    /// bytes) that mixes into the item's digest computation. The Mobile
    /// Security Object commits to <c>digest(IssuerSignedItem)</c>; the
    /// random prevents an attacker from precomputing the digest of a
    /// known claim value across credentials (rainbow-table resistance).
    /// </para>
    /// <para>
    /// Carries <see cref="Purpose.Salt"/> — ISO calls the field "Random"
    /// but the semantic is salt-shaped per
    /// <see href="https://csrc.nist.gov/publications/detail/sp/800-132/final">NIST SP 800-132</see>:
    /// not secret, unique per item, recoverable for verification.
    /// Library code allocates these salts via the configured entropy
    /// backend's <c>GenerateSalt</c> delegate, which stamps provider
    /// provenance on top of this tag.
    /// </para>
    /// </remarks>
    public static Tag MdocIssuerSignedItemRandom { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Salt),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    /// <summary>
    /// Tag for a selective-disclosure salt recovered from a wire decode of an
    /// SD-CWT (or SD-JWT) disclosure, where no entropy operation occurred in
    /// this process — the bytes were read off an already-issued token rather
    /// than freshly generated.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Carries <see cref="Purpose.Salt"/> with raw encoding, mirroring
    /// <see cref="MdocIssuerSignedItemRandom"/>. Parse callers that recover an
    /// issuer-signed SD-CWT to re-serialize a presentation (e.g. SD-CWT
    /// key-binding token issuance) stamp the re-parsed disclosure salts with
    /// this tag so CBOM/OTel can distinguish them from salts produced by a
    /// <c>GenerateSalt</c> entropy backend.
    /// </para>
    /// </remarks>
    public static Tag WireDecodedDisclosureSalt { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Salt),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //COSE wire-form tags. Pool-allocated buffers holding the byte form of
    //COSE_Sign1 (or its sub-structures) carry these tags so CBOM/OTel can
    //distinguish them from generic crypto material.

    /// <summary>
    /// Tag for the wire bytes of a complete <c>COSE_Sign1</c> message per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052">RFC 9052</see>
    /// — the CBOR tag(18)-wrapped 4-array carrying protected header,
    /// unprotected header, payload, and signature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used by carriers like <c>EncodedCoseSign1</c> (in
    /// <c>Verifiable.JCose</c>) for the bytes that flow through
    /// <c>CoseSerialization.SerializeCoseSign1</c>, get stored in
    /// credential-side fields (e.g. <c>MdocIssuerAuth.EncodedCoseSign1</c>,
    /// <c>MdocDeviceSignature.EncodedCoseSign1</c>), and transmit on the
    /// wire. Distinct from raw <c>Signature</c> bytes — the COSE envelope
    /// wraps the signature with the protected header + payload framing the
    /// verifier needs to reconstruct the Sig_structure.
    /// </para>
    /// </remarks>
    public static Tag CoseEncodedSign1 { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Cose));


    /// <summary>
    /// Tag for signature bytes extracted from a wire-form
    /// <c>COSE_Sign1</c> or similar envelope, where the parser has not yet
    /// determined the signing algorithm.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used by parse paths like
    /// <c>CoseSerialization.ParseCoseSign1</c> when wrapping the raw
    /// signature bytes into a <see cref="Signature"/> carrier. The
    /// algorithm is in the protected header; consumers that need
    /// algorithm-specific provenance can re-tag the signature after
    /// inspecting the header.
    /// </para>
    /// </remarks>
    public static Tag AlgorithmAgnosticSignature { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    /// <summary>
    /// Tag for the wire bytes of a complete <c>COSE_Mac0</c> message per
    /// RFC 9052 — the CBOR tag(17)-wrapped 4-array carrying protected
    /// header, unprotected header, payload, and MAC tag. Used by carriers
    /// like <c>EncodedCoseMac0</c> in <c>Verifiable.JCose</c>.
    /// </summary>
    public static Tag CoseEncodedMac0 { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Mac),
        (typeof(EncodingScheme), EncodingScheme.Cose));


    /// <summary>
    /// Tag for the CBOR-encoded <c>protected</c> header bytes of a
    /// <c>COSE_Sign1</c> per RFC 9052 §3 — the serialized form of the
    /// integer-keyed header map (alg, kid, x5chain, …) that is
    /// integrity-protected by the signature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The protected header bytes feed into the Sig_structure as the
    /// <c>body_protected</c> field per RFC 9052 §4.4. Verifiers must use
    /// the exact same byte sequence; preserving the original encoding (as
    /// opposed to re-encoding from a decoded dict) keeps deterministic CBOR
    /// reproducibility across stacks.
    /// </para>
    /// </remarks>
    public static Tag CoseEncodedProtectedHeader { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Data),
        (typeof(EncodingScheme), EncodingScheme.Cose));


    /// <summary>
    /// Tag for the DER wire bytes of a CMS SignedData structure per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652">RFC 5652</see> — the signature-envelope
    /// substrate of eMRTD Passive Authentication (EF.SOD) and the CAdES family of EU advanced
    /// signatures. The CMS analog of <see cref="CoseEncodedSign1"/>.
    /// </summary>
    public static Tag CmsEncodedSignedData { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Der));


    /// <summary>
    /// Tag for the DER-encoded value of a single CMS SignerInfo signed attribute (RFC 5652 §5.3) — for
    /// example the CAdES signing-certificate-v2 (ESS, RFC 5035) or signing-time attribute. The signature
    /// covers these attributes; surfacing them lets a format layer validate its own rules (CAdES).
    /// </summary>
    public static Tag CmsSignedAttributeValue { get; } = Tag.Create(
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Der));


    /// <summary>
    /// Tag for P-384 public keys used in ECDH key agreement.
    /// Uncompressed encoding: <c>0x04 || X || Y</c>.
    /// </summary>
    public static Tag P384ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for P-384 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag P384ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for P-521 public keys used in ECDH key agreement.
    /// Uncompressed encoding: <c>0x04 || X || Y</c>.
    /// </summary>
    public static Tag P521ExchangePublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.EcUncompressed));

    /// <summary>Tag for P-521 private key scalars used in ECDH key agreement. Raw encoding.</summary>
    public static Tag P521ExchangePrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //Digest tags. The hash family is carried via HashAlgorithmName per the existing
    //digest dispatch contract (see CryptoFormatConversions / MicrosoftEntropyFunctions.ComputeDigestAsync).

    /// <summary>
    /// Tag for SHA-256 digest values. Carries
    /// <see cref="HashAlgorithmName.SHA256"/>, <see cref="Purpose.Digest"/>, raw encoding.
    /// </summary>
    public static Tag Sha256Digest { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA256),
        (typeof(Purpose), Purpose.Digest),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for SHA-384 digest values. Carries
    /// <see cref="HashAlgorithmName.SHA384"/>, <see cref="Purpose.Digest"/>, raw encoding.
    /// </summary>
    public static Tag Sha384Digest { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA384),
        (typeof(Purpose), Purpose.Digest),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for SHA-512 digest values. Carries
    /// <see cref="HashAlgorithmName.SHA512"/>, <see cref="Purpose.Digest"/>, raw encoding.
    /// </summary>
    public static Tag Sha512Digest { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA512),
        (typeof(Purpose), Purpose.Digest),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //HMAC tags. Key and Value variants carry identical Tag composition; they exist for
    //ergonomic call-site clarity — `new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key)`
    //reads as a key, `new HmacValue(owner, CryptoTags.HmacSha256Value)` reads as a value.

    /// <summary>Tag for HMAC-SHA-256 keys.</summary>
    public static Tag HmacSha256Key { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA256),
        (typeof(Purpose), Purpose.Hmac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for HMAC-SHA-384 keys.</summary>
    public static Tag HmacSha384Key { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA384),
        (typeof(Purpose), Purpose.Hmac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for HMAC-SHA-512 keys.</summary>
    public static Tag HmacSha512Key { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA512),
        (typeof(Purpose), Purpose.Hmac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for HMAC-SHA-256 output values.</summary>
    public static Tag HmacSha256Value { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA256),
        (typeof(Purpose), Purpose.Hmac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for HMAC-SHA-384 output values.</summary>
    public static Tag HmacSha384Value { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA384),
        (typeof(Purpose), Purpose.Hmac),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for HMAC-SHA-512 output values.</summary>
    public static Tag HmacSha512Value { get; } = Tag.Create(
        (typeof(HashAlgorithmName), HashAlgorithmName.SHA512),
        (typeof(Purpose), Purpose.Hmac),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //ICAO Doc 9303 Basic Access Control / 3DES Secure Messaging operation-component tags.
    //Named after the symmetric algorithm and role, not after the eMRTD protocol. Two-key
    //Triple-DES in CBC mode (zero IV, ISO 9797-1 method 2 padding owned by the Secure
    //Messaging layer) provides confidentiality; the ISO 9797-1 MAC Algorithm 3 ("Retail
    //MAC") over DES, keyed by the same kind of 16-byte key, provides integrity. The
    //Purpose distinguishes the role.

    /// <summary>Tag for two-key Triple-DES CBC keys and the ciphertext produced under them.</summary>
    public static Tag TripleDesCbc { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.TripleDes),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for plaintext recovered by a two-key Triple-DES CBC decryption.</summary>
    public static Tag TripleDesCbcDecryptedContent { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.TripleDes),
        (typeof(Purpose), Purpose.Decrypted),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ISO/IEC 9797-1 MAC Algorithm 3 ("Retail MAC") keys and the 8-byte MAC values
    /// produced under them, as used by ICAO Doc 9303 BAC and 3DES Secure Messaging.
    /// </summary>
    public static Tag RetailMac { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.TripleDes),
        (typeof(Purpose), Purpose.Mac),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    //AES-128 CBC and CMAC operation-component tags, the confidentiality and integrity
    //primitives of ICAO Doc 9303 PACE and AES Secure Messaging. As with the Triple-DES
    //tags, the cipher uses no internal padding (the Secure Messaging layer owns it) and
    //AES-CMAC follows RFC 4493. The Purpose distinguishes the role.

    /// <summary>Tag for AES-128 CBC keys and the ciphertext produced under them.</summary>
    public static Tag Aes128Cbc { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes128),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>Tag for plaintext recovered by an AES-128 CBC decryption.</summary>
    public static Tag Aes128CbcDecryptedContent { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes128),
        (typeof(Purpose), Purpose.Decrypted),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for AES-128 CMAC (RFC 4493) keys and the MAC values produced under them.
    /// </summary>
    public static Tag Aes128Cmac { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Aes128),
        (typeof(Purpose), Purpose.Mac),
        (typeof(EncodingScheme), EncodingScheme.Raw));


    /// <summary>
    /// The curated set of every <see cref="Tag"/> declared on <see cref="CryptoTags"/>,
    /// in declaration order. This is the declarative source for a Cryptographic Bill of
    /// Materials (CBOM): it enumerates the cryptographic assets the library can describe,
    /// independent of which backend provider happens to be wired at runtime.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The list is hand-maintained rather than reflected so the surface stays
    /// browser/AOT/trim-clean: enumerating static properties via reflection would
    /// defeat the trimmer and pull metadata into AOT images. When a new convenience
    /// tag is added above, add it here too.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<Tag> AllTags { get; } =
    [
        P256PublicKey, P256PrivateKey, P256Signature, P256ExchangePublicKey, P256ExchangePrivateKey,
        P384PublicKey, P384PrivateKey, P384Signature, P384ExchangePublicKey, P384ExchangePrivateKey,
        P521PublicKey, P521PrivateKey, P521Signature, P521ExchangePublicKey, P521ExchangePrivateKey,
        Secp256k1PublicKey, Secp256k1PrivateKey, Secp256k1Signature,
        Rsa2048PublicKey, Rsa2048PrivateKey, Rsa2048Signature,
        Rsa4096PublicKey, Rsa4096PrivateKey, Rsa4096Signature,
        RsaSha256Pkcs1Signature, RsaSha256PssSignature,
        RsaSha384Pkcs1Signature, RsaSha384PssSignature,
        RsaSha512Pkcs1Signature, RsaSha512PssSignature,
        Ed25519PublicKey, Ed25519PrivateKey, Ed25519Signature,
        X25519PublicKey, X25519PrivateKey,
        WindowsPlatformEncrypted,
        MlDsa44PublicKey, MlDsa44PrivateKey, MlDsa44Signature,
        MlDsa65PublicKey, MlDsa65PrivateKey, MlDsa65Signature,
        MlDsa87PublicKey, MlDsa87PrivateKey, MlDsa87Signature,
        MlKem512PublicKey, MlKem512PrivateKey,
        MlKem768PublicKey, MlKem768PrivateKey,
        MlKem1024PublicKey, MlKem1024PrivateKey,
        AesGcmIv, AesGcmCiphertext, AesGcmAuthTag, AesGcmAad, AesGcmDecryptedContent, AesGcmCek,
        BrainpoolP224r1PublicKey, BrainpoolP224r1PrivateKey, BrainpoolP224r1Signature,
        BrainpoolP256r1PublicKey, BrainpoolP256r1PrivateKey, BrainpoolP256r1Signature,
        BrainpoolP320r1PublicKey, BrainpoolP320r1PrivateKey, BrainpoolP320r1Signature,
        BrainpoolP384r1PublicKey, BrainpoolP384r1PrivateKey, BrainpoolP384r1Signature,
        BrainpoolP512r1PublicKey, BrainpoolP512r1PrivateKey, BrainpoolP512r1Signature,
        BrainpoolP224r1ExchangePublicKey, BrainpoolP224r1ExchangePrivateKey,
        BrainpoolP256r1ExchangePublicKey, BrainpoolP256r1ExchangePrivateKey,
        BrainpoolP320r1ExchangePublicKey, BrainpoolP320r1ExchangePrivateKey,
        BrainpoolP384r1ExchangePublicKey, BrainpoolP384r1ExchangePrivateKey,
        BrainpoolP512r1ExchangePublicKey, BrainpoolP512r1ExchangePrivateKey,
        MdocIssuerSignedItemRandom, WireDecodedDisclosureSalt,
        CoseEncodedSign1, AlgorithmAgnosticSignature, CoseEncodedMac0, CoseEncodedProtectedHeader,
        CmsEncodedSignedData, CmsSignedAttributeValue,
        Sha256Digest, Sha384Digest, Sha512Digest,
        HmacSha256Key, HmacSha384Key, HmacSha512Key,
        HmacSha256Value, HmacSha384Value, HmacSha512Value,
        TripleDesCbc, TripleDesCbcDecryptedContent, RetailMac,
        Aes128Cbc, Aes128CbcDecryptedContent, Aes128Cmac
    ];
}
