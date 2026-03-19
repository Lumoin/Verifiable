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
}
