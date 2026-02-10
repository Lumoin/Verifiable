using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for common cryptographic key types.
/// </summary>
/// <remarks>
/// <para>
/// This static class provides ready-to-use tags for standard cryptographic algorithms
/// and key purposes. Each tag contains the appropriate <see cref="CryptoAlgorithm"/>,
/// <see cref="Purpose"/>, and <see cref="EncodingScheme"/> metadata.
/// </para>
/// <para>
/// <strong>Usage</strong>
/// </para>
/// <code>
/// //Use a pre-built tag when creating key memory.
/// var publicKey = new PublicKeyMemory(keyBytes, CryptoTags.P256PublicKey);
///
/// //Or retrieve components from a tag.
/// var algorithm = CryptoTags.Ed25519PrivateKey.Get&lt;CryptoAlgorithm&gt;();
/// </code>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="CryptoAlgorithm"/>
/// <seealso cref="Purpose"/>
/// <seealso cref="EncodingScheme"/>
public static class CryptoTags
{
    /// <summary>
    /// Tag for P-256 (secp256r1) public keys.
    /// </summary>
    public static Tag P256PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>
    /// Tag for P-256 (secp256r1) private keys.
    /// </summary>
    public static Tag P256PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for P-256 (secp256r1) signatures.
    /// </summary>
    public static Tag P256Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for P-384 (secp384r1) public keys.
    /// </summary>
    public static Tag P384PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>
    /// Tag for P-384 (secp384r1) private keys.
    /// </summary>
    public static Tag P384PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for P-384 (secp384r1) signatures.
    /// </summary>
    public static Tag P384Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P384),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for P-521 (secp521r1) public keys.
    /// </summary>
    public static Tag P521PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>
    /// Tag for P-521 (secp521r1) private keys.
    /// </summary>
    public static Tag P521PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for P-521 (secp521r1) signatures.
    /// </summary>
    public static Tag P521Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.P521),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for secp256k1 public keys.
    /// </summary>
    public static Tag Secp256k1PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Secp256k1),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.EcCompressed));

    /// <summary>
    /// Tag for secp256k1 private keys.
    /// </summary>
    public static Tag Secp256k1PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Secp256k1),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for secp256k1 signatures.
    /// </summary>
    public static Tag Secp256k1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Secp256k1),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA-2048 public keys.
    /// </summary>
    public static Tag Rsa2048PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa2048),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Der));

    /// <summary>
    /// Tag for RSA-2048 private keys.
    /// </summary>
    public static Tag Rsa2048PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa2048),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Pkcs1));

    /// <summary>
    /// Tag for RSA-2048 signatures.
    /// </summary>
    public static Tag Rsa2048Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa2048),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA-4096 public keys.
    /// </summary>
    public static Tag Rsa4096PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa4096),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Der));

    /// <summary>
    /// Tag for RSA-4096 private keys.
    /// </summary>
    public static Tag Rsa4096PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa4096),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Pkcs1));

    /// <summary>
    /// Tag for RSA-4096 signatures.
    /// </summary>
    public static Tag Rsa4096Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Rsa4096),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA signatures using SHA-256 hash with PKCS#1 v1.5 padding.
    /// </summary>
    public static Tag RsaSha256Pkcs1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha256),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA signatures using SHA-256 hash with PSS padding.
    /// </summary>
    public static Tag RsaSha256PssSignature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha256Pss),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA signatures using SHA-384 hash with PKCS#1 v1.5 padding.
    /// </summary>
    public static Tag RsaSha384Pkcs1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha384),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA signatures using SHA-384 hash with PSS padding.
    /// </summary>
    public static Tag RsaSha384PssSignature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha384Pss),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA signatures using SHA-512 hash with PKCS#1 v1.5 padding.
    /// </summary>
    public static Tag RsaSha512Pkcs1Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha512),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for RSA signatures using SHA-512 hash with PSS padding.
    /// </summary>
    public static Tag RsaSha512PssSignature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.RsaSha512Pss),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for Ed25519 public keys.
    /// </summary>
    public static Tag Ed25519PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Ed25519),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for Ed25519 private keys.
    /// </summary>
    public static Tag Ed25519PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Ed25519),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for Ed25519 signatures.
    /// </summary>
    public static Tag Ed25519Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.Ed25519),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for X25519 public keys (key exchange).
    /// </summary>
    public static Tag X25519PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Exchange),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for X25519 private keys.
    /// </summary>
    public static Tag X25519PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.X25519),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for Windows platform encrypted data.
    /// </summary>
    public static Tag WindowsPlatformEncrypted { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.WindowsPlatformEncrypted),
        (typeof(Purpose), Purpose.Encryption),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-44 public keys (post-quantum, NIST security level 2).
    /// </summary>
    public static Tag MlDsa44PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa44),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-44 private keys (post-quantum, NIST security level 2).
    /// </summary>
    public static Tag MlDsa44PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa44),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-44 signatures.
    /// </summary>
    public static Tag MlDsa44Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa44),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-65 public keys (post-quantum, NIST security level 3).
    /// </summary>
    public static Tag MlDsa65PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa65),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-65 private keys (post-quantum, NIST security level 3).
    /// </summary>
    public static Tag MlDsa65PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa65),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-65 signatures.
    /// </summary>
    public static Tag MlDsa65Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa65),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-87 public keys (post-quantum, NIST security level 5).
    /// </summary>
    public static Tag MlDsa87PublicKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa87),
        (typeof(Purpose), Purpose.Verification),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-87 private keys (post-quantum, NIST security level 5).
    /// </summary>
    public static Tag MlDsa87PrivateKey { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa87),
        (typeof(Purpose), Purpose.Signing),
        (typeof(EncodingScheme), EncodingScheme.Raw));

    /// <summary>
    /// Tag for ML-DSA-87 signatures.
    /// </summary>
    public static Tag MlDsa87Signature { get; } = Tag.Create(
        (typeof(CryptoAlgorithm), CryptoAlgorithm.MlDsa87),
        (typeof(Purpose), Purpose.Signature),
        (typeof(EncodingScheme), EncodingScheme.Raw));
}