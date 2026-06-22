namespace Verifiable.JCose;

/// <summary>
/// A descriptor for a JWE content encryption (<c>enc</c>) algorithm: the wire identifier, the
/// Content Encryption Key byte length, the initialization vector byte length, the
/// authentication tag byte length, and the AEAD <see cref="JweContentEncryptionFamily"/>.
/// </summary>
/// <remarks>
/// <para>
/// The structural lengths are facts of the algorithm (RFC 7518 §5.2 / §5.3) the JWE pipeline
/// needs at several points: the CEK length when generating a random CEK (RFC 7516 §5.1 step 2),
/// the IV and tag lengths when validating a parsed message, and the family when enforcing the
/// ECDH-1PU §2.1 content-encryption constraint. Carrying them on one descriptor — chosen as a
/// <see langword="readonly"/> <see langword="record"/> for the same reason as
/// <see cref="JweAlgorithm"/> — lets the JWE pipeline read each length as a
/// field wherever those steps need it.
/// </para>
/// <para>
/// For the AES_CBC_HMAC_SHA2 family the <see cref="CekByteLength"/> is the composite key (the
/// sum of the MAC and ENC halves): 32 for A128CBC-HS256, 48 for A192CBC-HS384, 64 for
/// A256CBC-HS512. For AES-GCM it is the AES key size: 16, 24, 32.
/// </para>
/// </remarks>
/// <param name="Name">The wire <c>enc</c> identifier, e.g. <c>A256CBC-HS512</c>.</param>
/// <param name="CekByteLength">The Content Encryption Key length in bytes.</param>
/// <param name="IvByteLength">The initialization vector length in bytes (16 for CBC, 12 for GCM).</param>
/// <param name="TagByteLength">The authentication tag length in bytes.</param>
/// <param name="Family">The AEAD construction family.</param>
public readonly record struct JweContentEncryption(
    string Name,
    int CekByteLength,
    int IvByteLength,
    int TagByteLength,
    JweContentEncryptionFamily Family)
{
    //AES_CBC_HMAC_SHA2 IV is one AES block per RFC 7518 §5.2.2.1 step 2.
    private const int AesCbcIvBytes = 16;

    //AES-GCM IV is 96 bits per NIST SP 800-38D, the JOSE-mandated length.
    private const int AesGcmIvBytes = 12;

    //AES-GCM tag is 128 bits per RFC 7518 §5.3.
    private const int AesGcmTagBytes = 16;

    //XChaCha20-Poly1305 extended nonce is 192 bits (draft-irtf-cfrg-xchacha-03 §2.3).
    private const int XChaCha20IvBytes = 24;

    //XChaCha20-Poly1305 key is 256 bits and the Poly1305 tag is 128 bits (draft-irtf-cfrg-xchacha-03 §2.3).
    private const int XChaCha20CekBytes = 32;
    private const int XChaCha20TagBytes = 16;


    /// <summary>A128CBC-HS256 (RFC 7518 §5.2.3): 32-byte composite key, 16-byte IV, 16-byte tag.</summary>
    public static JweContentEncryption A128CbcHs256 { get; } =
        new(WellKnownJweEncryptionAlgorithms.A128CbcHs256, 32, AesCbcIvBytes, 16, JweContentEncryptionFamily.AesCbcHmac);

    /// <summary>A192CBC-HS384 (RFC 7518 §5.2.4): 48-byte composite key, 16-byte IV, 24-byte tag.</summary>
    public static JweContentEncryption A192CbcHs384 { get; } =
        new(WellKnownJweEncryptionAlgorithms.A192CbcHs384, 48, AesCbcIvBytes, 24, JweContentEncryptionFamily.AesCbcHmac);

    /// <summary>A256CBC-HS512 (RFC 7518 §5.2.5): 64-byte composite key, 16-byte IV, 32-byte tag.</summary>
    public static JweContentEncryption A256CbcHs512 { get; } =
        new(WellKnownJweEncryptionAlgorithms.A256CbcHs512, 64, AesCbcIvBytes, 32, JweContentEncryptionFamily.AesCbcHmac);

    /// <summary>A128GCM (RFC 7518 §5.3): 16-byte key, 12-byte IV, 16-byte tag.</summary>
    public static JweContentEncryption A128Gcm { get; } =
        new(WellKnownJweEncryptionAlgorithms.A128Gcm, 16, AesGcmIvBytes, AesGcmTagBytes, JweContentEncryptionFamily.AesGcm);

    /// <summary>A192GCM (RFC 7518 §5.3): 24-byte key, 12-byte IV, 16-byte tag.</summary>
    public static JweContentEncryption A192Gcm { get; } =
        new(WellKnownJweEncryptionAlgorithms.A192Gcm, 24, AesGcmIvBytes, AesGcmTagBytes, JweContentEncryptionFamily.AesGcm);

    /// <summary>A256GCM (RFC 7518 §5.3): 32-byte key, 12-byte IV, 16-byte tag.</summary>
    public static JweContentEncryption A256Gcm { get; } =
        new(WellKnownJweEncryptionAlgorithms.A256Gcm, 32, AesGcmIvBytes, AesGcmTagBytes, JweContentEncryptionFamily.AesGcm);

    /// <summary>
    /// XC20P (XChaCha20-Poly1305, draft-irtf-cfrg-xchacha-03 §2.3): 32-byte key, 24-byte extended
    /// nonce, 16-byte Poly1305 tag.
    /// </summary>
    public static JweContentEncryption XC20P { get; } =
        new(WellKnownJweEncryptionAlgorithms.XC20P, XChaCha20CekBytes, XChaCha20IvBytes, XChaCha20TagBytes, JweContentEncryptionFamily.XChaCha20Poly1305);


    /// <summary>
    /// Maps a wire <c>enc</c> string to its descriptor, or <see langword="null"/> when the
    /// value is not a content encryption algorithm this library implements.
    /// </summary>
    /// <param name="contentEncryptionAlgorithm">The wire <c>enc</c> string.</param>
    /// <returns>The matching descriptor, or <see langword="null"/>.</returns>
    public static JweContentEncryption? FromWellKnownName(string contentEncryptionAlgorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);

        return contentEncryptionAlgorithm switch
        {
            _ when WellKnownJweEncryptionAlgorithms.IsA128CbcHs256(contentEncryptionAlgorithm) => A128CbcHs256,
            _ when WellKnownJweEncryptionAlgorithms.IsA192CbcHs384(contentEncryptionAlgorithm) => A192CbcHs384,
            _ when WellKnownJweEncryptionAlgorithms.IsA256CbcHs512(contentEncryptionAlgorithm) => A256CbcHs512,
            _ when WellKnownJweEncryptionAlgorithms.IsA128Gcm(contentEncryptionAlgorithm) => A128Gcm,
            _ when WellKnownJweEncryptionAlgorithms.IsA192Gcm(contentEncryptionAlgorithm) => A192Gcm,
            _ when WellKnownJweEncryptionAlgorithms.IsA256Gcm(contentEncryptionAlgorithm) => A256Gcm,
            _ when WellKnownJweEncryptionAlgorithms.IsXC20P(contentEncryptionAlgorithm) => XC20P,
            _ => null
        };
    }
}
