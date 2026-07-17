namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Resolves the registered <see cref="Tag"/> for an RSA public key extracted from an X.509
/// certificate, by the key's size in bits — the mapping the two X.509 backends
/// (<c>MicrosoftX509Functions.ExtractPublicKey</c> and <c>BouncyCastleX509Functions.ExtractPublicKey</c>)
/// both apply after decoding a leaf certificate's RSA public key, so the two backends resolve the
/// exact same set of supported key sizes to the exact same tags rather than each carrying its own
/// copy of the mapping.
/// </summary>
public static class X509RsaPublicKeyTags
{
    /// <summary>
    /// Resolves the verification-purpose <see cref="Tag"/> for an RSA public key of the given size.
    /// </summary>
    /// <param name="keySizeInBits">The RSA modulus size in bits, as the certificate declares it.</param>
    /// <returns>
    /// One of the pre-built <see cref="CryptoTags"/> members for <paramref name="keySizeInBits"/>.
    /// The returned <see cref="Tag"/> is never constructed ad hoc: it is the carrier's algorithm/
    /// purpose/encoding provenance context — the same instance <see cref="CryptoFunctionRegistry"/>
    /// dispatch keys off and the CBOM area (<c>Verifiable.Cryptography.Cbom</c>) uses to identify the
    /// key material — so a certificate-derived RSA public key carries identical provenance regardless
    /// of which backend extracted it.
    /// </returns>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="keySizeInBits"/> names a key size neither backend supports.
    /// </exception>
    public static Tag ResolvePublicKeyTag(int keySizeInBits) => keySizeInBits switch
    {
        2048 => CryptoTags.Rsa2048PublicKey,
        4096 => CryptoTags.Rsa4096PublicKey,
        _ => throw new NotSupportedException(
            $"RSA key size {keySizeInBits} bits is not supported. Supported sizes are 2048 and 4096.")
    };
}
