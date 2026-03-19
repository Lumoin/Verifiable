using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Convenience methods layered on top of the <see cref="CryptoFormatConversions"/> delegates.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CryptoFormatConversions"/> defines the delegate types and their default
/// implementations. Library callers can replace any delegate with their own implementation.
/// This class provides named helpers that delegate to the defaults, so call sites do not
/// need to pass <see cref="Purpose"/> explicitly for the common cases.
/// </para>
/// </remarks>
public static class CryptoFormatConversionsExtensions
{
    /// <summary>
    /// Returns the signing <see cref="Tag"/> for the specified JWA algorithm.
    /// </summary>
    /// <param name="jwaAlgorithm">
    /// The JWA algorithm identifier (e.g., <c>ES256</c>, <c>RS256</c>).
    /// </param>
    /// <returns>The corresponding signing <see cref="Tag"/>.</returns>
    public static Tag GetSigningTag(string jwaAlgorithm) =>
        CryptoFormatConversions.DefaultJwaToTagConverter(jwaAlgorithm, Purpose.Signing);


    /// <summary>
    /// Returns the verification <see cref="Tag"/> for the specified JWA algorithm.
    /// </summary>
    /// <param name="jwaAlgorithm">
    /// The JWA algorithm identifier (e.g., <c>ES256</c>, <c>RS256</c>).
    /// </param>
    /// <returns>The corresponding verification <see cref="Tag"/>.</returns>
    public static Tag GetVerificationTag(string jwaAlgorithm) =>
        CryptoFormatConversions.DefaultJwaToTagConverter(jwaAlgorithm, Purpose.Verification);


    /// <summary>
    /// Returns the signature value <see cref="Tag"/> for the specified JWA algorithm.
    /// </summary>
    /// <param name="jwaAlgorithm">
    /// The JWA algorithm identifier (e.g., <c>ES256</c>, <c>EdDSA</c>).
    /// </param>
    /// <returns>
    /// The corresponding signature tag, or <see cref="Tag.Empty"/> for RSA algorithms
    /// which do not have a dedicated signature tag in the library.
    /// </returns>
    public static Tag GetSignatureTag(string jwaAlgorithm)
    {
        if(string.IsNullOrEmpty(jwaAlgorithm))
        {
            throw new ArgumentException("JWA algorithm cannot be null or empty.", nameof(jwaAlgorithm));
        }

        if(WellKnownJwaValues.IsEs256(jwaAlgorithm)) { return CryptoTags.P256Signature; }
        if(WellKnownJwaValues.IsEs384(jwaAlgorithm)) { return CryptoTags.P384Signature; }
        if(WellKnownJwaValues.IsEs512(jwaAlgorithm)) { return CryptoTags.P521Signature; }
        if(WellKnownJwaValues.IsEs256k1(jwaAlgorithm)) { return CryptoTags.Secp256k1Signature; }
        if(WellKnownJwaValues.IsEdDsa(jwaAlgorithm)) { return CryptoTags.Ed25519Signature; }

        if(WellKnownJwaValues.IsRs256(jwaAlgorithm)
            || WellKnownJwaValues.IsRs384(jwaAlgorithm)
            || WellKnownJwaValues.IsRs512(jwaAlgorithm)
            || WellKnownJwaValues.IsPs256(jwaAlgorithm)
            || WellKnownJwaValues.IsPs384(jwaAlgorithm)
            || WellKnownJwaValues.IsPs512(jwaAlgorithm))
        {
            return Tag.Empty;
        }

        throw new NotSupportedException($"JWA algorithm '{jwaAlgorithm}' is not supported for signature tags.");
    }


    /// <summary>
    /// Returns the JWA algorithm identifier for the specified <see cref="Tag"/> with
    /// explicit hash algorithm selection for RSA.
    /// </summary>
    /// <param name="tag">The tag containing algorithm information.</param>
    /// <param name="hashAlgorithm">
    /// The hash algorithm name for RSA signatures (e.g., <c>SHA256</c>, <c>SHA384</c>,
    /// <c>SHA512</c>). Ignored for non-RSA algorithms.
    /// </param>
    /// <param name="usePss">Whether to use RSA-PSS padding instead of PKCS#1 v1.5.</param>
    /// <returns>The JWA algorithm identifier.</returns>
    public static string GetJwaAlgorithm(Tag tag, string? hashAlgorithm = null, bool usePss = false)
    {
        ArgumentNullException.ThrowIfNull(tag);

        CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();

        if(algorithm.Equals(CryptoAlgorithm.P256)) { return WellKnownJwaValues.Es256; }
        if(algorithm.Equals(CryptoAlgorithm.P384)) { return WellKnownJwaValues.Es384; }
        if(algorithm.Equals(CryptoAlgorithm.P521)) { return WellKnownJwaValues.Es512; }
        if(algorithm.Equals(CryptoAlgorithm.Secp256k1)) { return WellKnownJwaValues.Es256k1; }
        if(algorithm.Equals(CryptoAlgorithm.Ed25519)) { return WellKnownJwaValues.EdDsa; }

        if(algorithm.Equals(CryptoAlgorithm.Rsa2048) || algorithm.Equals(CryptoAlgorithm.Rsa4096))
        {
            return (hashAlgorithm, usePss) switch
            {
                (WellKnownHashAlgorithms.Sha384, false) => WellKnownJwaValues.Rs384,
                (WellKnownHashAlgorithms.Sha512, false) => WellKnownJwaValues.Rs512,
                (_, false) => WellKnownJwaValues.Rs256,
                (WellKnownHashAlgorithms.Sha384, true) => WellKnownJwaValues.Ps384,
                (WellKnownHashAlgorithms.Sha512, true) => WellKnownJwaValues.Ps512,
                (_, true) => WellKnownJwaValues.Ps256
            };
        }

        throw new NotSupportedException($"CryptoAlgorithm '{algorithm}' does not have a JWA mapping.");
    }
}
