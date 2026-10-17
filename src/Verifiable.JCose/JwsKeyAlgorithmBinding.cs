using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// The rule a JWS protected header's <c>alg</c> breaks against the key its signature is to be verified under, judged before
/// anything is verified (<see cref="JwsKeyAlgorithmBinding"/>).
/// </summary>
public enum JwsKeyAlgorithmRefusal
{
    /// <summary>
    /// The algorithm is not defined over the key's type: an RSA algorithm over an elliptic-curve key, an ECDSA algorithm over a
    /// curve other than the key's, EdDSA over a key that is no Ed25519 key, or an algorithm over a key of a type this binding
    /// names no algorithm for.
    /// </summary>
    AlgorithmOfAnotherKeyType,

    /// <summary>
    /// The algorithm is defined over the key's type but is not the one algorithm the registry's verification function for the
    /// key's tag computes: the function <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> resolves for an RSA
    /// key verifies RSASSA-PKCS1-v1_5 with SHA-256 alone, so RS384, RS512 and the RSASSA-PSS algorithms over it name an algorithm
    /// the verification would not perform.
    /// </summary>
    AlgorithmNotComputedByTheKeysVerification,

    /// <summary>
    /// The algorithm is not the one the verification the caller supplied performs
    /// (<see cref="JwsAlgorithmVerification.Algorithm"/>): a PS256 header over an RSA key presented to a verification that
    /// performs RS256 names an operation that verification would not perform, whether or not the signature verifies under it.
    /// </summary>
    AlgorithmNotPerformedByTheSuppliedVerification
}


/// <summary>
/// The binding of the algorithm a JWS protected header names to the key its signature is verified under, made before the
/// signature is verified. <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.2">RFC 7515 Section 5.2</see> step 8:
/// "Validate the JWS Signature against the JWS Signing Input ... in the manner defined for the algorithm being used, which MUST
/// be accurately represented by the value of the "alg" (algorithm) Header Parameter"; and
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The library MUST ensure that the
/// "alg" or "enc" header specifies the same algorithm that is used for the cryptographic operation. Moreover, each key MUST be
/// used with exactly one algorithm, and this MUST be checked when the cryptographic operation is performed." A key reconstructed
/// from a JWK is tagged by its material alone, never by the header, so the header's algorithm is judged against the key's tag
/// here and a disagreement is a typed refusal.
/// </summary>
public static class JwsKeyAlgorithmBinding
{
    /// <summary>
    /// Judges whether the algorithm a header names is the very algorithm a verification the caller supplied performs, for a
    /// verification whose function the caller selected and bound to its algorithm (<see cref="JwsAlgorithmVerification"/>):
    /// first that the header names the algorithm the verification carries, compared as the case-sensitive JWA name it is, then
    /// that the algorithm is defined over the key's type - <c>ES256</c> over P-256, <c>ES384</c> over P-384, <c>ES512</c> over
    /// P-521, <c>ES256K</c> over secp256k1, <c>EdDSA</c> over Ed25519, the RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms over an
    /// RSA key of 2048 or 4096 bits, and over every other key the one algorithm the library names a key of its tag by
    /// (<see cref="CryptoFormatConversions.ResolveJwaAlgorithm"/>).
    /// </summary>
    /// <param name="algorithm">The header's <c>alg</c>.</param>
    /// <param name="key">The key the signature is to be verified under.</param>
    /// <param name="verification">The verification the caller supplied, bound to the algorithm it performs.</param>
    /// <returns><see langword="null"/> when the supplied verification performs the algorithm over the key; otherwise the refusal.</returns>
    public static JwsKeyAlgorithmRefusal? JudgeSuppliedVerification(string algorithm, PublicKeyMemory key, JwsAlgorithmVerification verification)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(verification);

        if(!WellKnownJwaValues.Equals(verification.Algorithm, algorithm))
        {
            return JwsKeyAlgorithmRefusal.AlgorithmNotPerformedByTheSuppliedVerification;
        }

        return JudgeKeyType(algorithm, key);
    }


    /// <summary>
    /// Judges whether the algorithm a header names is the very algorithm the registry's verification function for the key's tag
    /// computes, for a verification resolved from the key's tag (<see cref="Jws.VerifyAsync(string, DecodeDelegate, BaseMemoryPool, PublicKeyMemory, CancellationToken)"/>):
    /// first that it is defined over the key's type, then that it is the one algorithm the library names a key of the tag by
    /// (<see cref="CryptoFormatConversions.ResolveJwaAlgorithm"/>), the algorithm the function the registry holds for that tag
    /// verifies.
    /// </summary>
    /// <param name="algorithm">The header's <c>alg</c>.</param>
    /// <param name="key">The key the signature is to be verified under.</param>
    /// <returns><see langword="null"/> when the verification resolved from the key's tag computes the algorithm; otherwise the refusal.</returns>
    public static JwsKeyAlgorithmRefusal? JudgeRegistryVerification(string algorithm, PublicKeyMemory key)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(key);

        if(JudgeKeyType(algorithm, key) is JwsKeyAlgorithmRefusal refusal)
        {
            return refusal;
        }

        return CryptoFormatConversions.ResolveJwaAlgorithm(key.Tag) is { IsNamed: true, Algorithm: string computed }
            && WellKnownJwaValues.Equals(computed, algorithm)
            ? null
            : JwsKeyAlgorithmRefusal.AlgorithmNotComputedByTheKeysVerification;
    }


    /// <summary>
    /// Judges whether an algorithm is defined over the key's type: the RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms over an RSA
    /// key, and over every other key the one algorithm the library names a key of its tag by.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <param name="key">The key.</param>
    /// <returns><see langword="null"/> when the algorithm is one of the key's type; otherwise the refusal.</returns>
    private static JwsKeyAlgorithmRefusal? JudgeKeyType(string algorithm, PublicKeyMemory key)
    {
        if(IsRsaKey(key.Tag.Get<CryptoAlgorithm>()))
        {
            return IsRsaSignatureAlgorithm(algorithm) ? null : JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType;
        }

        return CryptoFormatConversions.ResolveJwaAlgorithm(key.Tag) is { IsNamed: true, Algorithm: string named }
            && WellKnownJwaValues.Equals(named, algorithm)
            ? null
            : JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType;
    }


    /// <summary>Whether a key algorithm is an RSA key of a modulus length this library reads from a JWK.</summary>
    /// <param name="keyAlgorithm">The algorithm the key's tag names.</param>
    /// <returns><see langword="true"/> for an RSA key of 2048 or 4096 bits.</returns>
    private static bool IsRsaKey(CryptoAlgorithm keyAlgorithm) =>
        keyAlgorithm.Equals(CryptoAlgorithm.Rsa2048) || keyAlgorithm.Equals(CryptoAlgorithm.Rsa4096);


    /// <summary>Whether an algorithm is one of RFC 7518's RSA signature algorithms (Sections 3.3 and 3.5).</summary>
    /// <param name="algorithm">The header's <c>alg</c>.</param>
    /// <returns><see langword="true"/> for RS256, RS384, RS512, PS256, PS384 and PS512.</returns>
    private static bool IsRsaSignatureAlgorithm(string algorithm) =>
        WellKnownJwaValues.IsRs256(algorithm) || WellKnownJwaValues.IsRs384(algorithm) || WellKnownJwaValues.IsRs512(algorithm)
        || WellKnownJwaValues.IsPs256(algorithm) || WellKnownJwaValues.IsPs384(algorithm) || WellKnownJwaValues.IsPs512(algorithm);
}
