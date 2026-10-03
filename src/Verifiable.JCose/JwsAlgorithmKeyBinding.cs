using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// The binding of a JWS <c>alg</c> value to the key algorithms it can be verified with: the one table
/// the library holds a declared algorithm against the key that is to verify it.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 section 3.1</see>: "The
/// library MUST ensure that the "alg" or "enc" header specifies the same algorithm that is used for
/// the cryptographic operation. Moreover, each key MUST be used with exactly one algorithm, and this
/// MUST be checked when the cryptographic operation is performed."
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 section 4.1.1</see>:
/// "The JWS Signature value is not valid if the "alg" value does not represent a supported algorithm
/// or if there is not a key for use with that algorithm associated with the party that digitally
/// signed or MACed the content."
/// </para>
/// <para>
/// A verification the library runs is chosen by the key's algorithm, so a declared <c>alg</c> outside
/// the key's own algorithms names an operation that never ran. Each elliptic-curve, Edwards-curve and
/// ML-DSA algorithm binds the one key algorithm it is defined over. The RSASSA-PKCS1-v1_5 and RSASSA-PSS
/// algorithms all bind an RSA key of either size the library tags: the key's algorithm does not tell
/// them apart, so a caller that holds an RSA key to exactly one of them does so by the key's own
/// <c>alg</c> member (<see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.4">RFC 7517 section
/// 4.4</see>: "The "alg" (algorithm) parameter identifies the algorithm intended for use with the
/// key."). A key algorithm no JWS algorithm is defined over (an X25519 key-agreement key,
/// brainpoolP224r1) binds none.
/// </para>
/// </remarks>
public static class JwsAlgorithmKeyBinding
{
    /// <summary>
    /// Whether <paramref name="alg"/> is an algorithm of a key tagged <paramref name="keyAlgorithm"/>:
    /// <c>ES256</c> over P-256, <c>ES384</c> over P-384, <c>ES512</c> over P-521, <c>ES256K</c> over
    /// secp256k1, <c>EdDSA</c> over Ed25519, <c>RS256</c> to <c>RS512</c> and <c>PS256</c> to
    /// <c>PS512</c> over an RSA 2048 or RSA 4096 key, <c>ESB256</c>, <c>ESB320</c>, <c>ESB384</c> and
    /// <c>ESB512</c> over brainpoolP256r1, brainpoolP320r1, brainpoolP384r1 and brainpoolP512r1, and
    /// <c>ML-DSA-44</c>, <c>ML-DSA-65</c> and <c>ML-DSA-87</c> over the ML-DSA key of the same parameter
    /// set.
    /// </summary>
    /// <param name="alg">
    /// The declared algorithm, compared as the case-sensitive string RFC 7515 section 4.1.1 makes it.
    /// </param>
    /// <param name="keyAlgorithm">The algorithm the verifying key is tagged with.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="alg"/> is an algorithm of the key; otherwise
    /// <see langword="false"/>, among them for <c>none</c>, a MAC algorithm, a value no table names and
    /// a key no JWS algorithm is defined over.
    /// </returns>
    public static bool IsAlgorithmOfKey(string alg, CryptoAlgorithm keyAlgorithm) => alg switch
    {
        string when WellKnownJwaValues.IsEs256(alg) => keyAlgorithm == CryptoAlgorithm.P256,
        string when WellKnownJwaValues.IsEs384(alg) => keyAlgorithm == CryptoAlgorithm.P384,
        string when WellKnownJwaValues.IsEs512(alg) => keyAlgorithm == CryptoAlgorithm.P521,
        string when WellKnownJwaValues.IsEs256K(alg) => keyAlgorithm == CryptoAlgorithm.Secp256k1,
        string when WellKnownJwaValues.IsEdDsa(alg) => keyAlgorithm == CryptoAlgorithm.Ed25519,
        string when WellKnownJwaValues.IsRs256(alg)
            || WellKnownJwaValues.IsRs384(alg)
            || WellKnownJwaValues.IsRs512(alg)
            || WellKnownJwaValues.IsPs256(alg)
            || WellKnownJwaValues.IsPs384(alg)
            || WellKnownJwaValues.IsPs512(alg) => keyAlgorithm == CryptoAlgorithm.Rsa2048 || keyAlgorithm == CryptoAlgorithm.Rsa4096,
        string when WellKnownJwaValues.IsEsb256(alg) => keyAlgorithm == CryptoAlgorithm.BrainpoolP256r1,
        string when WellKnownJwaValues.IsEsb320(alg) => keyAlgorithm == CryptoAlgorithm.BrainpoolP320r1,
        string when WellKnownJwaValues.IsEsb384(alg) => keyAlgorithm == CryptoAlgorithm.BrainpoolP384r1,
        string when WellKnownJwaValues.IsEsb512(alg) => keyAlgorithm == CryptoAlgorithm.BrainpoolP512r1,
        string when WellKnownJwaValues.IsMlDsa44(alg) => keyAlgorithm == CryptoAlgorithm.MlDsa44,
        string when WellKnownJwaValues.IsMlDsa65(alg) => keyAlgorithm == CryptoAlgorithm.MlDsa65,
        string when WellKnownJwaValues.IsMlDsa87(alg) => keyAlgorithm == CryptoAlgorithm.MlDsa87,
        _ => false
    };
}
