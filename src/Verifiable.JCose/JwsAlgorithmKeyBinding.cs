using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// The binding of a JWS <c>alg</c> value to the key algorithms it can be verified with: the one table
/// the library holds a declared algorithm against the key algorithm of the verifying public key.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The
/// library MUST ensure that the "alg" or "enc" header specifies the same algorithm that is used for
/// the cryptographic operation. Moreover, each key MUST be used with exactly one algorithm, and this
/// MUST be checked when the cryptographic operation is performed."
/// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>:
/// "The JWS Signature value is not valid if the "alg" value does not represent a supported algorithm
/// or if there is not a key for use with that algorithm associated with the party that digitally
/// signed or MACed the content."
/// </para>
/// <para>
/// A verification the library runs is chosen by the key algorithm of the verifying public key, so the
/// table answers <see langword="true"/> only for the algorithm that verification computes: a declared
/// <c>alg</c> outside it names an operation that never ran. <c>ES256</c>, <c>ES384</c> and <c>ES512</c>
/// bind the P-256, P-384 and P-521 key algorithms
/// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">RFC 7518 Section 3.4</see>), and
/// <c>ES256K</c> binds secp256k1
/// (<see href="https://www.rfc-editor.org/rfc/rfc8812#section-3.2">RFC 8812 Section 3.2</see>).
/// </para>
/// <para>
/// <c>EdDSA</c> and <c>Ed25519</c> both bind the Ed25519 key algorithm.
/// <see href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037 Section 3.1</see> defines
/// <c>EdDSA</c> over the Ed25519 and Ed448 subtypes; the library tags no Ed448 public key, so
/// <c>EdDSA</c> binds the Ed25519 key algorithm alone, and
/// <see href="https://www.rfc-editor.org/rfc/rfc8037#section-3.2">RFC 8037 Section 3.2</see> keeps the
/// X25519 key agreement subtype from it: "These subtypes MUST NOT be used for signing."
/// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.1.1">RFC 9864 Section 4.1.1</see>
/// registers <c>Ed25519</c> with the description "EdDSA using the Ed25519 parameter set in Section 5.1
/// of [RFC8032]", and the deprecation of <c>EdDSA</c> beside it refuses nothing, since
/// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.4">RFC 9864 Section 4.4</see> defines
/// "Deprecated" as a preference: "There is a preferred mechanism to achieve functionality similar to
/// that referenced by the identifier; this replacement functionality SHOULD be utilized in new
/// deployments in preference to the deprecated identifier, unless there exist documented operational
/// or regulatory requirements that prevent migration away from the deprecated identifier."
/// </para>
/// <para>
/// An RSA public key a JWS verification meets carries one of two kinds of key tag. A size tag,
/// <see cref="CryptoAlgorithm.Rsa2048"/> or <see cref="CryptoAlgorithm.Rsa4096"/>, is verified by the
/// library's providers as RSASSA-PKCS1-v1_5 with SHA-256, so <c>RS256</c> is its one algorithm. A
/// padding-and-hash tag fixes both the padding and the hash its verifier computes, so it is the key
/// algorithm of exactly one name: <see cref="CryptoAlgorithm.RsaSha256"/>,
/// <see cref="CryptoAlgorithm.RsaSha384"/> and <see cref="CryptoAlgorithm.RsaSha512"/> of <c>RS256</c>,
/// <c>RS384</c> and <c>RS512</c>, RSASSA-PKCS1-v1_5 with SHA-256, SHA-384 and SHA-512
/// (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">RFC 7518 Section 3.3</see>), and
/// <see cref="CryptoAlgorithm.RsaSha256Pss"/>, <see cref="CryptoAlgorithm.RsaSha384Pss"/> and
/// <see cref="CryptoAlgorithm.RsaSha512Pss"/> of <c>PS256</c>, <c>PS384</c> and <c>PS512</c>, RSASSA-PSS
/// with the same hashes (<see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">RFC 7518 Section
/// 3.5</see>). Every other pair of an RSA name and an RSA key tag is refused, as
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see> asks:
/// "Moreover, each key MUST be used with exactly one algorithm, and this MUST be checked when the
/// cryptographic operation is performed."
/// </para>
/// <para>
/// The table binds an algorithm to a key algorithm and holds no size of a public key. The size floor of
/// the RSA algorithms is for the code that reads or uses an RSA public key to hold, not for this table:
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">RFC 7518 Section 3.3</see> says "A key
/// of size 2048 bits or larger MUST be used with these algorithms." and
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Section 3.5</see> says "A key of size
/// 2048 bits or larger MUST be used with this algorithm."
/// </para>
/// <para>
/// <c>ESB256</c>, <c>ESB320</c>, <c>ESB384</c> and <c>ESB512</c> are COSE algorithms:
/// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.2.1">RFC 9864 Section 4.2.1</see>
/// registers them in the COSE Algorithms registry, and no JOSE registration names them. This library
/// also accepts them as JOSE <c>alg</c> values, as its catalogue <see cref="WellKnownJwaValues"/> does,
/// each bound to the Brainpool curve its registration names: brainpoolP256r1, brainpoolP320r1,
/// brainpoolP384r1 and brainpoolP512r1. <c>ML-DSA-44</c>, <c>ML-DSA-65</c> and <c>ML-DSA-87</c> bind the
/// ML-DSA key algorithm of the same parameter set. A key algorithm no JWS algorithm is defined over binds
/// none: the X25519 key agreement curve, brainpoolP224r1, the BLS12-381, ML-KEM and symmetric key
/// algorithms among them, and the ISO/IEC 9796-2 RSA key algorithm
/// <see cref="CryptoAlgorithm.RsaIso9796d2"/>, whose signature scheme with message recovery is no JWS
/// algorithm.
/// </para>
/// </remarks>
public static class JwsAlgorithmKeyBinding
{
    /// <summary>
    /// Whether <paramref name="alg"/> is an algorithm of a public key tagged <paramref name="keyAlgorithm"/>:
    /// <c>ES256</c> over P-256, <c>ES384</c> over P-384, <c>ES512</c> over P-521, <c>ES256K</c> over
    /// secp256k1, <c>EdDSA</c> and <c>Ed25519</c> over Ed25519, <c>RS256</c> over the RSA size tags
    /// <see cref="CryptoAlgorithm.Rsa2048"/> and <see cref="CryptoAlgorithm.Rsa4096"/> and over
    /// <see cref="CryptoAlgorithm.RsaSha256"/>, <c>PS256</c> over <see cref="CryptoAlgorithm.RsaSha256Pss"/>,
    /// <c>RS384</c> over <see cref="CryptoAlgorithm.RsaSha384"/>, <c>PS384</c> over
    /// <see cref="CryptoAlgorithm.RsaSha384Pss"/>, <c>RS512</c> over <see cref="CryptoAlgorithm.RsaSha512"/>,
    /// <c>PS512</c> over <see cref="CryptoAlgorithm.RsaSha512Pss"/>, <c>ESB256</c>, <c>ESB320</c>,
    /// <c>ESB384</c> and <c>ESB512</c> over brainpoolP256r1, brainpoolP320r1, brainpoolP384r1 and
    /// brainpoolP512r1, and <c>ML-DSA-44</c>, <c>ML-DSA-65</c> and <c>ML-DSA-87</c> over the ML-DSA key
    /// algorithm of the same parameter set.
    /// </summary>
    /// <param name="alg">
    /// The declared algorithm, compared as the case-sensitive string
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see> makes
    /// it; <see langword="null"/> when a header carries no <c>alg</c>.
    /// </param>
    /// <param name="keyAlgorithm">The algorithm the verifying public key is tagged with.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="alg"/> is an algorithm of a public key tagged
    /// <paramref name="keyAlgorithm"/>; otherwise <see langword="false"/>: a <see langword="null"/> name
    /// answers <see langword="false"/> like any value the table does not name, and so do <c>none</c>, a MAC
    /// algorithm and any name over a key algorithm no JWS algorithm is defined over.
    /// </returns>
    public static bool IsAlgorithmOfKey(string? alg, CryptoAlgorithm keyAlgorithm) => alg switch
    {
        string when WellKnownJwaValues.IsEs256(alg) => keyAlgorithm == CryptoAlgorithm.P256,
        string when WellKnownJwaValues.IsEs384(alg) => keyAlgorithm == CryptoAlgorithm.P384,
        string when WellKnownJwaValues.IsEs512(alg) => keyAlgorithm == CryptoAlgorithm.P521,
        string when WellKnownJwaValues.IsEs256K(alg) => keyAlgorithm == CryptoAlgorithm.Secp256k1,
        string when WellKnownJwaValues.IsEdDsa(alg) => keyAlgorithm == CryptoAlgorithm.Ed25519,
        string when WellKnownJwaValues.IsEd25519(alg) => keyAlgorithm == CryptoAlgorithm.Ed25519,
        string when WellKnownJwaValues.IsRs256(alg) => keyAlgorithm == CryptoAlgorithm.Rsa2048
            || keyAlgorithm == CryptoAlgorithm.Rsa4096
            || keyAlgorithm == CryptoAlgorithm.RsaSha256,
        string when WellKnownJwaValues.IsPs256(alg) => keyAlgorithm == CryptoAlgorithm.RsaSha256Pss,
        string when WellKnownJwaValues.IsRs384(alg) => keyAlgorithm == CryptoAlgorithm.RsaSha384,
        string when WellKnownJwaValues.IsPs384(alg) => keyAlgorithm == CryptoAlgorithm.RsaSha384Pss,
        string when WellKnownJwaValues.IsRs512(alg) => keyAlgorithm == CryptoAlgorithm.RsaSha512,
        string when WellKnownJwaValues.IsPs512(alg) => keyAlgorithm == CryptoAlgorithm.RsaSha512Pss,
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
