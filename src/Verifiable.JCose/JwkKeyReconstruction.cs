using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>Why a JWK states no public key the library reconstructs (RFC 7517 section 4, RFC 7518 section 6).</summary>
public enum JwkPublicKeyFailureKind
{
    /// <summary>
    /// A member the key's type requires is absent: <c>kty</c>; <c>crv</c>, <c>x</c> and <c>y</c> of an EC key; <c>crv</c> and
    /// <c>x</c> of an OKP key; <c>n</c> and <c>e</c> of an RSA key; <c>pub</c> of an AKP key.
    /// </summary>
    MemberAbsent,

    /// <summary>
    /// A member defined as a string is present as a JSON value of another type: one of the required members above, or the
    /// optional <c>alg</c>.
    /// </summary>
    MemberNotAString,

    /// <summary>A member defined as base64url text (RFC 7518 sections 6.2.1, 6.3.1 and RFC 8037 section 2) is text the decoder refuses as no base64url.</summary>
    MemberNotBase64UrlText,

    /// <summary>The <c>kty</c> names a key type the library reconstructs no key of.</summary>
    UnsupportedKeyType,

    /// <summary>The key's curve, algorithm or size is none the library reconstructs a key of its type for.</summary>
    UnsupportedCurveOrAlgorithm,

    /// <summary>
    /// The key's <c>alg</c> is one the library recognizes for no key of the curve its <c>crv</c> names: an ECDSA algorithm of
    /// another curve (RFC 7518 section 3.4), an EdDSA or key-agreement algorithm beside a curve of the other use (RFC 8037
    /// sections 3.1 and 3.2), or an algorithm of a key with no elliptic curve.
    /// </summary>
    CurveAndAlgorithmContradict,

    /// <summary>
    /// The coordinates of an EC key name no point of its curve: <c>x</c> and <c>y</c> are not each the full width of the curve's
    /// coordinate (RFC 7518 sections 6.2.1.2 and 6.2.1.3), or the point they name does not lie on the curve (NIST SP 800-186
    /// appendix D.1.1.1).
    /// </summary>
    NotAPointOfTheCurve,

    /// <summary>The RSA key's modulus <c>n</c> is no positive integer (RFC 8017 section 3.1).</summary>
    RsaModulusInvalid,

    /// <summary>The RSA key's public exponent <c>e</c> is not odd with <c>3 &lt;= e &lt; n</c> (RFC 8017 section 3.1).</summary>
    RsaPublicExponentInvalid
}


/// <summary>What the reconstruction of the public key a JWK states answers: the key, or the refusal of the JWK.</summary>
public abstract record JwkKeyReconstruction;


/// <summary>
/// The public key a JWK states, reconstructed: its algorithm, the purpose it serves, the encoding of its material and the
/// material itself, which passes to the receiver to own and dispose, typically by wrapping it in a <see cref="PublicKeyMemory"/>.
/// </summary>
/// <param name="Algorithm">The key's algorithm.</param>
/// <param name="Purpose">The purpose the key serves.</param>
/// <param name="Scheme">The encoding of the key's material: a compressed point for an EC key, DER for an RSA key, raw otherwise.</param>
/// <param name="KeyMaterial">The key's material, owned by the receiver.</param>
public sealed record JwkKeyReconstructed(CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> KeyMaterial) : JwkKeyReconstruction
{
    /// <summary>
    /// The public key this reconstruction states, tagged with its algorithm, purpose and encoding; it takes the key material's
    /// ownership, so the caller disposes the key and never the material apart from it.
    /// </summary>
    /// <returns>The public key, which the caller owns and disposes.</returns>
    public PublicKeyMemory ToPublicKeyMemory() => new(KeyMaterial, Tag.Create(Algorithm).With(Purpose).With(Scheme));
}


/// <summary>The refusal of a JWK that states no public key the library reconstructs.</summary>
/// <param name="FailureKind">Why the JWK states no such key.</param>
/// <param name="Description">The refusal's description, naming the member or rule.</param>
public sealed record JwkKeyRefused(JwkPublicKeyFailureKind FailureKind, string Description) : JwkKeyReconstruction;
