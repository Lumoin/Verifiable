namespace Verifiable.JCose;

/// <summary>
/// Buffer size constants for pre-calculating the exact byte length of canonical
/// JWK JSON representations before renting from a memory pool.
/// </summary>
/// <remarks>
/// <para>
/// Each constant is the fixed overhead for the JSON structure of a given key type,
/// excluding the variable-length field values. Add the UTF-8 byte counts of all
/// field values to obtain the total required buffer length.
/// </para>
/// <para>
/// Used by <see cref="JwkThumbprintUtilities"/> and <see cref="EphemeralEncryptionKeyPair"/>
/// to avoid over-allocating when writing into pooled memory.
/// </para>
/// </remarks>
public static class JwkTemplateConstants
{
    /// <summary>
    /// SHA-256 hash output size in bytes. Used for JWK thumbprint computation per RFC 7638.
    /// </summary>
    public const int Sha256HashSizeInBytes = 32;
    /// <summary>
    /// Fixed JSON overhead for EC keys: <c>{"crv":"","kty":"","x":"","y":""}</c>.
    /// </summary>
    public const int EcTemplateOverhead = 46;

    /// <summary>
    /// Fixed JSON overhead for OKP keys: <c>{"crv":"","kty":"","x":""}</c>.
    /// </summary>
    public const int OkpTemplateOverhead = 32;

    /// <summary>
    /// Fixed JSON overhead for RSA keys: <c>{"e":"","kty":"","n":""}</c>.
    /// </summary>
    public const int RsaTemplateOverhead = 32;

    /// <summary>
    /// Fixed JSON overhead for symmetric keys: <c>{"k":"","kty":""}</c>.
    /// </summary>
    public const int OctTemplateOverhead = 20;

    /// <summary>
    /// Fixed JSON overhead for post-quantum keys: <c>{"alg":"","kty":"","x":""}</c>.
    /// Used for ML-DSA, ML-KEM, and SLH-DSA.
    /// </summary>
    public const int PqcTemplateOverhead = 32;

    /// <summary>
    /// Additional overhead for a <c>"use":"enc"</c> property including the leading comma:
    /// <c>,"use":"enc"</c> is 12 bytes.
    /// </summary>
    public const int UseEncOverhead = 12;

    /// <summary>
    /// Additional overhead for wrapping a single JWK inside a JWKS keys array:
    /// <c>{"keys":[</c> and <c>]}</c> is 11 bytes.
    /// </summary>
    public const int JwksArrayOverhead = 11;

    /// <summary>
    /// Expected base64url-encoded length of a P-256 coordinate (32 bytes → 43 characters).
    /// </summary>
    public const int P256CoordinateLength = 43;

    /// <summary>
    /// Expected base64url-encoded length of a P-384 coordinate (48 bytes → 64 characters).
    /// </summary>
    public const int P384CoordinateLength = 64;

    /// <summary>
    /// Expected base64url-encoded length of a P-521 coordinate (66 bytes → 88 characters).
    /// </summary>
    public const int P521CoordinateLength = 88;

    /// <summary>
    /// Expected base64url-encoded length of a secp256k1 coordinate (32 bytes → 43 characters).
    /// </summary>
    public const int Secp256k1CoordinateLength = 43;

    /// <summary>
    /// Expected base64url-encoded length of an Ed25519 public key (32 bytes → 43 characters).
    /// </summary>
    public const int Ed25519KeyLength = 43;

    /// <summary>
    /// Expected base64url-encoded length of an X25519 public key (32 bytes → 43 characters).
    /// </summary>
    public const int X25519KeyLength = 43;

    /// <summary>
    /// Standard RSA public exponent 65537 in base64url encoding.
    /// </summary>
    public const string RsaStandardExponent = "AQAB";
}
