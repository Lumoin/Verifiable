namespace Verifiable.Jose.SdJwt;

/// <summary>
/// Constants used in SD-JWT processing.
/// </summary>
public static class SdJwtConstants
{
    /// <summary>
    /// The claim name used to hold disclosure digests in objects.
    /// </summary>
    public const string SdClaimName = "_sd";

    /// <summary>
    /// The claim name used to specify the hash algorithm.
    /// </summary>
    public const string SdAlgorithmClaimName = "_sd_alg";

    /// <summary>
    /// The key used in array elements to hold disclosure digests.
    /// </summary>
    public const string ArrayDigestKey = "...";

    /// <summary>
    /// The separator character used in SD-JWT compact serialization.
    /// </summary>
    public const char Separator = '~';

    /// <summary>
    /// The default hash algorithm when <see cref="SdAlgorithmClaimName"/> is not specified.
    /// </summary>
    public const string DefaultHashAlgorithm = "sha-256";

    /// <summary>
    /// The type header value for Key Binding JWTs.
    /// </summary>
    public const string KeyBindingJwtType = "kb+jwt";

    /// <summary>
    /// The claim name for the SD-JWT hash in Key Binding JWTs.
    /// </summary>
    public const string SdHashClaimName = "sd_hash";

    /// <summary>
    /// The claim name for the nonce in Key Binding JWTs.
    /// </summary>
    public const string NonceClaim = "nonce";

    /// <summary>
    /// The recommended minimum salt entropy in bits.
    /// </summary>
    public const int RecommendedSaltEntropyBits = 128;

    /// <summary>
    /// The recommended salt length in bytes (128 bits / 8).
    /// </summary>
    public const int RecommendedSaltLengthBytes = 16;
}