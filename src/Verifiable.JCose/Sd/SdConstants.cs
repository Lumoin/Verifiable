namespace Verifiable.JCose.Sd;

/// <summary>
/// Constants used in selective disclosure tokens.
/// </summary>
/// <remarks>
/// <para>
/// These constants are shared between SD-JWT and SD-CWT formats.
/// Format-specific constants may be defined in their respective serializers.
/// </para>
/// </remarks>
public static class SdConstants
{
    /// <summary>
    /// The claim name used for selective disclosure digests in objects.
    /// </summary>
    /// <remarks>
    /// Per RFC 9901, the <c>_sd</c> claim contains an array of digests
    /// corresponding to the redacted claims.
    /// </remarks>
    public const string SdClaimName = "_sd";

    /// <summary>
    /// The claim name used for the hash algorithm identifier.
    /// </summary>
    /// <remarks>
    /// Per RFC 9901, the <c>_sd_alg</c> claim specifies the hash algorithm
    /// used for computing disclosure digests.
    /// </remarks>
    public const string SdAlgorithmClaimName = "_sd_alg";

    /// <summary>
    /// The key used for array element digests in the <c>...</c> object.
    /// </summary>
    /// <remarks>
    /// Per RFC 9901, array elements are replaced with <c>{"...": "&lt;digest&gt;"}</c>.
    /// </remarks>
    public const string ArrayDigestKey = "...";

    /// <summary>
    /// The default hash algorithm for disclosure digests.
    /// </summary>
    public const string DefaultHashAlgorithm = "sha-256";

    /// <summary>
    /// The separator character used in SD-JWT wire format.
    /// </summary>
    public const char JwtSeparator = '~';

    /// <summary>
    /// The typ header value for key binding JWTs.
    /// </summary>
    public const string KeyBindingJwtType = "kb+jwt";

    /// <summary>
    /// The claim name for the nonce in key binding.
    /// </summary>
    public const string NonceClaim = "nonce";

    /// <summary>
    /// The claim name for the SD hash in key binding.
    /// </summary>
    public const string SdHashClaim = "sd_hash";

    /// <summary>
    /// Minimum recommended salt length in bytes (128 bits).
    /// </summary>
    public const int MinimumSaltLengthBytes = 16;

    /// <summary>
    /// Default salt length in bytes (128 bits).
    /// </summary>
    public const int DefaultSaltLengthBytes = 16;


    /// <summary>
    /// Checks if a claim name is reserved and cannot be used in disclosures.
    /// </summary>
    /// <param name="claimName">The claim name to check.</param>
    /// <returns><c>true</c> if the claim name is reserved; otherwise, <c>false</c>.</returns>
    public static bool IsReservedClaimName(string claimName)
    {
        return claimName == SdClaimName || claimName == ArrayDigestKey;
    }
}