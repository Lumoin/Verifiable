namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Client metadata parameter name constants embedded in OID4VP authorization requests.
/// </summary>
/// <remarks>
/// These keys appear inside the <c>client_metadata</c> JSON object in the JAR.
/// </remarks>
public static class ClientMetadataParameters
{
    /// <summary>
    /// The verifier's JWK Set, containing the ephemeral encryption public key for
    /// <c>direct_post.jwt</c> responses. Each authorization request carries a fresh key.
    /// </summary>
    public const string Jwks = "jwks";

    /// <summary>
    /// The credential formats supported by the verifier, keyed by format identifier.
    /// </summary>
    public const string VpFormats = "vp_formats";

    /// <summary>
    /// The JWE algorithm for encrypting authorization responses.
    /// Must be <c>ECDH-ES</c> per HAIP 1.0.
    /// </summary>
    public const string EncryptedResponseAlg = "encrypted_response_alg";

    /// <summary>
    /// The JWE content encryption algorithm for authorization responses.
    /// Must be <c>A128GCM</c> or <c>A256GCM</c> per HAIP 1.0.
    /// </summary>
    public const string EncryptedResponseEnc = "encrypted_response_enc";
}
