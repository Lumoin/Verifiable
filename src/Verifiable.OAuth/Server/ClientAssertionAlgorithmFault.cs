namespace Verifiable.OAuth.Server;

/// <summary>
/// The hold a <c>private_key_jwt</c> client assertion's <c>alg</c> header failed, in the order the
/// validators <see cref="PrivateKeyJwtClientAuthentication"/> builds apply them. Each refuses the
/// assertion before any key verifies its signature, and is recorded by name under
/// <see cref="Diagnostics.OAuthEventNames.ClientAssertionAlgorithmFaultTagName"/> on a
/// <see cref="Diagnostics.OAuthEventNames.ClientAssertionAlgorithmRefused"/> event.
/// </summary>
/// <remarks>
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 section 3.1</see>:
/// "Libraries MUST enable the caller to specify a supported set of algorithms and MUST NOT use any
/// other algorithms when performing cryptographic operations. The library MUST ensure that the "alg"
/// or "enc" header specifies the same algorithm that is used for the cryptographic operation.
/// Moreover, each key MUST be used with exactly one algorithm, and this MUST be checked when the
/// cryptographic operation is performed."
/// </remarks>
public enum ClientAssertionAlgorithmFault
{
    /// <summary>
    /// The authorization server states the algorithms it supports for client assertions, the
    /// <c>token_endpoint_auth_signing_alg_values_supported</c> its discovery publishes, and the
    /// assertion names another.
    /// </summary>
    UnsupportedAlgorithm,

    /// <summary>
    /// The client's registered metadata names a <c>token_endpoint_auth_signing_alg</c> and the
    /// assertion names another.
    /// <see href="https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata">OpenID
    /// Connect Dynamic Client Registration 1.0 section 2</see>: "All Token Requests using these
    /// authentication methods from this Client MUST be rejected, if the JWT is not signed with this
    /// algorithm."
    /// </summary>
    RegisteredAlgorithmMismatch,

    /// <summary>
    /// The key the assertion selects carries an <c>alg</c> member naming another algorithm.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.4">RFC 7517 section 4.4</see>:
    /// "The "alg" (algorithm) parameter identifies the algorithm intended for use with the key."
    /// </summary>
    KeyAlgorithmMismatch,

    /// <summary>
    /// The algorithm is not an algorithm of the key the assertion selects
    /// (<see cref="JCose.JwsAlgorithmKeyBinding.IsAlgorithmOfKey"/>), so it does not name the
    /// verification that key would run.
    /// </summary>
    AlgorithmNotOfKey
}
